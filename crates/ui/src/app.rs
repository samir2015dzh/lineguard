use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use lineguard_agent::{Endpoint, call};
use lineguard_core::guard::State as GuardState;
use lineguard_core::{Command, Config, Diagnostic, MAX_IMPORT, Reply, Request, Snapshot, VERSION};
use std::{
    fs::File,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::Instant,
};

const BG: Color32 = Color32::from_rgb(16, 20, 28);
const PANEL: Color32 = Color32::from_rgb(23, 29, 39);
const RAISED: Color32 = Color32::from_rgb(30, 38, 50);
const LINE: Color32 = Color32::from_rgb(45, 55, 69);
const TEXT: Color32 = Color32::from_rgb(226, 233, 242);
const MUTED: Color32 = Color32::from_rgb(146, 160, 179);
const ACCENT: Color32 = Color32::from_rgb(143, 180, 215);
const AMBER: Color32 = Color32::from_rgb(226, 185, 123);
const BACKEND_MISSING: &str = "未找到本机后台";
const STRONG: Color32 = Color32::from_rgb(242, 246, 251);
const PRIMARY: Color32 = Color32::from_rgb(58, 96, 134);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Profiles,
    Diagnostics,
    Settings,
}
enum Job {
    Request(Request),
    /// After starting the background service: poll its console endpoint until it answers.
    AwaitBackend(Request),
    Import {
        path: String,
        generation: u64,
        id: u64,
    },
}
struct ResultMessage {
    id: u64,
    reply: Result<Reply, String>,
}

pub struct App {
    sender: SyncSender<Job>,
    receiver: Receiver<ResultMessage>,
    page: Page,
    changed: Instant,
    animations: bool,
    system_animations: bool,
    status: Option<Snapshot>,
    report: Option<Diagnostic>,
    pending: bool,
    sequence: u64,
    message: Option<(bool, String)>,
    path: String,
    /// Which endpoint the worker currently talks to; switched automatically when only the
    /// other one answers (unless `--console` pinned it).
    console: Arc<AtomicBool>,
    /// Background service this GUI started; killed with the GUI (kill-on-close Job).
    backend: Option<crate::backend::Backend>,
    backend_error: Option<String>,
    font_available: bool,
    core_info: Option<lineguard_core::engine::Info>,
    icon: egui::TextureHandle,
}
impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, console: bool) -> Self {
        let ctx = cc.egui_ctx.clone();
        // Always dark: egui would otherwise follow a light OS theme and mix light widgets and
        // black strong text into this dark layout.
        ctx.set_theme(egui::Theme::Dark);
        ctx.set_visuals_of(egui::Theme::Dark, visuals());
        ctx.style_mut_of(egui::Theme::Dark, |style| {
            style.spacing.item_spacing = Vec2::new(12.0, 12.0);
            style.spacing.button_padding = Vec2::new(16.0, 9.0);
            style.spacing.interact_size.y = 36.0;
            style.animation_time = 0.14;
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
            style
                .text_styles
                .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
            style
                .text_styles
                .insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
        });
        let icon = ctx.load_texture(
            "lineguard-icon",
            egui::ColorImage::from_rgba_unmultiplied(
                [64, 64],
                include_bytes!("../../../assets/lineguard-64.rgba"),
            ),
            egui::TextureOptions::LINEAR,
        );
        let font_available = load_font(&ctx);
        let system_animations = system_animations();
        let (sender, jobs) = mpsc::sync_channel::<Job>(2);
        let (results, receiver) = mpsc::sync_channel(2);
        let worker_ctx = ctx.clone();
        let mode = Arc::new(AtomicBool::new(console));
        let worker_mode = mode.clone();
        std::thread::spawn(move || {
            while let Ok(job) = jobs.recv() {
                let mut wait = false;
                let (id, request) = match job {
                    Job::Request(request) => (request.id, Ok(request)),
                    Job::AwaitBackend(request) => {
                        wait = true;
                        (request.id, Ok(request))
                    }
                    Job::Import {
                        path,
                        generation,
                        id,
                    } => {
                        let result = (|| {
                            let mut input = Vec::new();
                            File::open(path)
                                .map_err(|_| "无法读取离线文件")?
                                .take((MAX_IMPORT + 1) as u64)
                                .read_to_end(&mut input)
                                .map_err(|_| "读取文件失败")?;
                            let config = Config::parse(&input);
                            lineguard_core::wipe(&mut input);
                            let config = config
                                .map_err(|_| "配置无效：只接受版本 1 离线 JSON，最多 64 KiB")?;
                            Ok(Request {
                                version: VERSION,
                                id,
                                command: Command::Import {
                                    expected_generation: generation,
                                    config,
                                },
                            })
                        })();
                        (id, result.map_err(str::to_owned))
                    }
                };
                let reply = request.and_then(|request| {
                    if wait {
                        // The service we just started needs a moment to open its pipe.
                        for _ in 0..25 {
                            let Some(attempt) = resend(&request) else {
                                break;
                            };
                            if let Ok(r) = call(Endpoint { console: true }, attempt) {
                                worker_mode.store(true, Ordering::Relaxed);
                                return Ok(r.result);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                        return Err(BACKEND_MISSING.into());
                    }
                    let first = worker_mode.load(Ordering::Relaxed);
                    let fallback = resend(&request);
                    match call(Endpoint { console: first }, request) {
                        Ok(r) => Ok(r.result),
                        Err(_) if !console && fallback.is_some() => {
                            // Try the other endpoint: an installed service or a per-user one.
                            let r = call(Endpoint { console: !first }, fallback.unwrap())
                                .map_err(|_| BACKEND_MISSING.to_string())?;
                            worker_mode.store(!first, Ordering::Relaxed);
                            Ok(r.result)
                        }
                        Err(_) => Err(BACKEND_MISSING.into()),
                    }
                });
                if results.send(ResultMessage { id, reply }).is_err() {
                    break;
                }
                worker_ctx.request_repaint();
            }
        });
        let mut app = Self {
            sender,
            receiver,
            page: Page::Home,
            changed: Instant::now(),
            animations: system_animations,
            system_animations,
            status: None,
            report: None,
            pending: false,
            sequence: 0,
            message: None,
            path: String::new(),
            console: mode,
            backend: None,
            backend_error: None,
            font_available,
            core_info: None,
            icon,
        };
        app.submit(Command::Status);
        app
    }
    fn submit(&mut self, command: Command) {
        if self.pending {
            return;
        }
        self.sequence += 1;
        let request = Request {
            version: VERSION,
            id: self.sequence,
            command,
        };
        if self.sender.try_send(Job::Request(request)).is_ok() {
            self.pending = true;
        }
    }
    fn import(&mut self) {
        if self.pending {
            return;
        }
        let Some(snapshot) = &self.status else {
            self.message = Some((true, "先连接服务，才能导入配置".into()));
            return;
        };
        self.sequence += 1;
        let job = Job::Import {
            path: self.path.clone(),
            generation: snapshot.generation,
            id: self.sequence,
        };
        if self.sender.try_send(job).is_ok() {
            self.pending = true;
        }
    }
    fn drain(&mut self) {
        while let Ok(result) = self.receiver.try_recv() {
            if result.id != self.sequence {
                continue;
            }
            self.pending = false;
            match result.reply {
                Ok(Reply::Status { snapshot }) => {
                    self.status = Some(snapshot);
                }
                Ok(Reply::Imported { snapshot }) => {
                    self.status = Some(snapshot);
                    self.path.clear();
                    self.message = Some((
                        false,
                        "离线配置已加密保存；此操作不改变实验阻断规则。".into(),
                    ));
                }
                Ok(Reply::Diagnostics { report }) => {
                    self.report = Some(report);
                    self.page = Page::Diagnostics;
                }
                Ok(Reply::CoreInfo { info }) => {
                    self.core_info = Some(info);
                }
                Ok(Reply::CoreChecked { report }) => {
                    let healthy = report.syntax_accepted
                        && report.guard_after.state == GuardState::Configured
                        && !report.tunnel_started;
                    self.message = Some((!healthy, report.detail));
                }
                Ok(Reply::Failure { message, .. }) => {
                    self.message = Some((true, message));
                }
                Err(message) => {
                    // A missing backend gets its own card with a start button, not an error banner.
                    if message != BACKEND_MISSING {
                        self.message = Some((true, message));
                    }
                    self.status = None;
                }
            }
        }
    }
    /// One click instead of opening the service by hand: start the per-user background
    /// service next to this GUI, then wait for its pipe.
    fn start_backend(&mut self) {
        if self.pending || self.backend.is_some() {
            return;
        }
        match crate::backend::Backend::start() {
            Ok(backend) => {
                self.backend = Some(backend);
                self.backend_error = None;
                self.sequence += 1;
                let request = Request {
                    version: VERSION,
                    id: self.sequence,
                    command: Command::Status,
                };
                if self.sender.try_send(Job::AwaitBackend(request)).is_ok() {
                    self.pending = true;
                }
            }
            Err(e) => self.backend_error = Some(format!("无法启动后台：{e}")),
        }
    }
    fn backend_card(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(Color32::from_rgb(28, 34, 46))
            .stroke(Stroke::new(1.0, AMBER.gamma_multiply(0.45)))
            .corner_radius(14)
            .inner_margin(20)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("后台未运行").size(18.0).strong());
                        ui.label(
                            RichText::new(
                                "界面需要本机后台读取状态和保存配置。点击启动即可，无需手动打开其他程序。",
                            )
                            .color(MUTED),
                        );
                        ui.label(
                            RichText::new(
                                "以当前用户运行预览后台：不安装服务、不改网络；关闭界面时一起退出。",
                            )
                            .size(12.0)
                            .color(MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = if self.pending && self.backend.is_some() {
                            "正在启动…"
                        } else {
                            "启动本机后台"
                        };
                        if ui
                            .add_enabled(
                                !self.pending,
                                primary(label).min_size(Vec2::new(150.0, 40.0)),
                            )
                            .clicked()
                        {
                            self.start_backend();
                        }
                    });
                });
                if let Some(error) = &self.backend_error {
                    ui.label(RichText::new(error).color(AMBER));
                }
            });
        ui.add_space(14.0);
    }
    fn navigate(&mut self, page: Page) {
        if self.page != page {
            self.page = page;
            self.changed = Instant::now();
        }
    }
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .exact_size(204.0)
            .resizable(false)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(22))
            .show(ui, |ui| {
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(
                        self.icon.id(),
                        [30.0, 30.0],
                    )));
                    ui.label(RichText::new("LineGuard").size(21.0).strong());
                });
                ui.add_space(4.0);
                ui.label(RichText::new("私密连接 · 本机掌控").size(12.0).color(MUTED));
                ui.add_space(40.0);
                for (page, label, hint) in [
                    (Page::Home, "总览", "01"),
                    (Page::Profiles, "离线线路", "02"),
                    (Page::Diagnostics, "诊断", "03"),
                    (Page::Settings, "偏好设置", "04"),
                ] {
                    let selected = self.page == page;
                    let text = RichText::new(format!("{hint}    {label}")).color(if selected {
                        TEXT
                    } else {
                        MUTED
                    });
                    let button = egui::Button::new(text)
                        .fill(if selected {
                            RAISED
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(if selected {
                            Stroke::new(1.0, LINE)
                        } else {
                            Stroke::NONE
                        })
                        .corner_radius(9);
                    let response = ui.add_sized([160.0, 45.0], button);
                    let hover = ui.ctx().animate_bool_with_time(
                        response.id.with("hover"),
                        response.hovered(),
                        if self.animations && self.system_animations {
                            0.12
                        } else {
                            0.0
                        },
                    );
                    if hover > 0.0 {
                        ui.painter().line_segment(
                            [response.rect.left_bottom(), response.rect.right_bottom()],
                            Stroke::new(hover, ACCENT.gamma_multiply(hover * 0.4)),
                        );
                    }
                    if response.clicked() {
                        self.navigate(page);
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new(concat!("v", env!("CARGO_PKG_VERSION"), " · 未验证开发预览"))
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(if self.console.load(Ordering::Relaxed) {
                            "本机后台 · 当前用户"
                        } else {
                            "系统服务 · 按需刷新"
                        })
                        .size(11.0)
                        .color(ACCENT),
                    );
                    ui.add_space(10.0);
                    ui.separator();
                });
            });
    }
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                let (title, subtitle) = match self.page {
                    Page::Home => (
                        "连接的每一步，都应清楚可见",
                        "固定核心管理 · 数据通路尚不可用，不代表已保护",
                    ),
                    Page::Profiles => {
                        ("离线线路", "配置只保存在本机；本预览不会连接节点或下载订阅")
                    }
                    Page::Diagnostics => (
                        "可解释，而不泄露秘密",
                        "只导出白名单字段，不含节点地址、名称、密码或文件路径",
                    ),
                    Page::Settings => (
                        "让界面安静工作",
                        "按需绘制，无浏览器运行时；不以动效掩盖实际状态",
                    ),
                };
                ui.label(RichText::new(title).size(24.0).strong());
                ui.add_space(4.0);
                ui.label(RichText::new(subtitle).size(13.0).color(MUTED));
            });
        });
        ui.add_space(24.0);
    }
    fn home(&mut self, ui: &mut egui::Ui) {
        let state = self
            .status
            .as_ref()
            .map(|s| s.guard.state)
            .unwrap_or(GuardState::Unknown);
        let (title, description) = match state {
            GuardState::Emergency => (
                "独立救援阻断保持 · 未验收",
                "6条持久规则，不依赖服务；没有启动期或防泄露运行验证",
            ),
            GuardState::Configured => (
                "阻断规则完整 · 未验收",
                "最近回读：6 条持久 + 6 条启动期注册；这不是隧道或防泄露认证",
            ),
            GuardState::Narrowed => (
                "实验窄许可存在 · 不是全阻断",
                "M2基线+v3窄许可回读完整：仅TUN与单一节点被策略允许；执行效果、旁路与泄露均未验收",
            ),
            GuardState::Absent => ("尚未安装阻断", "最近回读未发现本产品规则；现有网络仍可直连"),
            GuardState::Drift => (
                "阻断证据不完整",
                "仍可能部分断网；规则或服务配置异常，请独立 inspect / rescue",
            ),
            GuardState::Unknown => (
                "阻断状态未知",
                "无法取得当前 WFP 证据；不能假定已保护或已解除",
            ),
        };
        let rule_count = self
            .status
            .as_ref()
            .filter(|s| s.guard.state != GuardState::Unknown)
            .map(|s| {
                format!(
                    "{} / {}",
                    s.guard.persistent_rules + s.guard.boot_rules,
                    s.guard.expected_rules
                )
            })
            .unwrap_or_else(|| "—".into());
        card().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                emblem(ui, 74.0, AMBER);
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(28.0).strong());
                    ui.add_space(5.0);
                    ui.label(RichText::new(description).color(AMBER));
                    if let Some(status) = &self.status {
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(&status.network.detail)
                                .size(12.0)
                                .color(MUTED),
                        );
                    }
                    ui.label(
                        RichText::new("默认不改网络；管理员实验命令可持续切断 IP 联网。")
                            .size(13.0)
                            .color(MUTED),
                    );
                });
            });
            ui.add_space(25.0);
            ui.separator();
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_enabled(
                    false,
                    primary("连接隧道 · 尚不可用").min_size(Vec2::new(210.0, 40.0)),
                )
                .on_disabled_hover_text(
                    "Connect 返回 Unsupported，不修改网络或已存在的管理员实验规则。",
                );
                if ui
                    .add_enabled(!self.pending, egui::Button::new("刷新本机状态"))
                    .clicked()
                {
                    self.submit(Command::Status);
                }
                if self.pending {
                    ui.label(RichText::new("正在读取…").color(MUTED));
                }
            });
        });
        ui.add_space(12.0);
        let count = self
            .status
            .as_ref()
            .map(|s| s.profiles.len().to_string())
            .unwrap_or_else(|| "—".into());
        let service = if self.status.is_some() {
            "最近可达"
        } else {
            "未读取"
        };
        ui.columns(3, |columns| {
            metric(
                &mut columns[0],
                "本机离线线路",
                &count,
                "不是在线节点检测结果",
            );
            metric(&mut columns[1], "可信后台", service, "按需刷新，非实时监测");
            metric(
                &mut columns[2],
                "最近匹配规则数",
                &rule_count,
                "存储字段证据，非流量验收",
            );
        });
        ui.add_space(16.0);
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("受控核心 · 离线优先").size(17.0).strong());
                    ui.label(
                        RichText::new("mihomo 1.19.34 / SHA256固定；未捆绑、未下载、未启动TUN")
                            .size(12.0)
                            .color(MUTED),
                    );
                });
                if ui
                    .add_enabled(!self.pending, egui::Button::new("校验本机核心文件"))
                    .clicked()
                {
                    self.submit(Command::CoreInfo);
                }
            });
            if let Some(info) = self
                .core_info
                .as_ref()
                .or_else(|| self.status.as_ref().map(|s| &s.core))
            {
                ui.add_space(8.0);
                let text = match info.integrity {
                    lineguard_core::engine::Integrity::NotChecked => "尚未校验",
                    lineguard_core::engine::Integrity::Missing => "尚未离线导入",
                    lineguard_core::engine::Integrity::Verified => {
                        "最近文件摘要匹配 · 非运行保护证明"
                    }
                    lineguard_core::engine::Integrity::Rejected => "校验失败 · 拒绝执行",
                };
                ui.label(RichText::new(text).color(AMBER));
                ui.label(
                    RichText::new(if info.license_confirmed {
                        "有管理员显式许可导入收据"
                    } else {
                        "尚无有效许可导入收据"
                    })
                    .size(12.0)
                    .color(MUTED),
                );
                ui.label(RichText::new(&info.detail).size(12.0).color(MUTED));
            }
            ui.label(
                RichText::new(
                    "管理员仅可做隔离配置检查。精确WFP + 独占TUN及独立恢复未闭合，连接保持禁用。",
                )
                .size(12.0)
                .color(AMBER),
            );
        });
        ui.add_space(16.0);
        card().show(ui, |ui| {
            ui.label(RichText::new("危险操作隔离在管理员终端").size(17.0).strong());
            ui.add_space(6.0);
            ui.label(
                RichText::new("独立救援：lineguard-rescue remove --confirm ALLOW-DIRECT")
                    .color(ACCENT),
            );
            ui.label(
                RichText::new(
                    "实验阻断没有 LAN / DHCP / 节点例外。不能联网时先在本机管理员终端独立救援；关闭界面不会撤规则。",
                )
                .size(13.0)
                .color(MUTED),
            );
            if ui.button("管理离线配置  →").clicked() {
                self.navigate(Page::Profiles);
            }
        });
    }
    fn profiles(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.label(RichText::new("导入本地 JSON").size(18.0).strong());
            ui.label(
                RichText::new("仅版本 1 / IP 端点 / 3 种 SS AEAD 密码算法；不会验证线路可用性。")
                    .size(13.0)
                    .color(MUTED),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .hint_text("选择离线配置文件，不在此粘贴密码")
                        .char_limit(4096)
                        .desired_width((ui.available_width() - 100.0).max(100.0)),
                );
                if ui.button("浏览…").clicked() {
                    if let Some(path) = pick_file() {
                        self.path = path;
                    }
                }
            });
            if ui
                .add_enabled(
                    !self.pending && self.status.is_some() && !self.path.is_empty(),
                    primary("校验并加密保存"),
                )
                .clicked()
            {
                self.import();
            }
            ui.label(
                RichText::new(
                    "将替换整个离线配置列表。原始导入文件不会被删除或加密，请自行妥善保管。",
                )
                .size(12.0)
                .color(AMBER),
            );
        });
        ui.add_space(16.0);
        let profiles = self
            .status
            .as_ref()
            .map(|s| s.profiles.as_slice())
            .unwrap_or(&[]);
        if profiles.is_empty() {
            card().show(ui, |ui| { ui.add_space(18.0); ui.label(RichText::new("还没有保存的线路").size(18.0)); ui.label(RichText::new("使用 examples/offline.example.json 了解格式。示例只用于结构校验，不含可用账号。").color(MUTED)); ui.add_space(18.0); });
        } else {
            for (i, profile) in profiles.iter().enumerate() {
                card().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:02}", i + 1)).color(MUTED));
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&profile.name).strong());
                            ui.label(
                                RichText::new(format!(
                                    "{}:{} · {}",
                                    profile.server,
                                    profile.port,
                                    profile.method.as_str()
                                ))
                                .size(12.0)
                                .color(MUTED),
                            );
                        });
                        ui.label(RichText::new("已保存 · 未连接").color(ACCENT));
                    });
                });
            }
        }
    }
    fn diagnostics(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.label(RichText::new("白名单诊断报告").size(18.0).strong());
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.pending, egui::Button::new("读取诊断")).clicked() { self.submit(Command::Diagnostics); }
                if let Some(report) = &self.report {
                    if ui.button("复制脱敏报告").clicked() { if let Ok(json) = serde_json::to_string_pretty(report) { ui.ctx().copy_text(json); self.message = Some((false, "已复制脱敏诊断到剪贴板".into())); } }
                }
            });
            ui.label(RichText::new("这不是泄露测试；探针、抓包和 30 项检查尚未实现。").color(AMBER));
            if let Some(report) = &self.report {
                ui.add_space(12.0);
                let text = format!("产品             {}\\n版本             {}\\n配置代次         {}\\n已保存线路       {}\\n存储读取异常     {}\\n隧道能力         尚未实现\\nWFP策略          {:?}\\n持久/启动期       {} / {}", report.product, report.version, report.generation, report.profile_count, if report.storage_error { "是" } else { "否" }, report.guard.state, report.guard.persistent_rules, report.guard.boot_rules);
                ui.label(RichText::new(text.replace("\\n", "\n")).monospace().color(MUTED));
            } else { ui.label(RichText::new("按需生成报告，不扫描或上传本机信息。").color(MUTED)); }
        });
        ui.add_space(16.0);
        card().show(ui, |ui| {
            ui.label(RichText::new("独立只读急救工具").size(17.0));
            ui.label("lineguard-rescue.exe inspect");
            ui.label(
                RichText::new("不依赖后台：inspect 只读；管理员 remove --confirm ALLOW-DIRECT 只移除产品自有规则。")
                    .color(MUTED),
            );
        });
    }
    fn settings(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.label(RichText::new("动效与资源").size(18.0).strong());
            if ui.checkbox(&mut self.animations, "轻量界面动效").changed() {
                ui.ctx().style_mut_of(egui::Theme::Dark, |style| style.animation_time = if self.animations && self.system_animations { 0.14 } else { 0.0 });
            }
            ui.label(RichText::new(if self.system_animations { "系统允许动画；页面与悬停使用短过渡。" } else { "系统减少动画已生效（或无法读取设置），不播放页面过渡。" }).color(MUTED));
            ui.label(RichText::new("静止无固定帧率重绘；IPC 使用独立工作线程和有界队列。没有后台测速、自动更新或遥测。").color(MUTED));
            ui.add_space(12.0); ui.separator(); ui.add_space(8.0);
            ui.label(RichText::new("窗口行为").size(17.0));
            ui.label("本预览关闭窗口会退出界面，不会停止独立后台。");
            ui.label(RichText::new("托盘与窗口隐藏入口尚未实现；不会假装已经收至托盘。").color(AMBER));
            ui.add_space(12.0); ui.label(RichText::new("隐私与字体").size(17.0));
            ui.label(RichText::new("后台需解密载入配置；界面不接收已保存密码，诊断只返回白名单字段。使用本机微软雅黑，不打包整套中文字库。").color(MUTED));
            if !self.font_available { ui.label(RichText::new("未找到系统中文字体；请在 Windows 安装中文字体后重启界面。").color(AMBER)); }
        });
    }
}
impl eframe::App for App {
    fn logic(&mut self, _: &egui::Context, _: &mut eframe::Frame) {
        self.drain();
        if let Some(code) = self.backend.as_mut().and_then(|b| b.exited()) {
            self.backend = None;
            self.backend_error = Some(format!(
                "后台已退出（代码 {code}）。如果已有另一个后台在运行，请点“刷新本机状态”。"
            ));
        }
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let system = system_animations();
        if system != self.system_animations {
            self.system_animations = system;
        }
        ui.ctx().style_mut_of(egui::Theme::Dark, |style| {
            style.animation_time = if self.animations && system { 0.14 } else { 0.0 }
        });
        self.sidebar(ui);
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(30)).show(ui, |ui| {
            let elapsed = self.changed.elapsed().as_secs_f32();
            let animate = self.animations && self.system_animations && elapsed < 0.16;
            if animate { ui.ctx().request_repaint(); ui.add_space((1.0 - elapsed / 0.16).powi(3) * 5.0); }
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                self.header(ui);
                if let Some((error, message)) = &self.message {
                    let mut dismiss = false;
                    egui::Frame::new().fill(if *error { Color32::from_rgb(53, 38, 32) } else { RAISED }).corner_radius(8).inner_margin(12).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| { ui.label(RichText::new(message).color(if *error { AMBER } else { ACCENT })); if ui.small_button("关闭提示").clicked() { dismiss = true; } });
                    });
                    ui.add_space(14.0);
                    if dismiss { self.message = None; }
                }
                if self.status.is_none() {
                    self.backend_card(ui);
                }
                if self.status.as_ref().is_some_and(|s| s.storage_error) { ui.colored_label(AMBER, "保存配置读取失败：已锁定导入以免覆盖，原文件保留。请运行独立只读诊断。"); }
                match self.page { Page::Home => self.home(ui), Page::Profiles => self.profiles(ui), Page::Diagnostics => self.diagnostics(ui), Page::Settings => self.settings(ui) }
                ui.add_space(18.0);
                ui.label(RichText::new("危险开发预览 · 非 VPN 成品 · WFP 字段回读不等于阻断效果已验证。").size(11.0).color(MUTED));
            });
        });
    }
}
/// Only data-free requests are re-sent (to another endpoint or while a backend starts);
/// an import carries secrets and is never duplicated.
fn resend(request: &Request) -> Option<Request> {
    let command = match &request.command {
        Command::Status => Command::Status,
        Command::Diagnostics => Command::Diagnostics,
        Command::CoreInfo => Command::CoreInfo,
        _ => return None,
    };
    Some(Request {
        version: request.version,
        id: request.id,
        command,
    })
}
fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = BG;
    v.faint_bg_color = PANEL;
    v.code_bg_color = RAISED;
    v.override_text_color = Some(TEXT);
    v.weak_text_color = Some(MUTED);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = AMBER;
    v.selection.bg_fill = Color32::from_rgb(50, 76, 100);
    v.selection.stroke = Stroke::new(1.0, STRONG);
    v.window_stroke = Stroke::new(1.0, LINE);
    let radius = egui::CornerRadius::same(8);
    let w = &mut v.widgets;
    // Separators and frames use the non-interactive stroke; keep it a quiet line, not white.
    w.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    w.noninteractive.bg_fill = PANEL;
    w.noninteractive.weak_bg_fill = PANEL;
    w.inactive.bg_fill = RAISED;
    w.inactive.weak_bg_fill = RAISED;
    w.inactive.bg_stroke = Stroke::new(1.0, LINE);
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.hovered.bg_fill = Color32::from_rgb(40, 52, 68);
    w.hovered.weak_bg_fill = Color32::from_rgb(40, 52, 68);
    w.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.6));
    w.hovered.fg_stroke = Stroke::new(1.5, STRONG);
    w.hovered.expansion = 0.0;
    // `strong()` text uses the active foreground colour.
    w.active.bg_fill = Color32::from_rgb(48, 66, 86);
    w.active.weak_bg_fill = Color32::from_rgb(48, 66, 86);
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.5, STRONG);
    w.active.expansion = 0.0;
    w.open = w.active;
    for state in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        state.corner_radius = radius;
    }
    v
}
/// The one emphasised action per card.
fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(STRONG))
        .fill(PRIMARY)
        .stroke(Stroke::new(1.0, PRIMARY.gamma_multiply(1.3)))
        .corner_radius(9)
}
fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(14)
        .inner_margin(22)
}
fn metric(ui: &mut egui::Ui, label: &str, value: &str, note: &str) {
    card().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.label(RichText::new(label).size(12.0).color(MUTED));
        ui.label(RichText::new(value).size(24.0).strong());
        ui.label(RichText::new(note).size(11.0).color(MUTED));
    });
}
fn emblem(ui: &mut egui::Ui, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let point = |x: f32, y: f32| rect.min + Vec2::new(x * size, y * size);
    let points = vec![
        point(0.5, 0.08),
        point(0.85, 0.23),
        point(0.81, 0.63),
        point(0.68, 0.80),
        point(0.5, 0.92),
        point(0.32, 0.80),
        point(0.19, 0.63),
        point(0.15, 0.23),
    ];
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        color.gamma_multiply(0.08),
        Stroke::new(1.5, color),
    ));
    ui.painter().line_segment(
        [point(0.5, 0.33), point(0.5, 0.58)],
        Stroke::new(2.0, color),
    );
    ui.painter().circle_filled(point(0.5, 0.70), 1.7, color);
}
fn system_animations() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
    };
    let mut enabled: i32 = 0;
    unsafe {
        SystemParametersInfoW(
            SPI_GETCLIENTAREAANIMATION,
            0,
            (&mut enabled as *mut i32).cast(),
            0,
        ) != 0
            && enabled != 0
    }
}
fn load_font(ctx: &egui::Context) -> bool {
    // Read a single system font, capped at 32 MiB; no remote font downloads or bundled CJK families.
    let Some(root) = std::env::var_os("WINDIR") else {
        return false;
    };
    let path = std::path::PathBuf::from(root)
        .join("Fonts")
        .join("msyh.ttc");
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    if file.metadata().map_or(true, |m| m.len() > 32 * 1024 * 1024) {
        return false;
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return false;
    }
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "system-cjk".into(),
        egui::FontData::from_owned(bytes).into(),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "system-cjk".into());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("system-cjk".into());
    ctx.set_fonts(fonts);
    true
}
fn pick_file() -> Option<String> {
    use windows_sys::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_DONTADDTORECENT, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR,
        OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };
    let mut buffer = vec![0u16; 4096];
    let filter: Vec<u16> = "JSON 离线配置\0*.json\0\0".encode_utf16().collect();
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    dialog.lpstrFilter = filter.as_ptr();
    dialog.lpstrFile = buffer.as_mut_ptr();
    dialog.nMaxFile = buffer.len() as u32;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        return None;
    }
    let len = buffer.iter().position(|c| *c == 0)?;
    Some(String::from_utf16_lossy(&buffer[..len]))
}
