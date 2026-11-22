//! Fixed core process lifetime. Network effects are exclusively owned by the network journal.
use super::{
    security::{self, Descriptor, Handle, wide},
    storage::Store,
    wfp,
};
use lineguard_core::{
    Profile,
    engine::{self, CheckReport, Info, Integrity},
};
use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_OBJECT_0},
    Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, WriteFile,
    },
    System::{
        JobObjects::*,
        Pipes::{CreatePipe, GetNamedPipeInfo},
        SystemInformation::GetSystemDirectoryW,
        Threading::*,
    },
};
fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn path_wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub fn info() -> Info {
    let mut result = Info::default();
    let inspect = (|| {
        let pin = engine::manifest().map_err(io::Error::other)?;
        let store = Store::core_assets(false)?;
        store.verified_core(&pin.core)?;
        store.core_license_confirmed(&pin.core)
    })();
    result.checked_at_unix_ms = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64,
    );
    match inspect {
        Ok(license_confirmed) => {
            result.license_confirmed = license_confirmed;
            result.integrity = Integrity::Verified;
            if !license_confirmed {
                result.detail =
                    "文件摘要匹配但无有效许可导入收据；禁止执行，请先阅读许可并显式离线导入".into();
                return result;
            }
            result.detail =
                "已按编译内置SHA256和大小校验本机核心；不是维护者签名/驱动签名/运行保护证明。"
                    .into();
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            result.integrity = Integrity::Missing;
            result.detail = "未离线导入固定核心；没有自动下载或执行。".into();
        }
        Err(_) => {
            result.integrity = Integrity::Rejected;
            result.detail =
                "核心/许可收据不可读、路径归属或摘要不符；拒绝执行，不记录敏感路径。".into();
        }
    }
    result
}
pub fn prepare_import() -> io::Result<std::path::PathBuf> {
    security::require_elevated_admin()?;
    let inbox = Store::core_inbox()?;
    Ok(inbox.directory().join("mihomo-candidate.exe"))
}
pub fn import(source: &Path, confirmation: &str) -> io::Result<Info> {
    security::require_elevated_admin()?;
    if confirmation != engine::IMPORT_INTENT {
        return Err(io::Error::other(
            "必须明确确认已阅读并接受第三方许可；未导入或执行",
        ));
    }
    // Never let an elevated importer open arbitrary user/UNC/device paths.
    // The operator stages the public binary into a separately admin-owned inbox first.
    let inbox = Store::core_inbox()?;
    let expected = inbox.directory().join("mihomo-candidate.exe");
    if !source
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.as_os_str().to_string_lossy())
    {
        return Err(io::Error::other(
            "仅接受core inbox返回的管理员专用目录中的mihomo-candidate.exe；先由管理员离线复制，再提供绝对路径",
        ));
    }
    let pin = engine::manifest().map_err(io::Error::other)?;
    let store = Store::core_assets(true)?;
    store.import_core(source, &pin.core)?;
    store.save_core_receipt(&serde_json::json!({"schema":1,"operation":"core_import",
        "core_version":pin.core.version,"sha256":pin.core.executable_sha256,
        "recorded_at_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64,
        "licenses_explicitly_confirmed":true,"executed":false,"tunnel_enabled":false})).map_err(|_|io::Error::other("核心文件已导入但许可收据写入失败；未执行。请先检查core info，不要假定整个导入成功"))?;
    drop(store);
    let evidence = info();
    if evidence.integrity != Integrity::Verified || !evidence.license_confirmed {
        return Err(io::Error::other("核心或许可收据复制后回读失败，未执行"));
    }
    Ok(evidence)
}

struct Attributes {
    bytes: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new() -> io::Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut size);
        }
        if size == 0 || size > 64 * 1024 {
            return Err(io::Error::other("进程属性大小无效"));
        }
        let mut value = Self {
            bytes: vec![0; size.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        check(unsafe { InitializeProcThreadAttributeList(value.raw(), 2, 0, &mut size) })?;
        value.initialized = true;
        Ok(value)
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.bytes.as_mut_ptr().cast()
    }
    fn set(&mut self, key: u32, handles: &[HANDLE]) -> io::Result<()> {
        check(unsafe {
            UpdateProcThreadAttribute(
                self.raw(),
                0,
                key as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        })
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.raw()) }
        }
    }
}

pub fn check_config(profile: &Profile, confirmation: &str) -> io::Result<CheckReport> {
    if confirmation != engine::CHECK_INTENT {
        return Err(io::Error::other("未明确请求隔离配置检查"));
    }
    security::require_service_sid()?;
    let before = wfp::inspect()?;
    if before.state != lineguard_core::guard::State::Configured {
        return Err(io::Error::other(
            "必须先在隔离VM显式安装并实时回读完整M2阻断；未运行核心",
        ));
    }
    let configuration = engine::config_for_check(profile).map_err(io::Error::other)?;
    let pin = engine::manifest().map_err(io::Error::other)?;
    let store = Store::core_assets(false)?;
    let (_locked_file, executable) = store.verified_core(&pin.core)?;
    if !store.core_license_confirmed(&pin.core)? {
        return Err(io::Error::other(
            "未找到匹配固定版本的明确许可导入收据，未执行",
        ));
    }
    let syntax_accepted = run_check(&executable, store.directory(), configuration.bytes())?;
    let after = wfp::inspect().unwrap_or_else(|_| lineguard_core::guard::Evidence::unknown());
    let detail = if after.state != lineguard_core::guard::State::Configured {
        "核心检查已结束，但阻断回读不完整；不能确认仍保持全阻断，请独立inspect/rescue"
    } else if syntax_accepted {
        "固定核心配置语法接受；仅执行-t，TUN关闭，无路由/DNS变更或联网保护验证"
    } else {
        "固定核心拒绝配置或超时；输出已丢弃以免泄露凭据，阻断规则未修改"
    };
    Ok(CheckReport {
        syntax_accepted,
        guard_after: after,
        tunnel_started: false,
        detail: detail.into(),
    })
}

struct CoreProcess {
    job: Handle,
    process: Handle,
    _image: Option<std::fs::File>,
}
impl CoreProcess {
    fn running(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_OBJECT_0 => Ok(false),
            258 => Ok(true),
            _ => Err(io::Error::last_os_error()),
        }
    }
    fn stop(&self) -> io::Result<()> {
        check(unsafe { TerminateJobObject(self.job.0, 1) })?;
        if unsafe { WaitForSingleObject(self.process.0, 1500) } != WAIT_OBJECT_0 {
            return Err(io::Error::other("核心停止未确认；保留阻断和journal"));
        }
        Ok(())
    }
}
fn run_check(executable: &Path, directory: &Path, configuration: &[u8]) -> io::Result<bool> {
    let child = spawn(executable, directory, configuration, None)?;
    if unsafe { WaitForSingleObject(child.process.0, 2000) } != WAIT_OBJECT_0 {
        child.stop()?;
        return Ok(false);
    }
    let mut exit = 1;
    check(unsafe { GetExitCodeProcess(child.process.0, &mut exit) })?;
    Ok(exit == 0)
}
fn spawn(
    executable: &Path,
    directory: &Path,
    configuration: &[u8],
    job_name: Option<&str>,
) -> io::Result<CoreProcess> {
    if configuration.len() > engine::MAX_GENERATED {
        return Err(io::Error::other("配置过大"));
    }
    let descriptor = Descriptor::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
    let mut sa = descriptor.attributes();
    sa.bInheritHandle = 1;
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    check(unsafe { CreatePipe(&mut read, &mut write, &sa, 64 * 1024) })?;
    let read = Handle::new(read)?;
    let write = Handle::new(write)?;
    let mut outbound = 0;
    let mut inbound = 0;
    check(unsafe {
        GetNamedPipeInfo(
            write.0,
            ptr::null_mut(),
            &mut outbound,
            &mut inbound,
            ptr::null_mut(),
        )
    })?;
    if outbound.max(inbound) < configuration.len() as u32 {
        return Err(io::Error::other("stdin管道缓冲不足，拒绝创建进程"));
    }
    // Prefill a verified-empty, sufficiently sized local pipe before creating a child.
    // No child can leave us blocked by refusing to read; the small payload fits the pipe buffer.
    let mut n = 0;
    check(unsafe {
        WriteFile(
            write.0,
            configuration.as_ptr(),
            configuration.len() as u32,
            &mut n,
            ptr::null_mut(),
        )
    })?;
    if n as usize != configuration.len() {
        return Err(io::Error::other("stdin预写不完整"));
    }
    drop(write);
    let null = Handle::new(unsafe {
        CreateFileW(
            wide(r"\\.\NUL").as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            3,
            &sa,
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    })?;
    let name = job_name.map(wide);
    let mut job_sa = descriptor.attributes();
    let raw = unsafe {
        CreateJobObjectW(
            &mut job_sa,
            name.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
        )
    };
    let existed = unsafe { windows_sys::Win32::Foundation::GetLastError() } == 183;
    let job = Handle::new(raw)?;
    if existed {
        return Err(io::Error::other("命名Job已存在，拒绝复用"));
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = 256 * 1024 * 1024; // Safety cap, not a measured working-set target.
    check(unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        )
    })?;
    // UpdateProcThreadAttribute retains lpValue, so these arrays outlive the list.
    let inherited_handles = [read.0, null.0];
    let job_handles = [job.0];
    let mut attributes = Attributes::new()?;
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited_handles)?;
    // Atomic job assignment at process creation closes the suspended-orphan crash gap.
    attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handles)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = read.0;
    startup.StartupInfo.hStdOutput = null.0;
    startup.StartupInfo.hStdError = null.0;
    startup.lpAttributeList = attributes.raw();
    let mut system = vec![0u16; 32768];
    let len = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if len == 0 || len >= system.len() {
        return Err(io::Error::other("系统目录不可用"));
    }
    let system = std::path::PathBuf::from(String::from_utf16_lossy(&system[..len]));
    let windows = system
        .parent()
        .ok_or_else(|| io::Error::other("系统目录无效"))?;
    let mut variables = vec![
        format!("SystemRoot={}", windows.display()),
        format!("WINDIR={}", windows.display()),
        format!("PATH={}", system.display()),
        "GOMAXPROCS=1".into(),
        "GOMEMLIMIT=64MiB".into(),
    ];
    variables.sort_by_key(|s| s.to_ascii_lowercase());
    let mut environment: Vec<u16> = variables.iter().flat_map(|s| wide(s)).collect();
    environment.push(0);
    let mut command = wide(&format!(
        "\"{}\" {} -f - -d \"{}\"",
        executable.display(),
        if job_name.is_none() { "-t" } else { "" },
        directory.display()
    ));
    let mut process = PROCESS_INFORMATION::default();
    check(unsafe {
        CreateProcessW(
            path_wide(executable).as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            path_wide(directory).as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    })?;
    let process_handle = Handle::new(process.hProcess)?;
    let thread = Handle::new(process.hThread)?;
    // Job remains the only lifetime owner and is not inherited by the child.
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    drop(thread);
    drop(read);
    drop(null);
    Ok(CoreProcess {
        job,
        process: process_handle,
        _image: None,
    })
}

/// Emergency path opens only the journal's exact nonce Job, never a PID from user input.
pub(super) fn stop_recorded_job(lease: &lineguard_core::network::Lease) -> io::Result<()> {
    lease.validate().map_err(io::Error::other)?;
    let raw = unsafe {
        OpenJobObjectW(
            windows_sys::Win32::System::SystemServices::JOB_OBJECT_QUERY
                | windows_sys::Win32::System::SystemServices::JOB_OBJECT_TERMINATE,
            0,
            wide(&lease.job).as_ptr(),
        )
    };
    if raw.is_null() {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(2) {
            Ok(())
        } else {
            Err(e)
        };
    }
    let job = Handle::new(raw)?;
    #[repr(C)]
    #[derive(Default)]
    struct Pids {
        assigned: u32,
        count: u32,
        pids: [usize; 1],
    }
    let mut pids = Pids::default();
    check(unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectBasicProcessIdList,
            (&mut pids as *mut Pids).cast(),
            size_of::<Pids>() as u32,
            ptr::null_mut(),
        )
    })?;
    if pids.count > 1 || pids.assigned > 1 {
        return Err(io::Error::other("Job进程数量异常；拒绝终止未知进程"));
    }
    let mut process = None;
    if pids.count == 1 {
        let p = Handle::new(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000,
                0,
                pids.pids[0] as u32,
            )
        })?;
        let token = security::process_token(p.0)?;
        security::require_service_token(token.0)?;
        let mut path = vec![0u16; 32768];
        let mut len = path.len() as u32;
        check(unsafe { QueryFullProcessImageNameW(p.0, 0, path.as_mut_ptr(), &mut len) })?;
        let expected = Store::core_assets(false)?.directory().join("mihomo.exe");
        if !String::from_utf16_lossy(&path[..len as usize])
            .eq_ignore_ascii_case(&expected.to_string_lossy())
        {
            return Err(io::Error::other("Job映像身份不符；不终止未知进程"));
        }
        process = Some(p);
    }
    check(unsafe { TerminateJobObject(job.0, 1) })?;
    if let Some(p) = process {
        if unsafe { WaitForSingleObject(p.0, 1500) } != WAIT_OBJECT_0 {
            return Err(io::Error::other("独立停止核心未确认；阻断保持"));
        }
    }
    Ok(())
}

struct Active {
    child: CoreProcess,
    lease: lineguard_core::network::Lease,
    store: Store,
    physical: lineguard_core::network::Interface,
    physical_routes: Vec<lineguard_core::network::Route>,
}
/// The pipe thread is the sole owner. No detached process, retry task or stale async result exists.
pub(super) struct Lifecycle {
    active: Option<Active>,
    status: lineguard_core::network::Status,
    last_poll: std::time::Instant,
    recovery_failed: bool,
}
impl Lifecycle {
    pub fn new() -> Self {
        use lineguard_core::network::{RunPhase, Stage, Status};
        let mut status = Status::default();
        match Store::network_journal(false).and_then(|s| s.load_network()) {
            Ok(Some(l)) if l.stage != Stage::Restored => {
                status.phase = RunPhase::RecoveryRequired;
                status.generation = Some(l.generation);
                status.detail =
                    "发现未完成网络journal；禁止重入启动，须独立rescue恢复。不会自动修改系统"
                        .into();
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                status.phase = RunPhase::RecoveryRequired;
                status.detail = "网络journal不可读；禁止启动和猜测性恢复".into();
            }
            _ => {}
        }
        Self {
            active: None,
            status,
            last_poll: std::time::Instant::now(),
            recovery_failed: false,
        }
    }
    pub fn status(&self) -> lineguard_core::network::Status {
        self.status.clone()
    }
    pub fn start(
        &mut self,
        profile: &Profile,
        generation: u64,
        index: usize,
        confirmation: &str,
    ) -> io::Result<()> {
        use lineguard_core::{
            guard::State,
            network::{self as n, RunPhase, Stage},
        };
        if confirmation != n::START_INTENT || self.active.is_some() {
            return Err(io::Error::other("需明确独占TUN隔离启动意图；不能并发启动"));
        }
        security::require_service_sid()?;
        wfp::require_rescue()?;
        let store = Store::network_journal(true)?;
        if store
            .load_network()?
            .is_some_and(|l| l.stage != Stage::Restored)
        {
            return Err(io::Error::other("尚有未恢复journal；先独立rescue"));
        }
        if wfp::inspect_m2()?.state != State::Configured {
            return Err(io::Error::other(
                "要求完整M2阻断基线；不会自动封网或临时移除阻断",
            ));
        }
        let std::net::IpAddr::V4(ip) = profile.server else {
            return Err(io::Error::other("仅单IPv4端点"));
        };
        let physical = super::network::physical_for(ip)?;
        let physical_routes = super::network::routes()?
            .into_iter()
            .filter(|r| r.luid == physical.luid)
            .collect::<Vec<_>>();
        let mut lease = super::network::prepare(generation, index)?;
        let config = engine::config_for_tunnel(profile, &lease.alias, &physical.alias)
            .map_err(io::Error::other)?;
        let pin = engine::manifest().map_err(io::Error::other)?;
        let assets = Store::core_assets(false)?;
        let (file, path) = assets.verified_core(&pin.core)?;
        if !assets.core_license_confirmed(&pin.core)? {
            return Err(io::Error::other("核心许可导入收据缺失"));
        }
        // Write-ahead intent includes absent-owned-interface plus physical DNS/IPv6/routes snapshot.
        store.save_network(&lease)?;
        lease.stage = Stage::CoreStarting;
        store.save_network(&lease)?;
        self.status.phase = RunPhase::Starting;
        self.status.generation = Some(generation);
        self.status.detail = "正在创建独占TUN；全IP阻断保留，不能传输".into();
        let mut child = match spawn(&path, assets.directory(), config.bytes(), Some(&lease.job)) {
            Ok(child) => child,
            Err(e) => {
                lease.stage = Stage::Conflict;
                lease.last_error = Some("核心启动失败，须独立恢复检查".into());
                self.status.phase = RunPhase::RecoveryRequired;
                self.status.detail = "启动未完成；阻断以inspect为准，需独立恢复".into();
                store.save_network(&lease)?;
                return Err(e);
            }
        };
        child._image = Some(file);
        self.active = Some(Active {
            child,
            lease,
            store,
            physical,
            physical_routes,
        });
        let result = (|| {
            let active = self
                .active
                .as_mut()
                .ok_or_else(|| io::Error::other("生命周期不存在"))?;
            // Bounded native readiness observation, not HTTP success nor configuration existence.
            for _ in 0..20 {
                if !active.child.running()? {
                    return Err(io::Error::other("核心在TUN证据就绪前退出"));
                }
                if let Some((device, Some(post))) = super::network::owned(&active.lease)? {
                    if post.interface.up
                        && post.interface.mtu == 1500
                        && post.interface.unicast.iter().any(|(ip, p)| {
                            *ip == std::net::Ipv4Addr::new(198, 18, 0, 1) && *p == 30
                        })
                        && post.interface.dns
                            == vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 2))]
                    {
                        if !n::partial_footprint(&active.lease, &post.interface, &post.routes) {
                            return Err(io::Error::other("核心初始网络后态超出受控范围"));
                        }
                        active.lease.owned_luid = Some(post.interface.luid);
                        active.lease.instance_id = Some(device.instance);
                        active.lease.expected_after = Some(post);
                        active.lease.stage = Stage::TunObserved;
                        active.store.save_network(&active.lease)?;
                        super::network::add_routes(&active.store, &mut active.lease)?;
                        if wfp::inspect_m2()?.state != State::Configured {
                            return Err(io::Error::other("启动后M2基线回读不完整"));
                        }
                        return Ok(());
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(io::Error::other(
                "TUN真实接口/DNS证据未在期限内就绪；不能视为连接成功",
            ))
        })();
        if let Err(error) = result {
            self.close_active("启动失败；全阻断和恢复证据保持")?;
            return Err(error);
        }
        self.status.phase = RunPhase::Quarantined;
        self.status.detail="独占TUN/两条自有路由已回读；M2全阻断保留，数据面仍不可用。无ALE/包层放行，无Windows VM验证".into();
        Ok(())
    }
    fn close_active(&mut self, reason: &str) -> io::Result<()> {
        use lineguard_core::network::{RunPhase, Stage};
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        // If either the barrier or poststate cannot be proved, do not destroy evidence or user edits.
        let result = (|| {
            wfp::ensure_closed()?;
            super::network::precheck_restore(&active.lease)?;
            active.child.stop()?;
            super::network::restore(&active.store, &mut active.lease)
        })();
        match result {
            Ok(()) => {
                self.active.take();
                self.status.phase = RunPhase::Stopped;
                self.status.detail =
                    format!("{reason}；网络已按后态恢复，独立阻断保留；自动重连禁用");
                Ok(())
            }
            Err(e) => {
                self.recovery_failed = true;
                self.status.phase = RunPhase::RecoveryRequired;
                self.status.detail="停止/恢复证据不完整；不覆盖后续修改，禁止自动重试。阻断以独立inspect为准；需管理员恢复".into();
                active.lease.stage = Stage::Conflict;
                active.lease.last_error =
                    Some("停止/恢复未完成；禁止重连，需独立inspect和恢复".into());
                active.store.save_network(&active.lease)?;
                Err(e)
            }
        }
    }
    pub fn tick(&mut self, generation: u64) -> bool {
        if self.recovery_failed
            || self.active.is_none()
            || self.last_poll.elapsed() < std::time::Duration::from_secs(1)
        {
            return false;
        }
        self.last_poll = std::time::Instant::now();
        let result = (|| {
            let active = self
                .active
                .as_ref()
                .ok_or_else(|| io::Error::other("生命周期不存在"))?;
            if generation != active.lease.generation || !active.child.running()? {
                return Err(io::Error::other("配置代次变化或核心退出"));
            }
            if wfp::inspect_m2()?.state != lineguard_core::guard::State::Configured {
                return Err(io::Error::other("基线漂移"));
            }
            let Some((_, Some(post))) = super::network::owned(&active.lease)? else {
                return Err(io::Error::other("独占接口已消失"));
            };
            if active.lease.expected_after.as_ref() != Some(&post) {
                return Err(io::Error::other("TUN/路由后态变化"));
            }
            let now = super::network::interfaces()?;
            let routes = super::network::routes()?
                .into_iter()
                .filter(|r| r.luid == active.physical.luid)
                .collect::<Vec<_>>();
            if now.iter().find(|i| i.luid == active.physical.luid) != Some(&active.physical)
                || routes != active.physical_routes
            {
                return Err(io::Error::other("物理网络发生变化"));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = self.close_active("健康证据失效");
            return true;
        }
        false
    }
    pub fn shutdown(&mut self) {
        if !self.recovery_failed {
            let _ = self.close_active("服务正在退出");
        }
        // Process exit always closes the kill-on-close Job. The TUN is explicitly disposable:
        // edits made by an administrator ON this ephemeral adapter cannot survive that OS lifetime.
    }
}
impl Drop for Lifecycle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// An explicitly elevated recovery may stop ONLY the authenticated product service.
/// No killing arbitrary PIDs and no forced unlock if SCM cannot stop it within the deadline.
pub(super) fn stop_service_owner() -> io::Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceState, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager =
        ServiceManager::local_computer(None::<&std::ffi::OsStr>, ServiceManagerAccess::CONNECT)
            .map_err(io::Error::other)?;
    let service = manager
        .open_service(
            "LineGuardPreview",
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .map_err(io::Error::other)?;
    let config = service.query_config().map_err(io::Error::other)?;
    let expected = std::env::current_exe()?.with_file_name("lineguard-service.exe");
    if config.service_type != ServiceType::OWN_PROCESS
        || !config
            .executable_path
            .to_string_lossy()
            .trim_matches('"')
            .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(io::Error::other("服务配置不是本产品独立进程；拒绝停止"));
    }
    let status = service.query_status().map_err(io::Error::other)?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    let pid = status
        .process_id
        .ok_or_else(|| io::Error::other("服务进程身份未知；拒绝停止"))?;
    let process = Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    let token = security::process_token(process.0)?;
    security::require_service_token(token.0)?;
    let mut image = vec![0u16; 32768];
    let mut len = image.len() as u32;
    check(unsafe { QueryFullProcessImageNameW(process.0, 0, image.as_mut_ptr(), &mut len) })?;
    if !String::from_utf16_lossy(&image[..len as usize])
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(io::Error::other("服务进程映像不符；拒绝停止"));
    }
    if status.current_state != ServiceState::StopPending {
        service.stop().map_err(io::Error::other)?;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if service
            .query_status()
            .map_err(io::Error::other)?
            .current_state
            == ServiceState::Stopped
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(io::Error::other(
        "产品服务未确认停止；没有强杀或绕过网络writer锁，阻断保持",
    ))
}
