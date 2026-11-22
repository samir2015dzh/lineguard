# LineGuard：Rust Windows 客户端架构（设计稿，不是已完成产品）

记录日期：2026-11-22（Asia/Shanghai / UTC+8）。目标：Windows 10 22H2 / Windows 11 x64；仅考虑仍有适用安全维护的系统部署。ARM64、32 位、其他系统、转发网关和企业域策略兼容不在首版承诺内。

## 当前实施状态（M2）

附件已完整读取；Rust+egui三package实现已存在。当前以README/BUILD-RESULTS/REQUIREMENTS为准。M2新增原生WFP实验阻断、受真实管理员令牌保护的独立install/remove与服务无关rescue、真实规则回读、版本快照journal；矩阵见WFP_POLICY_MATRIX.md，代码集中agent/windows/wfp.rs。无隧道，无Protected；Blocked仅为规则字段证据完整，流量效果仍未验收。普通IPC没有危险变更命令，GUI不提供启用/解除按钮。

单一业务状态owner保留Controller；高权限WFP变更只由显式管理员CLI/独立rescue经同一管理员文件锁串行执行，服务只回读、不回装。没有两个并发策略写者。隔离工具链已具备，未在Windows运行或改变实际网络。以下主体为初始决策背景，过时进度不是当前事实。

## 0. 初始输入与检查时事实（历史，不是当前进度）

- 用户要求：按附件做 Windows 软件；Rust 优先；代码简洁、可维护，不能以减少行数牺牲功能或安全。
- **本执行子代理读取附件时被隐私隔离拒绝。未完整读取原文，不绕过；本稿依据父代理提供的需求摘要，需父代理读完整附件后补齐逐条追踪。**
- 摘要涉及 SYSTEM 服务、原生 WFP、boot-time/persistent 过滤、mihomo TUN/fake-IP/DNS、订阅、DPAPI、命名管道、GUI/托盘、独立救援、签名安装更新、探针。
- 附件中的“27 规则 / 30 检查 / 300 测试 / VM 已通过”等均不是本项目结果；本项目没有代码、规则部署、Windows 二进制或测试通过记录。
- 本阶段只写本机资料，没有操作真实 Windows、网络配置、线路凭据，没有创建远端仓库、发布、上传或生成签名私钥。
- 已授权 gh 只读列举 samir2015dzh 可见的 40 个仓库，名称/描述匹配 lineguard、line.guard、 防泄露均无结果；这只说明本次可见范围未匹配，非证明所有私有仓不存在。

## 1. 两种结构与选择

| 方案 | 优点 | 成本与隔离 |
| --- | --- | --- |
| A：egui/eframe 原生 Rust GUI + Rust 服务 | 单语言、单 Cargo 依赖图、无 WebView2/Node、无前端 IPC 插件栈；足够状态/订阅/诊断页 | 中文字体、IME、键盘无障碍和 GPU/远程桌面兼容需实测；egui 升级常有 API 变更，要固定版本 |
| B：Vue/Tauri GUI + Rust 服务 | Web 表单、复杂交互、样式与无障碍工具更成熟 | Rust+TS+Node 两套构建/锁文件、WebView2 部署、Tauri capability 与本机管道两层边界；仍必须独立 SYSTEM 服务，不应把 WebView 提权 |

推荐 A；界面需求简单，减少长期维护面比页面框架丰富更重要。egui 不等于 Windows 原生控件，不承诺天然完整无障碍。中文界面优先加载 Windows 本地中文字体，不未经许可打包字体。先固定一个满足选定 Rust MSRV 的稳定 eframe 版本，不追 latest；官方最新文档当前显示 egui/eframe 0.37 需 Rust 1.95，而本机仅 1.85.1，不可直接假定可编译。

## 2. 最少边界：3 个 workspace package，不照搬 17 crate

```text
lineguard/
  crates/core/         # lineguard-core：纯领域类型、状态机、策略计划、配置校验、协议 DTO
  crates/agent/        # lineguard-agent：唯一状态 owner；Windows 适配器；3 个薄入口
    src/bin/lineguard-service.rs
    src/bin/lineguardctl.rs
    src/bin/lineguard-rescue.rs
    src/windows/{wfp,ipc,scm,secrets,network,core_process,storage}.rs
  crates/ui/           # lineguard-ui：egui + 无权限 IPC 客户端；不调用 WFP/SCM 写接口
  packaging/          # 后期 WiX 定义、版本/依赖清单、构建说明
  docs/               # 威胁模型、WFP 层矩阵、VM 验收记录（后期）
```

依赖方向：ui -> core；agent -> core。不得 core -> Windows 或 core -> GUI。不再为 logging、DTO、error、每个业务模块拆 crate。agent 的 CLI、rescue 用 required-features 或 bin 专用 feature 控制依赖，rescue 不依赖服务在线、GUI 或 mihomo；必要共享代码仅本地拥有对象的读取/清理，不复用主状态机启动逻辑。

- `Controller` 是服务唯一可变业务状态 owner；命令、进程退出、网卡变更、计时事件进入有界队列，串行决策。无全局 `Arc<Mutex<Everything>>`。
- 慢 I/O 为带 generation 的 effect；结果回队列，旧 generation 不得提交。策略/配置写者只有一个；rescue 只能在确认服务已停止并拿独占锁后写。
- GUI 只保存 view model 与等待中的 request id；托盘复用同一 IPC 客户端，不另建“真实状态”。UI 退出或崩溃不撤策略。
- 先用 std 线程/有界 channel + 同步命名管道；没有已证明需求不引入 Tokio。UI 线程不做 IPC 阻塞。若后续网络库强制异步，再局部引入一个 runtime。
- Windows FFI 用 `windows` 或 `windows-sys` **二选一**、按 feature 仅启用需要的 API；unsafe 与资源释放集中 RAII。系统级防护必须原生 WFP API，不用 PowerShell/netsh 防火墙规则充数。

首批依赖：serde/serde_json（有界协议与配置）、thiserror（结构化失败）、windows bindings（Windows 特性）、eframe（仅 UI）、tracing + 有界轮转输出（不记录秘密）。其后按里程碑加入 sha2、成熟签名验证实现（按原文 P-256/CNG）、HTTP/TLS、zeroize；不自写密码学，不默认引入数据库、插件系统、DI 框架或多套状态库。锁定 Cargo.lock 与 toolchain，检查传递依赖 MSRV/许可；此处尚未选定所有具体版本。

## 3. 领域与接口草图（非已实现代码）

```rust
struct Controller { desired: Desired, observed: Observation, generation: u64 }
enum Desired { Off, Guarded { profile: ProfileId } }
enum Phase { Unsupported, Off, Arming, Blocked, Connecting, Protected, Degraded, Recovering }
struct Snapshot { generation: u64, phase: Phase, evidence: Evidence, last_error: Option<Fault> }
struct Evidence { policy: PolicyEvidence, routing: RouteEvidence, core: CoreEvidence, dns: DnsEvidence }
enum Command { Status, ImportOffline(ValidatedImport), Connect(ProfileId), DisconnectKeepGuard,
               DisableGuard(ConfirmedIntent), ExportRedactedDiagnostics }
fn decide(state: &Controller, event: Event) -> Transition;
fn plan_policy(profile: &ValidatedProfile, network: &NetworkSnapshot) -> Result<PolicyPlan, Fault>;
fn compile_wfp(plan: &PolicyPlan, caps: &Capabilities) -> Result<FilterSet, Unsupported>;
fn reconcile(plan: &PolicyPlan, applied: &AppliedPolicy) -> Result<VerifiedPolicy, Fault>;
```

状态不能用多个布尔值拼出“不知道但显示绿色”。Evidence 带来源、generation、单调时钟时间和过期条件。`Protected` 必须来自同一代有效策略回读、适配路由/TUN 接口、受控核心健康、DNS 配置与健康证据；不是“进程已启动”、计时器到期或 ping 通。证据过期/变化立即降级，不等待下一次成功探针。支持能力未实现 -> `Unsupported`，从未安装拦截时不能显示“已断网保护”。

阶段语义：`Off` 明示未保护；`Arming` 尚不能承诺；`Blocked` 表示已验证阻断、无可用隧道；`Connecting` 同样保持阻断；`Protected` 仅限定义的威胁模型与证据；`Degraded` 明示保护未确认。若已装阻断仍有效，降级也保留；若 WFP 本身失效，只能报告无法保证并停止核心，不可声称程序能凭空 fail closed。

配置为版本化小 JSON + 加密秘密 blob + 恢复 journal，先写临时文件/flush 后原子替换；跨配置/WFP事务不伪装为一个原子事务，用 prepare/apply/verify/commit journal 恢复。日志脱敏订阅 token、节点密码、IP/域名等敏感字段。只导入白名单字段生成受控 mihomo 配置，拒绝任意路径、脚本、远程 provider、DIRECT 回退、任意 listener/controller 和未经批准的旁路规则；用户 YAML 不能成为 SYSTEM 任意指令。

## 4. 核心安全矛盾及保守修订

### 4.1 订阅引导：严格模式不偷偷直连

默认严格模式支持离线文件/文本导入；首次连接要求用户提供可用 IP 端点（可独立保留 TLS SNI）。域名端点无可信缓存/无隧道解析渠道时返回 `BootstrapRequired`，不走系统 DNS，不把 IP 提示当证书校验替代。已有隧道时订阅更新、端点 DNS、DoH 经隧道，失败保留旧可用配置/阻断。

**首版不实现直连引导例外**，因此无须先向用户问一长串选择题。若以后加入，它是另一个显式“受限引导”模式：单独确认会暴露目标 IP、时序、DNS/DoH 引导信息；限制专用进程身份、目标 IP/协议/端口、期限/大小、TLS 域名；拒绝重定向扩权和任意 URL/内网 SSRF，失败撤回例外但保留全局阻断。不能同时宣称严格零直连。首次获取域名解析器/DoH 域名也有引导问题，硬编码 DoH IP 仍是直连，不是逻辑豁免。

### 4.2 放行端点不等于放行所有应用

运行期端点许可至少 AND：受控 mihomo 可执行文件 app ID、出站方向、IPv4/IPv6 精确地址、协议、端口；相应 ALE 层条件允许时再约束进程服务身份/用户 SID。app ID 是路径身份不是代码签名；安装目录/父目录 ACL 禁止普通用户改写，服务启动前校验固定核心摘要，安全 DLL 搜索路径。

候选运行期层是 ALE_AUTH_CONNECT_V4/V6，入站需要单独审视 ALE_AUTH_RECV_ACCEPT；低层 IPPACKET/TRANSPORT **不能凭空使用 ALE_APP_ID**。传输/包层限制物理出口、接口与启动期阻断；必须结合 TUN 吞吐路径和重注入行为设计，不能“低层全 block + 高层 permit”就以为有跨层穿透。任何为兼容而放宽物理端点 IP 的全应用规则都禁止。

**发布阻塞项**：逐条写清 layer、适用 condition、子层/权重、动作及 override 权限、IPv4/v6、方向、接口/compartment、匹配理由，再在 VM 证明普通进程同 IP 同端口仍被拦截、mihomo 可连且应用经 TUN 正常。若内建层组合无法满足此矩阵，停止/标 Unsupported，重新设计；不可隐性扩大权限或用“27 条规则”替代证明。首版不自研内核 callout 驱动。

### 4.3 boot-time / persistent / 仲裁并非一个开关

- Microsoft 文档明确同一 filter 的 BOOTTIME 与 PERSISTENT 互斥，须分别创建；boot-time 仅支持内核层，并非任意 ALE 条件都可用。启动期保守阻断，可延迟联网直到运行期准备完毕，不能套运行期 app 条件。
- BFE 初始化时 boot -> persistent 的平台切换是原子的，但依赖两套已正确持久安装且实际加载；这不证明我们的层覆盖、例外、安装顺序或驱动前窗口安全。保护范围从 WFP 可执行层生效起，不包括固件/PXE 等更早网络。
- 与 serviceName 绑定的 provider，关联服务非自动启动可能导致持久对象不加载。默认不把防护存续依赖这种可禁用绑定，配显式 provider GUID 与 ACL；安装后验证下次启动的存储状态，卸载只删本产品对象。
- 阻断基线不可放进断开即清理的 dynamic session；会话/服务退出不能删基线。例外寿命与更新要 journal、回读与崩溃恢复；不可依赖用户态定时器撤长期许可。
- 权重只在规则仲裁上下文有意义，不是“最高优先级所以绝对安全”。明确 soft/hard permit/block、CLEAR_ACTION_RIGHT 与跨子层及跨层行为；不为联网随意 hard-permit 覆盖其他安全产品，冲突时阻断并诊断。具体 flag 以目标 SDK 类型定义/官方结构文档交叉核对，不照抄网上一段描述。
- 服务/核心崩溃应留阻断；BFE 停止/重启、系统崩溃、休眠恢复须单独验收。恶意管理员、恶意内核/驱动、内核自身失效不在绝对防御内。

### 4.4 网络变化、LAN 和 DNS

- 同时覆盖 IPv4/v6、已有流、绑定物理网卡的 socket、UDP/QUIC/ICMP、系统 DNS、应用自带 DoH、DNS fallback；不以仅修改系统 DNS 作为防泄露。
- 初版不支持 IPv6 隧道时明确阻断 IPv6 非本地出口；不能只设置一个“禁 IPv6”UI 开关便宣称覆盖。新网卡、Wi-Fi/有线切换、接口索引复用、VPN 冲突、compartment/Hyper-V/WSL 边界均须列支持矩阵；未覆盖虚拟转发不能报整机保护。
- DHCPv4/v6、ARP、NDP/RA、ICMPv6 PMTU 不是普通网页流量。ARP 为二层，不假设用户态 WFP 包规则能控制全部；必要链路控制例外应最小化且文档公开，未证明安全就容忍断网，不放行整个 svchost 或局域网。
- 默认 LAN 豁免关闭（loopback 仅必要端口）；不宽放 RFC1918、组播、mDNS/LLMNR/NetBIOS。开启 LAN 会向本地设备暴露流量，须另行确认范围。不能对严格模式无条件豁免私网端点或本地代理。
- 移除旧端点许可须考虑既有 flow 的重授权/终止；更新先保持阻断、加精确新许可/验证、再收旧许可，不在切换间全放行。
- 限制 mihomo 本地代理/controller：默认关闭非必要 listener，controller 如无管道则绑定 loopback+每安装随机秘密+ACL保护配置，禁止公开端口。loopback 不代表认证；同机应用不能借开放代理访问仅供核心引导的路径。

### 4.5 SYSTEM、命名管道、秘密

- GUI/CLI 默认普通权限。仅安装、救援、解除保护等改变安全边界操作显式 UAC；不把整套 GUI 作为管理员运行。
- 命名管道明确 DACL（SYSTEM、管理员、被授权 owner/logon SID）；拒绝远程客户端、首实例标志阻抢占，逐消息校验客户端 token，最小权限不给创建实例权。不能用默认 ACL（含 Everyone/anonymous 读取权限）或客户端自报 PID/SID 当认证。
- 普通授权 owner 的同 SID 恶意程序仍可冒充普通 GUI，这是边界；解除保护必须单独 elevated/admin 令牌确认，不能只靠 GUI 一个 confirm 布尔值。客户端也校验 server PID/token、映像与安装 ACL，避免连到伪服务后泄露订阅。
- 协议 version/request id、长度上限、深度/字段上限、超时/速率限制、乐观 generation 检查；不接受 shell、任意可执行路径或任意文件路径。线程 impersonation 用 RAII 保证 RevertToSelf 后才执行特权 effect。
- 机器作用域 DPAPI 不是“只有服务能解密”：同机任何用户拿到 blob 都可能解密；所以 ProgramData 秘密文件、备份、journal 的 ACL 同时必需（SYSTEM/服务 SID/授权管理员），UI 只收脱敏视图。密文不能同步到不可信目录。可选 SYSTEM 用户作用域 DPAPI需考虑恢复/重装，暂不擅改策略。
- mihomo 虽是 Go 外部程序仍属于高信任依赖。优先低权限受限 token/专属服务身份；若 TUN 初始化要求提升，先 VM 验证最小所需权限，不贸然承诺可完全降权。若必须 SYSTEM，明确攻击面并禁止不受控配置/插件/路径。

### 4.6 独立救援与更新

救援 exe 必须能在服务/GUI/核心全损坏时运行。先默认只读 `inspect` / 导出脱敏快照；写操作须管理员 UAC+明确“解除防护会允许直连”确认。停止服务、持独占锁，按固定 provider/filter GUID 清理本产品对象，基于 journal 条件恢复自己改过且未被他人改写的路由/DNS；不全局 reset 防火墙/网络、不重放整个陈旧机器快照。失败留下可诊断记录，不声称成功；不得以防护恢复为名自动删除文件或用户配置。

更新先离线签名 manifest（版本、架构、全部文件大小/摘要、最低兼容版本、防回滚序号），编入公钥；没有可信公钥则更新 Unsupported。不能运行时生成私钥并自签后称安全更新。发布签名密钥/证书由所有者在安全环境管理，本项目不自动创建或读取。

下载走现有隧道；先验证 staging，全停核心但保留阻断，原子切目录/版本指针，服务协议/配置迁移可回滚。失败回旧受信版本仍保留 guard；若旧版与安全防回滚序号冲突则停在 Blocked，绝不回退易受攻击版本。服务升级采用 Windows 安装器受控流程，验证失败不先卸旧规则。无证书可产出内部 unsigned 测试包（明确标识），不自动公开分发；正式产物需 Authenticode、安装卸载/更新回滚验收。

mihomo README 当前声明 GPL-3.0 且对下游名称另有限制；发布前锁定具体 tag/commit/架构/hash，核对实际 LICENSE、对应源代码提供义务与分发说明，不以“子进程所以一定无义务”下结论。LineGuard 命名不含 mihomo，不据此认为所有许可问题已解决。Wintun 源码 GPL-2.0 与官方签名 DLL 的额外分发许可不同，核对实际 zip 内许可；只考虑官方已签名驱动包，不自签驱动、不任意下载 latest DLL。

### 4.7 探针与可证明范围

探针只提供诊断证据：失败可能是断网、服务失效、被阻断；成功只证明一条路径，不能证明没有旁路。`Protected` 是有限威胁模型中证据成立，不等于绝对无泄露认证。VM 验收需外侧抓包与普通进程主动旁路对照；不得探测未授权第三方服务、上传真实订阅或以产品测试流量触达真实账号。

## 5. 本机与交付路径

实测：Linux x86_64，/usr/bin/rustc 1.85.1、cargo 1.85.1；没有 rustup、Windows std、MSVC SDK/CRT/linker、MinGW 编译器、cargo-xwin/zig、WiX/NSIS/签名工具（已查命令与包状态）。`rustc --print target-libdir` 只打印预期路径，Windows 实际目录不存在。没有安装任何新工具，也没尝试编译不存在的代码。

因此**现在不能交付 Windows exe**。Linux 可编写/检查纯领域逻辑；后续依赖解析/MSRV及纯逻辑测试可在本机进行，但不等于 Windows API 已编译或行为正确。Linux -> Windows GNU 需要 Windows std+MinGW，且不能替代 MSVC 发布链；Linux -> MSVC 可研究 cargo-xwin+clang/lld+微软 SDK/CRT，须许可/下载批准及逐依赖确认，Rust 官方不保证非 Windows 主机的 MSVC 交叉编译，不作为唯一交付路径。

推荐：开发继续本机 checkout；经授权后在**隔离 Windows 构建 VM**用固定 Rust MSVC + VS Build Tools（C++/SDK）+ 固定 WiX 构建 exe/MSI；构建本身不需安装服务或开 TUN。防护验收另用可回滚测试 VM（带独立控制台/外侧抓包），不碰用户真实电脑。Windows VM/构建 runner 当前未探测、未申请、未假定可用。无远端仓库授权，故不创建 GitHub 仓、不触发 Actions、不上传产物。

## 6. 快速核对的公共资料（2026-11-22 查阅）

- WFP 运行/boot-BFE 切换：https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation
- 生命周期及 serviceName：https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- filter flags：https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- 条件/层矩阵：https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- 仲裁：https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- 管道 ACL：https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- DPAPI：https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Rust Windows 官方要求：https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html
- GUI：https://docs.rs/egui/latest/egui/ 、https://v2.tauri.app/start/prerequisites/
- 核心许可：https://github.com/MetaCubeX/mihomo/blob/Meta/README.md
- 驱动：https://www.wintun.net/

这里只把官方资料作为设计约束；搜索摘要或 README 不替代固定版本原始许可/实测。文档自身对 flags 的描述如与 SDK 不一致，必须核对 API 结构定义和 VM 行为后再定实现。


## M3增量：仍保持3-package和单一业务状态owner

core/engine.rs只承载编译内置pin、流式纯校验、借用secret的受控JSON生成及DTO；engine-config.json是编译内置模板，不是用户YAML。Controller拥有配置代次/选取与最近证据。agent/windows/engine.rs拥有有限原生子进程生命周期，复用security/ACL/Store与WFP真实回读，无全局可变状态或常驻轮询。UI只持快照、有界后台任务，服务状态不跟随窗口退出。

候选A：仅ALE阻断+TUN例外，需重新证明包层/转发/既有流；候选B：保留M2包层默认拒绝，增加ALE身份门与同层包层窄许可，取交集。推荐B，但14条新增规则、TUN归属/快照/独立恢复尚未原生实现。未走“先宽放IP再补安全”的快捷路。详见WFP_POLICY_MATRIX.md。

目前只开放管理员经服务的固定核心-t检查，绝无启用TUN的隐形参数。专用服务SID来自真实令牌，不是客户端bool。Job在CreateProcess创建时原子关联，避免先创建再AssignJob的崩溃孤儿；stdin预写小型有界含密配置，stdout/stderr NUL，固定环境不继承CLASH_*脚本/controller注入。

本次是M3部分管理预览，不能因可编译/语法接受生成已保护状态。原生M3过滤、独占TUN/路由/DNS恢复、网变和完整进程状态机是下一实质开发，不跳过到订阅或安装美化。
