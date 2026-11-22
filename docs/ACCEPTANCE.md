# M2 验收步骤（全部未执行）

本次只构建Linux和Windows GNU，**未运行测试、Windows exe、服务安装、WFP规则或任何真实网络变更**。以下仅供获准验收者在隔离VM按快照执行，禁止日常电脑或真实线路凭据。不能把编译/规则枚举当防泄露验证。

## A. 纯逻辑回归（已写10个用例，未执行）

后续命令：`cargo test --locked -p lineguard-core`。

- 既有5个：Unsupported Connect不写配置；保存失败代次不变；旧代次拒绝；未知字段/超大输入拒绝；诊断没有秘密字段。
- 新状态用例：Absent->Unprotected，12规则字段完整->Blocked，缺半数->Degraded，实时读取失败->Unknown；无Protected。
- 规则计划：12个独立GUID，6层的persistent/boot成对，不会把两个互斥flag塞同一条；没有allow或动态会话的计划。
- 无规则/缺boot不产生Configured。
- 完整规则仍enforcement_verified=false，服务配置不符或未知额外规则要Drift。
- 变更前失败且abort成功才Aborted；commit尝试失败或abort失败必须Uncertain，不假报回滚。

这些纯逻辑用例不证明Windows FFI/仲裁/事务行为已通过。

## B. 无网络修改的基本链

1. 干净VM快照，不联网，四个M2 exe同目录，使用示例JSON而非真实凭据。普通用户启动service --console和GUI --console；此时没有任何install命令。
2. GUI/CLI离线导入、读取相同代次、DPAPI落盘、关闭/重启后台可加载；另一CLI导入后GUI按刷新取新状态。协议2与离线schema1分离，M1配置仍可读；不能混用M1/M2客户端。
3. `lineguardctl guard inspect`只读，检查固定GUID/真实filterId/flags/层/动作/权重；fresh machine可为Absent，读权限/BFE问题则Unknown/错误，不默认为无规则。
4. 界面没有install/remove按钮；Connect固定Unsupported，不改变已有规则。向普通IPC伪造危险command应被协议拒绝。
5. 独立rescue inspect在后台退出后仍检查配置/WFP，不创建journal/数据目录、不改ACL或网络。坏配置提示未知，不把线路数编成真实0；诊断不含节点地址/名称/密码/token/路径。

## C. 危险实验前置（先救援后阻断）

必须可从VM独立本机控制台操作，有可回滚快照；不能依赖RDP/SSH网络救援。没有LAN/DHCP例外，启用将故意断开IP联网。隔离实验网络的抓包端也必须事先批准，不探测第三方服务。

- M2 rescue的--version应显示策略v2能力marker；M1只读rescue、同名文本文件、非x64 PE都应令安装拒绝。marker不等于签名，不测试其抗恶意管理员伪造。
- 预先由验收者设置受保护目录内LineGuardPreview SCM服务（LocalSystem/AutoStart，同目录service.exe，无--console参数）。本项目不自动做安装/配置。当前控制管道仍只支持活动物理控制台用户；无人登录启动/RDP/多会话为已知限制，需单列，不声称后台全生命周期可用。
- 缺服务、非AutoStart、非LocalSystem、服务映像不匹配应在改WFP前拒绝；不能为了测试偷偷自动修服务。
- 普通用户运行install/remove，或管理员缺精确确认字符串，应失败且无WFP变化。`--experimental-vm-only`是操作者确认，不是虚拟化检测。

## D. 原生规则、证据与回滚

管理员明确执行：`lineguardctl guard install --experimental-vm-only --confirm BLOCK-ALL-IP`。验收前务必理解该命令会真实改VM的WFP，**本次未执行**。

1. 记录安装前所有系统规则快照；M2 journal Prepared保存仅本产品的实际对象元数据。正常提交后应有6条persistent+6条boot注册，provider/subLayer持久且marker/绑定/权重正确。
2. 以guard inspect详细输出和原生WFP工具交叉核对；普通Status/Diagnostics实时重读而非取journal。无法读取、缺规则、disabled、错误层/动作/权重/版本应Unknown/Drift，不显示Protected。Blocked只表示字段证据。
3. 外侧捕获IPv4/v6本机进出、已建立TCP/UDP、raw socket/QUIC/DNS/DoH、物理网卡绑定、LAN/DHCP/ICMPv6；预期IP路径被阻断，不把ARP仍可见当WFP能过滤二层。loopback/WSL/Hyper-V/vSwitch路径须单列实际覆盖，不假定经过所选层。
4. 冷启动抓包：TCP/IP驱动起至BFE接管两阶段，与boot注册存储区分。任一boot Add/回读失败应整事务abort，未有规则的机器不得显示Blocked。
5. 杀GUI/后台/安装CLI进程后persistent规则不因动态会话结束消失；新inspect实际取证。服务禁用、BFE停止/失败/重启单独测，不能假定boot在运行期自动接管或BFE停机无泄露。
6. 在VM用受控故障环境/调试构建验证：prepare写入失败时没有WFP变更；中途FwpmAdd失败或进程退出使整个事务撤销；abort/commit结果不确定时journal不写成功；commit后journal最终写失败要明确“可能已提交”。不在正常电脑制造磁盘满或终止系统服务。
7. 外来provider占同固定filterKey、marker不符、未知依赖：不得覆盖/扩大删除。六层内额外未知规则应拒绝变更；矩阵外引用由删除父对象时WFP依赖检查令事务abort，不能声称扫描全系统。
8. 同时开两个管理员CLI/救援，只能一个拿到产品journal目录独占写锁；服务只观察、不回装。不要把并发误当多个业务状态owner。

## E. 独立解除与幂等

1. 退出/禁用/移走服务（只在VM），保留独立M2rescue，管理员执行`lineguard-rescue remove --confirm ALLOW-DIRECT`，不需管道/WTS/AutoStart配置仍可直接删除已确认归属的规则。
2. 只删除固定v2 GUID过滤器，再删自有subLayer/provider；不存在的部分允许清理剩余合法对象。外来归属/未知依赖会拒绝，不为了联网而全局reset。
3. inspect应Absent（不是“保证互联网已恢复”）；再次remove为无变化。后台存活也不自动回装；DNS/IPv6/路由/其他防火墙规则与操作前一致。
4. 提交后读回失败、journal最终写失败、WFP拒绝删除，都不能显示“已解除”；先查看错误、快照、详细inspect。服务不可用不等于策略已撤。

## F. UI质感、低内存与时序（仍未测量）

- 四页中文/IME、100/150/200%缩放、长名称/路径、键盘Tab、错误关闭、文件对话框取消；无假网速/出口/安全分。Unknown/Drift危险提示清晰，Blocked也注明效果未验收。
- 系统动画关闭/应用开关都停短过渡；界面不能因WFP/IPC读取卡主线程。页面160ms/hover120ms为实现时长，不是测得帧率。
- Windows分别记录GUI/服务的WorkingSet64、PrivateMemorySize64、CPU增量：`Get-Process lineguard,lineguard-service | Select Id,ProcessName,WorkingSet64,PrivateMemorySize64,CPU`。记录稳定期/采样秒数/逻辑CPU数，按CPU增量归一，不比较累计CPU值。
- 分别采样首页静止、16条线路、切页/hover、WFP刷新、最小化、关GUI只后台；无固定60fps循环/自动测速。WFP仅按需查询，API开销不能算成空闲渲染；服务200ms接入轮询不是0唤醒。
- 获准工具可用时用WPR/WPA观察Present/CPU/内存与p95帧间隔，远程显示/无GPU单列兼容限制。不编造帧率/内存数字。
- 字体为单个系统CJK字体、上限32MiB读取，记录首次glyph atlas及稳定后是否增长。托盘未实现，不能把最小化指标叫托盘通过。

## G. 尚未进入的M3

固定核心/驱动许可与hash、单离线IP端点、按应用身份/方向/协议/端口许可、TUN路由/DNS健康证据、核心崩溃保阻断、同IP其他app旁路负例。没有这些就不能进入Protected；本轮不全订阅、不直连DoH引导。

## M3 部分管理预览新增用例（全部未执行，不代表隧道可用）

本版无TUN数据通路；先验证下列安全边界，之后另行实现M3余项。**不要在用户真实电脑运行**，只在另获授权的隔离WindowsVM，使用虚构SS密码。

### 纯逻辑（本轮只编译测试目标）

- 固定pin验证：正确短样本/篡改/截断/超长；内置manifest无签名成功宣称。
- SS密码中引号、反斜线、控制符不能注入配置；最大转义输出<=16KiB；Generated Debug不含密码。
- IPv6/广播/linklocal/fakeIP端点被M3生成器拒绝；所有规则只引用LG-ONLY，无DIRECT兜底、远程provider、controller、监听代理端口或脚本入口。
- TUN始终false、auto-route/strict-route false；核心摘要Verified不改变Guard状态或制造Protected。
- 伪造请求admin字段拒绝；旧协议CoreCheck不落后端/存储；配置代次/序号错误拒绝。

### 仅Windows隔离VM将来运行

1. 保留M2独立救援控制台/快照；先确认rescue可只移除自有WFP、其他规则保持。软件不安装服务，不自动提权；CoreCheck服务不在线/没有活动控制台登录时如实失败。
2. `core manifest`与公开release API/下载资产对照。无核心显示Missing；错大小/hash、重解析文件、不可信owner/目录拒绝，确认拒绝过程无进程、TUN、路由或DNS变化。
3. 在阅读GPL与Wintun许可后，管理员core inbox创建专用暂存目录，手动离线复制固定exe为mihomo-candidate.exe，再以完整绝对路径显式导入。验证任意其他/相对/UNC源路径在打开前拒绝，普通用户不能修改暂存目录。检查ProgramData/LineGuardCorePreview ACL、原子替换、两次校验、core-receipt.json许可收据；缺/坏/不匹配收据禁止执行。磁盘满/写失败、已占用/替换冲突不能误报全部成功，不覆盖其他路径。
4. 用普通UI或伪造JSON请求CoreCheck→PermissionDenied；console后端同样拒绝。其他用户/跨会话/远程管道客户端拒绝；不能以confirmation字符串代替真实管理员token。
5. 已提升同会话管理员、SYSTEM服务SID缺失/未启用、M2规则少一条或BFE不可达→拒绝运行。SCM/SID设置只由VM操作者预配置，本程序不修改。
6. M2完整+服务SID启用后，CoreCheck才可调用固定exe的 `-t -f - -d <受控目录>`。观察stdin而非命令行/环境/磁盘含密码；CLASH_POST_UP/DOWN、CONFIG_STRING、controller覆盖等环境不能注入；进程仅继承stdin/NUL，Job不继承。
7. 用Windows进程/Job审计核对创建即归Job、单进程上限、父服务崩溃无挂起孤儿、2秒预算超时终止、输出不泄漏。256MiB Job限制/GOMEMLIMIT64MiB是配置上限/目标，不是测量值。
8. 即便语法接受，也必须tunnel_started=false、Connect Unsupported、无Protected/TunnelReady、无TUN/路由/DNS修改、M2阻断不变。检查失败输出是脱敏通用失败，不回显上游可能含敏感值的文本。管理员同时显式rescue时检查结果不得假定guard仍完整。
9. 独立rescue仍支持M2归属清理，无自动重装/后台重启竞态；它没有恢复尚未修改的TUN/DNS/路由的虚假日志。

### 真实隧道尚待开发与验收，不可先打勾

- 文档候选14条M3扩展的原生事务/逐字段回读/v2迁移；ALE appID+服务SID+接口+端点+协议端口与包层必要条件交集。
- 真实独占TUN/写前快照/可独立回滚；同名已有适配器不许上游OpenAdapter后改动；启动失败/强杀/服务崩溃/网变均能恢复M2而不放行。
- 多层仲裁、已有flow重授权、普通app同端点/同端口、raw/ICMP、IPv6/forward、LAN/DHCP边界、DNS绕行、boot交接外侧抓包。探针不可达绝不是无泄露证明。

### UI和资源验收补充

- 中文核心卡片/空态/校验失败与离线端点不溢出、缩放下层级清晰；禁止以绿色成功图标暗示核心摘要等于保护。
- 仍按前述WindowsGUI工作集/私有内存、服务空闲CPU、hover/切页帧时延、最小化/GUI退出各自测量。额外单列63MB核心流式校验峰值与-t子进程峰值，结束后确认回收，不把exe字节大小当工作集。
- 当前无常驻Go核心/隧道/托盘，对应稳态指标标“不适用/未实现”而不是0MB/0CPU。没有固定重绘或自动全文件hash轮询。

## preview.2新增待验收（均未执行）
仅隔离WindowsVM+独立控制台/快照：先检查新rescue可用，再显式M2；管理员隔离TUN启动应只到Quarantined、不能联网。检查既有/幽灵Wintun拒绝、伪造名称/GUID/实例拒绝、DNS/路由写前journal、核心/服务硬退出各崩溃点、journal校验破坏/断电、已恢复路由后重建/修改的冲突、物理用户后来DNS/IPv6/路由不被覆盖、独立rescue在daemon失效时先阻断再恢复、默认保留阻断、明确ALLOW-DIRECT才解除；未知provider必须保留。检查早期未配置MTU65535/已配置1500与未识别后态安全拒绝。源代码30个纯回归断言未执行，不计通过。
临时TUN的管理员编辑不能跨其SwDevice生命周期保留；只验证明确的独占实验范围，不能称VPN并行共存已支持。完整数据面旁路/重授权/boot/第三方仲裁待M3许可实现后再验收。UI/服务/核心内存与空闲CPU、动画帧时延分开测，不以exe大小或LinuxRSS代替。
