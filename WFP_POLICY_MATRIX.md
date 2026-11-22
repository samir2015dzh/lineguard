# M3 评审结论（当前可执行策略仍为 M2 v2）

**本预览不启用隧道数据通路。** 本文区分“官方 API 能表达的候选”与“已经实现/验证的策略”。preview.2不加入任何PERMIT、不删除M2全局阻断；管理员可显式启动隔离TUN及其自有DNS/两条路由，但不能联网。Connect 明确 Unsupported，既无 Protected 也无 TunnelReady。

## 交叉层矛盾与候选（未落地为 native filters）

Microsoft 明确：没有跨层仲裁。ALE PERMIT 不能覆盖 IPPACKET BLOCK；在同一子层同一层才按权重比较。硬 PERMIT/CLEAR_ACTION_RIGHT 不能用来绕过其他安全产品。IPPACKET 层可匹配远端地址、本地接口 LUID，但**没有 App ID / 协议 / 端口**。因此只把节点 IP 加进包层白名单会改变安全边界，绝不是本产品可接受的实现。

候选是两道必要条件的交集，而不是跨层“高优先级放行”：

| 运行层 | 默认 | 高于本产品默认 BLOCK 的同层软 PERMIT 条件 | 状态 |
|---|---|---|---|
| IN/OUT IPPACKET V4 | BLOCK（保留M2） | 本产品 TUN 的实际 LUID；或实际物理 LUID + 单一远端 IPv4 | 未实现，不下发 |
| IN/OUT IPPACKET V6、IPFORWARD V4/V6 | BLOCK | 无 | M2已编译，运行未验证 |
| ALE_AUTH_CONNECT / ALE_AUTH_RECV_ACCEPT V4 | BLOCK | TUN LUID；或完整核心 App ID + 专用服务SID + 物理 LUID + IPv4 + TCP/UDP分别 + 远端端口 | 未实现，不下发 |
| ALE_AUTH_CONNECT / ALE_AUTH_RECV_ACCEPT V6 | BLOCK | 无 | 未实现，不下发 |
| boot-time 6层 | BLOCK | 无；启动阶段不尝试解析、DNS或联网 | M2已编译，boot切换未验证 |

候选合计保留原12条（6持久+6boot），另加4个ALE默认BLOCK、2个ALE TUN许可、4个ALE核心许可、4个包层许可，即14条新增持久规则。这个计数是候选规划，不是已安装结果。接口条件不能用请求里的字符串替代真实 LUID；IP/port在WFP条件中用host byte order。不能把其他应用或任意SYSTEM进程视作核心。

核心外层套接字由 mihomo 进程发起；必须由固定受控路径派生 App ID（FwpmGetAppIdFromFileName0），并通过 ALE_USER_ID 安全描述符匹配 SCM 已加入令牌的 `NT SERVICE\LineGuardPreview` SID。泛SYSTEM或调用管理员的SID不够：同账户可运行同一exe并换配置。当前只实现专用服务SID前置校验用于隔离配置检查；没有将其冒充已安装ALE身份条件。

## 候选事务/崩溃顺序（未实现，不能视为交接承诺）

1. 保留M2全部包层BLOCK，在同一产品命名空间事务加入ALE默认拒绝与精确身份许可，提交并逐字段回读；已有连接的策略变化需要ALE re-authorization，不是只检查新连接。
2. 由Job管理核心，在仍全阻断时创建并确认**本产品独占**TUN，确认物理接口、路由、DNS所有权及可独立撤销快照；最后一个事务才加包层窄许可。boot规则不作运行期开关。
3. 停止/退出/接口变化：先事务撤包层许可恢复M2，再终止核心和恢复仅自己改动的路由/DNS。失败不能宣称Blocked或恢复直连。服务崩溃依靠Job杀核心，但不能用“进程死了”证明驱动/路由残留已清理。
4. 独立rescue必须先能处理v3许可和TUN/路由journal，方可开放v3启动命令。不得先撤全局拒绝换联网；不得把持久规则装载与boot移除之间的时间窗口说成已验证无间隙。

## 当前具体未闭合项与保守决定

- 官方条件矩阵足以支持候选交集，并不证明 mihomo/sing-tun 的 Windows 包路径、回注、已有流重授权和每个接口变化时的实际行为。**没有证据说原生WFP一定不能表达；也没有把候选写成已经安全实现。**
- 固定 mihomo v1.19.34 / sing-tun v0.4.29 的 `tun_windows.go`：创建失败若是已存在，会 OpenAdapter 并继续配置；即使 dns-mode=disabled 仍会 SetDNS(nil)；AutoRoute可加路由，Close显式关适配器。不能假设禁用DNS模式就完全没有系统副作用，不能在无归属校验/快照/独立恢复时打开TUN。
- 新增网络journal/独立rescue，按新随机独占实例与后态恢复；Job不替代网络恢复。物理接口只读，临时TUN不承诺保留管理员在其上的编辑。
- 管理员可请求长驻隔离TUN：tun.enable=true，auto-route=false/strict-route=false，物理interface-name固定；M2全阻断保持，无数据许可。-t仍有独立关闭TUN的模板。没有连通或保护验证。
- 原生v3许可/原子交接仍须实现；独占TUN、写前journal及独立恢复已有代码但未Windows验证。独立应急provider尾号00050001、subLayer尾号00050002、6条filter从00051001到00051006，marker LineGuard.Emergency.v3，无serviceName绑定，persistent-only，子层权重0xfffe、filter权重u64::MAX、无条件BLOCK；不宣称boot有效。

## 官方依据

- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info
- https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.34/main.go
- https://raw.githubusercontent.com/MetaCubeX/sing-tun/v0.4.29/tun_windows.go
- https://raw.githubusercontent.com/MetaCubeX/sing-tun/v0.4.29/internal/wintun/dll_windows_amd64.go
- https://raw.githubusercontent.com/MetaCubeX/sing-tun/v0.4.29/internal/wintun/dll_windows.go

---

## M2 已实现矩阵与历史设计（下文仅指旧v2，当前网络救援边界见HANDOFF）

# M2 WFP 原生阻断矩阵（先于实现编写）

版本：策略2 / 软件0.2.0-preview.1。**实验室危险阻断，不是日常保护**。无Windows运行/抓包/启动验收；未提供隧道，启用会有意切断IP联网。默认启动不安装任何规则。只允许管理员在隔离VM显式确认安装；先具备同目录独立救援。

## 固定对象与规则

Provider：a9b29c63-2a1a-49c9-ae64-4e4700020001；SubLayer：a9b29c63-2a1a-49c9-ae64-4e4700020002。持久，两者providerData均为ASCII `LineGuard.Guard.v2`。provider绑定`LineGuardPreview`，必须预先存在且AutoStart/LocalSystem；本版不安装/改该服务配置。选择显式绑定以避开官方Object Management和PROVIDER0对未绑定serviceName加载条件的文字差异；服务崩溃不改变auto-start配置，禁用服务可能影响BFE下次加载，必须降级，不能保证此时持续阻断。

所有filterKey来自a9b29c63-2a1a-49c9-ae64-4e4700030000加下表序号（十进制）；每条也带同样providerData。SubLayer权重0x7000，filter weight类型FWP_UINT64、值0x1000。动作FWP_ACTION_BLOCK，0个条件（AND空集=匹配全部），无permit、无callout、无CLEAR_ACTION_RIGHT、无动态会话。采用系统默认filter block仲裁，不靠“最高权重”宣称不可覆盖；其它高层/高权重硬permit及第三方驱动须VM冲突测试。

| 序号 | Windows管理层 | 地址族/路径 | 生命周期flags | 条件/范围 |
|---|---|---|---|---|
| 1 | FWPM_LAYER_INBOUND_IPPACKET_V4 | IPv4本机接收 | PERSISTENT | 无，覆盖该层所有包 |
| 2 | FWPM_LAYER_INBOUND_IPPACKET_V6 | IPv6本机接收 | PERSISTENT | 同上 |
| 3 | FWPM_LAYER_OUTBOUND_IPPACKET_V4 | IPv4本机发送 | PERSISTENT | 同上 |
| 4 | FWPM_LAYER_OUTBOUND_IPPACKET_V6 | IPv6本机发送 | PERSISTENT | 同上 |
| 5 | FWPM_LAYER_IPFORWARD_V4 | IPv4转发 | PERSISTENT | 无，覆盖到达该层的转发包 |
| 6 | FWPM_LAYER_IPFORWARD_V6 | IPv6转发 | PERSISTENT | 同上 |
| 7 | FWPM_LAYER_INBOUND_IPPACKET_V4 | IPv4本机接收 | BOOTTIME | 无，仅从TCP/IP驱动启动至BFE接管 |
| 8 | FWPM_LAYER_INBOUND_IPPACKET_V6 | IPv6本机接收 | BOOTTIME | 同上 |
| 9 | FWPM_LAYER_OUTBOUND_IPPACKET_V4 | IPv4本机发送 | BOOTTIME | 同上 |
| 10 | FWPM_LAYER_OUTBOUND_IPPACKET_V6 | IPv6本机发送 | BOOTTIME | 同上 |
| 11 | FWPM_LAYER_IPFORWARD_V4 | IPv4转发 | BOOTTIME | 同上 |
| 12 | FWPM_LAYER_IPFORWARD_V6 | IPv6转发 | BOOTTIME | 同上 |

这些是文档定义的内核管理层，安装前用FwpmLayerGetByKey0验证FWPM_LAYER_FLAG_KERNEL；boot-time只能加在内核层。不使用ALE_APP_ID、端口、应用、接口等此版无必要的条件，不把ALE条件塞入包层。BOOT/PERSISTENT互斥，分别建6条。任何boot规则拒绝/读回不符 -> 整个写事务abort；**不退化为只有运行期却报告boot成功**。

**例外为空**：不放行LAN、节点IP、DHCPv4/v6、ICMPv6控制、系统DNS、loopback或TUN。这会妨碍获取IP、远程会话与连通性，故只能有独立控制台的VM实验。WFP不覆盖固件/PXE、ARP二层、未经过这些层的虚拟交换/内核旁路；不承诺对本机管理员/恶意内核保证。loopback是否遍历包层依Windows路径，不能把“零例外”解释成覆盖全部本地IPC。

## 生命周期、事务与读回

- FwpmEngineOpen0使用本机、RPC_C_AUTHN_WINNT、非dynamic session，txnWaitTimeout=1000ms；FwpmEngineClose0 RAII。不使用netsh/普通防火墙Shell。
- 显式读/写事务保证一致视图；写前读取现有provider/subLayer/固定12 GUID及产品provider枚举。非本版本/所有权冲突/额外未知规则拒绝；不“先删了再重装”。
- 变更前管理员专属目录写快照journal（版本、动作、pre-state、每条真实filterId/flags/layer/action/条件数/权重；transaction_objects保存新分配ID的提交前事务视图，须结合Committed/Aborted/Uncertain判断）；prepare落盘失败即不改WFP。新增对象/删自有对象全在一个事务。任一失败显式abort，RAII兜底；abort失败/commit结果不确定必须journal标uncertain，不报成功。
- 安装后在同事务验证12规则、provider/subLayer元数据/flags/服务绑定/权重，再commit；提交后重新开启读事务读取证据。后写journal失败须报告“可能已提交，inspect/rescue”，不可称回滚成功。
- 常规枚举默认不含boot和disabled，故使用FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | INCLUDE_DISABLED、actionMask=0xffffffff，按6层分别枚举产品provider，检查未知/重复key。枚举聚焦这6层；其他层引用并不被声称全部扫描，删除父对象时仍由WFP依赖检查拒绝未知依赖。还查询固定GUID，避免foreign provider占同key漏检。每层最多64条，超限拒绝，不无限读。
- 运行期persistent不能有DISABLED，provider不能有DISABLED；boot对象是**存储/下次启动注册证据**，当前BFE运行时不要求boot正在执行。它不是本次启动已防泄露的实测证据；boot存储对象的ID可能不代表当前活动运行期LUID，不强求其非零。
- 原生WFP持久存储、枚举、DISABLED状态、实际执行是不同证据。即使回读完整，也只可显示“阻断规则完整 / 效果未验收”的Blocked策略状态，无Protected；BFE不可达/字段漂移/缺规则 -> Unknown/Degraded，绝不根据journal推断Blocked。
- 平台描述boot到persistent原子交接，前提是正确安装/加载；**不等于运行期BFE停止/崩溃期间有无缝保证**，不把boot当BFE运行期故障备用。服务退出不主动撤规则；下一次状态查询实时回读，不自动重装。

## 授权与救援先行

普通命名管道只有status/import/connect(Unsupported)/diagnostics，无install/remove命令。管理员CLI直接调用WFP，校验真实elevated token和Administrators成员；`guard install --experimental-vm-only --confirm BLOCK-ALL-IP`，不会自行UAC提权。安装要求同目录rescue为x64 PE且含策略v2移除能力marker、服务为AutoStart/LocalSystem且映像是同目录service；marker不是签名，VM参数不是自动隔离检测。普通GUI永远没有安装/解除按钮。

`lineguard-rescue remove --confirm ALLOW-DIRECT`必须elevated并本地真实身份校验，不依赖服务/IPC、也不要求服务仍存在或auto-start。按固定GUID、provider/subLayer及版本标记确认所有权，只删除自有对象；不全局reset，不动其他provider、DNS/IPv6/路由。部分缺失时仍可移除剩余合法自有对象；如果GUID所有权冲突或未知依赖阻挡，事务abort并真实报告，不能扩大删除范围。单独管理员文件锁串行化CLI/救援，服务只观察不回装，所以救援后不会被后台自动封网。

## 官方依据（2026-11-22查阅）

- https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

不把搜索摘要/Microsoft Q&A当SDK保证。公开文档只能支持接口与生命周期设计；boot过滤具体Windows构建适用性、仲裁、已有流、进程崩溃/BFE失败、重启抓包仍全部未验证。
