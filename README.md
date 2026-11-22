# LineGuard · 未完成的Windows Rust开发版

原始整体思路全文：[docs/整体思路.md](docs/整体思路.md)；原文中的测试通过/性能数字是原始设想附带描述，不代表本项目已验证，实际状态见 [HANDOFF.md](HANDOFF.md)。

> **M3未完成、未经Windows运行验证、未签名，请勿日常使用。当前不能提供可用VPN或防泄露保护，Connect仍Unsupported。**
> 0.3.0-preview.3 / IPC5：在preview.2独占TUN隔离/网络journal/独立救援之上，新增v3窄许可（ALE身份门∩包层例外）计划、原生事务/逐字段回读/单事务撤销代码，rescue先撤许可；管理员可在已隔离TUN上以`tun open --confirm OPEN-NARROW-DATA-PATH`请求窄放行（仅隔离VM实验，**未验收，Connect仍Unsupported**）。
> CI（Linux+Windows）：构建、core 38个测试实际运行；Windows一次性VM冒烟已实测M2全阻断安装/回读/**出站确实被阻断**/独立救援撤销及console IPC。v3放行、冷启动、崩溃、旁路、视觉/性能验收未执行。继续开发入口及完整缺口：**[HANDOFF.md](HANDOFF.md)**。

Rust 原生 Windows 10/11 x64 桌面软件。中文深色界面、克制动效、按需绘制，不内嵌浏览器。

> **M3 尚未完成，不是可用 VPN。无隧道数据通路、无防泄露保证。** 本包未签名、未在 Windows 运行验证。已有 M2 原生 WFP 实验阻断会持续切断全部 IP 联网，没有 LAN / DHCP / 节点例外；危险命令仅可在具备独立控制台、快照的隔离 VM 验收。

## 当前能做什么

- 原生GUI ↔ 受限命名管道 ↔ Rust后台，离线JSON校验/DPAPI加密保存、脱敏诊断、独立WFP救援。
- WFP状态实时回读；界面显示最近读取，手动刷新，不从配置/journal推断成功。`Blocked`仅表示M2规则或独立应急规则字段完整，**执行效果未验收**。没有`Protected`。
- 固定 mihomo 1.19.34 的真实版本/大小/SHA256与许可证清单；管理员显式许可确认后可离线导入并原子保存，逐次运行前再校验。
- 管理员可通过SYSTEM服务执行固定核心的 `-t` **配置检查**，不是启动隧道。要求专用服务SID和实时完整实验阻断；秘密仅stdin，受Job/句柄白名单/超时约束。
- GUI显示离线端点与真实核心空态/校验错误，无假节点、测速、连通性或保护数据。

**不能做：** Connect返回Unsupported；普通运行不改网络。管理员实验可创建隔离TUN/其DNS和两条自有路由，但不放行节点、不下载订阅、不直连DoH、不自动更新。不把语法检查通过说成联网或保护通过。原因与剩余实质开发见 [docs/M3-STATUS.md](docs/M3-STATUS.md)。

## 普通离线预览：不改网络

四个exe须同目录。普通终端（仅未来 Windows 预览运行；本项目尚未运行验收）：

```powershell
.\lineguard-service.exe --console
# 另一个同用户、同登录会话终端
.\lineguard.exe --console
.\lineguardctl.exe --console status
.\lineguardctl.exe --console import .\examples\offline.example.json
.\lineguardctl.exe --console diagnostics
.\lineguard-rescue.exe inspect --console
```

打开/关闭界面、普通启动后台都不安装或撤规则；退出服务/删除文件也不会撤持久规则。原始导入文件仍可能是明文，程序不会删除它；预览不要使用真实凭据。

## 独立救援先于实验阻断

管理员终端可不经服务/IPC移除**本产品自有固定GUID规则**：

```powershell
.\lineguard-rescue.exe --version
.\lineguard-rescue.exe inspect
# 先恢复本产品临时网络并保持阻断
.\lineguard-rescue.exe recover --confirm RESTORE-OWN-NETWORK
# 明确允许恢复直连；不重置其他产品或物理接口配置
.\lineguard-rescue.exe remove --confirm ALLOW-DIRECT
```

失败、归属冲突、BFE不可达时不可假定已恢复。当前救援可按网络journal恢复本产品临时TUN/自有路由；recover默认保留独立应急阻断，remove才明确允许直连。恢复边界及尚未验收的缺口见HANDOFF。

## 危险命令：仅供隔离VM后续验收

预先具备 `LineGuardPreview` LocalSystem / AutoStart 服务、同目录可信service与rescue映像才允许安装。程序不自动安装/修改SCM、不自动提权。`--experimental-vm-only`是操作者确认，不是虚拟化检测。

```powershell
.\lineguardctl.exe guard inspect
.\lineguardctl.exe guard install --experimental-vm-only --confirm BLOCK-ALL-IP
# 安装6持久+6boot；任一不支持/回读不符则事务拒绝
```

**不要在日常电脑执行。先有独立控制台和救援，再装规则。** 没有规则也不意味着其他软件不会阻断；有规则也不是冷启动、BFE崩溃或流量执行通过。

### 可选核心管理（不是连接命令）

先阅读 [third-party/README.md](third-party/README.md) 和完整许可证；本包不附核心或驱动。取得准确官方公开exe后，未来仅在隔离VM管理员终端：

```powershell
.\lineguardctl.exe core manifest
.\lineguardctl.exe core inbox
# 管理员把固定公开exe离线复制到上一步给出的受控目录，文件名mihomo-candidate.exe
.\lineguardctl.exe core import <上一步暂存文件的完整绝对路径> --confirm ACCEPT-MIHOMO-GPL3-AND-EMBEDDED-WINTUN
.\lineguardctl.exe core info
# 只有已启动SYSTEM服务且令牌含启用的NT SERVICE\LineGuardPreview SID可执行：
.\lineguardctl.exe core check 1 --confirm CHECK-CONFIG-NO-TUNNEL
```

普通GUI没有核心执行权限；无需提权查看离线配置。core check仅验证受控生成配置能否被固定上游接受；TUN关闭、无网络设置变更。上游输出丢弃以免泄露密码，拒绝/超时显示真实失败；不保证它在Windows已验证可用。

管理员隔离TUN开发入口（**仍全阻断，非连接VPN**）：`lineguardctl.exe tun start 1 --confirm START-EXCLUSIVE-TUN-BLOCKED`。需要已核验M2、专用服务SID、固定核心及新救援版本；拒任何既有Wintun设备。不要在真实电脑执行。

## 数据与资源边界

- console：LocalAppData/LineGuardPreviewConsole，用户DPAPI；服务：ProgramData/LineGuardPreview，机器DPAPI+SYSTEM/管理员ACL。
- WFP journal：ProgramData/LineGuardGuardPreview；网络journal：ProgramData/LineGuardNetworkPreview；可选固定核心与导入收据：ProgramData/LineGuardCorePreview，均管理员/SYSTEM ACL。
- 服务控制管道目前绑定活动物理控制台登录，RDP/无人登录启动/多会话尚不支持；WFP独立救援不受此限制。
- 无托盘：关窗口退出界面，独立服务继续。系统减少动画/界面开关有效，无固定60fps、自动测速或遥测。核心校验流式缓冲32KiB；生成含密配置上限16KiB。Job安全上限不是实测内存数字。
- Windows工作集、私有内存、空闲CPU、动效帧延迟均**未测量**。后续验收要区分GUI/服务/核心、静止/动画/最小化/关闭。

构建：[BUILD.md](BUILD.md) / [BUILD-RESULTS.md](BUILD-RESULTS.md)。安全：[SECURITY.md](SECURITY.md) / [WFP_POLICY_MATRIX.md](WFP_POLICY_MATRIX.md)。需求：[REQUIREMENTS.md](REQUIREMENTS.md)。未执行验收：[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)。版本：软件0.3.0-preview.2，IPC 4，配置schema 1，实际WFP策略仍2；客户端整套升级，勿混用旧协议。
