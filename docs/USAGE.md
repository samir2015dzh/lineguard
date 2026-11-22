# 使用说明（开发预览，仅隔离 Windows 虚拟机）

> 本页是 0.3.0-preview.3 的详细操作说明。**不要在日常电脑上执行任何危险命令。** 概览见 [README](../README.md)。

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

先阅读 [third-party/README.md](../third-party/README.md) 和完整许可证；本包不附核心或驱动。取得准确官方公开exe后，未来仅在隔离VM管理员终端：

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

## v3 窄放行（实验）

在已隔离的独占 TUN 上（先执行上面的 `tun start`），管理员可请求加 v3 窄许可：

```powershell
.\lineguardctl.exe guard permit inspect          # 只读回读 v3 对象
.\lineguardctl.exe tun open --confirm OPEN-NARROW-DATA-PATH
```

服务先全量回读健康证据，再装 ALE 身份门、复核 TUN，最后加 4 条包层许可，进入 `NarrowOpen`。任一失败自动按“独立应急阻断 → 撤许可 → 停核心 → 恢复网络”收尾，不重试。收尾后应急阻断保留，须管理员 `lineguard-rescue.exe remove --confirm ALLOW-DIRECT` 才能直连。**放行后的真实联网与旁路均未验证。**
