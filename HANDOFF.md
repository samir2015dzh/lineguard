# 开发交接：0.3.0-preview.3 / IPC5（暂停，M3未完成）

**不是可用VPN，不要日用；未签名，未在Windows运行或验收。Connect仍Unsupported，没有Protected。**

## 本轮（preview.3）实际新增：v3窄许可事务层（未接入生命周期）
- `crates/core/src/permit.rs`：纯v3计划，按WFP_POLICY_MATRIX固定14个对象（键`…0004000001`–`…000400000e`），全部挂在M2 provider/subLayer下（同子层才按权重仲裁；不用硬许可/CLEAR_ACTION_RIGHT）。
  - 门（10条）：4个ALE默认BLOCK（connect/recv-accept × V4/V6，权重0x1000）；2个TUN LUID许可；4个核心许可=完整App ID+专用服务SID描述符+物理LUID+单一IPv4+TCP/UDP分别+远端端口（权重0x2000）。
  - 包层（4条）：OUT/IN IPPACKET V4 × {TUN LUID；物理LUID+节点IPv4}。包层绝无身份/协议/端口条件，物理接口许可必带节点地址；IPv6零许可。
  - 参数校验（LUID非零且不同、可路由IPv4单播且不与198.18/15冲突、端口非零、UTF-16LE App ID、S-1-5-80五段SID）、逐字段回读比对（条件顺序无关、重复/多余/任一字段漂移即Drift）、无可信预期参数时一律Drift、启用顺序前置条件、撤销顺序、带SHA256的许可journal。
- `crates/agent/src/windows/permit.rs`：原生实现。条件按WFP host byte order构造；ALE_USER_ID用`O:SYG:SYD:(A;;CC;;;<服务SID>)`，回读时解析DACL须恰1条ACCESS_ALLOWED、掩码MATCH_FILTER；App ID由固定受控核心路径经FwpmGetAppIdFromFileName0派生。
  - `install_gate`（意图`INSTALL-ALE-GATE-KEEP-BLOCK`）：要求M2 Configured且无v3对象；单事务加10条，事务内回读=Gate才提交。
  - `open`（意图`OPEN-NARROW-DATA-PATH`）：要求M2 Configured、无独立应急阻断、门精确、调用方给出TUN实时回读确认；最后一个单独事务只加4条包层许可。
  - `revoke_all`：单事务删除全部自有v3键（包层在前），不碰M2；外来占键/未知对象拒绝扩大删除。
  - 写前journal→变更→事务内回读→提交→新会话回读；失败按Aborted/Uncertain如实记录。
- 联动：M2 inspect把v3键排除在“多余规则”之外；有v3对象时M2安装/移除拒绝；`wfp::inspect`合成状态：Open+M2完整=新`Narrowed`（UI显示“实验窄许可存在·不是全阻断”，Phase=Degraded），Drift即Drift。rescue `recover/remove`在独立应急阻断确认后、停核心前先`revoke_all`；服务`close_active`同序。RESCUE_MARKER升级为`…PermitRevoke.v3`，旧rescue不再满足前置检查。
- `lineguardctl guard permit inspect`：只读v3回读。
- **生命周期接入（本轮后续提交）**：新IPC命令`OpenNarrowPath`/`lineguardctl tun open --confirm OPEN-NARROW-DATA-PATH`，仅同会话经令牌核验的管理员、仅在`Quarantined`独占TUN上、配置代次一致时可用。服务先做全量健康回读，再派生参数→门事务→重新回读TUN→包层事务；成功进入新阶段`NarrowOpen`，任一失败走`close_active`（独立应急阻断→撤许可→停核心→恢复），不重试。`tick`同时要求v3回读：Quarantined须无v3对象，NarrowOpen须14条精确，否则同样关闭。Connect仍Unsupported，普通UI无放行入口。
- CI：`.github/workflows/ci.yml`——Linux格式检查/构建/core测试执行/Windows GNU交叉release构建/PE检查，及Windows原生core测试执行。CI从不运行产品exe或改系统网络。
- IPC升为5（guard::State新增Narrowed）。

## 尚未闭合，不能称M3真实联网已形成
1. 生命周期已能显式放行，但**数据通路是否真的可用完全未验证**：需隔离VM实证门/包层许可对sing-tun真实收发、ALE re-authorization对已有流、关闭后应急阻断须管理员解除才能再次放行等行为。
2. 包层许可与sing-tun实际收发路径（回注、loopback、TUN上DNS/fakeIP）是否恰好被这4条覆盖，完全未验证；ALE recv-accept对UDP回包的作用亦未验证。
3. 事件通知/拓扑代次、有限重连、DNS/fakeIP/真实TUN数据通路健康证据仍需补齐。
4. 仅独占Wintun实验环境；不与其他VPN并行（见前版说明，未变）。
5. 物理接口从不写回；一次性TUN上管理员改动不跨OS生命周期保留；无原子CAS。
6. 回读字段严格比对（flags须恰为PERSISTENT等），真实Windows可能返回额外标志而被判Drift——属安全拒绝，需VM校准，不可放宽成猜测。

## Windows实机证据（GitHub托管一次性VM，windows-2022，CI任务windows-smoke）
2026-11-22首次全部通过（20项）：rescue `--version`/只读inspect；临时用户真实登录会话中console服务+命名管道status/导入/代次递增/诊断不泄露密码/Connect拒绝；预配服务SID后`guard install`事务提交，回读6持久+6boot逐字段精确（M2严格flags比对与真实Windows一致）；**安装后对1.1.1.1:443的出站TCP实际被阻断**；重复安装为无操作；`rescue remove`（应急阻断→撤许可→删M2→删应急）后无残留且直连恢复。
CI查出并修复：管理员未降权令牌下console数据目录默认所有者为Administrators导致自建目录被拒（现显式`O:<用户>`）。
仍未覆盖：v3门/包层许可的真实安装与数据通路（需固定核心+真实节点）、boot冷启动、服务/BFE崩溃、旁路抓包、物理网卡/TUN恢复。

## 实际构建与验证
2026-11-22（UTC）云端Linux容器：Linux workspace构建、Windows GNU debug/release四个exe构建、core测试目标Windows交叉编译均退出0；**core 38个测试在Linux实际运行全部通过**（含新增8个v3测试；此前30个首次真正执行）。新增代码clippy无告警（遗留告警未改）。未执行任何exe、服务、WFP或网络变更；未在Windows运行。

## 到最小可用版仍缺
生命周期接入v3事务+可用单端点隧道、健康/退出/重连与恢复闭环、隔离WindowsVM真实故障/旁路抓包验收、最低限度安装/卸载与清楚应急入口。不能用编译代替这些。

## 到附件全量版还另缺
托盘/状态推送/首次向导、订阅与有限协议扩展/选线、完整安全与泄露探针、可选LAN/浏览器/时区策略、签名安装与更新/防回滚/卸载清理、多场景Windows兼容及GUI资源实测。无已验证百分比或工期。

入口：crates/core/src/permit.rs、crates/agent/src/windows/{permit,engine,network,wfp}.rs、WFP_POLICY_MATRIX.md、docs/M3-STATUS.md。先完成M3，不跳M4。
