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
- `lineguardctl guard permit inspect`：只读v3回读。**没有任何CLI/IPC能安装门或放行**，`install_gate/open`目前无调用方。
- IPC升为5（guard::State新增Narrowed）。

## 尚未闭合，不能称M3真实联网已形成
1. **生命周期尚未调用install_gate/open**：下一单元是在`engine::Lifecycle::start`于TUN回读确认后依次调用（门→包层），`tick`在任一证据失效时走`close_active`（应急阻断→撤许可→停核心→恢复）。连同ALE re-authorization对已有流的影响需VM实证。
2. 包层许可与sing-tun实际收发路径（回注、loopback、TUN上DNS/fakeIP）是否恰好被这4条覆盖，完全未验证；ALE recv-accept对UDP回包的作用亦未验证。
3. 事件通知/拓扑代次、有限重连、DNS/fakeIP/真实TUN数据通路健康证据仍需补齐。
4. 仅独占Wintun实验环境；不与其他VPN并行（见前版说明，未变）。
5. 物理接口从不写回；一次性TUN上管理员改动不跨OS生命周期保留；无原子CAS。
6. 回读字段严格比对（flags须恰为PERSISTENT等），真实Windows可能返回额外标志而被判Drift——属安全拒绝，需VM校准，不可放宽成猜测。

## 实际构建与验证
2026-11-22（UTC）云端Linux容器：Linux workspace构建、Windows GNU debug/release四个exe构建、core测试目标Windows交叉编译均退出0；**core 38个测试在Linux实际运行全部通过**（含新增8个v3测试；此前30个首次真正执行）。新增代码clippy无告警（遗留告警未改）。未执行任何exe、服务、WFP或网络变更；未在Windows运行。

## 到最小可用版仍缺
生命周期接入v3事务+可用单端点隧道、健康/退出/重连与恢复闭环、隔离WindowsVM真实故障/旁路抓包验收、最低限度安装/卸载与清楚应急入口。不能用编译代替这些。

## 到附件全量版还另缺
托盘/状态推送/首次向导、订阅与有限协议扩展/选线、完整安全与泄露探针、可选LAN/浏览器/时区策略、签名安装与更新/防回滚/卸载清理、多场景Windows兼容及GUI资源实测。无已验证百分比或工期。

入口：crates/core/src/permit.rs、crates/agent/src/windows/{permit,engine,network,wfp}.rs、WFP_POLICY_MATRIX.md、docs/M3-STATUS.md。先完成M3，不跳M4。
