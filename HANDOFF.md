# 开发交接：0.3.0-preview.2 / IPC4（暂停，M3未完成）

**不是可用VPN，不要日用；未签名，未在Windows运行或验收。Connect仍Unsupported，没有Protected。**

## 本轮实际保存
- 仍3个Rust package/原生egui；中文质感与轻动效、按需重绘、有界IPC保持。GUI仅显示最近真实证据，无危险启用按钮。
- 新增core/network：受限所有权、512KiB校验journal、路由后态比较/恢复进度、状态和纯回归用例。
- Windows/network：只读物理网卡DNS/IPv6/路由快照；SetupAPI识别含幽灵Wintun设备；每次随机独占名称+上游派生GUID+实际LUID/实例ID，拒复用已有Wintun。
- Windows/engine：固定hash核心真实长进程启动、服务SID、命名Job原子归属、匿名stdin传密。管理员显式tun start可请求创建隔离TUN和两条写前记录的自有/1路由，M2全阻断一直保留。
- 只会进入Quarantined（不能联网），不产生隧道保护成功状态。活动时约1秒快照轮询，退出/网变/代次改变尝试先独立阻断再停止/恢复；失败冻结自动恢复重试，自动重连禁用。
- 新增不绑定SCM服务的独立6条persistent应急BLOCK；rescue recover先确认这套阻断，再核验Job进程身份/按后态恢复；remove需ALLOW-DIRECT。writer锁冲突可核验真实产品服务身份后经SCM有限等待停止，不强杀未知进程、不重置第三方网络。

## 尚未闭合，不能称M3真实联网已形成
1. **原生ALE身份门+包层精确例外还没有实现。** 当前绝无PERMIT，数据面不可用。不能把ALE permit当成覆盖IPPACKET block，不能只放节点IP。
2. 下一开发单元是上述交集的事务/逐字段回读/版本journal/独立撤销，再把包层许可作为最后启用步骤；撤许可先于停止核心。
3. 事件通知/拓扑代次、有限重连、fakeIP/DNS/真实TUN数据通路健康证据仍需补齐；当前快照轮询不是全网变检测或泄露探针。
4. 当前仅独占Wintun实验环境：固定上游会尝试OpenAdapter，且Create/Close可触发全局孤儿清理；因此拒任何现有含幽灵Wintun，不支持与其他VPN并行。Windows自定义FD不支持，未fork/写驱动。
5. 物理接口从不写回，因此保留用户后来物理DNS/IPv6/路由修改。新TUN是一次性设备：服务崩溃/Job关闭会触发OS移除它，不能承诺保留管理员在该临时设备上的修改；并发管理员变更没有原子CAS保证。冲突不猜测性覆盖。
6. 恢复/驱动初始化/路由规范化/boot交接/BFE故障/第三方仲裁/已有流均未经Windows验证；窄初始化白名单可能安全拒绝未认识的Windows后态，不能声称所有崩溃情形已通过。

## 实际构建与验证
2026-11-22 13:40 Asia/Shanghai：Linux workspace、Windows GNU release四个exe、core测试目标Linux和Windows两种编译均退出0；30个纯core测试函数只编译，断言未执行。静态PE检查x64、未签名。未执行exe、核心、服务、测试、任何系统网络变更。
本次源码保存前仅另做去本机绝对路径/可移植构建脚本整理；产品Rust源码对应上述编译。没有新增工具安装、远端release、上传exe。

## 到最小可用版仍缺
精确WFP交接+可用单端点隧道、健康/退出/重连与恢复闭环、隔离WindowsVM真实故障/旁路抓包验收、最低限度安装/卸载与清楚的应急入口。不能用编译代替这些。

## 到附件全量版还另缺
托盘/状态推送/首次向导、订阅与有限协议扩展/选线、完整安全与泄露探针、可选LAN/浏览器/时区策略、签名安装与P-256/CNG更新/防回滚/卸载清理、多场景Windows兼容及GUI资源实测。无已验证百分比或工期。

入口：docs/M3-STATUS.md、WFP_POLICY_MATRIX.md、crates/agent/src/windows/{engine,network,wfp}.rs、crates/core/src/network.rs。先完成M3，不跳M4。
