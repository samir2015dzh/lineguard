# M3 管理预览安全边界（数据通路未完成）

## 当前能力不是防泄露认证

已有实验室全IP阻断和固定核心离线管理/配置检查，新增管理员显式独占TUN隔离管理，但仍没有节点许可或可用隧道。默认运行不装规则；管理员以真实elevated token、Administrators成员与精确确认意图直接调用原生WFP。普通命名管道没有install/remove/disable操作，也没有shell/任意可执行路径接口。GUI不自行提权、没有危险启用按钮。

所有规则与语义详见WFP_POLICY_MATRIX.md。使用固定provider/subLayer GUID、版本marker、12个固定filterKey：6个包/转发内核层各一条PERSISTENT和BOOTTIME。没有LAN/DHCP/loopback/TUN/端点豁免。范围是到达指定层的IP包，不是ARP、固件/PXE、虚拟交换所有路径或恶意内核。管理员/驱动攻击不在绝对保证内。

## 真实证据与生命周期

读回必须是当前BFE事务视图，包含boot/disabled枚举、固定GUID查询、父对象归属/flags/服务绑定/权重、filter层/动作/条件数/flags/权重/真实ID。普通状态从实时回读更新单一Controller，journal不作为已阻断依据。无规则+安装失败不能变Blocked。

Blocked是“策略字段完整、运行效果未验收”的内部状态；enforcement_verified始终false，没有Protected。boot注册不是本次冷启动执行证据。WFP存储/枚举/未disabled/流量执行不同；其它子层硬permit/第三方过滤冲突仍需实测。

provider绑定LineGuardPreview。安装与完整性检查要求AutoStart、LocalSystem、同目录service映像（不接受其他命令参数）；程序不安装/调整服务。该配置让持久性不依赖当前进程存活，但管理员禁用服务可能影响后续BFE加载，读取应降级。冷启动boot->persistent交接的文档语义不是运行期BFE停机/崩溃持续有效的保证。BFE不可达必须Unknown；不靠自动删/重装规则掩盖故障。

## 事务、journal与独立救援

WFP engine/枚举内存/枚举句柄/事务集中RAII；非dynamic session、写事务可显式abort，失败兜底abort；不使用netsh。写前固定GUID归属校验，管理员专用文件锁串行化CLI/救援。准备快照journal落盘后才改WFP，任意对象不支持或同事务验证不符即abort；不会提交只有部分boot的集合。

journal是版本化、管理员ACL保护的JSON，保存变更前真实filterId/层/flags/动作/条件数/权重与操作状态。Prepared不是成功；commit尝试后失败或abort失败记Uncertain。提交成功后另开读事务取证；journal最终写失败明确警告可能已提交，不能声称回滚或已经恢复网络。磁盘/加密操作不受4秒管道I/O预算硬截断，请求超时要刷新确认。

安装先检查同目录rescue为x64 PE且含策略v2及网络恢复能力marker，避免误用只有只读能力的M1 rescue。marker只是兼容性提示，不是密码学真实性证明；预览未签名，所有管理员运行的目录/二进制必须可信。--experimental-vm-only是操作者确认，不是可靠的VM自动检测。

rescue remove直接访问WFP，不依赖服务、管道、WTS或自动启动配置；真实管理员+ALLOW-DIRECT意图。只移除固定GUID、关联provider/subLayer和v2 marker确认属于本产品的对象。部分缺失可清理剩余自有对象；外来归属/未知依赖导致abort而非扩大删除。枚举聚焦矩阵6层，其他层未知引用通过删除父对象的WFP依赖检查导致拒绝；不声称扫描全系统。系统其他防火墙及物理DNS/IPv6/路由不写回；网络恢复只针对自有临时资源。详见下方当前M3边界。

## IPC、存储与隐私

管道显式protected DACL、单登录SID、拒远程、首实例保护；读请求后核验Windows token的user/logon/session，恢复身份后才执行effect（Revert失败终止进程）。客户端发秘密前核验服务进程token、session、同目录映像路径。普通授权同SID恶意程序仍可能调用离线导入，这是边界，不以UI确认布尔值代替管理员授权。

128KiB帧/64KiB导入/16条线路/有界GUI队列/4秒管道I/O预算；服务空闲200ms接入等待，无无限日志。没有活动核心时仅请求读取WFP；活动隔离核心按约1秒读取健康快照，无网络探测或UI固定帧重绘。WFP事务锁等待1000ms；API/磁盘可能更慢，不能保证整个请求必在4秒完成。

console使用用户DPAPI；SCM使用机器DPAPI+SYSTEM/管理员目录/文件ACL。机器DPAPI不是用户隔离，密文ACL必需。使用Known Folder路径、拒重解析/不可信目录所有者、独占writer与原子密文替换；损坏配置锁定导入，保留原文件。诊断白名单不含节点地址、名称、密码、token或路径。输入/序列化buffer与秘密自身用zeroize清理，不保证清除所有库副本、换页或crash dump；不使用真实凭据测试。

## 未完成

没有Windows运行、WFP生效/冷启动/崩溃抓包、GUI视觉/内存/CPU/帧时延验收。没有托盘、订阅、直连DoH引导、浏览器/时区修改、安装器或在线更新。严格模式未来先离线引导，不能临时撤全局阻断下载；LAN默认不放行。探针不可达不是无泄露证明。

已下载公开mihomo/Wintun素材并只读核查真实hash/源码/完整许可，未执行、未捆绑；固定清单与供应链限制见third-party/README.md，不把子进程当许可免责。更新按原文P-256/CNG+可信公钥设计，未生成/保存私钥、未获取证书。当前只在本机打包unsigned危险预览，未公开发布。

## M3 preview.2新增边界

实际状态与未闭合安全条件以HANDOFF.md为准。新命名Job/核心长进程和TUN管理仅在M2全阻断下启动；不加入PERMIT。普通UI没有高权限操作入口，IPC StartExclusiveTun要求真实管理员token、同会话、SYSTEM服务SID与精确意图。
网络journal采用SYSTEM/管理员ACL、独占writer、写前快照、SHA256校验与同步原子替换；校验和防意外损坏，不是MAC。只恢复当前仍等于产品后态的自有路由；已恢复后重现的路由判冲突。物理DNS/IPv6/路由只读不写，不覆盖后来的用户改动。
独立应急provider无SCM绑定，6条持久BLOCK，无boot保证；先事务提交并实时回读再停核心/恢复。默认恢复保留阻断，解除需ALLOW-DIRECT。服务失效不依赖IPC；活跃writer仅可经真实身份核验后停止产品服务并有限等待，失败不强杀或破锁。
当前仅独占Wintun实验范围。上游全局driver/orphan操作不能靠自定义FD绕过（Windows不支持）；拒任何现有/幽灵Wintun，不宣称与其他VPN共存。临时TUN受SwDevice/Job生命周期约束，不能保证崩溃后保留管理员在其上的编辑；并发管理员改动没有原子比较删除API。详见HANDOFF。
活动核心约1秒快照轮询（加上IPC/native等待），不是即时全网变事件；无自动重连。恢复失败冻结重试并保留journal。所有FFI/ACL/恢复效果仅编译，未运行验收。无Protected、无泄露或运行期/boot零间隙保证。
