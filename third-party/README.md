# 固定核心与驱动来源（未捆绑、未运行、未验证签名）

机器可读真实清单：manifest.json。LineGuard将清单编译内置；用户不能在运行目录放一个新清单绕过校验。

- mihomo 官方 release：https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34
- 正常公开 API：https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.34
- 选择基础amd64-v1而非更高指令集，归档22417367字节；exe61192704字节。精确SHA256见manifest，不复制多处维护。
- API digest与实际归档SHA256一致；这是HTTPS元数据+固定hash的信任，不是维护者签名/不可变release/可复现构建证明。release immutable=false。
- 上游源码 GPL-3.0 完整文本：licenses/mihomo-GPL-3.0.txt。子进程边界不自动免除GPL义务，今后如分发核心需同时安排对应源码、构建材料和声明；本包没有分发该exe。
- mihomo固定版本go.mod固定sing-tun v0.4.29。其 `internal/wintun/dll_windows_amd64.go` 使用go:embed，`dll_windows.go`从内存加载；因此不能声称额外放个官方wintun.dll就能替换或证明实际嵌入驱动。
- 固定sing-tun源文件中的amd64/wintun.dll与官方 https://www.wintun.net/builds/wintun-0.14.1.zip 中同架构DLL SHA256一致。本地仅做公开文件字节摘要比对；没有反汇编、修改或从exe逆向提取DLL。未验证release内实际嵌入DLL字节、Authenticode链或实际内核加载签名。
- 官方二进制许可：licenses/wintun-0.14.1-prebuilt.txt；不要用源码GPL许可证冒充预编译DLL许可。未自动接受、未修改、未再分发驱动。
- 核心离线导入要求管理员显式 `ACCEPT-MIHOMO-GPL3-AND-EMBEDDED-WINTUN`；这是使用者确认，不是程序替用户或法律审查作决定。无自动下载或在线更新。

LineGuard Rust 新增sha2 0.11.1（MIT OR Apache-2.0），用于流式固定文件校验，Cargo.lock固定精确依赖。此前egui/eframe MIT/Apache-2.0、windows-sys MIT/Apache-2.0等仍须在正式发行时生成完整传递依赖许可清单。

公开依赖下载仅保存在开发目录 .tools/upstream，不进source/preview zip，不包含任何用户节点/订阅凭据。

离线导入先用管理员 `core inbox` 创建专用SYSTEM/管理员暂存目录，再由管理员将准确公开exe复制并改名mihomo-candidate.exe。import只接收该位置精确绝对路径，不从Downloads/UNC/网络盘等任意用户路径执行高权限读取；它仍只复制并校验，不运行。
