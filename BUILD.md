# M3 管理预览构建说明

> 0.3.0-preview.3 起：CI（`.github/workflows/ci.yml`）在 Linux 与 Windows 上构建并实际运行 core 测试，另有一次性 Windows VM 冒烟测试；发布由 `.github/workflows/release.yml` 从版本标签在 CI 中构建。以下为本地构建说明。

## 固定输入

- Rust 1.100.0（rust-toolchain.toml），Cargo.lock 已提交到本机源码。
- eframe/egui 0.37.0，glow 后端，无 WebView2/Node/Tauri。
- Windows GNU 开发预览目标 `x86_64-pc-windows-gnu`；正式发布链建议 Windows MSVC。
- 源码/工具链目录使用 remap-path-prefix；打包脚本仅白名单源码，不包含工具、target、数据、凭据。
- 0.3.0-preview.3 是 M3 未完成的管理预览；exe 在 target/x86_64-pc-windows-gnu/release，`scripts/package.py` 打包到 dist/m3。第三方核心/驱动不捆绑。
- 图标与版本信息：`crates/{agent,ui}/build.rs` 在 windows-gnu 目标下用 MinGW `windres`（可用 `WINDRES` 覆盖）把 `assets/lineguard.ico` 与 VERSIONINFO 嵌入所有 exe；MSVC 目标暂不嵌入。修改图标请运行 `python3 scripts/make-icon.py`（需 Pillow）。

本地预览未指定最终开源许可证；不得擅自公开分发。依赖许可证需随最终发行核查，参见 SECURITY.md。

## 本机 Linux 开发路径

本次在项目 `.tools/` 隔离目录安装官方 rustup（未改 shell profile、未替换 /usr/bin/rustc）。MinGW 来自 Debian 官方 apt 包 `gcc-mingw-w64-x86-64-posix`（本机系统级开发工具，不是用户 Windows 电脑）。

```bash
export RUSTUP_HOME="$PWD/.tools/rustup"
export CARGO_HOME="$PWD/.tools/cargo"
export PATH="$PWD/.tools/cargo/bin:$PATH"
cargo build --locked --workspace --release --target x86_64-pc-windows-gnu
# 纯逻辑与非 Windows Unsupported 边界构建（不执行测试）
cargo build --locked --workspace
```

便捷脚本 `scripts/build-linux.sh` 只检查现有工具并构建；不会安装工具或运行 exe。第一次 Cargo 会按锁文件正常下载依赖。`scripts/package.py` 产出本机 source zip / Windows 开发预览 zip / SHA256SUMS，不上传任何位置。

Windows exe 与 Linux 构建结果是两件事；Linux 主机 GUI 是明确 Unsupported 提示，不是另一个可用产品。Windows target 下的四个 exe 才编译真实 Windows FFI/GUI 路径。

## 可复现 Windows MSVC 路径（未在 Windows 实测）

在隔离 Windows 构建 VM 上准备官方 Rust 1.100.0 MSVC toolchain、VS C++ Build Tools 与 Windows SDK，然后：

```powershell
.\scripts\build-windows.ps1
# 等价命令：
cargo build --locked --workspace --release --target x86_64-pc-windows-msvc
```

脚本不安装/启动服务，不调用 sc、netsh、WFP、注册表或 TUN；只构建。不保证跨编译出的 GNU exe 等同 MSVC 正式发布验证。MSVC、WiX/MSI、Authenticode、Windows VM 运行与系统验收都尚未完成。

GNU exe 分发依赖以 `objdump -p` 的 DLL 表为准，打包不附第三方DLL；实际导入表须再次核对，出现非Windows系统runtime依赖则先处理许可/可用性再分发；若出现缺失 runtime，须解决后才能声称包自包含。无数字签名的预览可能触发 SmartScreen；不要靠关闭系统安全防护或绕过签名策略来验收。

## 内存、重绘与性能口径

不承诺未测量的 MB/帧率。无固定 60fps timer、无自动网络轮询、无无限日志/缓存；工作线程只接收有界任务，响应使界面按需重绘。当前状态按用户刷新/导入更新，状态/诊断请求真实查询WFP，**不会自动追踪另一个 CLI 的修改**；显式刷新可见最新代次。UI 隐藏时 eframe 不调用绘制，只处理真实响应；此版没有托盘入口，托盘指标不适用。

读取一次系统微软雅黑（上限 32 MiB）而非打包整套 CJK；glyph atlas 按实际文字生成。不意味着字体内存为零，必须在 Windows 独立测量。验收步骤见 docs/ACCEPTANCE.md，区分 GUI 工作集/私有字节、后台服务、空闲 CPU、交互/动画、最小化和关闭 GUI；禁止把 Linux RSS 或 exe 大小当 Windows 工作集。

## M3新增构建输入与限制

Cargo.lock新增sha2 0.11.1（关闭非必要默认OID/alloc features），用于流式校验；没有引入HTTP客户端、YAML任意输入解析器、WebView或额外异步运行时。公开上游下载只在.tools/upstream供只读供应链核查，不参与Rust链接，不进打包白名单。

编译内置third-party/manifest.json与core/engine-config.json；修改它们属于源码变更，需重建。外置manifest不被加载。source包保留完整第三方许可文本，但不附GPL核心/驱动二进制。正式分发前仍需完整依赖许可/对应源码安排；不私自签名或生成密钥。

可选只编译纯逻辑测试目标、不执行：`cargo build --locked -p lineguard-core --tests`。本轮没有cargo test，也没有运行生成的测试程序。即便测试目标编译成功也不是断言通过。

Windows最小目标Win10：配置检查使用PROC_THREAD_ATTRIBUTE_JOB_LIST原子创建归入Job；属性不支持时返回错误，不退回有崩溃窗口的先spawn后绑定。检查用最小环境、stdin配置、NUL输出；本次Windows FFI只编译未运行。

当前源码保存状态见HANDOFF.md。core测试仅编译可增加`--target x86_64-pc-windows-gnu`，不要运行测试二进制。可移植Linux构建脚本动态设置路径remap，不含开发机绝对路径。构建不是Windows验收。
