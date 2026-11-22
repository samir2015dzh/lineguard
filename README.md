<p align="center">
  <img src="assets/lineguard-256.png" width="128" height="128" alt="LineGuard 图标">
</p>

<h1 align="center">LineGuard</h1>

<p align="center">
  Rust 原生 Windows 10/11 x64 线路防护客户端 · 中文深色界面 · 不内嵌浏览器
</p>

<p align="center">
  <a href="https://github.com/samir2015dzh/lineguard/actions/workflows/ci.yml"><img src="https://github.com/samir2015dzh/lineguard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/samir2015dzh/lineguard/releases"><img src="https://img.shields.io/github/v/release/samir2015dzh/lineguard?include_prereleases&label=预览版" alt="预览版"></a>
</p>

> [!WARNING]
> **开发预览，不是可用 VPN。请勿在日常电脑上使用。**
> Connect 仍返回 Unsupported，没有任何“已保护”状态。实验命令会**有意切断本机全部 IP 联网**，只能在带独立控制台和快照的隔离 Windows 虚拟机中使用。exe 未签名。

## 它要做什么

LineGuard 的目标是：只允许经过身份核验的代理核心，经独占 TUN 走向**单一**节点，其余流量一律由 Windows 过滤平台（WFP）在内核阻断；出任何问题都先阻断、再恢复，绝不“失败放行”。完整设想见 [docs/整体思路.md](docs/整体思路.md)（其中数字是原始设想，并非本项目实测）。

## 当前进度（0.3.0-preview.4）

| 模块 | 状态 |
|---|---|
| 原生 GUI ↔ 受限命名管道 ↔ Rust 后台服务，离线配置导入（DPAPI 加密）、脱敏诊断 | ✅ 已实现，Windows CI 实测 |
| M2 全阻断：6 条持久 + 6 条开机 WFP 规则，事务安装与逐字段回读 | ✅ 已实现，Windows CI 实测**出站确实被阻断** |
| 独立救援 `lineguard-rescue`：不依赖服务，按所有权撤销本产品规则 | ✅ 已实现，Windows CI 实测撤销后直连恢复 |
| M3 独占 TUN 隔离、写前网络 journal、独立应急阻断与恢复 | 🟡 已实现，未在 Windows 运行 |
| v3 窄许可（ALE 身份门 ∩ 包层例外）：计划、原生事务、回读、单事务撤销、生命周期接入 | 🟡 已实现，未在 Windows 运行 |
| 真实隧道数据通路、冷启动、崩溃恢复、旁路/泄露抓包 | ⛔ 未验证 |
| 托盘、订阅、安装包、签名、自动更新 | ⛔ 未开始（M4/M5） |

“Windows CI 实测”指在 GitHub 托管的一次性 Windows 虚拟机上真实运行 exe（见 [CI](.github/workflows/ci.yml) 的 `windows-smoke` 任务），不是完整验收。详细缺口与下一步见 **[HANDOFF.md](HANDOFF.md)**。

## 下载

在 [Releases](https://github.com/samir2015dzh/lineguard/releases) 下载预发布版：

- `…-windows-x64-M3-PARTIAL-DANGEROUS-UNVERIFIED-UNSIGNED.zip`：4 个 exe（必须放在同一目录）+ 文档与第三方许可证。不附带 mihomo 核心或 Wintun 驱动。
- `SHA256SUMS`：校验和。所有 exe 均由 CI 从对应标签的提交构建。

| 程序 | 作用 |
|---|---|
| `lineguard.exe` | 图形界面：平时只需打开它；可一键启动本机后台（没有放行按钮） |
| `lineguard-service.exe` | 后台服务（SCM 服务或 `--console`） |
| `lineguardctl.exe` | 命令行控制与管理员实验命令 |
| `lineguard-rescue.exe` | 独立救援，不依赖服务或管道 |

## 快速试用（不改网络）

1. 把下载包解压到一个文件夹（4 个 exe 必须在同一目录）。
2. 双击 `lineguard.exe`，点击 **启动本机后台**。界面会在后台静默启动 `lineguard-service.exe`（当前用户、无窗口），关闭界面时它会一起退出。
3. 在「离线线路」页导入 `examples/offline.example.json` 试试格式校验。

如果已经安装了系统服务 `LineGuardPreview`，界面会自动连接它，不需要点启动。`lineguardctl.exe` 和 `lineguard-rescue.exe` 是命令行工具，只在管理员实验和紧急恢复时使用，平时不用打开。

普通启动不安装也不撤销任何规则。危险命令（全阻断、独占 TUN、窄放行）和数据目录说明见 **[docs/USAGE.md](docs/USAGE.md)**。

**紧急恢复**（管理员终端，不需要服务在线）：

```powershell
.\lineguard-rescue.exe remove --confirm ALLOW-DIRECT
```

## 从源码构建

需要 Rust 1.100.0（由 `rust-toolchain.toml` 固定）；交叉编译 Windows 需要 MinGW-w64。

```bash
cargo test --locked -p lineguard-core
cargo build --locked --workspace --release --target x86_64-pc-windows-gnu
```

更多说明见 [BUILD.md](BUILD.md)。图标由 `scripts/make-icon.py` 从同一份几何定义生成 SVG/PNG/ICO，构建时嵌入所有 exe。

## 文档

| 文档 | 内容 |
|---|---|
| [HANDOFF.md](HANDOFF.md) | 当前实现、实测证据、未闭合项与下一步 |
| [docs/USAGE.md](docs/USAGE.md) | 详细使用说明与危险命令 |
| [SECURITY.md](SECURITY.md) | 安全边界与威胁模型 |
| [WFP_POLICY_MATRIX.md](WFP_POLICY_MATRIX.md) | WFP 规则矩阵（M2 与 v3） |
| [docs/M3-STATUS.md](docs/M3-STATUS.md) · [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) | M3 状态与待验收项 |
| [REQUIREMENTS.md](REQUIREMENTS.md) | 需求 |

## 许可

尚未选择开源许可证，保留所有权利；详见 [LICENSE-NOTICE.md](LICENSE-NOTICE.md)。第三方组件（mihomo、Wintun）的许可文本见 [third-party/](third-party/README.md)，本项目不捆绑它们的二进制。
