# preview.2实际构建（未Windows运行）

2026-11-22 13:40 Asia/Shanghai（UTC+8），软件0.3.0-preview.2/IPC4。下列全部退出0：

```sh
cargo fmt --all
cargo build --locked --workspace
cargo build --locked -p lineguard-core --tests
cargo build --locked --workspace --release --target x86_64-pc-windows-gnu
cargo build --locked -p lineguard-core --tests --target x86_64-pc-windows-gnu
python3 scripts/inspect-artifacts.py
```

30个core测试函数的测试目标仅编译，断言全部未执行。4个Windows release PE均为x64、证书目录为空；未发现额外MinGW运行时导入。exe字节数：GUI5790720，service845312，ctl770048，rescue674816。大小不是内存指标。

没有执行任何产品/核心/测试exe，没有服务安装或系统网络变更、WindowsVM验收、签名或公开发布。本轮无新工具安装，仅扩展现有windows-sys feature和3个workspace版本号。

提交保存前仅整理可移植构建脚本/去本机绝对路径；产品Rust源码已按上列构建。旧包不包含preview.2更新。本轮不压包、不上传exe。真实实现/缺口见HANDOFF.md。
