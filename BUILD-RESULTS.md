# preview.3实际构建（未Windows运行）

2026-11-22（UTC），云端Linux容器，软件0.3.0-preview.3/IPC5，工具链1.100.0 + mingw-w64 gcc 13。下列全部退出0：

```sh
cargo fmt --all
cargo build --locked --workspace
cargo test --locked -p lineguard-core          # 38 passed，实际运行
cargo build --locked --workspace --release --target x86_64-pc-windows-gnu
cargo build --locked -p lineguard-core --tests --target x86_64-pc-windows-gnu
python3 scripts/inspect-artifacts.py
```

core测试在Linux主机执行（纯逻辑，无系统调用）；Windows目标测试只编译未执行。没有执行任何产品/核心exe，没有服务安装、WFP或网络变更、WindowsVM验收、签名或发布。本轮不压包、不上传exe。真实实现/缺口见HANDOFF.md。
