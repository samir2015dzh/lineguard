$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
# Requires preinstalled Rust MSVC and VS C++/SDK. No system runtime operations.
cargo build --locked --workspace --release --target x86_64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) { throw "Windows build failed" }
