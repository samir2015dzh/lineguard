#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -x .tools/cargo/bin/cargo ]]; then
  export RUSTUP_HOME="$PWD/.tools/rustup" CARGO_HOME="$PWD/.tools/cargo"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$PWD=LineGuard --remap-path-prefix=$PWD/.tools=toolchain"
command -v x86_64-w64-mingw32-gcc >/dev/null
cargo build --locked --workspace --release --target x86_64-pc-windows-gnu
