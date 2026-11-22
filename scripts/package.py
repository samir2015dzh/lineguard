#!/usr/bin/env python3
"""Package only this project's local source / preview exes. Never uploads."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib
import shutil
import tomllib

root = Path(__file__).resolve().parent.parent
out = root / "dist" / "m3"
out.mkdir(parents=True, exist_ok=True)
name = "lineguard-" + tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
source = out / (name + "-source.zip")
allowed_dirs = ("crates", "scripts", "examples", "docs", ".cargo", "third-party", "assets", "build-support", ".github")
files = [p for p in root.iterdir() if p.is_file() and (p.suffix in (".md", ".toml", ".lock") or p.name == ".gitignore")]
for directory in allowed_dirs:
    files.extend(p for p in (root / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
with ZipFile(source, "w", ZIP_DEFLATED) as archive:
    for path in sorted(files):
        archive.write(path, Path(name) / path.relative_to(root))
preview = out / (name + "-windows-x64-M3-PARTIAL-DANGEROUS-UNVERIFIED-UNSIGNED.zip")
executables = ["lineguard", "lineguard-service", "lineguardctl", "lineguard-rescue"]
with ZipFile(preview, "w", ZIP_DEFLATED) as archive:
    for exe in executables:
        path = root / "target/x86_64-pc-windows-gnu/release" / (exe + ".exe")
        if not path.is_file():
            raise SystemExit("Missing built Windows exe: " + exe)
        archive.write(path, exe + ".exe")
        shutil.copy2(path, out / path.name)
    for relative in ["README.md", "HANDOFF.md", "BUILD.md", "BUILD-RESULTS.md", "SECURITY.md", "WFP_POLICY_MATRIX.md", "REQUIREMENTS.md", "LICENSE-NOTICE.md", "examples/offline.example.json", "docs/ACCEPTANCE.md", "docs/M3-STATUS.md", "docs/USAGE.md", "third-party/README.md", "third-party/manifest.json", "third-party/licenses/mihomo-GPL-3.0.txt", "third-party/licenses/wintun-0.14.1-prebuilt.txt"]:
        archive.write(root / relative, relative)
artifacts = [source, preview] + [out / (exe + ".exe") for exe in executables]
(out / "SHA256SUMS").write_text("".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in artifacts))
for path in artifacts:
    print(path.relative_to(root), path.stat().st_size, "bytes")
