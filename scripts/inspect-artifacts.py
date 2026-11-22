#!/usr/bin/env python3
"""Static PE/size/hash/import inspection only. Does not execute product binaries or tests."""
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import hashlib, json, re, subprocess
root = Path(__file__).resolve().parent.parent
folder = root / 'target/x86_64-pc-windows-gnu/release'
results = []
for name in ['lineguard', 'lineguard-service', 'lineguardctl', 'lineguard-rescue']:
    path = folder / (name + '.exe')
    raw = path.read_bytes()
    metadata = subprocess.run(['x86_64-w64-mingw32-objdump', '-p', str(path)],
                              check=True, capture_output=True, text=True).stdout
    directory = re.search(r'Entry 4\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+Security Directory', metadata)
    results.append({'file': path.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'pe_x64': 'pei-x86-64' in metadata,
                    'dll_imports': re.findall(r'DLL Name:\s+(\S+)', metadata),
                    'certificate_directory_present': None if directory is None else bool(int(directory[1],16) or int(directory[2],16)),
                    'raw_build_paths_found': [label for label, prefix in
                        {'source-root':str(root).encode(),'builder-home':str(Path.home()).encode()}.items() if prefix in raw]})
print(json.dumps({'time': datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(),
                  'zone':'Asia/Shanghai (UTC+8)', 'kind':'static-artifact-inspection-not-runtime-test',
                  'artifacts': results}, ensure_ascii=False, indent=2))
