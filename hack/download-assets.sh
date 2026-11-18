#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p downloads
files=(
  noble-server-cloudimg-arm64.squashfs
  unpacked/noble-server-cloudimg-arm64-vmlinuz-generic
  unpacked/noble-server-cloudimg-arm64-initrd-generic
)
for mirror in \
  https://mirrors.tuna.tsinghua.edu.cn \
  https://mirrors.ustc.edu.cn; do
  base="$mirror/ubuntu-cloud-images/noble/current"
  if curl -fL -A 'Mozilla/5.0' --retry 2 -o downloads/guest-SHA256SUMS "$base/SHA256SUMS" && \
     curl -fL -A 'Mozilla/5.0' --retry 2 -o downloads/unpacked-SHA256SUMS "$base/unpacked/SHA256SUMS"; then
    ok=1
    for file in "${files[@]}"; do
      dest="downloads/${file##*/}"
      if ! curl -fL -A 'Mozilla/5.0' --retry 3 -C - -o "$dest" "$base/$file"; then
        ok=0
        break
      fi
    done
    if ((ok)); then
      echo "$base" > downloads/mirror-url
      break
    fi
  fi
  if [[ "$mirror" == *ustc* ]]; then
    echo 'No mirror could supply the guest assets' >&2
    exit 1
  fi
done
python3 - <<'PY'
import hashlib
from pathlib import Path
checks = {}
for sums in ('downloads/guest-SHA256SUMS', 'downloads/unpacked-SHA256SUMS'):
    for line in Path(sums).read_text().splitlines():
        parts = line.split()
        if len(parts) == 2:
            checks[parts[1].lstrip('*')] = parts[0]
for path in sorted(Path('downloads').glob('noble-server-cloudimg-arm64*')):
    if not path.is_file():
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = checks.get(path.name)
    if expected is None:
        raise SystemExit(f'No checksum for {path.name}')
    if digest != expected:
        raise SystemExit(f'Checksum mismatch for {path.name}: {digest} != {expected}')
    print(f'{path.name}: {digest}')
PY

if [[ ! -s downloads/vmlinux-arm64 ]]; then
  gzip -dc downloads/noble-server-cloudimg-arm64-vmlinuz-generic > downloads/vmlinux-arm64
fi
python3 - <<'PY'
from pathlib import Path
kernel = Path('downloads/vmlinux-arm64').read_bytes()
assert kernel[56:60] == b'ARM\x64'
print('ARM64 kernel header verified')
PY
