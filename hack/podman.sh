#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/.podman/root" "$ROOT/.podman/run" "$ROOT/.podman/tmp"
exec /usr/bin/podman \
  --root "$ROOT/.podman/root" \
  --runroot "$ROOT/.podman/run" \
  --tmpdir "$ROOT/.podman/tmp" \
  --storage-driver=overlay \
  "$@"
