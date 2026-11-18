#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/hack/env.sh"
VM="${1:?usage: start-backend.sh vm1|vm2}"
export SSL_CERT_FILE="$ROOT/run/headscale/tls.crt"
exec "$ROOT/bin/tsnet-vhost" \
  --name "$VM" \
  --state-dir "$ROOT/run/$VM/tsnet" \
  --status-file "$ROOT/run/$VM/status.json" \
  --control-url https://localhost:18443 \
  --auth-key-file "$ROOT/run/headscale/auth-key" \
  --socket "$ROOT/run/$VM/vhost.sock"
