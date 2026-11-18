#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/hack/env.sh"
set -a
source "$ROOT/env"
set +a
export TS_AUTHKEY="${TS_AUTH:?TS_AUTH is required}"
unset SSL_CERT_FILE
exec "$ROOT/bin/tsnet-vhost" \
  --name crosvm-http \
  --state-dir "$ROOT/run/http/tsnet" \
  --status-file "$ROOT/run/http/status.json" \
  --control-url https://controlplane.tailscale.com \
  --exit-node "${TS_EXIT_NODE:-nqTRxV4CNTRL}" \
  --socket "$ROOT/run/http/vhost.sock"
