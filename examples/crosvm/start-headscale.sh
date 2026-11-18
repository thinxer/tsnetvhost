#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/hack/env.sh"
mkdir -p "$ROOT/run/headscale"
chmod 700 "$ROOT/run/headscale"
if [[ ! -s "$ROOT/run/headscale/tls.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
    -keyout "$ROOT/run/headscale/tls.key" \
    -out "$ROOT/run/headscale/tls.crt" \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' \
    -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
  chmod 600 "$ROOT/run/headscale/tls.key"
fi
exec "$ROOT/bin/headscale" serve --config "$ROOT/examples/headscale/config.yaml"
