#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/hack/env.sh"
"$ROOT/examples/crosvm/start-vm.sh" vm1 > "$ROOT/run/vm1/crosvm.log" 2>&1 &
pid1=$!
"$ROOT/examples/crosvm/start-vm.sh" vm2 > "$ROOT/run/vm2/crosvm.log" 2>&1 &
pid2=$!
cleanup() {
  kill "$pid1" "$pid2" 2>/dev/null || true
  wait "$pid1" "$pid2" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
wait -n "$pid1" "$pid2"
