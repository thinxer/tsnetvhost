#!/usr/bin/env bash
set -euo pipefail

export LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export HOME="$LAB_ROOT/.home"
export XDG_CONFIG_HOME="$LAB_ROOT/.xdg/config"
export XDG_CACHE_HOME="$LAB_ROOT/.xdg/cache"
export XDG_DATA_HOME="$LAB_ROOT/.xdg/data"
export XDG_RUNTIME_DIR="$LAB_ROOT/.xdg/runtime"
export TMPDIR="$LAB_ROOT/.tmp"
export GOPATH="$LAB_ROOT/.go"
export GOMODCACHE="$LAB_ROOT/.go/pkg/mod"
export GOCACHE="$LAB_ROOT/.go/cache"
export CARGO_HOME="$LAB_ROOT/.cargo"
export RUSTUP_HOME="$LAB_ROOT/.rustup"
export CONTAINERS_STORAGE_CONF="$LAB_ROOT/.podman/storage.conf"
export CONTAINERS_CONF="$LAB_ROOT/.podman/containers.conf"
export GIT_CONFIG_NOSYSTEM=1
export NO_PROXY="${NO_PROXY:+$NO_PROXY,}localhost,127.0.0.1,::1"
export no_proxy="${no_proxy:+$no_proxy,}localhost,127.0.0.1,::1"
export PATH="$LAB_ROOT/hack:$LAB_ROOT/bin:$PATH"

mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" \
  "$XDG_RUNTIME_DIR" "$TMPDIR" "$GOPATH" "$GOMODCACHE" "$GOCACHE" \
  "$CARGO_HOME" "$RUSTUP_HOME" "$LAB_ROOT/bin" "$LAB_ROOT/run"
chmod 700 "$XDG_RUNTIME_DIR"
