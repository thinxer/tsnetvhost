#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/hack/env.sh"
VM="${1:?usage: start-vm.sh vm1|vm2}"
[[ -S "$ROOT/run/$VM/vhost.sock" ]]
exec sg kvm -c "'$ROOT/bin/crosvm' run \
  --disable-sandbox \
  --cpus 2 \
  --mem 1024 \
  --block path='$ROOT/images/$VM/rootfs.ext4' \
  --block path='$ROOT/images/$VM/seed.iso',ro=true \
  --vhost-user net,socket='$ROOT/run/$VM/vhost.sock' \
  --serial type=file,path='$ROOT/run/$VM/console.log',console=true \
  --initrd '$ROOT/downloads/noble-server-cloudimg-arm64-initrd-generic' \
  --params 'root=LABEL=cloudimg-rootfs rw console=ttyS0,115200n8' \
  '$ROOT/downloads/vmlinux-arm64'" </dev/null
