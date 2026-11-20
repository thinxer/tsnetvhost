# tsnet-vhost

`tsnet-vhost` is an experimental vhost-user-net backend that connects a VM's virtio-net device directly to an embedded [Tailscale `tsnet`](https://pkg.go.dev/tailscale.com/tsnet) node.

The guest owns the Tailscale node's IP addresses and transport connections. No Tailscale daemon, TUN device, bridge, or NAT is required in the guest or on the host.

## How it works

```text
Linux guest
  │ virtio-net
  ▼
crosvm
  │ vhost-user Unix socket
  ▼
tsnet-vhost
  ├─ Ethernet ↔ raw-IP adapter
  ├─ synthetic-gateway ARP/NDP
  └─ tsnet.Server with persistent state
              │
              ▼
     Tailscale or Headscale
```

Outbound packets follow this path:

```text
Guest → virtio TX → remove Ethernet framing → tsnet tun.Device.Read
      → WireGuard peer or DERP relay
```

Inbound packets follow the reverse path:

```text
Peer or relay → tsnet decryption → tun.Device.Write
              → add Ethernet framing → virtio RX → guest
```

`tsnet-vhost` listens on the vhost-user socket; crosvm connects to it. One backend process serves one VM, with one RX/TX queue pair and a separate persistent tsnet state directory.

### Properties

- Uses upstream Go `tsnet`; no Rust Tailscale reimplementation is required.
- No host TAP, TUN, bridge, routes, firewall changes, or `tailscale0` is created.
- No packet-to-socket conversion using `tsnet.Dial` or `tsnet.Listen`.
- Supports Tailscale IPv4 `/32`, IPv6 `/128`, and IPv6-only nodes.
- MTU defaults to 1280; checksum and segmentation offloads are disabled initially.
- Source addresses are checked against the node's assigned addresses.
- Control-plane and MagicDNS nameservers are published for guest provisioning.
- Sequential crosvm reconnects are always accepted without restarting tsnet.
- Headscale and the real Tailscale control plane are both supported.

## Status

This is working experimental software, not a production-hardened release. The vhost-user protocol surface is intentionally small, and advanced features such as migration, multiqueue, checksum/GSO offload, and dynamic guest provisioning are not implemented.

The current implementation targets **Linux/arm64**. Other architectures need appropriate virtqueue memory-barrier implementations and validation.

### Performance notes for contributors

Virtio-net checksum and segmentation offloads (`VIRTIO_NET_F_CSUM`, `GUEST_CSUM`, `HOST_TSO4/6`, `GUEST_TSO4/6`, `MRG_RXBUF`) are **intentionally omitted** rather than merely unimplemented. On Linux/arm64, batched direct virtqueue I/O (`BatchSize = 128`, pre-resolved rings, batched `used.idx`/`callFD`) already reaches ~8.9 Gbps guest-to-guest TCP over WireGuard at MTU 1280 (~870k pps), where the bottleneck sits inside `wireguard-go`/`tstun`'s single-goroutine per-packet stages rather than `vhost-user`:

- **TX CSUM + TSO4/6 (`tun.GSOSplit`) regresses throughput** (~8.9 → ~6.4 Gbps): `wireguard-go/tun` lacks ARM64 assembly checksums (`checksum_generic.go`), so moving TCP checksums out of the guest kernel's ARM64-assembly `csum_partial` into Go's scalar checksum inside `RoutineReadFromTUN` bottlenecks TX and shrinks `Read()` batch sizes.
- **RX GRO + `MRG_RXBUF` does not increase throughput** (~8.7 vs ~8.9 Gbps) despite significant added complexity, because `wireguard-go`/`tstun` per-packet processing remains the ceiling at MTU 1280.

Do not re-introduce TX/RX virtio-net GSO/GRO offloads unless `wireguard-go`/`tstun` can carry GSO frames end-to-end or benchmarks show a clear net win. For higher throughput beyond ~9 Gbps, investigate larger path MTUs or `VIRTIO_NET_F_MQ` + `tun.MultiQueueDevice` for multi-stream workloads instead.

## Requirements

Runtime:

- Linux with KVM access
- Crosvm, built separately and unmodified
- A Linux guest with a standard virtio-net driver
- A Tailscale or Headscale control plane
- Authentication suitable for your control plane, normally `TS_AUTHKEY`

Build:

- Go 1.27.4 or a compatible newer Go release
- `tailscale.com` and `github.com/tailscale/wireguard-go`, pinned in `go.mod`

The examples currently run crosvm with sandboxing disabled for experimentation. Review and enable an appropriate sandbox configuration before considering production use.

## Build

```bash
go build -trimpath -o bin/tsnet-vhost ./cmd/tsnet-vhost
```

Run standard checks:

```bash
go test ./...
go vet ./...
```

## Start a backend

Using the real Tailscale control plane:

```bash
TS_AUTHKEY=... ./bin/tsnet-vhost --name vm1
```

Using Headscale:

```bash
TS_AUTHKEY=... ./bin/tsnet-vhost \
  --name vm1 \
  --control-url https://headscale.example.com
```

Using qarch or another approved exit node:

```bash
TS_AUTHKEY=... ./bin/tsnet-vhost \
  --name vm1 \
  --exit-node STABLE_NODE_ID
```

Options:

```text
--name NAME                 Required VM and tsnet hostname
--control-url URL          Default: https://controlplane.tailscale.com
--state-dir PATH           Default: ~/.local/state/tsnet-vhost/NAME
--socket PATH              Default: $XDG_RUNTIME_DIR/tsnet-vhost/NAME.sock
--status-file PATH         Default: STATE_DIR/status.json
--auth-key-file PATH       Optional alternative to TS_AUTHKEY
--exit-node NODE_ID        Optional required exit node
--mtu BYTES                Default: 1280
--log-level LEVEL          info or debug; default: info
```

Do not put authentication keys directly on the command line. Prefer `TS_AUTHKEY` or a protected key file.

## Read the status file

The backend publishes an atomic, generation-based JSON status file. Updates happen on lifecycle and connection changes, not on a periodic heartbeat.

```json
{
  "schemaVersion": 1,
  "generation": 4,
  "state": "ready",
  "hostname": "vm1",
  "socket": "/run/user/1000/tsnet-vhost/vm1.sock",
  "addresses": [
    "100.64.0.1/32",
    "fd7a:115c:a1e0::1/128"
  ],
  "mac": "02:54:53:7b:11:e3",
  "mtu": 1280,
  "gateway4": "169.254.254.1",
  "gateway6": "fe80::1",
  "dns": [
    "1.1.1.1",
    "fd7a:115c:a1e0::53"
  ],
  "exitNode": {
    "id": "STABLE_NODE_ID",
    "required": true,
    "available": true
  },
  "vhostConnected": true,
  "updatedAt": "2026-11-18T07:30:00Z"
}
```

`ready` means that the node has addresses, any required exit node is available, and the vhost-user listener is active. `vhostConnected` independently reports whether crosvm is currently attached.

On an orderly shutdown the backend writes `stopped`; startup or runtime errors produce `failed` with an `error` field. After a crash, a status file may be stale, so consumers should also verify process and socket state.

## Attach crosvm

After the status reaches `ready`, attach crosvm to the advertised socket:

```bash
crosvm run \
  --vhost-user net,socket="$XDG_RUNTIME_DIR/tsnet-vhost/vm1.sock" \
  <kernel, disk, and other crosvm options>
```

If crosvm disconnects, the backend stays alive and accepts a later connection. Queue and guest-memory state is renegotiated; tsnet identity and addresses remain persistent. Only one active connection is served at a time.

## Guest provisioning

Cloud-init is optional and is deliberately outside the core backend. The guest contract is:

```text
virtio-net + addresses from status.json + synthetic-gateway routes + MTU/DNS
```

A guest needs:

- Its assigned Tailscale addresses
- Routes through the synthetic gateway
- The published MTU and DNS configuration
- No Tailscale package or daemon

Example NoCloud generators are in `examples/cloudinit/`. They are reference integrations, not part of the runtime API. The example scripts in `examples/crosvm/` and `examples/headscale/` contain lab-specific values and should be adjusted for your environment.

## Repository layout

```text
cmd/tsnet-vhost/       CLI entry point
internal/backend/      tsnet, Ethernet, ARP/NDP, and status handling
internal/vhostuser/    vhost-user protocol and virtqueue processing
examples/              Optional cloud-init, crosvm, and Headscale examples
hack/                  Development utilities and container build files
test/integration/      Integration-test assets
```

Crosvm is an unmodified external dependency. Its development revision is recorded in `hack/crosvm-revision`; it is not included as a submodule.

## Security notes

- State and socket directories should remain private to the invoking user.
- Status files never intentionally contain authentication keys or private node keys.
- The vhost-user backend parses VMM-provided messages and guest-memory descriptors. Run crosvm and the backend with appropriate sandboxing and least privilege.
- Required exit-node availability is checked before the listener starts. Continuous availability monitoring and fail-closed behavior after startup remain experimental.
- Do not expose the vhost-user or status sockets to untrusted users.

## Development

Use workspace-local state and rootless Podman where possible. `hack/env.sh` redirects common build caches and runtime paths into the workspace. The helper files under `hack/podman/` build development tools without installing them on the host.

The project is not affiliated with Tailscale Inc. Tailscale and WireGuard are trademarks of their respective owners.
