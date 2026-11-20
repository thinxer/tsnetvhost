# Performance Notes & Benchmarks

This document records the measured performance of `tsnet-vhost` and documents design tradeoffs for future contributors—specifically which optimizations delivered large wins and which virtio-net offload features were tested and intentionally **not** kept.

## Test Setup

- **Host:** Linux/arm64 (`aarch64`), Go 1.27.4
- **Topology:** Two `crosvm` guests (`vm1` → `vm2`), each with 2 vCPUs, 1024 MiB RAM, Ubuntu 24.04 arm64, MTU 1280
- **Control / Data Plane:** Local Headscale with direct WireGuard peer path between `vm1` (`100.64.0.1` / `fd7a:115c:a1e0::1`) and `vm2` (`100.64.0.2` / `fd7a:115c:a1e0::2`)
- **Workload:** 10-second `iperf3` runs (`-P 1` IPv4, `-P 4` IPv4, `-P 1` IPv6); 0 TCP retransmits in all runs
- **CPU Accounting:** Exact host process CPU (`utime + stime` from `/proc/<pid>/stat`) sampled across each 10s test window (`100%` = 1 full host core)

## Two-Guest `iperf3` Results

### Bandwidth

| Configuration | IPv4 1-stream | IPv4 4-streams | IPv6 1-stream |
|---|---:|---:|---:|
| Pre-refactor baseline (`4e20ae4`) | 1.14 Gbps | 1.13 Gbps | 1.12 Gbps |
| **Current: batched direct virtqueue (`9478206`+)** | **8.90 Gbps** | **8.82 Gbps** | **8.63 Gbps** |
| Experiment: TX TSO + RX GRO + `MRG_RXBUF` | 6.37 Gbps | 6.25 Gbps | 6.07 Gbps |
| Experiment: RX GRO + `MRG_RXBUF` only | 8.69 Gbps | 8.64 Gbps | 8.51 Gbps |

### Host CPU Cost (IPv4 1-stream)

| Configuration | `tsnet` vm1 TX (`u+s`) | `tsnet` vm2 RX (`u+s`) | `crosvm` vm1 TX (`u+s`) | `crosvm` vm2 RX (`u+s`) | Total Host CPU | Cores / Gbps |
|---|---:|---:|---:|---:|---:|---:|
| Pre-refactor baseline | `244.6 + 115.6 = 360.1%` | `215.1 + 93.8 = 308.9%` | `53.0 + 138.6 = 191.6%` | `52.5 + 166.9 = 219.5%` | 10.80 cores | 9.50 |
| **Current (`9478206`+)** | `297.1 + 65.4 = 362.5%` | `325.1 + 69.3 = 394.4%` | `103.7 + 57.0 = 160.8%` | `72.5 + 144.9 = 217.4%` | 11.35 cores | **1.28** |
| Exp: TX TSO + RX GRO | `241.4 + 65.1 = 306.5%` | `243.8 + 59.0 = 302.8%` | `24.7 + 108.3 = 133.0%` | `33.8 + 172.2 = 206.1%` | 9.50 cores | 1.49 |
| Exp: RX GRO only | `289.4 + 59.9 = 349.3%` | `308.5 + 58.7 = 367.2%` | `105.7 + 58.7 = 164.4%` | `37.9 + 158.9 = 196.8%` | 10.78 cores | 1.24 |

### Virtqueue Microbenchmarks (`go test -bench=. -benchmem ./internal/vhostuser`)

64 × 1280 B packets per batch on Linux/arm64:

- `BenchmarkVhostTXBatch64`: **3,707 ns/op** (~58 ns/pkt), **22,100 MB/s**, **0 B/op, 0 allocs/op**
- `BenchmarkVhostRXBatch64`: **3,077 ns/op** (~48 ns/pkt), **26,622 MB/s**, **0 B/op, 0 allocs/op**

## What Worked (~7.8× Throughput, ~7.5× Better CPU Efficiency)

1. **Collapsing the data path (`9478206`):** Removed intermediate `outbound`/`inbound` channels, `Adapter.RunInbound()`, and per-queue polling goroutines so `tun.Device.Read`/`Write` access the TX/RX virtqueues directly (4 copies → 1 copy per packet).
2. **`BatchSize() = conn.IdealBatchSize` (`128`):** Unlocked `wireguard-go` and `tstun` batching (`sendmmsg`/`recvmmsg`, batched encryption).
3. **Pre-resolved ring slices + zero-copy TX fast paths:** Eliminated per-packet heap allocations and linear guest-memory scans.
4. **Batched `used.idx` / `callFD` interrupts + `VRING_AVAIL_F_NO_INTERRUPT` + RX `VRING_USED_F_NO_NOTIFY`:** Slashed kernel/KVM-exit `sys%` by ~90% per Gbps.

## Do Not Bother Re-Introducing (Tested & Rejected)

Virtio-net checksum and segmentation offloads (`VIRTIO_NET_F_CSUM`, `GUEST_CSUM`, `HOST_TSO4/6`, `GUEST_TSO4/6`, `MRG_RXBUF`) are **intentionally omitted**:

1. **TX CSUM + `HOST_TSO4/6` (`tun.GSOSplit`) regresses throughput (8.90 → 6.37 Gbps):**
   - `wireguard-go/tun` has no ARM64 assembly checksum (`checksum_generic.go`). Moving TCP checksums out of the guest kernel's ARM64-assembly `csum_partial` into Go's scalar checksum synchronously inside the single `RoutineReadFromTUN` goroutine bottlenecks TX at ~800 MB/s.
   - Each 64 KB TSO super-packet also splits into ~51 segments, which fills roughly half of `wireguard-go`'s 128 KB `Read()` slab and reduces effective batch size from ~96 packets to ~51.
2. **RX GRO + `MRG_RXBUF` does not increase throughput (8.90 → 8.69 Gbps):**
   - Although RX GRO cut guest RX `user%` in half (`72.5% → 37.9%`), end-to-end throughput did not improve because the ceiling at ~8.9 Gbps / MTU 1280 (~870k packets/sec) is now inside `wireguard-go`/`tstun`'s single-goroutine per-packet stages (`RoutineReadFromTUN`, `RoutineSequentialSender`, `RoutineSequentialReceiver`)—not `vhost-user`.
   - The ~350 lines of GRO and mergeable-buffer complexity are not justified for a ~3% CPU savings with no bandwidth gain.

## Where the Remaining Bottleneck Sits

At ~8.9 Gbps with MTU 1280 (~870k pps), both 1-stream and 4-stream TCP hit the same ceiling inside `wireguard-go`/`tstun` per-packet processing. Future work aiming beyond ~9 Gbps should focus on:

- **Higher `--mtu`** where the underlying network path supports it (linearly reduces packets/sec through `wireguard-go`).
- **`VIRTIO_NET_F_MQ` + `tun.MultiQueueDevice`** to parallelize `wireguard-go`'s per-queue goroutines for multi-stream workloads.
