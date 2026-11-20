package backend

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
	"tsnetvhost/internal/vhostuser"
)

type fakeTransport struct {
	txFrames [][]byte
	rxFrames [][]byte
	closed   bool
}

func (f *fakeTransport) DrainTX(handle func(frame []byte) (vhostuser.TXAction, []byte)) error {
	for len(f.txFrames) > 0 {
		action, reply := handle(f.txFrames[0])
		if action == vhostuser.TXStop {
			return nil
		}
		f.txFrames = f.txFrames[1:]
		if len(reply) > 0 {
			f.rxFrames = append(f.rxFrames, append([]byte(nil), reply...))
		}
	}
	return nil
}

func (f *fakeTransport) WriteRX(n int, get func(i int) ([14]byte, []byte, bool)) {
	for i := 0; i < n; i++ {
		hdr, payload, ok := get(i)
		if !ok {
			continue
		}
		frame := make([]byte, 14+len(payload))
		copy(frame[:14], hdr[:])
		copy(frame[14:], payload)
		f.rxFrames = append(f.rxFrames, frame)
	}
}

func (f *fakeTransport) Close() error {
	f.closed = true
	return nil
}

func makeIPv4Frame(src, dst netip.Addr, payloadLen int) []byte {
	pkt := make([]byte, 20+payloadLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	src4 := src.As4()
	dst4 := dst.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])

	frame := make([]byte, 14+len(pkt))
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	copy(frame[14:], pkt)
	return frame
}

func makeARPRequest(guestMAC [6]byte, srcIP, targetIP netip.Addr) []byte {
	frame := make([]byte, 42)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)
	binary.BigEndian.PutUint16(frame[14:16], 1)      // Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // IPv4
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 1) // Request
	copy(frame[22:28], guestMAC[:])
	s4 := srcIP.As4()
	t4 := targetIP.As4()
	copy(frame[28:32], s4[:])
	copy(frame[38:42], t4[:])
	return frame
}

func TestDeviceBatchReadWriteAndARP(t *testing.T) {
	ipv4 := netip.MustParseAddr("100.64.0.1")
	ipv6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	peer4 := netip.MustParseAddr("100.64.0.2")

	adapter := NewAdapter("vm1", DefaultMTU)
	adapter.SetAddresses(ipv4, ipv6)
	tr := &fakeTransport{}
	dev := NewDevice(adapter, tr, DefaultMTU)

	if dev.BatchSize() != conn.IdealBatchSize {
		t.Fatalf("BatchSize() = %d, want %d", dev.BatchSize(), conn.IdealBatchSize)
	}

	// Queue: 1 ARP request, 1 spoofed IPv4 packet (must be dropped), 3 valid IPv4 packets.
	valid1 := makeIPv4Frame(ipv4, peer4, 100)
	valid2 := makeIPv4Frame(ipv4, peer4, 200)
	valid3 := makeIPv4Frame(ipv4, peer4, 300)
	spoofed := makeIPv4Frame(peer4, ipv4, 50)
	arpReq := makeARPRequest(adapter.guestMAC, ipv4, syntheticIPv4)
	tr.txFrames = [][]byte{arpReq, spoofed, valid1, valid2, valid3}

	slab := make([]byte, 64*1024)
	packets := make([]tun.ReadPacket, dev.BatchSize())
	n, err := dev.Read(slab, packets)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 3 {
		t.Fatalf("Read returned %d packets, want 3", n)
	}
	if len(tr.rxFrames) != 1 || binary.BigEndian.Uint16(tr.rxFrames[0][12:14]) != etherTypeARP ||
		binary.BigEndian.Uint16(tr.rxFrames[0][20:22]) != 2 {
		t.Fatalf("expected 1 ARP reply on RX, got %d frames", len(tr.rxFrames))
	}

	// Verify ReadPacketSpacing and payload integrity.
	want := [][]byte{valid1[14:], valid2[14:], valid3[14:]}
	for i := 0; i < n; i++ {
		p := packets[i]
		if !bytes.Equal(slab[p.Offset:p.Offset+p.Size], want[i]) {
			t.Fatalf("packet %d payload mismatch", i)
		}
		if i == 0 && p.Offset != tun.ReadPacketSpacing {
			t.Fatalf("packet 0 offset = %d, want %d", p.Offset, tun.ReadPacketSpacing)
		}
		if i > 0 && p.Offset-packets[i-1].Offset-packets[i-1].Size != tun.ReadPacketSpacing {
			t.Fatalf("packet %d spacing != %d", i, tun.ReadPacketSpacing)
		}
	}

	// Test exact-fit slab where next offset lands beyond len(slab)-ReadPacketSpacing
	// does not panic and leaves remaining packets for the next Read.
	tr.txFrames = [][]byte{valid1, valid2}
	exactSlab := make([]byte, 2*tun.ReadPacketSpacing+len(valid1[14:]))
	n, err = dev.Read(exactSlab, packets)
	if err != nil || n != 1 {
		t.Fatalf("exact slab Read = (%d, %v), want (1, nil)", n, err)
	}
	if len(tr.txFrames) != 1 {
		t.Fatalf("expected 1 remaining frame after exact slab, got %d", len(tr.txFrames))
	}

	// Test short slab leaves packet unconsumed and returns io.ErrShortBuffer.
	tr.txFrames = [][]byte{valid1}
	smallSlab := make([]byte, 2*tun.ReadPacketSpacing+10)
	if _, err := dev.Read(smallSlab, packets); err != io.ErrShortBuffer {
		t.Fatalf("small slab err = %v, want io.ErrShortBuffer", err)
	}
	if len(tr.txFrames) != 1 {
		t.Fatalf("packet was consumed on ErrShortBuffer")
	}

	// Test Write batching and destination IP filtering.
	tr.rxFrames = nil
	const off = 16
	inValid := append(make([]byte, off), makeIPv4Frame(peer4, ipv4, 64)[14:]...)
	inWrongDst := append(make([]byte, off), makeIPv4Frame(peer4, peer4, 64)[14:]...)
	written, err := dev.Write([][]byte{inValid, inWrongDst, inValid}, off)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written != 3 {
		t.Fatalf("Write = %d, want 3", written)
	}
	if len(tr.rxFrames) != 2 {
		t.Fatalf("RX received %d frames, want 2 (wrong-dst filtered)", len(tr.rxFrames))
	}
}
