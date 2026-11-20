package vhostuser

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type testFrontend struct {
	conn     *net.UnixConn
	memFile  *os.File
	mem      []byte
	qSize    uint16
	rxDesc   uint64
	rxAvail  uint64
	rxUsed   uint64
	txDesc   uint64
	txAvail  uint64
	txUsed   uint64
	rxKickFD int
	rxCallFD int
	txKickFD int
	txCallFD int
	rxAvailI uint16
	txAvailI uint16
	rxBufOff uint64
	txBufOff uint64
}

func newTestFrontend(t testing.TB, sockPath string, qSize uint16) *testFrontend {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial vhost socket: %v", err)
	}
	memSize := 2 << 20 // 2 MiB
	memFile, err := os.CreateTemp(t.TempDir(), "guest-mem-*")
	if err != nil {
		t.Fatalf("create mem file: %v", err)
	}
	if err := memFile.Truncate(int64(memSize)); err != nil {
		t.Fatalf("truncate mem file: %v", err)
	}
	mem, err := unix.Mmap(int(memFile.Fd()), 0, memSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap guest mem: %v", err)
	}

	makeEFD := func() int {
		fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
		if err != nil {
			t.Fatalf("eventfd: %v", err)
		}
		return fd
	}

	f := &testFrontend{
		conn:     conn,
		memFile:  memFile,
		mem:      mem,
		qSize:    qSize,
		rxDesc:   0x0000,
		rxAvail:  0x2000,
		rxUsed:   0x4000,
		txDesc:   0x6000,
		txAvail:  0x8000,
		txUsed:   0xa000,
		rxBufOff: 0x10000,
		txBufOff: 0x100000,
		rxKickFD: makeEFD(),
		rxCallFD: makeEFD(),
		txKickFD: makeEFD(),
		txCallFD: makeEFD(),
	}

	// Negotiate vhost-user handshake.
	features := f.reqU64(t, vhostGetFeatures, nil, nil)
	if features&(1<<virtioVersion1) == 0 {
		t.Fatalf("missing VIRTIO_F_VERSION_1 in %#x", features)
	}
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], features)
	f.reqAck(t, vhostSetFeatures, u64[:], nil)

	proto := f.reqU64(t, vhostGetProtocolFeatures, nil, nil)
	binary.LittleEndian.PutUint64(u64[:], proto)
	f.reqAck(t, vhostSetProtocolFeatures, u64[:], nil)

	// SET_MEM_TABLE: 1 region at GPA 0, VMM addr 0x10000000.
	memBody := make([]byte, 8+32)
	binary.LittleEndian.PutUint32(memBody[0:4], 1)
	binary.LittleEndian.PutUint64(memBody[8:16], 0)
	binary.LittleEndian.PutUint64(memBody[16:24], uint64(memSize))
	binary.LittleEndian.PutUint64(memBody[24:32], 0x10000000)
	binary.LittleEndian.PutUint64(memBody[32:40], 0)
	f.reqAck(t, vhostSetMemTable, memBody, []int{int(memFile.Fd())})

	setupQueue := func(idx uint32, desc, used, avail uint64, kickFD, callFD int) {
		var st [8]byte
		binary.LittleEndian.PutUint32(st[0:4], idx)
		binary.LittleEndian.PutUint32(st[4:8], uint32(qSize))
		f.reqAck(t, vhostSetVringNum, st[:], nil)

		addr := make([]byte, 40)
		binary.LittleEndian.PutUint32(addr[0:4], idx)
		binary.LittleEndian.PutUint64(addr[8:16], 0x10000000+desc)
		binary.LittleEndian.PutUint64(addr[16:24], 0x10000000+used)
		binary.LittleEndian.PutUint64(addr[24:32], 0x10000000+avail)
		f.reqAck(t, vhostSetVringAddr, addr, nil)

		binary.LittleEndian.PutUint32(st[4:8], 0)
		f.reqAck(t, vhostSetVringBase, st[:], nil)

		binary.LittleEndian.PutUint64(u64[:], uint64(idx))
		f.reqAck(t, vhostSetVringKick, u64[:], []int{kickFD})
		f.reqAck(t, vhostSetVringCall, u64[:], []int{callFD})

		binary.LittleEndian.PutUint32(st[0:4], idx)
		binary.LittleEndian.PutUint32(st[4:8], 1)
		f.reqAck(t, vhostSetVringEnable, st[:], nil)
	}

	setupQueue(0, f.rxDesc, f.rxUsed, f.rxAvail, f.rxKickFD, f.rxCallFD)
	setupQueue(1, f.txDesc, f.txUsed, f.txAvail, f.txKickFD, f.txCallFD)
	return f
}

func (f *testFrontend) close() {
	_ = f.conn.Close()
	unix.Close(f.rxKickFD)
	unix.Close(f.rxCallFD)
	unix.Close(f.txKickFD)
	unix.Close(f.txCallFD)
	_ = unix.Munmap(f.mem)
	_ = f.memFile.Close()
}

func (f *testFrontend) sendMsg(t testing.TB, req, flags uint32, body []byte, fds []int) {
	t.Helper()
	msg := make([]byte, 12+len(body))
	binary.LittleEndian.PutUint32(msg[0:4], req)
	binary.LittleEndian.PutUint32(msg[4:8], flags)
	binary.LittleEndian.PutUint32(msg[8:12], uint32(len(body)))
	copy(msg[12:], body)
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if _, _, err := f.conn.WriteMsgUnix(msg, oob, nil); err != nil {
		t.Fatalf("send vhost msg %d: %v", req, err)
	}
}

func (f *testFrontend) recvReply(t testing.TB, wantReq uint32) []byte {
	t.Helper()
	var hdr [12]byte
	if _, err := f.conn.Read(hdr[:]); err != nil {
		t.Fatalf("read reply hdr %d: %v", wantReq, err)
	}
	req := binary.LittleEndian.Uint32(hdr[0:4])
	size := binary.LittleEndian.Uint32(hdr[8:12])
	if req != wantReq {
		t.Fatalf("reply req mismatch: got %d want %d", req, wantReq)
	}
	body := make([]byte, size)
	for off := 0; off < len(body); {
		n, err := f.conn.Read(body[off:])
		if err != nil {
			t.Fatalf("read reply body: %v", err)
		}
		off += n
	}
	return body
}

func (f *testFrontend) reqU64(t testing.TB, req uint32, body []byte, fds []int) uint64 {
	t.Helper()
	f.sendMsg(t, req, 1, body, fds)
	reply := f.recvReply(t, req)
	return binary.LittleEndian.Uint64(reply)
}

func (f *testFrontend) reqAck(t testing.TB, req uint32, body []byte, fds []int) {
	t.Helper()
	f.sendMsg(t, req, 1|vhostFlagNeedReply, body, fds)
	reply := f.recvReply(t, req)
	if binary.LittleEndian.Uint64(reply) != 0 {
		t.Fatalf("non-zero ack for req %d", req)
	}
}

func (f *testFrontend) postRXBuffer(descIdx uint16, bufSize uint32) uint64 {
	addr := f.rxBufOff + uint64(descIdx)*2048
	off := f.rxDesc + uint64(descIdx)*16
	binary.LittleEndian.PutUint64(f.mem[off:off+8], addr)
	binary.LittleEndian.PutUint32(f.mem[off+8:off+12], bufSize)
	binary.LittleEndian.PutUint16(f.mem[off+12:off+14], descriptorWrite)
	binary.LittleEndian.PutUint16(f.mem[off+14:off+16], 0)

	ringOff := f.rxAvail + 4 + 2*uint64(f.rxAvailI%f.qSize)
	binary.LittleEndian.PutUint16(f.mem[ringOff:ringOff+2], descIdx)
	f.rxAvailI++
	memoryBarrier()
	binary.LittleEndian.PutUint16(f.mem[f.rxAvail+2:f.rxAvail+4], f.rxAvailI)
	return addr
}

// postTXPacket2Desc posts a TX packet using the standard Linux virtio-net
// 2-descriptor layout: desc d0 = 12B vnet hdr, desc d1 = Ethernet frame.
func (f *testFrontend) postTXPacket2Desc(slot uint16, frame []byte) {
	d0 := (slot * 2) % f.qSize
	d1 := (slot*2 + 1) % f.qSize
	hdrAddr := f.txBufOff + uint64(slot)*2048
	frmAddr := hdrAddr + 12
	clear(f.mem[hdrAddr : hdrAddr+12])
	copy(f.mem[frmAddr:frmAddr+uint64(len(frame))], frame)

	off0 := f.txDesc + uint64(d0)*16
	binary.LittleEndian.PutUint64(f.mem[off0:off0+8], hdrAddr)
	binary.LittleEndian.PutUint32(f.mem[off0+8:off0+12], 12)
	binary.LittleEndian.PutUint16(f.mem[off0+12:off0+14], descriptorNext)
	binary.LittleEndian.PutUint16(f.mem[off0+14:off0+16], d1)

	off1 := f.txDesc + uint64(d1)*16
	binary.LittleEndian.PutUint64(f.mem[off1:off1+8], frmAddr)
	binary.LittleEndian.PutUint32(f.mem[off1+8:off1+12], uint32(len(frame)))
	binary.LittleEndian.PutUint16(f.mem[off1+12:off1+14], 0)
	binary.LittleEndian.PutUint16(f.mem[off1+14:off1+16], 0)

	ringOff := f.txAvail + 4 + 2*uint64(f.txAvailI%f.qSize)
	binary.LittleEndian.PutUint16(f.mem[ringOff:ringOff+2], d0)
	f.txAvailI++
}

func (f *testFrontend) commitTX() {
	memoryBarrier()
	binary.LittleEndian.PutUint16(f.mem[f.txAvail+2:f.txAvail+4], f.txAvailI)
	var one [8]byte
	binary.LittleEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(f.txKickFD, one[:])
}

func (f *testFrontend) readCallCount(fd int) uint64 {
	var buf [8]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil || n != 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(buf[:])
}

func startTestEndpoint(t testing.TB) (*Endpoint, string, context.CancelFunc) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "vhost.sock")
	ep, err := NewEndpoint(func() []byte { return make([]byte, 12) })
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	go func() {
		_ = ep.Serve(ctx, sockPath, Hooks{
			OnListening: func() { close(listening) },
		})
	}()
	select {
	case <-listening:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for vhost listener")
	}
	t.Cleanup(func() {
		cancel()
		_ = ep.Close()
	})
	return ep, sockPath, cancel
}

func TestVhostBatchedTXAndRX(t *testing.T) {
	ep, sockPath, _ := startTestEndpoint(t)
	fe := newTestFrontend(t, sockPath, 256)
	defer fe.close()

	const batch = 64
	frame := bytes.Repeat([]byte{0xab}, 1280+14)
	for i := uint16(0); i < batch; i++ {
		fe.postTXPacket2Desc(i, frame)
	}
	fe.commitTX()

	got := 0
	if err := ep.DrainTX(func(f []byte) (TXAction, []byte) {
		if len(f) != len(frame) {
			t.Errorf("TX frame len = %d, want %d", len(f), len(frame))
		}
		got++
		return TXConsume, nil
	}); err != nil {
		t.Fatalf("DrainTX: %v", err)
	}
	if got != batch {
		t.Fatalf("DrainTX got %d frames, want %d", got, batch)
	}
	if usedIdx := binary.LittleEndian.Uint16(fe.mem[fe.txUsed+2 : fe.txUsed+4]); usedIdx != batch {
		t.Fatalf("TX used.idx = %d, want %d", usedIdx, batch)
	}
	if calls := fe.readCallCount(fe.txCallFD); calls != 1 {
		t.Fatalf("TX callFD interrupts = %d, want 1 (batched)", calls)
	}

	// Test batched RX delivery.
	rxAddrs := make([]uint64, batch)
	for i := uint16(0); i < batch; i++ {
		rxAddrs[i] = fe.postRXBuffer(i, 2048)
	}
	var ethHdr [14]byte
	ethHdr[12] = 0x08
	payload := bytes.Repeat([]byte{0xcd}, 1280)
	ep.WriteRX(batch, func(i int) ([14]byte, []byte, bool) {
		return ethHdr, payload, true
	})
	if usedIdx := binary.LittleEndian.Uint16(fe.mem[fe.rxUsed+2 : fe.rxUsed+4]); usedIdx != batch {
		t.Fatalf("RX used.idx = %d, want %d", usedIdx, batch)
	}
	if usedFlags := binary.LittleEndian.Uint16(fe.mem[fe.rxUsed : fe.rxUsed+2]); usedFlags&vringUsedFNoNotify == 0 {
		t.Fatalf("RX used.flags = %#x, want VRING_USED_F_NO_NOTIFY set", usedFlags)
	}
	if calls := fe.readCallCount(fe.rxCallFD); calls != 1 {
		t.Fatalf("RX callFD interrupts = %d, want 1 (batched)", calls)
	}
	// Spot-check first and last RX buffers.
	for _, idx := range []int{0, batch - 1} {
		addr := rxAddrs[idx]
		gotBuf := fe.mem[addr : addr+12+14+uint64(len(payload))]
		if !bytes.Equal(gotBuf[:12], make([]byte, 12)) {
			t.Fatalf("RX[%d] vnet hdr not zero", idx)
		}
		if !bytes.Equal(gotBuf[12:26], ethHdr[:]) {
			t.Fatalf("RX[%d] eth hdr mismatch", idx)
		}
		if !bytes.Equal(gotBuf[26:], payload) {
			t.Fatalf("RX[%d] payload mismatch", idx)
		}
	}
}

func TestVhostNoInterruptSuppression(t *testing.T) {
	ep, sockPath, _ := startTestEndpoint(t)
	fe := newTestFrontend(t, sockPath, 64)
	defer fe.close()

	// Suppress interrupts on both RX and TX avail rings.
	binary.LittleEndian.PutUint16(fe.mem[fe.txAvail:fe.txAvail+2], vringAvailFNoInterrupt)
	binary.LittleEndian.PutUint16(fe.mem[fe.rxAvail:fe.rxAvail+2], vringAvailFNoInterrupt)

	frame := bytes.Repeat([]byte{0x11}, 64)
	fe.postTXPacket2Desc(0, frame)
	fe.commitTX()

	if err := ep.DrainTX(func([]byte) (TXAction, []byte) { return TXConsume, nil }); err != nil {
		t.Fatalf("DrainTX: %v", err)
	}
	if calls := fe.readCallCount(fe.txCallFD); calls != 0 {
		t.Fatalf("TX callFD fired %d times despite NO_INTERRUPT", calls)
	}

	fe.postRXBuffer(0, 2048)
	ep.WriteRX(1, func(int) ([14]byte, []byte, bool) {
		return [14]byte{}, []byte("hello"), true
	})
	if calls := fe.readCallCount(fe.rxCallFD); calls != 0 {
		t.Fatalf("RX callFD fired %d times despite NO_INTERRUPT", calls)
	}
}

func TestVhostReconnect(t *testing.T) {
	ep, sockPath, _ := startTestEndpoint(t)

	// Session 1.
	fe1 := newTestFrontend(t, sockPath, 64)
	fe1.postTXPacket2Desc(0, bytes.Repeat([]byte{0x01}, 64))
	fe1.commitTX()
	if err := ep.DrainTX(func([]byte) (TXAction, []byte) { return TXConsume, nil }); err != nil {
		t.Fatalf("session 1 DrainTX: %v", err)
	}
	fe1.close()

	// Start DrainTX while disconnected, then connect Session 2.
	done := make(chan error, 1)
	go func() {
		done <- ep.DrainTX(func([]byte) (TXAction, []byte) { return TXConsume, nil })
	}()

	time.Sleep(20 * time.Millisecond)
	fe2 := newTestFrontend(t, sockPath, 64)
	defer fe2.close()
	fe2.postTXPacket2Desc(0, bytes.Repeat([]byte{0x02}, 64))
	fe2.commitTX()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session 2 DrainTX: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for session 2 DrainTX")
	}
}

func BenchmarkVhostTXBatch64(b *testing.B) {
	ep, sockPath, _ := startTestEndpoint(b)
	fe := newTestFrontend(b, sockPath, 256)
	defer fe.close()
	binary.LittleEndian.PutUint16(fe.mem[fe.txAvail:fe.txAvail+2], vringAvailFNoInterrupt)

	const batch = 64
	frame := bytes.Repeat([]byte{0xab}, 1280+14)
	dst := make([]byte, 1280)
	b.SetBytes(int64(batch * 1280))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := uint16(0); j < batch; j++ {
			fe.postTXPacket2Desc(j, frame)
		}
		memoryBarrier()
		binary.LittleEndian.PutUint16(fe.mem[fe.txAvail+2:fe.txAvail+4], fe.txAvailI)
		if err := ep.DrainTX(func(f []byte) (TXAction, []byte) {
			copy(dst, f[14:])
			return TXConsume, nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVhostRXBatch64(b *testing.B) {
	ep, sockPath, _ := startTestEndpoint(b)
	fe := newTestFrontend(b, sockPath, 256)
	defer fe.close()
	binary.LittleEndian.PutUint16(fe.mem[fe.rxAvail:fe.rxAvail+2], vringAvailFNoInterrupt)

	const batch = 64
	var ethHdr [14]byte
	payload := bytes.Repeat([]byte{0xcd}, 1280)
	b.SetBytes(int64(batch * 1280))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := uint16(0); j < batch; j++ {
			fe.postRXBuffer(j, 2048)
		}
		ep.WriteRX(batch, func(int) ([14]byte, []byte, bool) {
			return ethHdr, payload, true
		})
	}
}
