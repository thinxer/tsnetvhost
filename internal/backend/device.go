package backend

import (
	"crypto/sha256"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
	"tsnetvhost/internal/vhostuser"
)

const DefaultMTU = 1280

// Transport is the virtqueue data plane used by Device.
type Transport interface {
	DrainTX(handle func(frame []byte) (vhostuser.TXAction, []byte)) error
	WriteRX(n int, get func(i int) (ethHdr [14]byte, payload []byte, ok bool))
	Close() error
}

type addrState struct {
	has4 bool
	ipv4 [4]byte
	has6 bool
	ipv6 [16]byte
}

// Device implements wireguard-go's tun.Device directly over a vhost-user
// Transport, handling Ethernet framing, source/destination IP validation,
// and synthetic-gateway ARP/NDP without intermediate channels or goroutines.
type Device struct {
	transport Transport
	guestMAC  [6]byte
	mtu       int
	addrs     atomic.Pointer[addrState]
	events    chan tun.Event
	closeOnce sync.Once
	closed    atomic.Bool
}

func NewDevice(hostname string, mtu int, transport Transport) *Device {
	digest := sha256.Sum256([]byte(hostname))
	d := &Device{
		transport: transport,
		guestMAC:  [6]byte{0x02, 0x54, 0x53, digest[0], digest[1], digest[2]},
		mtu:       mtu,
		events:    make(chan tun.Event, 1),
	}
	d.addrs.Store(&addrState{})
	return d
}

func (d *Device) SetAddresses(ipv4, ipv6 netip.Addr) {
	st := &addrState{
		has4: ipv4.IsValid(),
		has6: ipv6.IsValid(),
	}
	if st.has4 {
		st.ipv4 = ipv4.As4()
	}
	if st.has6 {
		st.ipv6 = ipv6.As16()
	}
	d.addrs.Store(st)
}

func (d *Device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, io.ErrShortBuffer
	}
	maxEnd := len(slab) - tun.ReadPacketSpacing
	for {
		if d.closed.Load() {
			return 0, os.ErrClosed
		}
		count := 0
		offset := tun.ReadPacketSpacing
		shortBuf := false
		err := d.transport.DrainTX(func(frame []byte) (vhostuser.TXAction, []byte) {
			if count >= len(packets) || offset >= maxEnd {
				return vhostuser.TXStop, nil
			}
			n, reply, fit := d.decodeGuestFrame(frame, slab[offset:maxEnd])
			if !fit {
				if count == 0 {
					shortBuf = true
				}
				return vhostuser.TXStop, nil
			}
			if n > 0 {
				packets[count] = tun.ReadPacket{Offset: offset, Size: n}
				offset += n + tun.ReadPacketSpacing
				count++
			}
			return vhostuser.TXConsume, reply
		})
		if shortBuf {
			return 0, io.ErrShortBuffer
		}
		if count > 0 || err != nil {
			return count, err
		}
	}
}

func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	for i, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return i, io.ErrUnexpectedEOF
		}
	}
	addrs := d.addrs.Load()
	d.transport.WriteRX(len(bufs), func(i int) ([14]byte, []byte, bool) {
		packet := bufs[i][offset:]
		debugPacket("tsnet-write", packet)
		return d.frameInbound(packet, addrs)
	})
	return len(bufs), nil
}

func (d *Device) File() *os.File { return nil }

func (d *Device) MTU() (int, error) { return d.mtu, nil }

func (d *Device) Name() (string, error) { return "tsnet-vhost", nil }

func (d *Device) Events() <-chan tun.Event { return d.events }

func (d *Device) BatchSize() int { return conn.IdealBatchSize }

func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		_ = d.transport.Close()
		close(d.events)
	})
	return nil
}
