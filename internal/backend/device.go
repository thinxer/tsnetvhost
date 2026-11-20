package backend

import (
	"io"
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

// Device implements wireguard-go's tun.Device directly over a vhost-user
// Transport without intermediate packet channels or goroutines.
type Device struct {
	adapter   *Adapter
	transport Transport
	events    chan tun.Event
	closeOnce sync.Once
	closed    atomic.Bool
	mtu       int
}

func NewDevice(adapter *Adapter, transport Transport, mtu int) *Device {
	return &Device{
		adapter:   adapter,
		transport: transport,
		events:    make(chan tun.Event, 1),
		mtu:       mtu,
	}
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
			n, reply, fit := d.adapter.DecodeGuestFrame(frame, slab[offset:maxEnd])
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
	addrs := d.adapter.loadAddresses()
	d.transport.WriteRX(len(bufs), func(i int) ([14]byte, []byte, bool) {
		packet := bufs[i][offset:]
		debugPacket("tsnet-write", packet)
		return d.adapter.FrameInbound(packet, addrs)
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
