package backend

import (
	"io"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

const DefaultMTU = 1280

type MemoryDevice struct {
	outbound chan []byte
	inbound  chan []byte
	events   chan tun.Event
	done     chan struct{}
	close    sync.Once
	mtu      int
}

func NewMemoryDevice(mtu int) *MemoryDevice {
	return &MemoryDevice{
		outbound: make(chan []byte, 256),
		inbound:  make(chan []byte, 256),
		events:   make(chan tun.Event, 1),
		done:     make(chan struct{}),
		mtu:      mtu,
	}
}

func (d *MemoryDevice) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case packet := <-d.outbound:
		if len(packet)+2*tun.ReadPacketSpacing > len(slab) {
			return 0, io.ErrShortBuffer
		}
		copy(slab[tun.ReadPacketSpacing:len(slab)-tun.ReadPacketSpacing], packet)
		debugPacket("tsnet-read", packet)
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: len(packet)}
		return 1, nil
	}
}

func (d *MemoryDevice) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return written, io.ErrUnexpectedEOF
		}
		packet := append([]byte(nil), buf[offset:]...)
		debugPacket("tsnet-write", packet)
		select {
		case <-d.done:
			return written, os.ErrClosed
		case d.inbound <- packet:
			written++
		}
	}
	return written, nil
}

func (d *MemoryDevice) File() *os.File { return nil }

func (d *MemoryDevice) MTU() (int, error) { return d.mtu, nil }

func (d *MemoryDevice) Name() (string, error) { return "tsnet-vhost", nil }

func (d *MemoryDevice) Events() <-chan tun.Event { return d.events }

func (d *MemoryDevice) BatchSize() int { return 1 }

func (d *MemoryDevice) Close() error {
	d.close.Do(func() {
		close(d.done)
		close(d.events)
	})
	return nil
}
