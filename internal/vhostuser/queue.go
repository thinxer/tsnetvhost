package vhostuser

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
)

const (
	descriptorNext  = 1
	descriptorWrite = 2

	vringAvailFNoInterrupt = 1
	vringUsedFNoNotify     = 1
	virtioNetHdrSize       = 12
)

type memoryRegion struct {
	base   uint64
	user   uint64
	mapped []byte
	data   []byte
}

type virtQueue struct {
	mu        sync.Mutex
	size      uint16
	desc      uint64
	avail     uint64
	used      uint64
	descMem   []byte
	availMem  []byte
	usedMem   []byte
	kickFD    int
	callFD    int
	errFD     int
	nextAvail uint16
	nextUsed  uint16
	enabled   bool
	txScratch []byte
}

type descriptor struct {
	address uint64
	length  uint32
	flags   uint16
	next    uint16
}

func (s *vhostSession) resolveQueueRings(q *virtQueue) error {
	if q.size == 0 {
		return nil
	}
	descLen := 16 * int(q.size)
	availLen := 4 + 2*int(q.size)
	usedLen := 4 + 8*int(q.size)
	descMem, ok := s.guestSlice(q.desc, descLen)
	if !ok {
		return fmt.Errorf("descriptor ring %#x (%d bytes) is unmapped", q.desc, descLen)
	}
	availMem, ok := s.guestSlice(q.avail, availLen)
	if !ok {
		return fmt.Errorf("avail ring %#x (%d bytes) is unmapped", q.avail, availLen)
	}
	usedMem, ok := s.guestSlice(q.used, usedLen)
	if !ok {
		return fmt.Errorf("used ring %#x (%d bytes) is unmapped", q.used, usedLen)
	}
	q.descMem = descMem
	q.availMem = availMem
	q.usedMem = usedMem
	if q == &s.queues[0] {
		// Backend never polls RX kickFD; suppress guest RX kicks (VM-exits).
		binary.LittleEndian.PutUint16(q.usedMem[0:2], vringUsedFNoNotify)
	}
	return nil
}

func (s *vhostSession) vmmToGPA(address uint64) (uint64, error) {
	for _, region := range s.regions {
		if address >= region.user && address < region.user+uint64(len(region.data)) {
			return address - region.user + region.base, nil
		}
	}
	return 0, fmt.Errorf("VMM address %#x is not in the memory table", address)
}

func (s *vhostSession) locate(address uint64) (*memoryRegion, int, error) {
	for i := range s.regions {
		region := &s.regions[i]
		if address >= region.base && address < region.base+uint64(len(region.data)) {
			return region, int(address - region.base), nil
		}
	}
	return nil, 0, fmt.Errorf("guest address %#x is unmapped", address)
}

func (s *vhostSession) guestSlice(address uint64, length int) ([]byte, bool) {
	if length < 0 {
		return nil, false
	}
	region, offset, err := s.locate(address)
	if err != nil || offset+length > len(region.data) {
		return nil, false
	}
	return region.data[offset : offset+length], true
}

func (s *vhostSession) appendGuestMemory(dst []byte, address uint64, size int) ([]byte, error) {
	if slice, ok := s.guestSlice(address, size); ok {
		return append(dst, slice...), nil
	}
	for copied := 0; copied < size; {
		region, offset, err := s.locate(address + uint64(copied))
		if err != nil {
			return dst, err
		}
		avail := len(region.data) - offset
		want := size - copied
		if want > avail {
			want = avail
		}
		if want == 0 {
			return dst, io.ErrUnexpectedEOF
		}
		dst = append(dst, region.data[offset:offset+want]...)
		copied += want
	}
	return dst, nil
}

func (s *vhostSession) writeGuestMemory(address uint64, data []byte) error {
	if slice, ok := s.guestSlice(address, len(data)); ok {
		copy(slice, data)
		return nil
	}
	for written := 0; written < len(data); {
		region, offset, err := s.locate(address + uint64(written))
		if err != nil {
			return err
		}
		n := copy(region.data[offset:], data[written:])
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		written += n
	}
	return nil
}

func (q *virtQueue) ready() bool {
	return len(q.descMem) > 0 && len(q.availMem) > 0 && len(q.usedMem) > 0
}

func (q *virtQueue) availFlags() uint16 {
	return binary.LittleEndian.Uint16(q.availMem[0:2])
}

func (q *virtQueue) availIdx() uint16 {
	return binary.LittleEndian.Uint16(q.availMem[2:4])
}

func (q *virtQueue) availEntry(i uint16) uint16 {
	off := 4 + 2*int(i%q.size)
	return binary.LittleEndian.Uint16(q.availMem[off : off+2])
}

func (q *virtQueue) readDesc(i uint16) descriptor {
	off := 16 * int(i)
	d := q.descMem[off : off+16]
	return descriptor{
		address: binary.LittleEndian.Uint64(d[0:8]),
		length:  binary.LittleEndian.Uint32(d[8:12]),
		flags:   binary.LittleEndian.Uint16(d[12:14]),
		next:    binary.LittleEndian.Uint16(d[14:16]),
	}
}

func (q *virtQueue) writeUsedEntry(i uint16, id, length uint32) {
	off := 4 + 8*int(i%q.size)
	binary.LittleEndian.PutUint32(q.usedMem[off:off+4], id)
	binary.LittleEndian.PutUint32(q.usedMem[off+4:off+8], length)
}

func (q *virtQueue) publishUsed() {
	memoryBarrier()
	binary.LittleEndian.PutUint16(q.usedMem[2:4], q.nextUsed)
	memoryBarrier()
	if q.callFD >= 0 && q.availFlags()&vringAvailFNoInterrupt == 0 {
		signalEventFD(q.callFD)
	}
}

func (s *vhostSession) readTXFrame(q *virtQueue, head uint16) ([]byte, error) {
	d0 := q.readDesc(head)
	if d0.flags&descriptorWrite != 0 {
		return nil, fmt.Errorf("TX descriptor is writable")
	}
	// Fast path 1: single descriptor containing vnet header + Ethernet frame.
	if d0.flags&descriptorNext == 0 {
		if d0.length < virtioNetHdrSize {
			return nil, nil
		}
		if buf, ok := s.guestSlice(d0.address, int(d0.length)); ok {
			return buf[virtioNetHdrSize:], nil
		}
	} else if d0.length == virtioNetHdrSize && d0.next < q.size {
		// Fast path 2: standard Linux virtio-net 2-descriptor chain (12B vnet hdr + frame).
		d1 := q.readDesc(d0.next)
		if d1.flags&descriptorWrite != 0 {
			return nil, fmt.Errorf("TX descriptor is writable")
		}
		if d1.flags&descriptorNext == 0 {
			if buf, ok := s.guestSlice(d1.address, int(d1.length)); ok {
				return buf, nil
			}
		}
	}

	// General path: gather arbitrarily fragmented descriptor chain into reusable scratch.
	scratch := q.txScratch[:0]
	index := head
	for range q.size {
		if index >= q.size {
			return nil, fmt.Errorf("descriptor next out of range: head=%d next=%d size=%d", head, index, q.size)
		}
		item := q.readDesc(index)
		if item.flags&descriptorWrite != 0 {
			return nil, fmt.Errorf("TX descriptor is writable")
		}
		var err error
		scratch, err = s.appendGuestMemory(scratch, item.address, int(item.length))
		if err != nil {
			return nil, err
		}
		if item.flags&descriptorNext == 0 {
			q.txScratch = scratch
			if len(scratch) < virtioNetHdrSize {
				return nil, nil
			}
			return scratch[virtioNetHdrSize:], nil
		}
		index = item.next
	}
	return nil, fmt.Errorf("descriptor chain is too long")
}

func (s *vhostSession) writeRXBatch(n int, get func(i int) (ethHdr [14]byte, payload []byte, ok bool)) {
	q := &s.queues[0]
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.enabled || q.size == 0 || !q.ready() {
		return
	}
	availIdx := q.availIdx()
	if availIdx == q.nextAvail {
		return
	}
	memoryBarrier()

	var zeroHdr [virtioNetHdrSize]byte
	completed := 0
	for i := 0; i < n; i++ {
		ethHdr, payload, ok := get(i)
		if !ok {
			continue
		}
		if q.nextAvail == availIdx {
			availIdx = q.availIdx()
			if q.nextAvail == availIdx {
				break
			}
			memoryBarrier()
		}
		head := q.availEntry(q.nextAvail)
		if head >= q.size {
			log.Printf("RX queue: descriptor head out of range: head=%d size=%d", head, q.size)
			break
		}
		written, err := s.writeRXDescriptor(q, head, zeroHdr[:], ethHdr[:], payload)
		if err != nil {
			log.Printf("RX queue: %v", err)
			break
		}
		q.writeUsedEntry(q.nextUsed, uint32(head), uint32(written))
		q.nextAvail++
		q.nextUsed++
		completed++
	}
	if completed > 0 {
		q.publishUsed()
	}
}

func (s *vhostSession) writeRXDescriptor(q *virtQueue, head uint16, vnetHdr, ethHdr, payload []byte) (int, error) {
	total := len(vnetHdr) + len(ethHdr) + len(payload)
	first := q.readDesc(head)
	if first.flags&descriptorWrite == 0 {
		return 0, fmt.Errorf("RX descriptor is not writable")
	}
	// Fast path: single contiguous RX buffer holds the entire frame.
	if int(first.length) >= total {
		if buf, ok := s.guestSlice(first.address, total); ok {
			copy(buf[0:len(vnetHdr)], vnetHdr)
			copy(buf[len(vnetHdr):len(vnetHdr)+len(ethHdr)], ethHdr)
			copy(buf[len(vnetHdr)+len(ethHdr):], payload)
			return total, nil
		}
	}

	chunks := [3][]byte{vnetHdr, ethHdr, payload}
	chunkIdx := 0
	chunkOff := 0
	written := 0
	index := head
	for range q.size {
		if index >= q.size {
			return 0, fmt.Errorf("descriptor next out of range: head=%d next=%d size=%d", head, index, q.size)
		}
		item := q.readDesc(index)
		if item.flags&descriptorWrite == 0 {
			return 0, fmt.Errorf("RX descriptor is not writable")
		}
		descAddr := item.address
		descRem := int(item.length)
		for descRem > 0 && chunkIdx < len(chunks) {
			src := chunks[chunkIdx][chunkOff:]
			if len(src) == 0 {
				chunkIdx++
				chunkOff = 0
				continue
			}
			n := len(src)
			if n > descRem {
				n = descRem
			}
			if err := s.writeGuestMemory(descAddr, src[:n]); err != nil {
				return 0, err
			}
			descAddr += uint64(n)
			descRem -= n
			chunkOff += n
			written += n
			if chunkOff == len(chunks[chunkIdx]) {
				chunkIdx++
				chunkOff = 0
			}
		}
		if written == total {
			return written, nil
		}
		if item.flags&descriptorNext == 0 {
			return 0, fmt.Errorf("RX buffer too small: %d < %d", written, total)
		}
		index = item.next
	}
	return 0, fmt.Errorf("descriptor chain is too long")
}
