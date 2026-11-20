package vhostuser

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	vhostGetFeatures         = 1
	vhostSetFeatures         = 2
	vhostSetOwner            = 3
	vhostResetOwner          = 4
	vhostSetMemTable         = 5
	vhostSetVringNum         = 8
	vhostSetVringAddr        = 9
	vhostSetVringBase        = 10
	vhostGetVringBase        = 11
	vhostSetVringKick        = 12
	vhostSetVringCall        = 13
	vhostSetVringErr         = 14
	vhostGetProtocolFeatures = 15
	vhostSetProtocolFeatures = 16
	vhostGetQueueNum         = 17
	vhostSetVringEnable      = 18
	vhostGetConfig           = 24
	vhostSetConfig           = 25

	vhostFlagReply     = 1 << 2
	vhostFlagNeedReply = 1 << 3

	vhostProtocolMQ       = 1 << 0
	vhostProtocolReplyAck = 1 << 3
	vhostProtocolConfig   = 1 << 9

	virtioNetMTU     = 3
	virtioNetMAC     = 5
	virtioNetStatus  = 16
	virtioVersion1   = 32
	vhostProtocolBit = 30
)

type vhostSession struct {
	endpoint   *Endpoint
	configFn   func() []byte
	fd         int
	file       *os.File
	ctx        context.Context
	regions    []memoryRegion
	retiredFDs []int
	queues     [3]virtQueue
	features   uint64
	protocol   uint64
	closing    atomic.Bool
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

func (s *vhostSession) close() {
	s.closeOnce.Do(func() {
		s.file.Close()
		for i := range s.queues {
			for _, fd := range []*int{&s.queues[i].kickFD, &s.queues[i].callFD, &s.queues[i].errFD} {
				if *fd >= 0 {
					unix.Close(*fd)
					*fd = -1
				}
			}
		}
		for _, fd := range s.retiredFDs {
			unix.Close(fd)
		}
		s.retiredFDs = nil
		for _, region := range s.regions {
			unix.Munmap(region.mapped)
		}
		s.regions = nil
	})
}

func (s *vhostSession) run() error {
	for {
		request, flags, body, fds, err := s.receive()
		if err != nil {
			if errors.Is(err, io.EOF) && s.ctx.Err() != nil {
				return nil
			}
			return err
		}
		if flags&3 != 1 {
			closeFDs(fds)
			return fmt.Errorf("invalid vhost-user flags %#x", flags)
		}
		if err := s.handle(request, flags, body, fds); err != nil {
			closeFDs(fds)
			return fmt.Errorf("vhost-user request %d: %w", request, err)
		}
	}
}

func (s *vhostSession) receive() (uint32, uint32, []byte, []int, error) {
	header := make([]byte, 12)
	oob := make([]byte, unix.CmsgSpace(4*64))
	read := 0
	var fds []int
	for read < len(header) {
		n, oobn, _, _, err := unix.Recvmsg(s.fd, header[read:], oob, 0)
		if err != nil {
			return 0, 0, nil, fds, err
		}
		if n == 0 {
			return 0, 0, nil, fds, io.EOF
		}
		read += n
		if oobn > 0 {
			messages, err := unix.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				return 0, 0, nil, fds, err
			}
			for _, message := range messages {
				rights, err := unix.ParseUnixRights(&message)
				if err == nil {
					fds = append(fds, rights...)
				}
			}
		}
	}
	request := binary.LittleEndian.Uint32(header[0:4])
	flags := binary.LittleEndian.Uint32(header[4:8])
	size := binary.LittleEndian.Uint32(header[8:12])
	if size > 1<<20 {
		return 0, 0, nil, fds, fmt.Errorf("oversized message: %d", size)
	}
	body := make([]byte, size)
	for read := 0; read < len(body); {
		n, err := unix.Read(s.fd, body[read:])
		if err != nil {
			return 0, 0, nil, fds, err
		}
		if n == 0 {
			return 0, 0, nil, fds, io.EOF
		}
		read += n
	}
	return request, flags, body, fds, nil
}

func (s *vhostSession) reply(request uint32, body []byte) error {
	header := make([]byte, 12)
	binary.LittleEndian.PutUint32(header[0:4], request)
	binary.LittleEndian.PutUint32(header[4:8], 1|vhostFlagReply)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(body)))
	if err := writeAll(s.fd, header); err != nil {
		return err
	}
	return writeAll(s.fd, body)
}

func (s *vhostSession) replyU64(request uint32, value uint64) error {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint64(body, value)
	return s.reply(request, body)
}

func (s *vhostSession) ack(request, flags uint32) error {
	if flags&vhostFlagNeedReply == 0 {
		return nil
	}
	return s.reply(request, make([]byte, 8))
}

func (s *vhostSession) handle(request, flags uint32, body []byte, fds []int) error {
	defer func() {
		closeFDs(fds)
	}()
	switch request {
	case vhostGetFeatures:
		features := uint64(1<<virtioVersion1 | 1<<vhostProtocolBit | 1<<virtioNetMTU | 1<<virtioNetMAC | 1<<virtioNetStatus)
		return s.replyU64(request, features)
	case vhostSetFeatures:
		if len(body) != 8 {
			return io.ErrUnexpectedEOF
		}
		s.features = binary.LittleEndian.Uint64(body)
		log.Printf("negotiated virtio features: %#x", s.features)
		return s.ack(request, flags)
	case vhostGetProtocolFeatures:
		return s.replyU64(request, s.protocol)
	case vhostSetProtocolFeatures:
		if len(body) != 8 {
			return io.ErrUnexpectedEOF
		}
		s.protocol = binary.LittleEndian.Uint64(body)
		return s.ack(request, flags)
	case vhostGetQueueNum:
		return s.replyU64(request, 3)
	case vhostSetOwner, vhostResetOwner:
		return s.ack(request, flags)
	case vhostSetMemTable:
		if err := s.setMemory(body, fds); err != nil {
			return err
		}
		return s.ack(request, flags)
	case vhostSetVringNum:
		index, value, err := parseVringState(body)
		if err != nil || index >= len(s.queues) || value == 0 || value > 32768 {
			return fmt.Errorf("invalid queue size: index=%d value=%d body=%x parse=%v", index, value, body, err)
		}
		q := &s.queues[index]
		q.mu.Lock()
		q.size = uint16(value)
		q.mu.Unlock()
		return s.ack(request, flags)
	case vhostSetVringAddr:
		if len(body) != 40 {
			return io.ErrUnexpectedEOF
		}
		index := binary.LittleEndian.Uint32(body[0:4])
		if int(index) >= len(s.queues) {
			return fmt.Errorf("invalid queue %d", index)
		}
		q := &s.queues[index]
		desc, err := s.vmmToGPA(binary.LittleEndian.Uint64(body[8:16]))
		if err != nil {
			return err
		}
		used, err := s.vmmToGPA(binary.LittleEndian.Uint64(body[16:24]))
		if err != nil {
			return err
		}
		avail, err := s.vmmToGPA(binary.LittleEndian.Uint64(body[24:32]))
		if err != nil {
			return err
		}
		q.mu.Lock()
		q.desc = desc
		q.used = used
		q.avail = avail
		err = s.resolveQueueRings(q)
		q.mu.Unlock()
		if err != nil {
			return err
		}
		log.Printf("queue %d: size=%d desc=%#x avail=%#x used=%#x", index, q.size, q.desc, q.avail, q.used)
		return s.ack(request, flags)
	case vhostSetVringBase:
		index, value, err := parseVringState(body)
		if err != nil || index >= len(s.queues) {
			return fmt.Errorf("invalid queue base")
		}
		q := &s.queues[index]
		q.mu.Lock()
		q.nextAvail = uint16(value)
		q.nextUsed = uint16(value)
		q.mu.Unlock()
		return s.ack(request, flags)
	case vhostGetVringBase:
		index, _, err := parseVringState(body)
		if err != nil || index >= len(s.queues) {
			return fmt.Errorf("invalid queue base")
		}
		q := &s.queues[index]
		q.mu.Lock()
		nextAvail := q.nextAvail
		q.mu.Unlock()
		reply := make([]byte, 8)
		binary.LittleEndian.PutUint32(reply[0:4], uint32(index))
		binary.LittleEndian.PutUint32(reply[4:8], uint32(nextAvail))
		return s.reply(request, reply)
	case vhostSetVringKick, vhostSetVringCall, vhostSetVringErr:
		if len(body) != 8 {
			return io.ErrUnexpectedEOF
		}
		index := int(binary.LittleEndian.Uint64(body) & 0xff)
		if index >= len(s.queues) {
			return fmt.Errorf("invalid event queue %d", index)
		}
		fd := -1
		if len(fds) == 1 {
			fd = fds[0]
			fds = nil
		}
		q := &s.queues[index]
		q.mu.Lock()
		var destination *int
		switch request {
		case vhostSetVringKick:
			destination = &q.kickFD
		case vhostSetVringCall:
			destination = &q.callFD
		case vhostSetVringErr:
			destination = &q.errFD
		}
		if *destination >= 0 {
			s.retiredFDs = append(s.retiredFDs, *destination)
		}
		*destination = fd
		q.mu.Unlock()
		if request == vhostSetVringKick && index == 1 {
			s.endpoint.signalWake()
		}
		log.Printf("queue %d request=%d fd=%d", index, request, fd)
		return s.ack(request, flags)
	case vhostSetVringEnable:
		index, value, err := parseVringState(body)
		if err != nil || index >= len(s.queues) || value > 1 {
			return fmt.Errorf("invalid queue enable")
		}
		q := &s.queues[index]
		q.mu.Lock()
		q.enabled = value == 1
		q.mu.Unlock()
		if index == 1 {
			s.endpoint.signalWake()
		}
		return s.ack(request, flags)
	case vhostGetConfig:
		if len(body) < 12 {
			return io.ErrUnexpectedEOF
		}
		offset := binary.LittleEndian.Uint32(body[0:4])
		size := int(binary.LittleEndian.Uint32(body[4:8]))
		if size < 0 || size > 4096 || len(body) != 12+size {
			return fmt.Errorf("invalid config read")
		}
		if offset >= 0x100 {
			offset -= 0x100
		}
		config := s.configFn()
		response := append([]byte(nil), body[:12]...)
		if uint64(offset)+uint64(size) <= uint64(len(config)) {
			response = append(response, config[offset:offset+uint32(size)]...)
		} else {
			binary.LittleEndian.PutUint32(response[4:8], 0)
		}
		return s.reply(request, response)
	case vhostSetConfig:
		return s.ack(request, flags)
	default:
		return fmt.Errorf("unsupported request")
	}
}

func (s *vhostSession) setMemory(body []byte, fds []int) error {
	if len(body) < 8 {
		return io.ErrUnexpectedEOF
	}
	count := int(binary.LittleEndian.Uint32(body[0:4]))
	if count == 0 || count > 64 || len(body) != 8+32*count || len(fds) != count {
		return fmt.Errorf("invalid memory table: regions=%d fds=%d bytes=%d", count, len(fds), len(body))
	}
	regions := make([]memoryRegion, 0, count)
	page := int64(os.Getpagesize())
	for i := 0; i < count; i++ {
		entry := body[8+32*i : 8+32*(i+1)]
		base := binary.LittleEndian.Uint64(entry[0:8])
		size := binary.LittleEndian.Uint64(entry[8:16])
		user := binary.LittleEndian.Uint64(entry[16:24])
		offset := binary.LittleEndian.Uint64(entry[24:32])
		if size == 0 || size > 1<<34 {
			for _, r := range regions {
				unix.Munmap(r.mapped)
			}
			return fmt.Errorf("invalid memory region size %d", size)
		}
		aligned := int64(offset) &^ (page - 1)
		delta := int64(offset) - aligned
		mapped, err := unix.Mmap(fds[i], aligned, int(size)+int(delta), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			for _, r := range regions {
				unix.Munmap(r.mapped)
			}
			return err
		}
		regions = append(regions, memoryRegion{
			base:   base,
			user:   user,
			mapped: mapped,
			data:   mapped[delta : delta+int64(size)],
		})
	}
	for i := range s.queues {
		s.queues[i].mu.Lock()
	}
	old := s.regions
	s.regions = regions
	var resolveErr error
	for i := range s.queues {
		q := &s.queues[i]
		if q.size > 0 && q.desc != 0 {
			if err := s.resolveQueueRings(q); err != nil && resolveErr == nil {
				resolveErr = err
			}
		}
		q.mu.Unlock()
	}
	for _, region := range old {
		unix.Munmap(region.mapped)
	}
	return resolveErr
}

func parseVringState(body []byte) (int, uint32, error) {
	if len(body) != 8 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return int(binary.LittleEndian.Uint32(body[0:4])), binary.LittleEndian.Uint32(body[4:8]), nil
}

func writeAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
