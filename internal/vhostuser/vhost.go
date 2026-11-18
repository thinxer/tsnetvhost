package vhostuser

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

	descriptorNext  = 1
	descriptorWrite = 2
)

var activeVhost atomic.Pointer[vhostServer]

func SendFrame(frame []byte) error {
	server := activeVhost.Load()
	if server == nil {
		return nil
	}
	return server.sendFrame(frame)
}

type Adapter interface {
	HandleGuestFrame([]byte) error
	Config() []byte
}

type memoryRegion struct {
	base uint64
	user uint64
	data []byte
}

type virtQueue struct {
	mu        sync.Mutex
	size      uint16
	desc      uint64
	avail     uint64
	used      uint64
	kickFD    int
	callFD    int
	errFD     int
	nextAvail uint16
	nextUsed  uint16
	enabled   bool
	started   bool
}

type vhostServer struct {
	fd        int
	file      *os.File
	adapter   Adapter
	regions   []memoryRegion
	queues    [3]virtQueue
	features  uint64
	protocol  uint64
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

type Hooks struct {
	OnListening        func()
	OnConnectionChange func(bool)
}

func Serve(ctx context.Context, path string, adapter Adapter, hooks Hooks) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	if hooks.OnListening != nil {
		hooks.OnListening()
	}
	log.Printf("vhost-user listening on %s", path)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		file, err := connection.(*net.UnixConn).File()
		if err != nil {
			connection.Close()
			return err
		}
		connection.Close()
		serverContext, cancel := context.WithCancel(ctx)
		server := &vhostServer{
			fd:       int(file.Fd()),
			file:     file,
			adapter:  adapter,
			ctx:      serverContext,
			cancel:   cancel,
			protocol: vhostProtocolMQ | vhostProtocolReplyAck | vhostProtocolConfig,
		}
		for i := range server.queues {
			server.queues[i].kickFD = -1
			server.queues[i].callFD = -1
			server.queues[i].errFD = -1
		}
		activeVhost.Store(server)
		if hooks.OnConnectionChange != nil {
			hooks.OnConnectionChange(true)
		}
		log.Printf("vhost-user frontend connected")
		err = server.run()
		activeVhost.Store(nil)
		server.close()
		if hooks.OnConnectionChange != nil {
			hooks.OnConnectionChange(false)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("vhost-user session ended: %v", err)
		}
	}
}

func (s *vhostServer) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.file.Close()
		for i := range s.queues {
			for _, fd := range []*int{&s.queues[i].kickFD, &s.queues[i].callFD, &s.queues[i].errFD} {
				if *fd >= 0 {
					unix.Close(*fd)
					*fd = -1
				}
			}
		}
		for _, region := range s.regions {
			unix.Munmap(region.data)
		}
	})
}

func (s *vhostServer) run() error {
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

func (s *vhostServer) receive() (uint32, uint32, []byte, []int, error) {
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

func (s *vhostServer) reply(request uint32, body []byte) error {
	header := make([]byte, 12)
	binary.LittleEndian.PutUint32(header[0:4], request)
	binary.LittleEndian.PutUint32(header[4:8], 1|vhostFlagReply)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(body)))
	if err := writeAll(s.fd, header); err != nil {
		return err
	}
	return writeAll(s.fd, body)
}

func (s *vhostServer) ack(request, flags uint32) error {
	if flags&vhostFlagNeedReply == 0 {
		return nil
	}
	return s.reply(request, make([]byte, 8))
}

func (s *vhostServer) handle(request, flags uint32, body []byte, fds []int) error {
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
		s.queues[index].size = uint16(value)
		return s.ack(request, flags)
	case vhostSetVringAddr:
		if len(body) != 40 {
			return io.ErrUnexpectedEOF
		}
		index := binary.LittleEndian.Uint32(body[0:4])
		if int(index) >= len(s.queues) {
			return fmt.Errorf("invalid queue %d", index)
		}
		queue := &s.queues[index]
		var err error
		queue.desc, err = s.vmmToGPA(binary.LittleEndian.Uint64(body[8:16]))
		if err != nil {
			return err
		}
		queue.used, err = s.vmmToGPA(binary.LittleEndian.Uint64(body[16:24]))
		if err != nil {
			return err
		}
		queue.avail, err = s.vmmToGPA(binary.LittleEndian.Uint64(body[24:32]))
		if err != nil {
			return err
		}
		log.Printf("queue %d: size=%d desc=%#x avail=%#x used=%#x", index, queue.size, queue.desc, queue.avail, queue.used)
		return s.ack(request, flags)
	case vhostSetVringBase:
		index, value, err := parseVringState(body)
		if err != nil || index >= len(s.queues) {
			return fmt.Errorf("invalid queue base")
		}
		s.queues[index].nextAvail = uint16(value)
		s.queues[index].nextUsed = uint16(value)
		return s.ack(request, flags)
	case vhostGetVringBase:
		index, _, err := parseVringState(body)
		if err != nil || index >= len(s.queues) {
			return fmt.Errorf("invalid queue base")
		}
		reply := make([]byte, 8)
		binary.LittleEndian.PutUint32(reply[0:4], uint32(index))
		binary.LittleEndian.PutUint32(reply[4:8], uint32(s.queues[index].nextAvail))
		return s.reply(request, reply)
	case vhostSetVringKick, vhostSetVringCall, vhostSetVringErr:
		if len(body) != 8 {
			return io.ErrUnexpectedEOF
		}
		index := int(binary.LittleEndian.Uint64(body))
		if index >= len(s.queues) {
			return fmt.Errorf("invalid event queue %d", index)
		}
		fd := -1
		if len(fds) == 1 {
			fd = fds[0]
			fds = nil
		}
		queue := &s.queues[index]
		var destination *int
		switch request {
		case vhostSetVringKick:
			destination = &queue.kickFD
		case vhostSetVringCall:
			destination = &queue.callFD
		case vhostSetVringErr:
			destination = &queue.errFD
		}
		if *destination >= 0 {
			unix.Close(*destination)
		}
		*destination = fd
		log.Printf("queue %d request=%d fd=%d", index, request, fd)
		return s.ack(request, flags)
	case vhostSetVringEnable:
		index, value, err := parseVringState(body)
		if err != nil || index >= len(s.queues) || value > 1 {
			return fmt.Errorf("invalid queue enable")
		}
		queue := &s.queues[index]
		queue.mu.Lock()
		queue.enabled = value == 1
		start := queue.enabled && !queue.started && queue.kickFD >= 0 && queue.size > 0
		if start {
			queue.started = true
		}
		queue.mu.Unlock()
		if start {
			go s.queueLoop(index)
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
		config := s.adapter.Config()
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

func (s *vhostServer) replyU64(request uint32, value uint64) error {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint64(body, value)
	return s.reply(request, body)
}

func (s *vhostServer) setMemory(body []byte, fds []int) error {
	if len(body) < 8 {
		return io.ErrUnexpectedEOF
	}
	count := int(binary.LittleEndian.Uint32(body[0:4]))
	if count == 0 || count > 64 || len(body) != 8+32*count || len(fds) != count {
		return fmt.Errorf("invalid memory table: regions=%d fds=%d bytes=%d", count, len(fds), len(body))
	}
	regions := make([]memoryRegion, 0, count)
	for i := 0; i < count; i++ {
		entry := body[8+32*i : 8+32*(i+1)]
		base := binary.LittleEndian.Uint64(entry[0:8])
		size := binary.LittleEndian.Uint64(entry[8:16])
		user := binary.LittleEndian.Uint64(entry[16:24])
		offset := binary.LittleEndian.Uint64(entry[24:32])
		if size == 0 || size > 1<<34 {
			return fmt.Errorf("invalid memory region size %d", size)
		}
		page := int64(os.Getpagesize())
		aligned := int64(offset) &^ (page - 1)
		delta := int64(offset) - aligned
		mapped, err := unix.Mmap(fds[i], aligned, int(size)+int(delta), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			return err
		}
		regions = append(regions, memoryRegion{base: base, user: user, data: mapped[delta : delta+int64(size)]})
	}
	for _, region := range s.regions {
		unix.Munmap(region.data)
	}
	s.regions = regions
	return nil
}

func (s *vhostServer) vmmToGPA(address uint64) (uint64, error) {
	for _, region := range s.regions {
		if address >= region.user && address < region.user+uint64(len(region.data)) {
			return address - region.user + region.base, nil
		}
	}
	return 0, fmt.Errorf("VMM address %#x is not in the memory table", address)
}

func parseVringState(body []byte) (int, uint32, error) {
	if len(body) != 8 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return int(binary.LittleEndian.Uint32(body[0:4])), binary.LittleEndian.Uint32(body[4:8]), nil
}

func (s *vhostServer) readMemory(address uint64, size int) ([]byte, error) {
	result := make([]byte, size)
	for written := 0; written < size; {
		region, offset, err := s.locate(address + uint64(written))
		if err != nil {
			return nil, err
		}
		n := copy(result[written:], region.data[offset:])
		if n == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		written += n
	}
	return result, nil
}

func (s *vhostServer) writeMemory(address uint64, data []byte) error {
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

func (s *vhostServer) locate(address uint64) (*memoryRegion, int, error) {
	for i := range s.regions {
		region := &s.regions[i]
		if address >= region.base && address < region.base+uint64(len(region.data)) {
			return region, int(address - region.base), nil
		}
	}
	return nil, 0, fmt.Errorf("guest address %#x is unmapped", address)
}

func (s *vhostServer) read16(address uint64) (uint16, error) {
	data, err := s.readMemory(address, 2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data), nil
}

func (s *vhostServer) write16(address uint64, value uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, value)
	return s.writeMemory(address, data)
}

func (s *vhostServer) queueLoop(index int) {
	queue := &s.queues[index]
	for {
		queue.mu.Lock()
		fd := queue.kickFD
		enabled := queue.enabled
		queue.mu.Unlock()
		if !enabled || fd < 0 {
			return
		}
		_, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		buffer := make([]byte, 8)
		_, _ = unix.Read(fd, buffer)
		if index == 1 {
			queue.mu.Lock()
			if err := s.processTX(queue); err != nil {
				log.Printf("TX queue: %v", err)
			}
			queue.mu.Unlock()
		}
	}
}

type descriptor struct {
	address uint64
	length  uint32
	flags   uint16
	next    uint16
}

func (s *vhostServer) nextDescriptor(queue *virtQueue) (uint16, []descriptor, error) {
	available, err := s.read16(queue.avail + 2)
	if err != nil {
		return 0, nil, err
	}
	if available == queue.nextAvail {
		return 0, nil, nil
	}
	memoryBarrier()
	head, err := s.read16(queue.avail + 4 + 2*uint64(queue.nextAvail%queue.size))
	if err != nil {
		return 0, nil, err
	}
	if head >= queue.size {
		return 0, nil, fmt.Errorf("descriptor head out of range: head=%d size=%d avail=%#x desc=%#x next=%d published=%d", head, queue.size, queue.avail, queue.desc, queue.nextAvail, available)
	}
	index := head
	var chain []descriptor
	for range queue.size {
		if index >= queue.size {
			return 0, nil, fmt.Errorf("descriptor next out of range: head=%d next=%d size=%d desc=%#x", head, index, queue.size, queue.desc)
		}
		data, err := s.readMemory(queue.desc+16*uint64(index), 16)
		if err != nil {
			return 0, nil, err
		}
		item := descriptor{
			address: binary.LittleEndian.Uint64(data[0:8]),
			length:  binary.LittleEndian.Uint32(data[8:12]),
			flags:   binary.LittleEndian.Uint16(data[12:14]),
			next:    binary.LittleEndian.Uint16(data[14:16]),
		}
		chain = append(chain, item)
		if item.flags&descriptorNext == 0 {
			return head, chain, nil
		}
		index = item.next
	}
	return 0, nil, fmt.Errorf("descriptor chain is too long")
}

func (s *vhostServer) processTX(queue *virtQueue) error {
	for {
		head, chain, err := s.nextDescriptor(queue)
		if err != nil || chain == nil {
			return err
		}
		var packet []byte
		for _, item := range chain {
			if item.flags&descriptorWrite != 0 {
				return fmt.Errorf("TX descriptor is writable")
			}
			data, err := s.readMemory(item.address, int(item.length))
			if err != nil {
				return err
			}
			packet = append(packet, data...)
		}
		if len(packet) >= 12 {
			if err := s.adapter.HandleGuestFrame(packet[12:]); err != nil {
				return err
			}
		}
		s.finishDescriptor(queue, head, 0)
	}
}

func (s *vhostServer) sendFrame(frame []byte) error {
	queue := &s.queues[0]
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if !queue.enabled || queue.size == 0 {
		return nil
	}
	head, chain, err := s.nextDescriptor(queue)
	if err != nil || chain == nil {
		return err
	}
	packet := make([]byte, 12+len(frame))
	copy(packet[12:], frame)
	written := 0
	for _, item := range chain {
		if item.flags&descriptorWrite == 0 {
			return fmt.Errorf("RX descriptor is not writable")
		}
		if written == len(packet) {
			break
		}
		data := packet[written:]
		if len(data) > int(item.length) {
			data = data[:item.length]
		}
		if err := s.writeMemory(item.address, data); err != nil {
			return err
		}
		written += len(data)
	}
	if written != len(packet) {
		return fmt.Errorf("RX buffer too small: %d < %d", written, len(packet))
	}
	s.finishDescriptor(queue, head, uint32(written))
	return nil
}

func (s *vhostServer) finishDescriptor(queue *virtQueue, head uint16, length uint32) {
	entry := make([]byte, 8)
	binary.LittleEndian.PutUint32(entry[0:4], uint32(head))
	binary.LittleEndian.PutUint32(entry[4:8], length)
	_ = s.writeMemory(queue.used+4+8*uint64(queue.nextUsed%queue.size), entry)
	queue.nextUsed++
	queue.nextAvail++
	memoryBarrier()
	_ = s.write16(queue.used+2, queue.nextUsed)
	if queue.callFD >= 0 {
		event := make([]byte, 8)
		binary.LittleEndian.PutUint64(event, 1)
		_, _ = unix.Write(queue.callFD, event)
	}
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
