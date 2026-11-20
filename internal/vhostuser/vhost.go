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

	vringAvailFNoInterrupt = 1
	vringUsedFNoNotify     = 1
	virtioNetHdrSize       = 12
)

// TXAction controls whether DrainTX consumes the current descriptor or leaves
// it in the virtqueue for the next call.
type TXAction int

const (
	TXConsume TXAction = iota
	TXStop
)

type Hooks struct {
	OnListening        func()
	OnConnectionChange func(bool)
}

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

// Endpoint serves vhost-user connections sequentially and exposes direct,
// batched TX/RX virtqueue access to the tunnel device.
type Endpoint struct {
	configFn func() []byte
	wakeFD   int

	mu      sync.Mutex
	active  *vhostSession
	drainWG sync.WaitGroup
	closed  atomic.Bool
	close   sync.Once
}

func NewEndpoint(configFn func() []byte) (*Endpoint, error) {
	fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		configFn: configFn,
		wakeFD:   fd,
	}, nil
}

func (e *Endpoint) Close() error {
	e.close.Do(func() {
		e.mu.Lock()
		e.closed.Store(true)
		var one [8]byte
		binary.LittleEndian.PutUint64(one[:], 1)
		_, _ = unix.Write(e.wakeFD, one[:])
		e.mu.Unlock()
		e.drainWG.Wait()
		unix.Close(e.wakeFD)
	})
	return nil
}

func (e *Endpoint) signalWake() {
	e.mu.Lock()
	if !e.closed.Load() {
		var one [8]byte
		binary.LittleEndian.PutUint64(one[:], 1)
		_, _ = unix.Write(e.wakeFD, one[:])
	}
	e.mu.Unlock()
}

func (e *Endpoint) drainWake() {
	var buf [8]byte
	_, _ = unix.Read(e.wakeFD, buf[:])
}

func (e *Endpoint) setSession(s *vhostSession) {
	e.mu.Lock()
	e.active = s
	e.mu.Unlock()
	e.signalWake()
}

func (e *Endpoint) clearSession(s *vhostSession) {
	e.mu.Lock()
	if e.active == s {
		e.active = nil
	}
	s.closing.Store(true)
	e.mu.Unlock()
	e.signalWake()
	s.wg.Wait()
}

func (e *Endpoint) acquireSession() *vhostSession {
	e.mu.Lock()
	s := e.active
	if s != nil && !s.closing.Load() {
		s.wg.Add(1)
	} else {
		s = nil
	}
	e.mu.Unlock()
	return s
}

func (e *Endpoint) Serve(ctx context.Context, path string, hooks Hooks) error {
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
		session := &vhostSession{
			endpoint: e,
			fd:       int(file.Fd()),
			file:     file,
			ctx:      ctx,
			protocol: vhostProtocolMQ | vhostProtocolReplyAck | vhostProtocolConfig,
		}
		for i := range session.queues {
			session.queues[i].kickFD = -1
			session.queues[i].callFD = -1
			session.queues[i].errFD = -1
		}
		e.setSession(session)
		if hooks.OnConnectionChange != nil {
			hooks.OnConnectionChange(true)
		}
		log.Printf("vhost-user frontend connected")
		err = session.run()
		e.clearSession(session)
		session.close()
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

// DrainTX waits for available TX descriptors from the guest and passes each
// Ethernet frame (with the 12-byte virtio-net header stripped) to handle.
// It batches used-ring publication and guest IRQ notification once per call.
func (e *Endpoint) DrainTX(handle func(frame []byte) (TXAction, []byte)) error {
	e.mu.Lock()
	if e.closed.Load() {
		e.mu.Unlock()
		return os.ErrClosed
	}
	e.drainWG.Add(1)
	e.mu.Unlock()
	defer e.drainWG.Done()

	var pollFDs [2]unix.PollFd
	var eventBuf [8]byte
	var replies [][]byte

	for {
		if e.closed.Load() {
			return os.ErrClosed
		}
		s := e.acquireSession()
		if s == nil {
			pollFDs[0] = unix.PollFd{Fd: int32(e.wakeFD), Events: unix.POLLIN}
			if _, err := unix.Poll(pollFDs[:1], -1); err != nil && err != unix.EINTR {
				return err
			}
			e.drainWake()
			continue
		}

		q := &s.queues[1]
		q.mu.Lock()
		ready := q.enabled && q.size > 0 && q.ready()
		kickFD := q.kickFD
		if !ready {
			q.mu.Unlock()
			s.wg.Done()
			pollFDs[0] = unix.PollFd{Fd: int32(e.wakeFD), Events: unix.POLLIN}
			if _, err := unix.Poll(pollFDs[:1], -1); err != nil && err != unix.EINTR {
				return err
			}
			e.drainWake()
			continue
		}

		availIdx := q.availIdx()
		if availIdx == q.nextAvail {
			q.mu.Unlock()
			nPoll := 1
			pollFDs[0] = unix.PollFd{Fd: int32(e.wakeFD), Events: unix.POLLIN}
			if kickFD >= 0 {
				pollFDs[1] = unix.PollFd{Fd: int32(kickFD), Events: unix.POLLIN}
				nPoll = 2
			}
			_, err := unix.Poll(pollFDs[:nPoll], -1)
			if err == nil {
				if pollFDs[0].Revents&unix.POLLIN != 0 {
					e.drainWake()
				}
				if nPoll == 2 && pollFDs[1].Revents&unix.POLLIN != 0 {
					_, _ = unix.Read(kickFD, eventBuf[:])
				}
			}
			s.wg.Done()
			if err != nil && err != unix.EINTR {
				return err
			}
			continue
		}

		memoryBarrier()
		completed := 0
		var txErr error
		replies = replies[:0]
		for q.nextAvail != availIdx {
			head := q.availEntry(q.nextAvail)
			if head >= q.size {
				txErr = fmt.Errorf("TX descriptor head out of range: head=%d size=%d", head, q.size)
				log.Printf("TX queue: %v", txErr)
				break
			}
			frame, err := s.readTXFrame(q, head)
			if err != nil {
				txErr = err
				log.Printf("TX queue: %v", err)
				break
			}
			if frame != nil {
				action, reply := handle(frame)
				if action == TXStop {
					break
				}
				if len(reply) >= 14 {
					replies = append(replies, reply)
				}
			}
			q.writeUsedEntry(q.nextUsed, uint32(head), 0)
			q.nextAvail++
			q.nextUsed++
			completed++
		}
		if completed > 0 {
			q.publishUsed(&eventBuf)
		}
		q.mu.Unlock()

		for _, reply := range replies {
			s.writeRXBatch(1, func(int) ([14]byte, []byte, bool) {
				return [14]byte(reply[:14]), reply[14:], true
			})
		}
		s.wg.Done()
		if completed == 0 && txErr != nil {
			return txErr
		}
		return nil
	}
}

// WriteRX writes up to n frames directly into the guest's RX virtqueue,
// publishing used.idx and signaling callFD at most once for the batch.
func (e *Endpoint) WriteRX(n int, get func(i int) (ethHdr [14]byte, payload []byte, ok bool)) {
	if n <= 0 {
		return
	}
	s := e.acquireSession()
	if s == nil {
		return
	}
	s.writeRXBatch(n, get)
	s.wg.Done()
}

type vhostSession struct {
	endpoint   *Endpoint
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
		config := s.endpoint.configFn()
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

func (s *vhostSession) replyU64(request uint32, value uint64) error {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint64(body, value)
	return s.reply(request, body)
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

func (s *vhostSession) guestSlice(address uint64, length int) ([]byte, bool) {
	if length < 0 {
		return nil, false
	}
	for i := range s.regions {
		region := &s.regions[i]
		if address >= region.base && address < region.base+uint64(len(region.data)) {
			offset := int(address - region.base)
			if offset+length <= len(region.data) {
				return region.data[offset : offset+length], true
			}
			return nil, false
		}
	}
	return nil, false
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

func (q *virtQueue) publishUsed(eventBuf *[8]byte) {
	memoryBarrier()
	binary.LittleEndian.PutUint16(q.usedMem[2:4], q.nextUsed)
	memoryBarrier()
	if q.callFD >= 0 && q.availFlags()&vringAvailFNoInterrupt == 0 {
		binary.LittleEndian.PutUint64(eventBuf[:], 1)
		_, _ = unix.Write(q.callFD, eventBuf[:])
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
	var eventBuf [8]byte
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
		q.publishUsed(&eventBuf)
	}
}

func (s *vhostSession) writeRXDescriptor(q *virtQueue, head uint16, vnetHdr, ethHdr, payload []byte) (int, error) {
	total := len(vnetHdr) + len(ethHdr) + len(payload)
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
