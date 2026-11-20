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

// Endpoint serves vhost-user connections sequentially and exposes direct,
// batched TX/RX virtqueue access to the tunnel device.
type Endpoint struct {
	wakeFD int

	mu      sync.Mutex
	active  *vhostSession
	drainWG sync.WaitGroup
	closed  atomic.Bool
	close   sync.Once
}

func NewEndpoint() (*Endpoint, error) {
	fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &Endpoint{wakeFD: fd}, nil
}

func (e *Endpoint) Close() error {
	e.close.Do(func() {
		e.mu.Lock()
		e.closed.Store(true)
		signalEventFD(e.wakeFD)
		e.mu.Unlock()
		e.drainWG.Wait()
		unix.Close(e.wakeFD)
	})
	return nil
}

func (e *Endpoint) signalWakeLocked() {
	if !e.closed.Load() {
		signalEventFD(e.wakeFD)
	}
}

func (e *Endpoint) signalWake() {
	e.mu.Lock()
	e.signalWakeLocked()
	e.mu.Unlock()
}

func (e *Endpoint) setSession(s *vhostSession) {
	e.mu.Lock()
	e.active = s
	e.signalWakeLocked()
	e.mu.Unlock()
}

func (e *Endpoint) clearSession(s *vhostSession) {
	e.mu.Lock()
	if e.active == s {
		e.active = nil
	}
	s.closing.Store(true)
	e.signalWakeLocked()
	e.mu.Unlock()
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

func (e *Endpoint) waitWake(kickFD int, eventBuf *[8]byte) error {
	var pollFDs [2]unix.PollFd
	pollFDs[0] = unix.PollFd{Fd: int32(e.wakeFD), Events: unix.POLLIN}
	nPoll := 1
	if kickFD >= 0 {
		pollFDs[1] = unix.PollFd{Fd: int32(kickFD), Events: unix.POLLIN}
		nPoll = 2
	}
	_, err := unix.Poll(pollFDs[:nPoll], -1)
	if err != nil {
		if err == unix.EINTR {
			return nil
		}
		return err
	}
	if pollFDs[0].Revents&unix.POLLIN != 0 {
		_, _ = unix.Read(e.wakeFD, eventBuf[:])
	}
	if nPoll == 2 && pollFDs[1].Revents&unix.POLLIN != 0 {
		_, _ = unix.Read(kickFD, eventBuf[:])
	}
	return nil
}

func (e *Endpoint) Serve(ctx context.Context, path string, configFn func() []byte, hooks Hooks) error {
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
			configFn: configFn,
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

	var eventBuf [8]byte
	var replies [][]byte

	for {
		if e.closed.Load() {
			return os.ErrClosed
		}
		s := e.acquireSession()
		if s == nil {
			if err := e.waitWake(-1, &eventBuf); err != nil {
				return err
			}
			continue
		}

		q := &s.queues[1]
		q.mu.Lock()
		if !q.enabled || q.size == 0 || !q.ready() {
			q.mu.Unlock()
			s.wg.Done()
			if err := e.waitWake(-1, &eventBuf); err != nil {
				return err
			}
			continue
		}

		availIdx := q.availIdx()
		if availIdx == q.nextAvail {
			kickFD := q.kickFD
			q.mu.Unlock()
			err := e.waitWake(kickFD, &eventBuf)
			s.wg.Done()
			if err != nil {
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
			q.publishUsed()
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

func signalEventFD(fd int) {
	var one [8]byte
	binary.LittleEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(fd, one[:])
}
