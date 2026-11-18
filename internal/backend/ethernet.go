package backend

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeIPv6 = 0x86dd
)

var syntheticIPv4 = netip.MustParseAddr("169.254.254.1")
var syntheticIPv6 = netip.MustParseAddr("fe80::1")
var gatewayMAC = [6]byte{0x02, 0x54, 0x53, 0xff, 0xfe, 0x01}

type Adapter struct {
	device   *MemoryDevice
	guestMAC [6]byte
	send     func([]byte) error

	mu   sync.RWMutex
	ipv4 netip.Addr
	ipv6 netip.Addr
}

func NewAdapter(device *MemoryDevice, hostname string, send func([]byte) error) *Adapter {
	digest := sha256.Sum256([]byte(hostname))
	mac := [6]byte{0x02, 0x54, 0x53, digest[0], digest[1], digest[2]}
	return &Adapter{device: device, guestMAC: mac, send: send}
}

func (a *Adapter) SetAddresses(ipv4, ipv6 netip.Addr) {
	a.mu.Lock()
	a.ipv4 = ipv4
	a.ipv6 = ipv6
	a.mu.Unlock()
}

func (a *Adapter) SetSendFunc(send func([]byte) error) {
	a.send = send
}

func (a *Adapter) addresses() (netip.Addr, netip.Addr) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ipv4, a.ipv6
}

func (a *Adapter) RunInbound() error {
	for {
		select {
		case <-a.device.done:
			return nil
		case packet := <-a.device.inbound:
			ipv4, ipv6 := a.addresses()
			if len(packet) == 0 {
				continue
			}
			version := packet[0] >> 4
			if version == 4 && (len(packet) < 20 || netip.AddrFrom4([4]byte(packet[16:20])) != ipv4) {
				continue
			}
			if version == 6 && (len(packet) < 40 || netip.AddrFrom16([16]byte(packet[24:40])) != ipv6) {
				continue
			}
			if version != 4 && version != 6 {
				continue
			}
			frame := make([]byte, 14+len(packet))
			copy(frame[0:6], a.guestMAC[:])
			copy(frame[6:12], gatewayMAC[:])
			if version == 4 {
				binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
			} else {
				binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)
			}
			copy(frame[14:], packet)
			if err := a.send(frame); err != nil {
				return err
			}
		}
	}
}

func (a *Adapter) HandleGuestFrame(frame []byte) error {
	if len(frame) < 14 {
		return nil
	}
	debugPacket("guest-tx", frame)
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case etherTypeARP:
		return a.handleARP(frame)
	case etherTypeIPv6:
		if a.handleNDP(frame) {
			return nil
		}
	case etherTypeIPv4:
	default:
		return nil
	}
	ipv4, ipv6 := a.addresses()
	packet := frame[14:]
	if len(packet) == 0 {
		return nil
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || !ipv4.IsValid() || netip.AddrFrom4([4]byte(packet[12:16])) != ipv4 {
			return nil
		}
	case 6:
		if len(packet) < 40 || !ipv6.IsValid() || netip.AddrFrom16([16]byte(packet[8:24])) != ipv6 {
			return nil
		}
	default:
		return nil
	}
	select {
	case <-a.device.done:
		return nil
	case a.device.outbound <- append([]byte(nil), packet...):
		return nil
	}
}

func (a *Adapter) handleARP(frame []byte) error {
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[14:16]) != 1 ||
		binary.BigEndian.Uint16(frame[16:18]) != 0x0800 || frame[18] != 6 || frame[19] != 4 ||
		binary.BigEndian.Uint16(frame[20:22]) != 1 {
		return nil
	}
	ipv4, _ := a.addresses()
	if !ipv4.IsValid() || netip.AddrFrom4([4]byte(frame[38:42])) != syntheticIPv4 {
		return nil
	}
	reply := make([]byte, 42)
	copy(reply[0:6], a.guestMAC[:])
	copy(reply[6:12], gatewayMAC[:])
	binary.BigEndian.PutUint16(reply[12:14], etherTypeARP)
	copy(reply[14:22], frame[14:22])
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], gatewayMAC[:])
	copy(reply[28:32], syntheticIPv4.AsSlice())
	copy(reply[32:38], frame[22:28])
	copy(reply[38:42], frame[28:32])
	return a.send(reply)
}

func (a *Adapter) handleNDP(frame []byte) bool {
	if len(frame) < 78 || frame[14]>>4 != 6 || frame[20] != 58 || frame[54] != 135 || frame[55] != 0 {
		return false
	}
	if netip.AddrFrom16([16]byte(frame[62:78])) != syntheticIPv6 {
		return false
	}
	source := netip.AddrFrom16([16]byte(frame[22:38]))
	_, ipv6 := a.addresses()
	if !ipv6.IsValid() || (!source.IsUnspecified() && source != ipv6) {
		return true
	}
	packet := make([]byte, 72)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 32)
	packet[6] = 58
	packet[7] = 255
	copy(packet[8:24], syntheticIPv6.AsSlice())
	if source.IsUnspecified() {
		copy(packet[24:40], ipv6.AsSlice())
	} else {
		copy(packet[24:40], source.AsSlice())
	}
	packet[40] = 136
	binary.BigEndian.PutUint32(packet[44:48], 0x60000000)
	copy(packet[48:64], syntheticIPv6.AsSlice())
	packet[64] = 2
	packet[65] = 1
	copy(packet[66:72], gatewayMAC[:])
	binary.BigEndian.PutUint16(packet[42:44], 0)
	checksum := internetChecksum(append(ndpPseudoHeader(packet), packet[40:]...))
	binary.BigEndian.PutUint16(packet[42:44], checksum)
	response := make([]byte, 14+len(packet))
	copy(response[0:6], a.guestMAC[:])
	copy(response[6:12], gatewayMAC[:])
	binary.BigEndian.PutUint16(response[12:14], etherTypeIPv6)
	copy(response[14:], packet)
	_ = a.send(response)
	return true
}

func ndpPseudoHeader(packet []byte) []byte {
	header := make([]byte, 40)
	copy(header[0:16], packet[8:24])
	copy(header[16:32], packet[24:40])
	binary.BigEndian.PutUint32(header[32:36], uint32(len(packet)-40))
	header[39] = 58
	return header
}

func internetChecksum(data []byte) uint16 {
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (a *Adapter) Config() []byte {
	config := make([]byte, 12)
	copy(config[0:6], a.guestMAC[:])
	binary.LittleEndian.PutUint16(config[6:8], 1)
	binary.LittleEndian.PutUint16(config[8:10], 1)
	binary.LittleEndian.PutUint16(config[10:12], uint16(a.device.mtu))
	return config
}

func (a *Adapter) MACString() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a.guestMAC[0], a.guestMAC[1], a.guestMAC[2], a.guestMAC[3], a.guestMAC[4], a.guestMAC[5])
}
