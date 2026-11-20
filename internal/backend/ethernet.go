package backend

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeIPv6 = 0x86dd
)

var syntheticIPv4 = netip.MustParseAddr("169.254.254.1")
var syntheticIPv6 = netip.MustParseAddr("fe80::1")
var syntheticIPv4Bytes = syntheticIPv4.As4()
var syntheticIPv6Bytes = syntheticIPv6.As16()
var gatewayMAC = [6]byte{0x02, 0x54, 0x53, 0xff, 0xfe, 0x01}

func (d *Device) frameInbound(packet []byte, st *addrState) (ethHdr [14]byte, payload []byte, ok bool) {
	if st == nil || len(packet) == 0 {
		return ethHdr, nil, false
	}
	var etherType uint16
	switch packet[0] >> 4 {
	case 4:
		if !st.has4 || len(packet) < 20 || [4]byte(packet[16:20]) != st.ipv4 {
			return ethHdr, nil, false
		}
		etherType = etherTypeIPv4
	case 6:
		if !st.has6 || len(packet) < 40 || [16]byte(packet[24:40]) != st.ipv6 {
			return ethHdr, nil, false
		}
		etherType = etherTypeIPv6
	default:
		return ethHdr, nil, false
	}
	copy(ethHdr[0:6], d.guestMAC[:])
	copy(ethHdr[6:12], gatewayMAC[:])
	binary.BigEndian.PutUint16(ethHdr[12:14], etherType)
	return ethHdr, packet, true
}

func (d *Device) decodeGuestFrame(frame []byte, dst []byte) (n int, reply []byte, fit bool) {
	if len(frame) < 14 {
		return 0, nil, true
	}
	debugPacket("guest-tx", frame)
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case etherTypeARP:
		return 0, d.handleARP(frame), true
	case etherTypeIPv6:
		if reply, handled := d.handleNDP(frame); handled {
			return 0, reply, true
		}
	case etherTypeIPv4:
	default:
		return 0, nil, true
	}
	packet := frame[14:]
	if len(packet) == 0 {
		return 0, nil, true
	}
	st := d.addrs.Load()
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || !st.has4 || [4]byte(packet[12:16]) != st.ipv4 {
			return 0, nil, true
		}
	case 6:
		if len(packet) < 40 || !st.has6 || [16]byte(packet[8:24]) != st.ipv6 {
			return 0, nil, true
		}
	default:
		return 0, nil, true
	}
	if len(packet) > len(dst) {
		return 0, nil, false
	}
	copy(dst, packet)
	debugPacket("tsnet-read", packet)
	return len(packet), nil, true
}

func (d *Device) handleARP(frame []byte) []byte {
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[14:16]) != 1 ||
		binary.BigEndian.Uint16(frame[16:18]) != 0x0800 || frame[18] != 6 || frame[19] != 4 ||
		binary.BigEndian.Uint16(frame[20:22]) != 1 {
		return nil
	}
	st := d.addrs.Load()
	if !st.has4 || [4]byte(frame[38:42]) != syntheticIPv4Bytes {
		return nil
	}
	reply := make([]byte, 42)
	copy(reply[0:6], d.guestMAC[:])
	copy(reply[6:12], gatewayMAC[:])
	binary.BigEndian.PutUint16(reply[12:14], etherTypeARP)
	copy(reply[14:22], frame[14:22])
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], gatewayMAC[:])
	copy(reply[28:32], syntheticIPv4Bytes[:])
	copy(reply[32:38], frame[22:28])
	copy(reply[38:42], frame[28:32])
	return reply
}

func (d *Device) handleNDP(frame []byte) ([]byte, bool) {
	if len(frame) < 78 || frame[14]>>4 != 6 || frame[20] != 58 || frame[54] != 135 || frame[55] != 0 {
		return nil, false
	}
	if [16]byte(frame[62:78]) != syntheticIPv6Bytes {
		return nil, false
	}
	source := [16]byte(frame[22:38])
	st := d.addrs.Load()
	var zero16 [16]byte
	if !st.has6 || (source != zero16 && source != st.ipv6) {
		return nil, true
	}
	packet := make([]byte, 72)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 32)
	packet[6] = 58
	packet[7] = 255
	copy(packet[8:24], syntheticIPv6Bytes[:])
	if source == zero16 {
		copy(packet[24:40], st.ipv6[:])
	} else {
		copy(packet[24:40], source[:])
	}
	packet[40] = 136
	binary.BigEndian.PutUint32(packet[44:48], 0x60000000)
	copy(packet[48:64], syntheticIPv6Bytes[:])
	packet[64] = 2
	packet[65] = 1
	copy(packet[66:72], gatewayMAC[:])
	binary.BigEndian.PutUint16(packet[42:44], 0)
	checksum := internetChecksum(append(ndpPseudoHeader(packet), packet[40:]...))
	binary.BigEndian.PutUint16(packet[42:44], checksum)
	response := make([]byte, 14+len(packet))
	copy(response[0:6], d.guestMAC[:])
	copy(response[6:12], gatewayMAC[:])
	binary.BigEndian.PutUint16(response[12:14], etherTypeIPv6)
	copy(response[14:], packet)
	return response, true
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

func (d *Device) Config() []byte {
	config := make([]byte, 12)
	copy(config[0:6], d.guestMAC[:])
	binary.LittleEndian.PutUint16(config[6:8], 1)
	binary.LittleEndian.PutUint16(config[8:10], 1)
	binary.LittleEndian.PutUint16(config[10:12], uint16(d.mtu))
	return config
}

func (d *Device) MACString() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", d.guestMAC[0], d.guestMAC[1], d.guestMAC[2], d.guestMAC[3], d.guestMAC[4], d.guestMAC[5])
}
