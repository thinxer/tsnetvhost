package backend

import (
	"log"
	"sync"
	"sync/atomic"
)

var packetDebugCounters sync.Map
var debugEnabled atomic.Bool

func SetDebug(enabled bool) {
	debugEnabled.Store(enabled)
}

func debugPacket(prefix string, packet []byte) {
	if !debugEnabled.Load() {
		return
	}
	value, _ := packetDebugCounters.LoadOrStore(prefix, &atomic.Uint64{})
	count := value.(*atomic.Uint64).Add(1)
	if count > 200 {
		return
	}
	length := len(packet)
	if length > 48 {
		length = 48
	}
	log.Printf("%s packet=%d len=%d data=%x", prefix, count, len(packet), packet[:length])
}
