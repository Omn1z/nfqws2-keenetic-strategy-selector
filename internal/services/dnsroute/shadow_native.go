package dnsroute

import (
	"net"
	"time"
)

// The reader owns its packet socket and never acquires adapter locks. Only
// discovery consumes these snapshots, under discoveryMu, after WAN validation.
type shadowNativeReader interface {
	snapshot() shadowNativeSnapshot
	close()
}

type shadowNativeSnapshot struct {
	started           time.Time
	sequence          uint64
	requests, replies uint64
	observation       shadowNativeDHCPObservation
	observedAt        time.Time
	err               error
	closed            bool
}

type shadowNativeState struct {
	reader                       shadowNativeReader
	key, iface, device, identity string
	client                       net.IP
	applied                      uint64
	inspected, withdrawn         uint64
}

func (s *shadowNativeState) changed() bool {
	return s.reader != nil && s.reader.snapshot().sequence != s.applied
}

func (s *shadowNativeState) stop() {
	if s.reader != nil {
		s.reader.close()
	}
	*s = shadowNativeState{}
}

func (a *Adapter) closeShadowNative() {
	a.shadow.discoveryMu.Lock()
	defer a.shadow.discoveryMu.Unlock()
	a.shadow.native.stop()
}
