package awgroute

import "sync"

// sniSniffer passively reads TLS ClientHellos off the LAN bridges and calls onHello
// with each (destination IP, SNI). SNI-routing uses it to learn which server IPs a
// matched domain currently lives on and route those IPs through the tunnel — which
// works even when the device uses encrypted DNS (DoH/DoT) or the site is behind a
// CDN with rotating IPs (DNS-based matching can't catch either).
//
// The packet capture is Linux-only (AF_PACKET, in snisniff_linux.go); on other OSes
// start() is a no-op (snisniff_other.go). The struct itself is portable so the
// awgRouteState field compiles everywhere.
type sniSniffer struct {
	mu      sync.Mutex
	fds     []int
	stopCh  chan struct{}
	running bool
	onHello func(dstIP, sni string)
}

func newSNISniffer(onHello func(dstIP, sni string)) *sniSniffer {
	return &sniSniffer{onHello: onHello}
}
