package awgroute

import (
	"net/netip"
	"sync"
)

// Domain-based split routing eventually becomes IP routing. Shared CDN edge
// addresses can serve unrelated hostnames. A direct exception must not silently
// bypass VPN for all those neighbours. An explicit tunnel rule, however, must
// route the requested destination even when it shares a CDN edge. This remains
// IP routing: other names on that exact address may follow the same rule.
// Keep explicit user-entered IP/CIDR rules untouched.
//
// Cloudflare publishes the current ranges at:
// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
type sharedCDNPrefix struct {
	provider string
	prefix   netip.Prefix
}

var sharedCDNPrefixSource = []struct {
	provider string
	cidr     string
}{
	{"Cloudflare", "173.245.48.0/20"},
	{"Cloudflare", "103.21.244.0/22"},
	{"Cloudflare", "103.22.200.0/22"},
	{"Cloudflare", "103.31.4.0/22"},
	{"Cloudflare", "141.101.64.0/18"},
	{"Cloudflare", "108.162.192.0/18"},
	{"Cloudflare", "190.93.240.0/20"},
	{"Cloudflare", "188.114.96.0/20"},
	{"Cloudflare", "197.234.240.0/22"},
	{"Cloudflare", "198.41.128.0/17"},
	{"Cloudflare", "162.158.0.0/15"},
	{"Cloudflare", "104.16.0.0/13"},
	{"Cloudflare", "104.24.0.0/14"},
	{"Cloudflare", "172.64.0.0/13"},
	{"Cloudflare", "131.0.72.0/22"},
	{"Cloudflare", "8.47.69.0/24"},
	{"Cloudflare", "8.6.112.0/24"},
	{"Cloudflare", "2400:cb00::/32"},
	{"Cloudflare", "2606:4700::/32"},
	{"Cloudflare", "2803:f800::/32"},
	{"Cloudflare", "2405:b500::/32"},
	{"Cloudflare", "2405:8100::/32"},
	{"Cloudflare", "2a06:98c0::/29"},
	{"Cloudflare", "2c0f:f248::/32"},
}

var (
	sharedCDNOnce     sync.Once
	sharedCDNPrefixes []sharedCDNPrefix
)

func sharedCDNProvider(ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	sharedCDNOnce.Do(func() {
		for _, src := range sharedCDNPrefixSource {
			p, err := netip.ParsePrefix(src.cidr)
			if err == nil {
				sharedCDNPrefixes = append(sharedCDNPrefixes, sharedCDNPrefix{provider: src.provider, prefix: p.Masked()})
			}
		}
	})
	for _, p := range sharedCDNPrefixes {
		if p.prefix.Contains(addr) {
			return p.provider, true
		}
	}
	return "", false
}

// skipSharedCDNDomainIP applies only to domain-derived destinations. A tunnel
// selection must not turn into an unmarked/direct flow because its answer is a
// CDN address. Preserve the shared-address guard for LAN-wide direct exceptions;
// source-bound rules already limit their effect to explicitly selected devices.
// The common tunnel path avoids a prefix lookup entirely.
func skipSharedCDNDomainIP(route string, sourceBound bool, ip string) bool {
	if route != "direct" || sourceBound {
		return false
	}
	_, shared := sharedCDNProvider(ip)
	return shared
}

// awgNoteSharedCDNSkip deduplicates guarded direct exceptions without creating a
// log entry for every CDN answer. The routing trace reports the skipped address.
func (svc *Service) awgNoteSharedCDNSkip(source, ip string) {
	svc.route.sharedCDNSkips.LoadOrStore(source+"|"+ip, struct{}{})
}
