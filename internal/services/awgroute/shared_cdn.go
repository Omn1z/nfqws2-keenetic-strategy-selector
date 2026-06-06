package awgroute

import (
	"fmt"
	"net/netip"
	"sync"

	"nfqws2strategy/internal/tools/logbuf"
)

// Domain-based split routing eventually becomes IP routing. Shared CDN edge
// addresses are unsafe to learn from one matched hostname because the same IP can
// serve unrelated hostnames; adding such an IP to an ipset would route/bypass all
// those neighbours too. Keep explicit user-entered IP/CIDR rules untouched.
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

func (svc *Service) awgNoteSharedCDNSkip(source, name, ip, provider string) {
	key := source + "|" + provider + "|" + ip
	if _, loaded := svc.route.sharedCDNSkips.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	suffix := ""
	if name != "" {
		suffix = " for " + name
	}
	logbuf.Append("awg2", "warn", fmt.Sprintf("%s: skipped learned %s IP %s%s to avoid routing unrelated shared-CDN sites", source, provider, ip, suffix))
}
