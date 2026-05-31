// Package tgfronts lists the Telegram web-front IPs (kwsN.web.telegram.org) that
// some ISPs block and that the Telegram proxies must therefore reach through the
// AWG2 tunnel. It is a tiny leaf package shared by two callers so the IP list
// lives in exactly one place:
//
//   - internal/services/tgws — the MTProto/SOCKS5 proxies dial these fronts for the
//     affected DCs, but ONLY while the AWG2 tunnel is up (else the normal fallback).
//   - internal/services/awgroute — the AWG2 client adds a route for each of these
//     IPs via awg0 while the tunnel is up, so the dial above actually tunnels.
//
// DC2/DC4 are served by an unblocked front (149.154.167.220) and are intentionally
// NOT listed here — they work directly without the VPN.
package tgfronts

// byDC maps the DCs whose real web-front (kwsN.web.telegram.org) is commonly
// ISP-blocked to that front IP. Verified live: DC1/DC3 share 149.154.174.100;
// DC5 (flora) is a different cluster, 149.154.170.100. Both are blocked on the
// bare WAN here and return HTTP 101 only through the AWG2 tunnel. DC2/DC4 use an
// unblocked front (149.154.167.220) and are intentionally absent.
var byDC = map[int]string{
	1: "149.154.174.100",
	3: "149.154.174.100",
	5: "149.154.170.100",
}

// FrontForDC returns the VPN-only front IP for a DC and whether one is known.
func FrontForDC(dc int) (string, bool) {
	ip, ok := byDC[dc]
	return ip, ok
}

// IPs returns the distinct front IPs to route through the tunnel (deduped).
func IPs() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(byDC))
	for _, ip := range byDC {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}
