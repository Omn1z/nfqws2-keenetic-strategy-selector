package dnsserver

import (
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

func dnsAgeMessage(msg *mdns.Msg, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	age := uint32(elapsed / time.Second)
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == mdns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > age {
				rr.Header().Ttl -= age
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
}

func dnsClipNegativeSOA(msg *mdns.Msg) {
	if _, negative := dnsCacheLifetime(msg, ^uint32(0)); !negative {
		return
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*mdns.SOA); ok && soa.Hdr.Ttl > soa.Minttl {
			soa.Hdr.Ttl = soa.Minttl
		}
	}
}

// Negative answers require the authority's SOA proof and lifetime. This also
// handles a CNAME chain ending in NODATA: its nonempty Answer is not a positive
// answer for the requested type. Never manufacture a TTL for missing proof.
// RFC 2308 sections 3 and 5: min(SOA TTL, SOA MINIMUM), then normal aging.
func dnsCacheLifetime(msg *mdns.Msg, maximum uint32) (ttl uint32, negative bool) {
	if msg == nil || len(msg.Question) != 1 || msg.Truncated || msg.Rcode != mdns.RcodeSuccess && msg.Rcode != mdns.RcodeNameError {
		return 0, false
	}
	question := msg.Question[0]
	owner, valid := dnsCacheTerminalName(msg, question.Name, question.Qclass)
	if !valid {
		return 0, false
	}
	positive := false
	for _, rr := range msg.Answer {
		if rr.Header().Class == question.Qclass && (strings.EqualFold(rr.Header().Name, question.Name) || strings.EqualFold(rr.Header().Name, owner)) && (rr.Header().Rrtype == question.Qtype || question.Qtype == mdns.TypeANY && rr.Header().Rrtype != mdns.TypeRRSIG) {
			positive = true
			break
		}
	}
	negative = msg.Rcode == mdns.RcodeNameError || !positive
	ttl = maximum
	if negative {
		found := false
		for _, rr := range msg.Ns {
			soa, ok := rr.(*mdns.SOA)
			if !ok || soa.Hdr.Class != question.Qclass || !mdns.IsSubDomain(strings.ToLower(soa.Hdr.Name), owner) {
				continue
			}
			found = true
			if soa.Hdr.Ttl < ttl {
				ttl = soa.Hdr.Ttl
			}
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
		}
		if !found {
			return 0, true
		}
	}
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != mdns.TypeOPT && rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	return ttl, negative
}

func dnsCacheTerminalName(msg *mdns.Msg, question string, class uint16) (string, bool) {
	owner := strings.ToLower(mdns.Fqdn(question))
	seen := map[string]bool{}
	for depth := 0; depth < 16; depth++ {
		if seen[owner] {
			return "", false
		}
		seen[owner] = true
		next := ""
		for _, rr := range msg.Answer {
			if cname, ok := rr.(*mdns.CNAME); ok && cname.Hdr.Class == class && strings.EqualFold(cname.Hdr.Name, owner) {
				next = strings.ToLower(mdns.Fqdn(cname.Target))
				break
			}
		}
		if next == "" {
			return owner, true
		}
		owner = next
	}
	return "", false
}
