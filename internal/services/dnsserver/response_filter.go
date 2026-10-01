package dnsserver

import (
	"net"
	"strings"

	mdns "github.com/miekg/dns"
)

func (out *Outcome) setBlocked(domain string, match BlockMatch) {
	out.Blocked, out.Cached = true, false
	out.BlockCategory, out.BlockRule, out.BlockSource = match.Category, match.Rule, match.Source
	out.BlockDomain, out.Route, out.Upstream = domain, "blocked", ""
}

// filterResponse checks only records reachable from the original question in
// the answer section. Additional records and unrelated owners must not cause a
// valid answer to be blocked. The visited set bounds cycles and duplicate RRs.
// Both network and cached answers pass through the current policy here.
func (r *Resolver) filterResponse(q, response *mdns.Msg, out *Outcome) bool {
	blocker := r.blocker.Load()
	if blocker == nil || len(q.Question) != 1 {
		return false
	}
	domain, qtype := out.Domain, q.Question[0].Qtype
	// A download or settings change may have finished while DNS was in flight.
	match, blocked, allowed := blocker.evaluateDNS(domain, qtype, false)
	if blocked {
		out.setBlocked(domain, match)
		return true
	}
	// An original-question exception permits its complete answer. Its DNS type
	// remains the question type even when the answer contains aliases or IPs.
	if len(response.Answer) == 0 || allowed {
		return false
	}
	byOwner := make(map[string][]mdns.RR, len(response.Answer))
	for _, rr := range response.Answer {
		owner := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")
		byOwner[owner] = append(byOwner[owner], rr)
	}
	visited := map[string]bool{domain: true}
	queue := []string{domain}
	check := func(target string, rrtype uint16) bool {
		if match, blocked := blocker.matchDNS(target, rrtype, true); blocked {
			out.setBlocked(target, match)
			return true
		}
		return false
	}
	checkIPs := func(ips []net.IP, rrtype uint16) bool {
		for _, ip := range ips {
			if check(ip.String(), rrtype) {
				return true
			}
		}
		return false
	}
	for len(queue) > 0 {
		owner := queue[0]
		queue = queue[1:]
		for _, rr := range byOwner[owner] {
			switch record := rr.(type) {
			case *mdns.CNAME:
				target, ok := normalizedLookupDomain(record.Target)
				if !ok {
					continue
				}
				if check(target, mdns.TypeCNAME) {
					return true
				}
				if !visited[target] {
					visited[target] = true
					queue = append(queue, target)
				}
			case *mdns.A:
				if check(record.A.String(), mdns.TypeA) {
					return true
				}
			case *mdns.AAAA:
				if check(record.AAAA.String(), mdns.TypeAAAA) {
					return true
				}
			case *mdns.HTTPS:
				if blockedSVCBHints(record.Value, mdns.TypeHTTPS, checkIPs) {
					return true
				}
			case *mdns.SVCB:
				if blockedSVCBHints(record.Value, mdns.TypeSVCB, checkIPs) {
					return true
				}
			}
		}
	}
	return false
}

func blockedSVCBHints(values []mdns.SVCBKeyValue, rrtype uint16, check func([]net.IP, uint16) bool) bool {
	for _, value := range values {
		switch hint := value.(type) {
		case *mdns.SVCBIPv4Hint:
			if check(hint.Hint, rrtype) {
				return true
			}
		case *mdns.SVCBIPv6Hint:
			if check(hint.Hint, rrtype) {
				return true
			}
		}
	}
	return false
}
