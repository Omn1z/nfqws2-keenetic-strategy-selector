package awg

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// prepareReply finishes learning before the DNS packet leaves either listener
// or the encrypted-DNS observer. Trace callbacks are deliberately separate:
// recording a successful route must not turn a failed install into success.
func (p *DNSProxy) prepareReply(ctx context.Context, srcIP, name string, valid bool, response []byte) error {
	return p.prepareReplySnapshot(ctx, srcIP, name, valid, response, p.beforeReply.Load())
}

func (p *DNSProxy) prepareReplySnapshot(ctx context.Context, srcIP, name string, valid bool, response []byte, cb *func(context.Context, string, string, []string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.retired.Load() {
		return fmt.Errorf("DNS routing policy was replaced; retry the query")
	}
	if !valid || name == "" {
		return nil
	}
	if cb != nil {
		ips := answerIPs(response)
		learn := ips
		if isSinkholeResponse(response) {
			learn = nil // null destinations need readiness, not an ipset entry.
		}
		if err := (*cb)(ctx, srcIP, name, learn); err != nil {
			return err
		}
		if len(learn) > 0 {
			p.remember(name, ips)
		}
	} else {
		p.inspectParsed(name, valid, response)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.retired.Load() {
		return fmt.Errorf("DNS routing policy was replaced; retry the query")
	}
	return nil
}

// dnsFailureResponse includes only the echoed question, never stale answer or
// EDNS bytes. A route-install failure must not hand out usable WAN addresses.
func dnsFailureResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	name, questionEnd, ok := readName(query, 12)
	if !ok || questionEnd+4 > len(query) {
		return nil
	}
	question := append([]byte(nil), query[:12]...)
	question[4], question[5] = 0, 1
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) > 63 {
				return nil
			}
			question = append(question, byte(len(label)))
			question = append(question, label...)
		}
	}
	question = append(question, 0)
	question = append(question, query[questionEnd:questionEnd+4]...)
	response := emptyNoErrorResponse(question)
	response[2] &^= 0x06 // A synthetic reply is neither authoritative nor truncated.
	response[3] = 0x82   // RA + SERVFAIL, with AD cleared.
	return response
}

// filterIPv6Hints lets an IPv4-only tunnel fall back to ordinary A lookups.
// Return a question-only NODATA response instead of rewriting a signed SVCB
// RRset or exposing an IPv6 hint that would bypass AAAA suppression. The
// original cached response is left intact for clients with another policy.
func (p *DNSProxy) filterIPv6Hints(srcIP, name string, qtype uint16, question, response []byte) []byte {
	if qtype != 64 && qtype != 65 {
		return response
	}
	block := false
	if b := p.aaaaBlocker.Load(); b != nil {
		block = (*b)(srcIP, name)
	} else if ms := p.matchers.Load(); ms != nil {
		block = ms.MatchAny(name)
	}
	if !block {
		return response
	}
	for _, raw := range answerIPs(response) {
		if ip := net.ParseIP(raw); ip != nil && ip.To4() == nil {
			filtered := dnsFailureResponse(question)
			if filtered == nil {
				return response
			}
			filtered[3] = 0x80 // NODATA, with AD cleared.
			return filtered
		}
	}
	return response
}
