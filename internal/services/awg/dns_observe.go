package awg

import (
	"fmt"
	"strings"
)

// ObserveAnswer applies the same DNS policy and learning as the transparent
// proxy to a validated response obtained over DoH/DoT/DoQ. It never changes the
// original byte slice, so callers may retain an unfiltered shared cache entry.
func (p *DNSProxy) ObserveAnswer(srcIP, expectedName string, response []byte) ([]byte, error) {
	name, qtype, ok := questionInfo(response)
	_, questionEnd, nameOK := readName(response, 12)
	if !ok || !nameOK || len(response) < questionEnd+4 || response[4] != 0 || response[5] != 1 || response[2]&0x80 == 0 || !strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(expectedName, ".")) {
		return nil, fmt.Errorf("DNS response question does not match the requested domain")
	}
	// Build a question-only packet. Feeding the full response to the legacy
	// query helper would leave answer bytes behind after ANCOUNT was cleared.
	question := append([]byte(nil), response[:12]...)
	question[4], question[5] = 0, 1
	for i := 6; i < 12; i++ {
		question[i] = 0
	}
	if name != "" {
		for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			question = append(question, byte(len(label)))
			question = append(question, label...)
		}
	}
	question = append(question, 0, byte(qtype>>8), byte(qtype), response[questionEnd+2], response[questionEnd+3])
	if filtered, blocked := p.maybeBlockAAAAParsed(srcIP, question, name, qtype, true); blocked {
		if p.onBlock != nil {
			p.onBlock(srcIP, name)
		}
		return filtered, nil
	}
	ips := answerIPs(response)
	if len(ips) > 64 {
		ips = ips[:64]
	} // bound synchronous routing work per response
	if len(ips) > 0 {
		p.remember(name, ips)
	}
	if ms := p.matchers.Load(); ms != nil && ms.MatchAny(name) && p.onMatch != nil {
		p.onMatch(name, ips)
	}
	if p.onQuery != nil {
		p.onQuery(srcIP, name, dnsQTypeStr(qtype), ips, isSinkholeResponse(response))
	}
	return response, nil
}
