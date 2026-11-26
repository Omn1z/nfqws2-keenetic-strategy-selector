package awg

import (
	"context"
	"fmt"
	"strings"
)

// ObserveAnswer applies the same DNS policy and learning as the transparent
// proxy to a validated response obtained over DoH/DoT/DoQ. It never changes the
// original byte slice, so callers may retain an unfiltered shared cache entry.
func (p *DNSProxy) ObserveAnswer(srcIP, expectedName string, response []byte) ([]byte, error) {
	return p.ObserveAnswerContext(context.Background(), srcIP, expectedName, response)
}

// ValidatedDNSAnswerIPs returns an unfiltered upstream hint for internal route
// preparation. It neither applies policy nor authorizes delivering an answer.
// Negative, truncated and malformed replies cannot seed a recovery address.
func ValidatedDNSAnswerIPs(expectedName string, response []byte) ([]string, error) {
	name, _, ok := questionInfo(response)
	_, questionEnd, nameOK := readName(response, 12)
	if !ok || !nameOK || len(response) < questionEnd+4 || response[4] != 0 || response[5] != 1 || response[2]&0x80 == 0 || !strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(expectedName, ".")) {
		return nil, fmt.Errorf("DNS response question does not match the requested domain")
	}
	if response[2]&0x02 != 0 || response[3]&0x0f != 0 || isSinkholeResponse(response) {
		return nil, nil
	}
	pos := questionEnd + 4
	records := int(response[6])<<8 | int(response[7])
	records += int(response[8])<<8 | int(response[9])
	records += int(response[10])<<8 | int(response[11])
	for range records {
		_, next, valid := readName(response, pos)
		if !valid || next+10 > len(response) {
			return nil, fmt.Errorf("malformed DNS recovery hint")
		}
		length := int(response[next+8])<<8 | int(response[next+9])
		pos = next + 10 + length
		if pos > len(response) {
			return nil, fmt.Errorf("malformed DNS recovery hint")
		}
	}
	if pos != len(response) {
		return nil, fmt.Errorf("malformed DNS recovery hint")
	}
	return answerIPs(response), nil
}

// ObserveAnswerContext preserves cancellation while the route learner waits
// for a policy replacement or installs the destinations of a cached reply.
func (p *DNSProxy) ObserveAnswerContext(ctx context.Context, srcIP, expectedName string, response []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policy := p.beforeReply.Load()
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
		if err := p.prepareReplySnapshot(ctx, srcIP, name, true, filtered, policy); err != nil {
			return nil, err
		}
		if p.onBlock != nil {
			p.onBlock(srcIP, name)
		}
		return filtered, nil
	}
	response = p.filterIPv6Hints(srcIP, name, qtype, question, response)
	if err := p.prepareReplySnapshot(ctx, srcIP, name, true, response, policy); err != nil {
		return nil, err
	}
	if p.onQuery != nil {
		p.onQuery(srcIP, name, dnsQTypeStr(qtype), answerIPs(response), isSinkholeResponse(response))
	}
	return response, nil
}
