//go:build linux

package awgroute

import (
	"fmt"
	"net"
	"strings"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// awgEnsureMultiDNSProxy wires the transparent DNS learner to the multi-policy
// ipsets (awgm_XXX). Static apply still resolves plain domains once, but this
// path closes the "first opens are slow" gap: the client's own DNS answer is
// inserted into the first matching rule's set before the DNS response is sent
// back to the browser.
func (svc *Service) awgEnsureMultiDNSProxy(rules []awgMultiRule) bool {
	rules = awgCloneMultiRules(rules)
	ms := awgMultiRulesMatcherSet(rules)
	if ms.Len() == 0 {
		svc.awgStopDNSProxy()
		return false
	}

	// The callbacks close over a rules snapshot. Recreate the proxy on each
	// multi-policy apply so edits cannot keep learning into old awgm_* sets.
	svc.awgSaveRecent()
	svc.awgStopDNSProxy()

	np := awg.NewDNSProxy(awgDNSAddr, svc.awgEffectiveDNSUpstream(), func(name string, ips []string) {
		// SetMatchers replay runs through onMatch without a client IP. Re-add
		// cached global-domain answers without blocking the apply path.
		svc.awgMultiLearnDNSAnswer(rules, name, "", ips, false)
	})
	np.SetOnQuery(func(srcIP, qname, qtype string, ips []string, sinkholed bool) {
		if !sinkholed {
			// Live DNS answer: block until the destination is in awgm_XXX so the
			// client's first connection after this DNS response sees the route.
			svc.awgMultiLearnDNSAnswer(rules, qname, srcIP, ips, true)
		}
		svc.awgTraceMultiDNSQuery(rules, srcIP, qname, qtype, ips, sinkholed)
	})
	np.SetOnBlock(func(srcIP, qname string) {
		traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: "AAAA", Decision: "blocked", Reason: "multi-routing: tunnel rule, AAAA suppressed -> v4 fallback"})
	})
	np.SetAAAABlocker(func(srcIP, name string) bool {
		r := awgMultiRuleForName(rules, name, srcIP)
		return r != nil && r.Zone.RouteValue() == "tunnel"
	})
	svc.awgLoadRecent(np)
	np.SetMatchers(ms)
	if err := np.Start(); err != nil {
		logbuf.Append("awg2", "error", "multi-routing: DNS learner failed to start: "+err.Error())
		return false
	}
	svc.route.mu.Lock()
	svc.route.dnsProxy = np
	svc.route.mu.Unlock()
	logbuf.Append("awg2", "info", fmt.Sprintf("multi-routing: DNS learner enabled for %d domain rules", awgMultiDynamicRuleCount(rules)))
	return true
}

func awgCloneMultiRules(rules []awgMultiRule) []awgMultiRule {
	out := make([]awgMultiRule, len(rules))
	copy(out, rules)
	return out
}

func awgMultiRulesMatcherSet(rules []awgMultiRule) *awg.MatcherSet {
	var entries []string
	for _, r := range rules {
		if r.Dynamic {
			entries = append(entries, r.DomainEntries...)
		}
	}
	ms, _ := awg.CompileMatcherSet(entries)
	return &ms
}

func awgMultiDynamicRuleCount(rules []awgMultiRule) int {
	n := 0
	for _, r := range rules {
		if r.Dynamic {
			n++
		}
	}
	return n
}

func awgMultiRuleForName(rules []awgMultiRule, name, srcIP string) *awgMultiRule {
	for i := range rules {
		r := &rules[i]
		if len(r.Sources) > 0 && !srcIPMatches(srcIP, r.Sources) {
			continue
		}
		if r.CatchAll || (!r.HasDst && r.StaticOK) {
			return r
		}
		if r.Matchers != nil && r.Matchers.MatchAny(name) {
			return r
		}
	}
	return nil
}

func (svc *Service) awgMultiLearnDNSAnswer(rules []awgMultiRule, name, srcIP string, ips []string, immediate bool) {
	r := awgMultiRuleForName(rules, name, srcIP)
	if r == nil || !r.HasDst || strings.TrimSpace(r.SetName) == "" {
		return
	}
	v4 := awgDNSIPv4Answers(ips)
	v4 = svc.awgFilterMultiDNSLearnIPs(v4)
	if len(v4) == 0 {
		return
	}
	if immediate {
		awgIPSetAddManySync(r.SetName, v4)
		return
	}
	for _, ip := range v4 {
		ipsetAddAsync(r.SetName, ip)
	}
}

func (svc *Service) awgFilterMultiDNSLearnIPs(ips []string) []string {
	out := ips[:0]
	for _, ip := range ips {
		if _, ok := sharedCDNProvider(ip); ok {
			svc.awgNoteSharedCDNSkip("multi-dns", ip)
			continue
		}
		out = append(out, ip)
	}
	return out
}

func awgDNSIPv4Answers(ips []string) []string {
	out := make([]string, 0, len(ips))
	seen := map[string]struct{}{}
	for _, raw := range ips {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		s := v4.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func awgIPSetAddManySync(set string, ips []string) {
	for _, ip := range ips {
		if out, err := awgRun("ipset add " + set + " " + ip + " -exist"); err != nil {
			logbuf.Append("awg2", "warn", "multi-routing: DNS learn ipset add failed for "+set+" "+ip+": "+err.Error()+" "+out)
		}
	}
}

func (svc *Service) awgTraceMultiDNSQuery(rules []awgMultiRule, srcIP, qname, qtype string, ips []string, sinkholed bool) {
	if sinkholed {
		if len(ips) == 0 {
			traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Decision: "blocked", Reason: "pi-hole: domain blocked"})
			return
		}
		for _, ip := range ips {
			traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Dst: ip, Decision: "blocked", Reason: "pi-hole: null-route"})
		}
		return
	}
	r := awgMultiRuleForName(rules, qname, srcIP)
	decision, reason, rule := "direct", "multi-routing: no matching rule", 0
	if r != nil {
		decision = r.Zone.RouteValue()
		rule = r.RuleIndex + 1
		reason = fmt.Sprintf("multi-routing: rule #%d (%s)", rule, decision)
	}
	if len(ips) == 0 {
		traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Decision: decision, Rule: rule, Reason: reason})
		return
	}
	for _, ip := range ips {
		traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Dst: ip, Decision: decision, Rule: rule, Reason: reason})
	}
}
