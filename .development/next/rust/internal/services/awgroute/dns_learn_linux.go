//go:build linux

package awgroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

func (svc *Service) awgSetLegacyDNSLearner(p *awg.DNSProxy, configs ...*awg.ServerConfig) {
	generation := svc.routingDNSGate.version()
	var snapshot []routingDiscoveryRule
	if len(configs) > 0 && configs[0] != nil {
		rules := cloneAWGZones(configs[0].Routing.Zones)
		owner := svc.activeServerID()
		for i := range rules {
			rules[i].TunnelID = strings.TrimSpace(rules[i].TunnelID)
			if rules[i].TunnelID == "" && !rules[i].WaitingForConnection {
				rules[i].TunnelID = owner
			}
			if rules[i].RouteValue() == "tunnel" {
				candidates := fallbackCandidates(rules[i].TunnelID, rules[i].FallbackTunnelIDs)
				rules[i].FallbackTunnelIDs = nil
				if len(candidates) > 1 {
					rules[i].FallbackTunnelIDs = candidates[1:]
				}
			} else {
				rules[i].FallbackTunnelIDs = nil
			}
		}
		snapshot = svc.legacyRoutingDiscoverySnapshot(rules)
	}
	p.SetBeforeReply(func(ctx context.Context, srcIP, name string, ips []string) error {
		return svc.awgLearnLegacyDNSAnswerWithSnapshot(ctx, name, srcIP, ips, generation, snapshot, svc.awgIPSetLearnSync)
	})
	p.SetReplayMatch(func(name string, ips []string) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := svc.awgLearnLegacyDNSAnswer(ctx, name, "", ips, generation); err != nil {
			logbuf.Append("awg2", "warn", "DNS replay: "+err.Error())
		}
	})
}

func (svc *Service) awgLearnLegacyDNSAnswer(ctx context.Context, name, srcIP string, ips []string, generation uint64) error {
	return svc.awgLearnLegacyDNSAnswerWith(ctx, name, srcIP, ips, generation, svc.awgIPSetLearnSync)
}

func (svc *Service) awgLearnLegacyDNSAnswerWith(ctx context.Context, name, srcIP string, ips []string, generation uint64, learn func(context.Context, []ipsetAddReq) error) error {
	return svc.awgLearnLegacyDNSAnswerWithSnapshot(ctx, name, srcIP, ips, generation, nil, learn)
}

func (svc *Service) awgLearnLegacyDNSAnswerWithSnapshot(ctx context.Context, name, srcIP string, ips []string, generation uint64, snapshot []routingDiscoveryRule, learn func(context.Context, []ipsetAddReq) error) error {
	release, err := svc.routingDNSGate.acquire(ctx, generation, true)
	if err != nil {
		return err
	}
	defer release()
	dec := svc.routeFor(name, "")
	observedDecision := svc.routeFor(name, srcIP)
	tbl := svc.route.routeTable.Load()
	var requests []ipsetAddReq
	for _, ip := range ips {
		v6Suffix := ""
		if isIPv6(ip) {
			v6Suffix = "_6"
		}
		if tbl != nil {
			for _, sb := range tbl.source {
				if srcIP != "" && !srcIPMatches(srcIP, sb.Sources) {
					continue
				}
				if sb.Matchers != nil && sb.Matchers.Len() > 0 && sb.Matchers.MatchAny(name) {
					requests = append(requests, ipsetAddReq{set: sb.SetName + v6Suffix, ip: ip})
				}
			}
		}
		// Only a global direct exception needs the shared-address guard.
		// Explicit tunnel destinations must be installed before replying.
		if skipSharedCDNDomainIP(string(dec.Route), false, ip) {
			svc.awgNoteSharedCDNSkip("dnsproxy", ip)
			continue
		}
		switch dec.Route {
		case RouteDirect:
			requests = append(requests, ipsetAddReq{set: awgSetExc + v6Suffix, ip: ip})
		case RouteTunnel:
			requests = append(requests, ipsetAddReq{set: awgSetInc + v6Suffix, ip: ip})
		}
	}
	return svc.confirmRoutingDNSLearning(ctx, generation, func() error {
		return learn(ctx, requests)
	}, func() {
		z, matched := svc.legacyRoutingDiscoveryRule(snapshot, observedDecision, name, srcIP)
		if !matched {
			return
		}
		winnerSet := observedDecision.SourceSet
		if !observedDecision.SourceBound {
			if observedDecision.Route == RouteTunnel {
				winnerSet = awgSetInc
			} else if observedDecision.Route == RouteDirect {
				winnerSet = awgSetExc
			}
		}
		installed := []string{}
		for _, request := range requests {
			if request.set == winnerSet || request.set == winnerSet+"_6" {
				installed = append(installed, request.ip)
			}
		}
		if len(installed) > 0 {
			svc.recordRoutingDiscovery(z, name, srcIP, installed, "dns", generation)
		}
	})
}

// A single bounded restore covers the complete reply. Returning an error is
// essential: the caller must send SERVFAIL instead of leaking the first flow
// while an asynchronous add is queued or a command has failed.
func (svc *Service) awgIPSetLearnSync(ctx context.Context, requests []ipsetAddReq) error {
	return svc.awgIPSetLearnWith(ctx, requests, awgRunShell)
}

func (svc *Service) awgIPSetLearnWith(ctx context.Context, requests []ipsetAddReq, run func(context.Context, string, string) (string, error)) error {
	return svc.awgIPSetLearnWithAcceleration(ctx, requests, run, svc.awgSelectiveAccelerationActive, svc.awgInvalidateAccelerationCache)
}

func (svc *Service) awgIPSetLearnWithAcceleration(ctx context.Context, requests []ipsetAddReq, run func(context.Context, string, string) (string, error), selectiveActive func() bool, invalidate func() error) error {
	script, err := awgDNSLearnScript(requests)
	if err != nil || script == "" {
		return err
	}
	g := &svc.routingDNSGate
	g.mu.Lock()
	if g.learnToken == nil {
		g.learnToken = make(chan struct{}, 1)
	}
	token := g.learnToken
	g.mu.Unlock()
	select {
	case token <- struct{}{}:
		defer func() { <-token }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The memo contains only confirmed kernel adds. Keeping it within this
	// bounded writer slot coalesces simultaneous queries for the same address.
	const memoLimit = 4096
	const memoTTL = time.Minute
	now := time.Now()
	g.mu.Lock()
	// A queued reader may obtain the writer slot after replacement began.
	// Drain it without a fork so a busy DNS queue cannot prolong reconfiguration.
	if g.applying {
		g.mu.Unlock()
		return fmt.Errorf("DNS routing policy changed; retry the query")
	}
	if g.err != nil {
		err := fmt.Errorf("DNS routing policy is not ready: %w", g.err)
		g.mu.Unlock()
		return err
	}
	epoch := g.writeEpoch
	pending := make([]ipsetAddReq, 0, len(requests))
	for _, request := range requests {
		key := request.set + " " + net.ParseIP(strings.TrimSpace(request.ip)).String()
		if !now.Before(g.learned[key]) {
			pending = append(pending, request)
		}
	}
	g.mu.Unlock()
	// A previous restore may already have inserted the address even though
	// flushing its formerly direct accelerated flow failed. Retry the flush
	// before membership checks: an existing member must not hide that debt.
	flushDirty := func() error {
		g.mu.Lock()
		dirty := g.accelerationDirty
		g.mu.Unlock()
		if !dirty {
			return nil
		}
		if err := invalidate(); err != nil {
			return fmt.Errorf("DNS route acceleration cache: %w", err)
		}
		g.mu.Lock()
		g.accelerationDirty = false
		g.mu.Unlock()
		return nil
	}
	if err := flushDirty(); err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	script, err = awgDNSLearnScript(pending)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	selective := selectiveActive()
	if selective {
		check, err := awgDNSLearnMembershipScript(pending)
		if err != nil {
			return err
		}
		out, err := run(ctx, "sh", check)
		if err != nil {
			return awgCmdErr("DNS route ipset membership", out, err)
		}
		switch strings.TrimSpace(out) {
		case "present":
			// A memo expiry only rechecks the kernel. Multi-policy sets have
			// no member timeout; an existing route needs neither add nor flush.
			script = ""
		case "missing":
		default:
			return fmt.Errorf("invalid DNS route membership result")
		}
	}
	if script != "" {
		if selective {
			g.mu.Lock()
			g.accelerationDirty = true
			g.mu.Unlock()
		}
		out, err := run(ctx, "ipset restore -exist", script)
		if err != nil {
			err = awgCmdErr("DNS route ipset restore", out, err)
			logbuf.Append("awg2", "warn", err.Error())
			// Restore is not transactional: clear old acceleration even if a
			// later add failed, then keep the DNS answer unsuccessful.
			return errors.Join(err, flushDirty())
		}
		if err := flushDirty(); err != nil {
			return err
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if epoch == g.writeEpoch && !g.applying && g.err == nil {
		if g.learned == nil || len(g.learned)+len(pending) > memoLimit {
			g.learned = make(map[string]time.Time)
		}
		expires := time.Now().Add(memoTTL)
		for _, request := range pending {
			if len(g.learned) >= memoLimit {
				break
			}
			key := request.set + " " + net.ParseIP(strings.TrimSpace(request.ip)).String()
			g.learned[key] = expires
		}
	}
	return nil
}

// One bounded shell invocation tests only the reply's validated destinations,
// without dumping potentially large GeoIP sets. Stop at the first missing
// member: the subsequent checked restore installs the complete reply. Some
// ipset versions also use exit 1 for a missing set; restore must still fail
// closed for that case rather than treating it as an unchanged membership.
func awgDNSLearnMembershipScript(requests []ipsetAddReq) (string, error) {
	restore, err := awgDNSLearnScript(requests)
	if err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString("set -e\n")
	for _, line := range strings.Split(strings.TrimSpace(restore), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		script.WriteString("if ipset test " + fields[1] + " " + fields[2] + " >/dev/null 2>&1; then\n :\nelse\n rc=$?\n [ \"$rc\" -eq 1 ] || exit \"$rc\"\n printf 'missing\\n'\n exit 0\nfi\n")
	}
	script.WriteString("printf 'present\\n'\n")
	return script.String(), nil
}

func awgDNSLearnScript(requests []ipsetAddReq) (string, error) {
	var script strings.Builder
	seen := make(map[string]struct{}, len(requests))
	destinations := make(map[string]struct{})
	for _, request := range requests {
		set := request.set
		if set == "" || len(set) > 31 || strings.IndexFunc(set, func(c rune) bool {
			return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-')
		}) >= 0 {
			return "", fmt.Errorf("invalid DNS routing set name")
		}
		ip := net.ParseIP(strings.TrimSpace(request.ip))
		if ip == nil || ip.IsUnspecified() {
			return "", fmt.Errorf("invalid DNS routing destination")
		}
		destinations[ip.String()] = struct{}{}
		if len(destinations) > 64 {
			return "", fmt.Errorf("DNS response has too many routed destinations")
		}
		key := set + " " + ip.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		script.WriteString("add " + key + " -exist\n")
	}
	return script.String(), nil
}
