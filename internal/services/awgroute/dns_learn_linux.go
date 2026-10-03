//go:build linux

package awgroute

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

func (svc *Service) awgSetLegacyDNSLearner(p *awg.DNSProxy) {
	generation := svc.routingDNSGate.version()
	p.SetBeforeReply(func(ctx context.Context, srcIP, name string, ips []string) error {
		return svc.awgLearnLegacyDNSAnswer(ctx, name, srcIP, ips, generation)
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
	release, err := svc.routingDNSGate.acquire(ctx, generation, true)
	if err != nil {
		return err
	}
	defer release()
	dec := svc.routeFor(name, "")
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
		// Shared-CDN addresses remain excluded from LAN-wide domain sets;
		// source-bound sets above preserve the user's explicit device scope.
		if _, ok := sharedCDNProvider(ip); ok {
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
	if err := svc.awgIPSetLearnSync(ctx, requests); err != nil {
		return err
	}
	return svc.routingDNSGate.verify(generation)
}

// A single bounded restore covers the complete reply. Returning an error is
// essential: the caller must send SERVFAIL instead of leaking the first flow
// while an asynchronous add is queued or a command has failed.
func (svc *Service) awgIPSetLearnSync(ctx context.Context, requests []ipsetAddReq) error {
	return svc.awgIPSetLearnWith(ctx, requests, awgRunShell)
}

func (svc *Service) awgIPSetLearnWith(ctx context.Context, requests []ipsetAddReq, run func(context.Context, string, string) (string, error)) error {
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
	if len(pending) == 0 {
		return nil
	}
	script, err = awgDNSLearnScript(pending)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := run(ctx, "ipset restore -exist", script)
	if err != nil {
		err = awgCmdErr("DNS route ipset restore", out, err)
		logbuf.Append("awg2", "warn", err.Error())
		return err
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
