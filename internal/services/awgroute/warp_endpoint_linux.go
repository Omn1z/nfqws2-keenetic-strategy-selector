//go:build linux

package awgroute

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/shell"
)

const (
	warpEndpointAttemptLimit = 16
	warpEndpointProbeWait    = 1800 * time.Millisecond
)

type warpEndpointScore struct {
	host string
	rtt  time.Duration
	ok   bool
}

func (svc *Service) awgApplyBestWARPEndpoint(ctx context.Context, am *awg.Manager, cfg awg.ServerConfig, p awg.Peer, iface string) (awg.ServerConfig, error) {
	current := normalizeWARPEndpoint(cfg.Endpoint)
	lastConfigured := cfg
	failures := []string{}
	attempts := 0

	candidates := svc.awgRankWARPEndpointCandidates(ctx, cfg.Endpoint)
	candidates = svc.awgPrioritizedWARPEndpointCandidates(current, candidates)
	if len(candidates) == 0 {
		return cfg, nil
	}
	if len(candidates) > warpEndpointAttemptLimit {
		candidates = candidates[:warpEndpointAttemptLimit]
	}
	for i, endpoint := range candidates {
		if err := ctx.Err(); err != nil {
			return lastConfigured, err
		}
		attempts++
		next, ok, err := svc.awgTryWARPEndpoint(ctx, am, cfg, p, iface, endpoint, i+1, len(candidates))
		if next.Endpoint != cfg.Endpoint {
			lastConfigured = next
		}
		if ok {
			return next, nil
		}
		if err != nil {
			failures = append(failures, err.Error())
		}
	}
	detail := strings.Join(failures, "; ")
	if len(detail) > 320 {
		detail = detail[:320] + "..."
	}
	if detail == "" {
		detail = "no candidates"
	}
	err := fmt.Errorf("WARP endpoint: no fresh handshake after %d probes: %s", attempts, detail)
	logbuf.Append("awg2", "warn", err.Error())
	return lastConfigured, err
}

func (svc *Service) awgTryWARPEndpoint(ctx context.Context, am *awg.Manager, cfg awg.ServerConfig, p awg.Peer, iface, endpoint string, idx, total int) (awg.ServerConfig, bool, error) {
	if err := ctx.Err(); err != nil {
		return cfg, false, err
	}
	host, port, ok := splitHostPortDefault(endpoint, 2408)
	if !ok {
		return cfg, false, fmt.Errorf("%s: invalid endpoint", endpoint)
	}
	ip := resolveHostIP(host)
	if ip == "" {
		return cfg, false, fmt.Errorf("%s: resolve failed", endpoint)
	}
	selectedEndpoint := net.JoinHostPort(ip, strconv.Itoa(port))
	if gw, dev := awgDefaultRoute(); dev != "" {
		_, _ = awgRun(awgEndpointRouteCmd(ip, gw, dev))
	}

	next := cfg
	next.Endpoint = selectedEndpoint
	next.ListenPort = port
	setText, err := awg.RenderUAPISet(&next, p, ip, port)
	if err != nil {
		return cfg, false, err
	}
	start := time.Now().Unix()
	resp, err := uapiRequestIfaceContext(ctx, iface, setText)
	if err != nil {
		return cfg, false, fmt.Errorf("%s: UAPI: %w", selectedEndpoint, err)
	}
	if !strings.Contains(resp, "errno=0") {
		return cfg, false, fmt.Errorf("%s: UAPI rejected: %s", selectedEndpoint, strings.TrimSpace(resp))
	}
	if cfg.PeerKeepaliveValue(p) == "0" {
		if err := svc.awgProbeClientOS(am); err != nil {
			return next, false, err
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("WARP endpoint probe %d/%d: %s", idx, total, selectedEndpoint))
	// replace_peers creates a new peer whose nonzero persistent keepalive
	// immediately triggers a handshake. No temporary public /32 main-table
	// route is needed (that used to disturb unrelated 1.1.1.1 DNS traffic).
	if !awgWaitEndpointHandshake(ctx, iface, ip, port, start, warpEndpointProbeWait) {
		return next, false, fmt.Errorf("%s: no handshake", selectedEndpoint)
	}
	endpointChanged := strings.TrimSpace(cfg.Endpoint) != selectedEndpoint
	if endpointChanged {
		if err := am.SetConfig(&next); err != nil {
			return cfg, false, err
		}
		svc.awgSave()
	}
	logbuf.Append("awg2", "info", "WARP endpoint selected: "+selectedEndpoint)
	return next, true, nil
}

func (svc *Service) awgRankWARPEndpointCandidates(ctx context.Context, current string) []string {
	candidates := warpEndpointCandidates(current)
	if len(candidates) <= 1 {
		return candidates
	}
	hostOrder := []string{}
	seenHost := map[string]bool{}
	for _, endpoint := range candidates {
		host, _, ok := splitHostPortDefault(endpoint, 2408)
		if !ok {
			continue
		}
		key := strings.ToLower(host)
		if seenHost[key] {
			continue
		}
		seenHost[key] = true
		hostOrder = append(hostOrder, host)
	}
	scores := warpScoreHosts(ctx, hostOrder)
	scoreOf := func(endpoint string) warpEndpointScore {
		host, _, ok := splitHostPortDefault(endpoint, 2408)
		if !ok {
			return warpEndpointScore{}
		}
		return scores[strings.ToLower(host)]
	}
	order := map[string]int{}
	for i, endpoint := range candidates {
		order[endpoint] = i
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := scoreOf(candidates[i]), scoreOf(candidates[j])
		if a.ok != b.ok {
			return a.ok
		}
		_, ap, _ := splitHostPortDefault(candidates[i], 2408)
		_, bp, _ := splitHostPortDefault(candidates[j], 2408)
		if warpPortRank(ap) != warpPortRank(bp) {
			return warpPortRank(ap) < warpPortRank(bp)
		}
		if a.ok && b.ok && a.rtt != b.rtt {
			return a.rtt < b.rtt
		}
		return order[candidates[i]] < order[candidates[j]]
	})
	return candidates
}

func warpScoreHosts(ctx context.Context, hosts []string) map[string]warpEndpointScore {
	out := map[string]warpEndpointScore{}
	type result struct {
		score warpEndpointScore
	}
	jobs := make(chan string)
	results := make(chan result, len(hosts))
	workers := 16
	if len(hosts) < workers {
		workers = len(hosts)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				rtt, ok := warpPingHost(ctx, host)
				results <- result{score: warpEndpointScore{host: host, rtt: rtt, ok: ok}}
			}
		}()
	}
sendJobs:
	for _, host := range hosts {
		select {
		case jobs <- host:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	for r := range results {
		out[strings.ToLower(r.score.host)] = r.score
	}
	return out
}

func warpPingHost(parent context.Context, host string) (time.Duration, bool) {
	ctx, cancel := context.WithTimeout(parent, 1100*time.Millisecond)
	defer cancel()
	cmd := "ping -c 1 -W 1 " + shell.Quote(host) + " 2>&1"
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	if err != nil && ctx.Err() != nil {
		return 0, false
	}
	return parsePingRTT(string(out))
}

func parsePingRTT(out string) (time.Duration, bool) {
	if i := strings.Index(out, "time="); i >= 0 {
		s := out[i+len("time="):]
		if fields := strings.Fields(s); len(fields) > 0 {
			raw := strings.TrimSuffix(fields[0], "ms")
			if ms, err := strconv.ParseFloat(raw, 64); err == nil {
				return time.Duration(ms * float64(time.Millisecond)), true
			}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "min/avg") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		vals := strings.Split(strings.TrimSpace(parts[1]), "/")
		if len(vals) >= 2 {
			if ms, err := strconv.ParseFloat(strings.TrimSpace(vals[1]), 64); err == nil {
				return time.Duration(ms * float64(time.Millisecond)), true
			}
		}
	}
	return 0, false
}

func warpPortRank(port int) int {
	switch port {
	case 2408:
		return 0
	case 500:
		return 1
	case 1701:
		return 2
	case 4500:
		return 3
	case 8886:
		return 4
	default:
		return 10
	}
}

func awgWaitEndpointHandshake(ctx context.Context, iface, ip string, port int, since int64, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		st := awgClientStatusIfaceContextOS(ctx, iface)
		if st != nil && st.LastHandshake >= since && endpointMatches(st.Endpoint, ip, port) {
			return true
		}
		if !waitClientContext(ctx, 180*time.Millisecond) {
			return false
		}
	}
	return false
}

func endpointMatches(endpoint, ip string, port int) bool {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return false
	}
	return host == ip && portStr == strconv.Itoa(port)
}
