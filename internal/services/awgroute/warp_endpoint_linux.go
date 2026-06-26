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

func (svc *Service) awgApplyBestWARPEndpoint(am *awg.Manager, cfg awg.ServerConfig, p awg.Peer, iface string) (awg.ServerConfig, error) {
	current := normalizeWARPEndpoint(cfg.Endpoint)
	failures := []string{}
	attempts := 0

	candidates := svc.awgRankWARPEndpointCandidates(cfg.Endpoint)
	candidates = svc.awgPrioritizedWARPEndpointCandidates(current, candidates)
	if len(candidates) == 0 {
		return cfg, nil
	}
	if len(candidates) > warpEndpointAttemptLimit {
		candidates = candidates[:warpEndpointAttemptLimit]
	}
	for i, endpoint := range candidates {
		attempts++
		next, ok, err := svc.awgTryWARPEndpoint(am, cfg, p, iface, endpoint, i+1, len(candidates))
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
	return cfg, err
}

func (svc *Service) awgTryWARPEndpoint(am *awg.Manager, cfg awg.ServerConfig, p awg.Peer, iface, endpoint string, idx, total int) (awg.ServerConfig, bool, error) {
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
	resp, err := uapiRequestIface(iface, setText)
	if err != nil {
		return cfg, false, fmt.Errorf("%s: UAPI: %w", selectedEndpoint, err)
	}
	if !strings.Contains(resp, "errno=0") {
		return cfg, false, fmt.Errorf("%s: UAPI rejected: %s", selectedEndpoint, strings.TrimSpace(resp))
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("WARP endpoint probe %d/%d: %s", idx, total, selectedEndpoint))
	awgTriggerWARPHandshake(iface)
	if !awgWaitEndpointHandshake(iface, ip, port, start, warpEndpointProbeWait) {
		return cfg, false, fmt.Errorf("%s: no handshake", selectedEndpoint)
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

func (svc *Service) awgRankWARPEndpointCandidates(current string) []string {
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
	scores := warpScoreHosts(hostOrder)
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

func warpScoreHosts(hosts []string) map[string]warpEndpointScore {
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
				rtt, ok := warpPingHost(host)
				results <- result{score: warpEndpointScore{host: host, rtt: rtt, ok: ok}}
			}
		}()
	}
	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)
	wg.Wait()
	close(results)
	for r := range results {
		out[strings.ToLower(r.score.host)] = r.score
	}
	return out
}

func warpPingHost(host string) (time.Duration, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
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

func awgTriggerWARPHandshake(iface string) {
	target := "1.1.1.1"
	cmd := strings.Join([]string{
		"ip route replace " + target + "/32 dev " + shell.Quote(iface) + " 2>/dev/null || true",
		"ping -c 1 -W 1 -I " + shell.Quote(iface) + " " + target + " >/dev/null 2>&1 || true",
		"ip route del " + target + "/32 dev " + shell.Quote(iface) + " 2>/dev/null || true",
	}, "; ")
	ctx, cancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)
	defer cancel()
	_ = exec.CommandContext(ctx, "sh", "-c", cmd).Run()
}

func awgWaitEndpointHandshake(iface, ip string, port int, since int64, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st := awgClientStatusIfaceOS(iface)
		if st != nil && st.LastHandshake >= since && endpointMatches(st.Endpoint, ip, port) {
			return true
		}
		time.Sleep(180 * time.Millisecond)
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
