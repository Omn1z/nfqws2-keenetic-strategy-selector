//go:build linux

package awgroute

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/netmon"
)

const (
	awgFlowTracePoll         = time.Second
	awgFlowTraceRulesTTL     = 5 * time.Second
	awgFlowTraceUnrepliedTTL = 2 * time.Second
	awgFlowTraceGoneTTL      = 3 * time.Second
	awgFlowTracePruneAfter   = 30 * time.Second
	awgFlowTraceMaxState     = 4096
	awgFlowTraceHardMaxState = 8192
	awgFlowTracePTRTimeout   = 800 * time.Millisecond
	awgFlowTracePTRNegative  = 10 * time.Minute
)

var awgFlowPTR = struct {
	sync.Mutex
	inFlight map[string]bool
	negative map[string]time.Time
	slots    chan struct{}
}{
	inFlight: map[string]bool{},
	negative: map[string]time.Time{},
	slots:    make(chan struct{}, 4),
}

type awgFlowTraceState struct {
	conn              netmon.Conn
	decision          awgFlowTraceDecision
	firstSeen         time.Time
	lastSeen          time.Time
	unreplied         bool
	reportedUnreplied bool
}

type awgFlowTraceDecision struct {
	Decision    string
	Rule        int
	Reason      string
	TunnelID    string
	TunnelIface string
}

type awgFlowTraceRule struct {
	name        string
	route       string
	rule        int
	tunnelID    string
	tunnelIface string
	sources     []string
	prefixes    []netip.Prefix
	catchAll    bool
	matchAll    bool
}

func (svc *Service) awgFlowTraceLoop() {
	defer func() {
		if r := recover(); r != nil {
			logbuf.Append("awg2", "warn", fmt.Sprintf("flow trace loop stopped: %v", r))
		}
	}()

	seen := map[string]*awgFlowTraceState{}
	rules := []awgFlowTraceRule{}
	var rulesAt time.Time
	rulesRev := int64(-1)

	t := time.NewTicker(awgFlowTracePoll)
	defer t.Stop()
	for now := range t.C {
		if !traceEnabled() {
			if len(seen) > 0 {
				seen = map[string]*awgFlowTraceState{}
			}
			continue
		}
		rev := svc.zonesRevision.Load()
		if rulesAt.IsZero() || now.Sub(rulesAt) >= awgFlowTraceRulesTTL || rev != rulesRev {
			rules = svc.awgFlowTraceRules()
			rulesAt = now
			rulesRev = rev
		}
		svc.awgTraceConntrackFlows(seen, rules, now)
	}
}

func (svc *Service) awgTraceConntrackFlows(seen map[string]*awgFlowTraceState, rules []awgFlowTraceRule, now time.Time) {
	conns, err := netmon.Conntrack()
	if err != nil {
		return
	}
	present := make(map[string]bool, len(conns))
	for _, c := range conns {
		if !awgFlowTraceInteresting(c) {
			continue
		}
		key := awgFlowTraceKey(c)
		present[key] = true
		dec := awgFlowDecisionFor(c, rules)
		st := seen[key]
		if st == nil {
			seen[key] = &awgFlowTraceState{
				conn:              c,
				decision:          dec,
				firstSeen:         now,
				lastSeen:          now,
				unreplied:         c.Unreplied,
				reportedUnreplied: false,
			}
			svc.awgFlowTraceMaybeResolveHost(c, dec)
			traceAppend(awgFlowTraceEntry(c, dec, "new"))
			continue
		}

		if st.unreplied && !c.Unreplied {
			traceAppend(awgFlowTraceEntry(c, dec, "replied"))
		}
		if c.Unreplied && !st.reportedUnreplied && now.Sub(st.firstSeen) >= awgFlowTraceUnrepliedTTL {
			traceAppend(awgFlowTraceEntry(c, dec, "unreplied"))
			st.reportedUnreplied = true
		}
		st.conn = c
		st.decision = dec
		st.lastSeen = now
		st.unreplied = c.Unreplied
	}

	for key, st := range seen {
		if present[key] {
			continue
		}
		if now.Sub(st.lastSeen) < awgFlowTraceGoneTTL {
			continue
		}
		if st.conn.Failing() {
			traceAppend(awgFlowTraceEntry(st.conn, st.decision, "gone"))
		}
		delete(seen, key)
	}
	if len(seen) > awgFlowTraceMaxState {
		awgPruneFlowTraceState(seen, now)
	}
}

func (svc *Service) awgFlowTraceRules() []awgFlowTraceRule {
	servers := map[string]*managedServer{}
	for _, srv := range svc.serverSnapshot() {
		servers[srv.ID] = srv
	}
	out := []awgFlowTraceRule{}
	for i, z := range svc.awgRoutingRules() {
		if !z.Enabled {
			continue
		}
		srv := servers[strings.TrimSpace(z.TunnelID)]
		if srv == nil {
			continue
		}
		cfg := srv.Manager.Config()
		if !cfg.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			continue
		}
		route := z.RouteValue()
		if route != "tunnel" && route != "direct" {
			continue
		}
		tunnelIface := ""
		if route == "tunnel" {
			tunnelIface = awgClientIfaceName(cfg)
			if tunnelIface == "" {
				continue
			}
		}
		entries, catchAll, staticOK := svc.awgMultiRuleEntries(z)
		prefixes := awgFlowTracePrefixes(entries)
		if !catchAll && len(prefixes) == 0 && !staticOK {
			continue
		}
		out = append(out, awgFlowTraceRule{
			name:        z.Name,
			route:       route,
			rule:        i + 1,
			tunnelID:    z.TunnelID,
			tunnelIface: tunnelIface,
			sources:     append([]string(nil), z.SourceIPs...),
			prefixes:    prefixes,
			catchAll:    catchAll,
			matchAll:    catchAll || (len(prefixes) == 0 && staticOK),
		})
	}
	return out
}

func awgFlowTracePrefixes(entries []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(entries))
	for _, ent := range entries {
		p, err := netip.ParsePrefix(strings.TrimSpace(ent))
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

func awgFlowDecisionFor(c netmon.Conn, rules []awgFlowTraceRule) awgFlowTraceDecision {
	for _, r := range rules {
		if len(r.sources) > 0 && !srcIPMatches(c.Src.String(), r.sources) {
			continue
		}
		if !r.matchAll && !awgFlowDstMatches(c.Dst, r.prefixes) {
			continue
		}
		dec := awgFlowTraceDecision{
			Decision:    r.route,
			Rule:        r.rule,
			TunnelID:    r.tunnelID,
			TunnelIface: r.tunnelIface,
		}
		if r.route == "tunnel" {
			dec.Reason = fmt.Sprintf("flow: rule #%d %q -> %s", r.rule, r.name, r.tunnelIface)
		} else {
			dec.Reason = fmt.Sprintf("flow: rule #%d %q -> direct", r.rule, r.name)
		}
		return dec
	}
	return awgFlowTraceDecision{Decision: "direct", Reason: "flow: no AWG2 rule matched"}
}

func awgFlowDstMatches(dst netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(dst) {
			return true
		}
	}
	return false
}

func awgFlowTraceEntry(c netmon.Conn, dec awgFlowTraceDecision, event string) TraceEntry {
	reason := dec.Reason
	if detail := awgFlowEventReason(event, c); detail != "" {
		if reason != "" {
			reason += "; " + detail
		} else {
			reason = detail
		}
	}
	name := awgFlowTraceName(c)
	if host := traceHostForIP(c.Dst.String()); host != "" {
		name = host
		if reason != "" {
			reason += "; host=" + host
		} else {
			reason = "host=" + host
		}
	}
	return TraceEntry{
		Kind:        "flow",
		Src:         c.Src.String(),
		Name:        name,
		Dst:         c.Dst.String(),
		Decision:    dec.Decision,
		Rule:        dec.Rule,
		Reason:      reason,
		Proto:       c.Proto,
		Sport:       c.SrcPort,
		Dport:       c.DstPort,
		State:       c.State,
		Event:       event,
		Packets:     c.Packets,
		Bytes:       c.Bytes,
		ReplyBytes:  c.ReplyBytes,
		Unreplied:   c.Unreplied,
		Assured:     c.Assured,
		TunnelID:    dec.TunnelID,
		TunnelIface: dec.TunnelIface,
	}
}

func (svc *Service) awgFlowTraceMaybeResolveHost(c netmon.Conn, dec awgFlowTraceDecision) {
	ip := c.Dst.String()
	if ip == "" || traceHostForIP(ip) != "" {
		return
	}
	now := time.Now()
	awgFlowPTR.Lock()
	if until, ok := awgFlowPTR.negative[ip]; ok {
		if until.After(now) {
			awgFlowPTR.Unlock()
			return
		}
		delete(awgFlowPTR.negative, ip)
	}
	if awgFlowPTR.inFlight[ip] {
		awgFlowPTR.Unlock()
		return
	}
	awgFlowPTR.inFlight[ip] = true
	awgFlowPTR.Unlock()

	go func() {
		defer func() {
			awgFlowPTR.Lock()
			delete(awgFlowPTR.inFlight, ip)
			awgFlowPTR.Unlock()
		}()
		select {
		case awgFlowPTR.slots <- struct{}{}:
			defer func() { <-awgFlowPTR.slots }()
		default:
			awgFlowPTR.Lock()
			awgFlowPTR.negative[ip] = time.Now().Add(time.Minute)
			awgFlowPTR.Unlock()
			return
		}
		host := awgFlowTraceLookupPTR(ip)
		if host == "" {
			awgFlowPTR.Lock()
			awgFlowPTR.negative[ip] = time.Now().Add(awgFlowTracePTRNegative)
			awgFlowPTR.Unlock()
			return
		}
		traceRememberHost(ip, host)
		if traceEnabled() {
			traceAppend(awgFlowTraceEntry(c, dec, "host"))
		}
	}()
}

func awgFlowTraceLookupPTR(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), awgFlowTracePTRTimeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return ""
	}
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" || net.ParseIP(name) != nil {
			continue
		}
		return name
	}
	return ""
}

func awgFlowTraceName(c netmon.Conn) string {
	proto := strings.ToLower(c.Proto)
	switch {
	case proto == "udp" && c.DstPort == 443:
		return "QUIC udp/443"
	case proto == "udp" && c.DstPort > 0:
		return "UDP/" + strconv.Itoa(c.DstPort)
	case proto == "udp":
		return "UDP"
	case proto == "tcp" && c.DstPort == 443:
		return "TLS tcp/443"
	case proto == "tcp" && c.DstPort > 0:
		return "TCP/" + strconv.Itoa(c.DstPort)
	case proto == "tcp":
		return "TCP"
	case proto == "icmp":
		return "ICMP"
	default:
		return strings.ToUpper(proto)
	}
}

func awgFlowEventReason(event string, c netmon.Conn) string {
	switch event {
	case "new":
		if c.Failing() {
			return "new flow, no reply yet"
		}
		return "new flow"
	case "unreplied":
		return "no reply for more than 2s"
	case "replied":
		return "reply appeared"
	case "host":
		return "reverse DNS"
	case "gone":
		return "flow disappeared while still failing"
	default:
		return ""
	}
}

func awgFlowTraceInteresting(c netmon.Conn) bool {
	if !c.Src.IsValid() || !c.Dst.IsValid() {
		return false
	}
	if c.Zone == "swan" {
		return false
	}
	if !awgFlowTraceLANSource(c.Src, c.Zone) || !awgFlowTraceMeaningfulDst(c.Dst) {
		return false
	}
	switch strings.ToLower(c.Proto) {
	case "tcp", "udp", "icmp":
		return true
	default:
		return false
	}
}

func awgFlowTraceLANSource(src netip.Addr, zone string) bool {
	if !src.IsValid() || src.IsLoopback() || src.IsLinkLocalUnicast() || src.IsMulticast() {
		return false
	}
	if zone == "slan" {
		return true
	}
	return src.IsPrivate()
}

func awgFlowTraceMeaningfulDst(dst netip.Addr) bool {
	if !dst.IsValid() || dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsMulticast() {
		return false
	}
	if dst.IsPrivate() {
		return false
	}
	if dst.Is4() {
		a := dst.As4()
		if a == ([4]byte{255, 255, 255, 255}) {
			return false
		}
	}
	return true
}

func awgFlowTraceKey(c netmon.Conn) string {
	return strings.Join([]string{
		c.Proto,
		c.Src.String(),
		strconv.Itoa(c.SrcPort),
		c.Dst.String(),
		strconv.Itoa(c.DstPort),
	}, "|")
}

func awgPruneFlowTraceState(seen map[string]*awgFlowTraceState, now time.Time) {
	for key, st := range seen {
		if now.Sub(st.lastSeen) > awgFlowTracePruneAfter {
			delete(seen, key)
		}
	}
	if len(seen) <= awgFlowTraceHardMaxState {
		return
	}
	type item struct {
		key string
		at  time.Time
	}
	items := make([]item, 0, len(seen))
	for key, st := range seen {
		items = append(items, item{key: key, at: st.lastSeen})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	for _, it := range items[:len(items)-awgFlowTraceMaxState] {
		delete(seen, it.key)
	}
}
