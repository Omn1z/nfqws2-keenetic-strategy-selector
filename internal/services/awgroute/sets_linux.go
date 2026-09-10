//go:build linux

package awgroute

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// ipsetAddReq batches an "add this IP to that set" command from the DNS proxy
// or the SNI sniffer to a shared background flusher. ttlSec>0 emits a
// "timeout N" suffix (for the awg2_sni set which TTL-expires entries).
type ipsetAddReq struct {
	set    string
	ip     string
	ttlSec int
}

var (
	ipsetAddOnce sync.Once
	ipsetAddCh   chan ipsetAddReq
)

// ipsetAddAsync enqueues `ipset add <set> <ip> -exist` for batched execution.
// The batcher coalesces up to 128 adds (or 50ms, whichever fires first) into a
// single `ipset restore -exist` pipe — one fork+exec per ≤50ms instead of one
// per match. On a busy LAN that's ~30-50× fewer forks on the DNS-proxy and SNI
// hot paths. If the queue is full the caller falls back to a direct add so we
// never silently lose a learned IP.
func ipsetAddAsync(set, ip string) { ipsetAddAsyncTTL(set, ip, 0) }

// ipsetAddAsyncTTL is the timeout-aware variant for entries in the SNI ipset
// (which expires entries after awgSNITTL seconds). ttlSec=0 means no timeout.
func ipsetAddAsyncTTL(set, ip string, ttlSec int) {
	ipsetAddOnce.Do(func() {
		ipsetAddCh = make(chan ipsetAddReq, 4096)
		go ipsetAddBatcher(ipsetAddCh)
	})
	req := ipsetAddReq{set: set, ip: ip, ttlSec: ttlSec}
	select {
	case ipsetAddCh <- req:
	default:
		// Queue saturated — flusher is slower than producers. Direct add so we
		// don't drop the learned IP; the next packet to this destination still
		// gets routed correctly.
		if ttlSec > 0 {
			_, _ = awgRun("ipset add " + set + " " + ip + " timeout " + strconv.Itoa(ttlSec) + " -exist")
		} else {
			_, _ = awgRun("ipset add " + set + " " + ip + " -exist")
		}
	}
}

func ipsetAddBatcher(ch <-chan ipsetAddReq) {
	const maxBatch = 128
	const flushAfter = 50 * time.Millisecond
	buf := make([]ipsetAddReq, 0, maxBatch)
	var sb strings.Builder
	flush := func() {
		if len(buf) == 0 {
			return
		}
		sb.Reset()
		sb.Grow(len(buf) * 48)
		for _, r := range buf {
			sb.WriteString("add ")
			sb.WriteString(r.set)
			sb.WriteByte(' ')
			sb.WriteString(r.ip)
			if r.ttlSec > 0 {
				sb.WriteString(" timeout ")
				sb.WriteString(strconv.Itoa(r.ttlSec))
			}
			sb.WriteString(" -exist\n")
		}
		buf = buf[:0]
		_, _ = awgRunStdin("ipset restore", sb.String())
	}
	for {
		// First entry: block until something arrives, then start a flush timer.
		req, ok := <-ch
		if !ok {
			flush()
			return
		}
		buf = append(buf, req)
		timer := time.NewTimer(flushAfter)
	gather:
		for len(buf) < maxBatch {
			select {
			case r, ok2 := <-ch:
				if !ok2 {
					timer.Stop()
					flush()
					return
				}
				buf = append(buf, r)
			case <-timer.C:
				timer = nil
				break gather
			}
		}
		if timer != nil {
			timer.Stop()
		}
		flush()
	}
}

// ipset membership for split-routing + on-disk persistence so the learned IPs and
// the DNS proxy's seen-domains cache survive a panel restart / reboot.

const (
	awgSetDir     = "/opt/etc/nfqws2-strategy"
	awgRecentFile = awgSetDir + "/awg2_recent.json"
	// awgFMWMarker is the one-shot upgrade marker. Its absence on the first
	// awgBuildSetsForce call after upgrading to first-match-wins triggers a
	// fixup: flush awg2_inc/exc/_6, drop awg2_recent.json, force-rebuild
	// ignoring lastZonesHash. Without this, stale entries from the old
	// exclude-wins era would keep RETURNing tunnel traffic for IPs that
	// under the new semantics should be marked through awg0.
	awgFMWMarker = awgSetDir + "/.awg2_fmw_v1"
)

// awgEffectiveMode, isMaskEntry, awgUsesDNSProxy and the catch-all helpers live in
// mode.go (build-tag-free, so they can be unit-tested on any platform).

func (svc *Service) awgBuildSets(cfg *awg.ServerConfig) error {
	return svc.awgBuildSetsForce(cfg, false)
}

// awgBuildSetsForce is the actual builder. When force=false the call short-
// circuits if the zones config is byte-for-byte the same as the last successful
// build — the watchdog uses this so a "nothing changed" tick doesn't burn 30 s
// re-resolving 14 k entries and re-warming the geo parse cache (~150 MB).
// Apply / on-zone-change always passes force=true so a user edit always rebuilds.
func (svc *Service) awgBuildSetsForce(cfg *awg.ServerConfig, force bool) error {
	zb, _ := json.Marshal(cfg.Routing.Zones)
	sum := sha256.Sum256(zb)
	h := hex.EncodeToString(sum[:])
	// One-shot migration: stale awg2_inc/exc entries from the old "exclude
	// beats include" era keep firing in the firewall until they're flushed.
	// On the FIRST call after upgrade — marker absent — flush everything,
	// drop the persisted recent-cache, ignore lastZonesHash, then create the
	// marker so subsequent boots are normal.
	migrate := false
	if _, err := os.Stat(awgFMWMarker); err != nil {
		migrate = true
	}
	if !force && !migrate {
		if last := svc.route.lastZonesHash.Load(); last != nil && *last == h {
			return nil // zones unchanged since last build — leave the kernel ipsets alone
		}
	}
	defer svc.route.lastZonesHash.Store(&h)

	// Batch create + (optional) flush into the SAME `ipset restore -exist`
	// stream as the per-entry adds below. Was: 4 create forks + 4 flush
	// forks at the start of every apply. Now: zero extra forks here — they
	// piggyback on the single restore at the end.
	var preamble strings.Builder
	preamble.WriteString("create " + awgSetInc + " hash:net family inet -exist\n")
	preamble.WriteString("create " + awgSetExc + " hash:net family inet -exist\n")
	preamble.WriteString("create " + awgSetInc + "_6 hash:net family inet6 -exist\n")
	preamble.WriteString("create " + awgSetExc + "_6 hash:net family inet6 -exist\n")
	// When the DNS proxy is in use it adds matched mask IPs dynamically — don't flush
	// them here (the refresh path flushes explicitly when zones change), otherwise the
	// watchdog's periodic rebuild would wipe every proxy-learned IP between queries.
	// On migration we force the flush regardless so stale exclude-wins-era IPs go.
	if migrate || !awgUsesDNSProxy(cfg) {
		preamble.WriteString("flush " + awgSetInc + "\n")
		preamble.WriteString("flush " + awgSetExc + "\n")
		preamble.WriteString("flush " + awgSetInc + "_6\n")
		preamble.WriteString("flush " + awgSetExc + "_6\n")
	}
	if migrate {
		_ = os.Remove(awgRecentFile)
		logbuf.Append("awg2", "info", "first-match-wins: миграция — ipset awg2_inc/exc сброшены, recent-кеш удалён")
	}

	// Build the whole load script and pipe it into a single `ipset restore`. With
	// catch-all zones (geosite:cn + geoip:cn) the entries can be > 30k; one
	// fork+exec saves minutes vs N invocations of `ipset add`.
	//
	// First-match-wins dedup: key on ENTRY ALONE (not "set+entry"). The first
	// zone naming an IP claims it; later zones with the opposite route never
	// override that claim. Without this, the same IP could land in BOTH
	// awg2_inc AND awg2_exc and the kernel chain decided the winner — which
	// was the old "exclude beats include" bug at the ipset layer.
	claimed := map[string]struct{}{}
	var b strings.Builder
	addLine := func(set, entry string) bool {
		if _, ok := claimed[entry]; ok {
			return false
		}
		claimed[entry] = struct{}{}
		b.WriteString("add ")
		b.WriteString(set)
		b.WriteByte(' ')
		b.WriteString(entry)
		b.WriteByte('\n')
		return true
	}

	nInc, nExc := 0, 0
	for _, z := range effectiveZones(cfg.Routing) {
		if !z.Enabled {
			continue
		}
		// Source-bound zones get their own per-zone ipset built below — skip them
		// here so their destinations don't leak into the global include/exclude
		// sets that would apply to every device on the LAN.
		if len(z.SourceIPs) > 0 {
			continue
		}
		// Catch-all rule: nothing to write into the ipset — the firewall's
		// effective mode (full/exclude/"") handles it at the chain level.
		// We still HONOR the rest of the zone's IPs/Domains (if any) so a
		// rule like {tunnel, ["*", "1.2.3.0/24"]} still seeds 1.2.3.0/24
		// into awg2_inc.
		_ = z.IsCatchAll() // documents intent; loop below filters "*" via awgIsCatchAll
		// Each zone feeds its OWN direction's set; v4 and v6 entries go to the
		// family-matching ipset (awg2_inc / awg2_inc_6 etc.) so ip6tables can
		// match them in the IPv6 chain.
		set4, set6 := awgSetInc, awgSetInc+"_6"
		if z.RouteValue() == "direct" {
			set4, set6 = awgSetExc, awgSetExc+"_6"
		}
		bump := func() {
			if z.RouteValue() == "direct" {
				nExc++
			} else {
				nInc++
			}
		}
		// Expand xray-style prefixes (geosite:/geoip:/list:/domain:/full:) into the
		// flat (plain domains, plain IPs) the resolver and ipset below already know.
		// Plain entries pass through unchanged, so legacy zones stay byte-identical.
		expDomains, expIPs := svc.expandEntries(z.Domains)
		for _, ip := range append(append([]string{}, z.IPs...), expIPs...) {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			target := set4
			if isIPv6(strings.SplitN(ip, "/", 2)[0]) {
				target = set6
			}
			if addLine(target, ip) {
				bump()
			}
		}
		// Plain domains are resolved live via the shared parallel resolver (used
		// by source-bound zones too). Mask/regex stays in DNSProxy/SNI matchers.
		var plain []string
		for _, d := range expDomains {
			if !isMaskEntry(d) {
				plain = append(plain, d)
			}
		}
		for _, r := range parallelResolve(plain, 32) {
			for _, ip := range r {
				if _, ok := sharedCDNProvider(ip); ok {
					svc.awgNoteSharedCDNSkip("resolve", ip)
					continue
				}
				target, suffix := set4, "/32"
				if isIPv6(ip) {
					target, suffix = set6, "/128"
				}
				if addLine(target, ip+suffix) {
					bump()
				}
			}
		}
	}
	// Single fork: preamble (create + optional flush) ++ all adds. Replaces
	// 8 standalone create/flush forks at apply start.
	if preamble.Len() > 0 || b.Len() > 0 {
		full := preamble.String() + b.String()
		if _, err := awgRunStdin("ipset restore -exist", full); err != nil {
			logbuf.Append("awg2", "warn", "ipset restore (global): "+err.Error())
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("ipset: tunnel=%d, direct=%d записей (first-match-wins)", nInc, nExc))
	svc.awgBuildSourceSets(cfg)
	if migrate {
		_ = os.WriteFile(awgFMWMarker, []byte("ok\n"), 0o644)
	}
	return nil
}

// awgBuildSourceSets creates one ipset per enabled source-bound zone and fills
// it with the zone's expanded domains/IPs. The firewall hook references these
// sets in the per-source mangle rules (see firewall_linux.go). Source-bound
// zones are intentionally isolated from awg2_inc/exc so they only affect the
// devices named in `source_ips`, never the rest of the LAN.
func (svc *Service) awgBuildSourceSets(cfg *awg.ServerConfig) {
	sb := sourceBoundZones(cfg.Routing.Zones)
	// Single fork covers create + flush + every per-zone add across ALL
	// source-bound zones. Was: 4 ipset forks per zone (create v4, create v6,
	// flush v4, flush v6) + one restore per zone → 5N forks. Now: 1 fork
	// total regardless of N. With N=3-5 source-bound rules this saves
	// ~150-250 ms per apply.
	var b strings.Builder
	seen := map[string]struct{}{}
	addLine := func(set, entry string) {
		key := set + " " + entry
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		b.WriteString("add ")
		b.WriteString(set)
		b.WriteByte(' ')
		b.WriteString(entry)
		b.WriteByte('\n')
	}
	for i, z := range sb {
		set4 := sourceZoneSetName(i)
		set6 := sourceZoneSetName6(i)
		b.WriteString("create " + set4 + " hash:net family inet -exist\n")
		b.WriteString("create " + set6 + " hash:net family inet6 -exist\n")
		b.WriteString("flush " + set4 + "\n")
		b.WriteString("flush " + set6 + "\n")
		if len(z.Domains) == 0 && len(z.IPs) == 0 {
			continue // empty destinations = whole-source rule, no ipset entries needed
		}
		expDomains, expIPs := svc.expandEntries(z.Domains)
		for _, ip := range append(append([]string{}, z.IPs...), expIPs...) {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			target := set4
			if isIPv6(strings.SplitN(ip, "/", 2)[0]) {
				target = set6
			}
			addLine(target, ip)
		}
		// Plain domains need a live DNS resolve each. With geosite:category-ru that
		// is thousands of names; serial nslookup made apply take ~2 minutes. Fan
		// out across a small worker pool — the router's resolver handles parallel
		// queries fine and the wall-clock collapses to ~5 s.
		var plain []string
		for _, d := range expDomains {
			if !isMaskEntry(d) {
				plain = append(plain, d)
			}
		}
		for _, r := range parallelResolve(plain, 32) {
			for _, ip := range r {
				if _, ok := sharedCDNProvider(ip); ok {
					continue
				}
				target, suffix := set4, "/32"
				if isIPv6(ip) {
					target, suffix = set6, "/128"
				}
				addLine(target, ip+suffix)
			}
		}
	}
	// One ipset restore for the ENTIRE source-bound set tree.
	if b.Len() > 0 {
		if _, err := awgRunStdin("ipset restore -exist", b.String()); err != nil {
			logbuf.Append("awg2", "warn", "ipset restore (source-bound): "+err.Error())
		}
	}
}

// awgResetSNISet was rewritten as a single create+flush over `ipset restore`
// for the same fork-saving reason.
func awgResetSNISetBatched() string {
	return "create " + awgSetSNI + " hash:ip family inet timeout " + strconv.Itoa(awgSNITTL) + " -exist\n" +
		"flush " + awgSetSNI + "\n"
}

func awgResetSNISet() {
	// One fork via restore stream instead of two separate ipset invocations.
	_, _ = awgRunStdin("ipset restore -exist", awgResetSNISetBatched())
}

// awgSaveSets persists the ipset members so the IPs the DNS proxy learned for
// masked domains survive a panel restart / reboot (otherwise those domains fall
// out of the tunnel until each is queried again).
func awgSaveSets() {
	for _, s := range []string{awgSetInc, awgSetExc} {
		_, _ = awgRun("ipset save " + s + " 2>/dev/null > " + awgSetDir + "/" + s + ".ipset 2>/dev/null")
	}
}

// awgRestoreSets re-adds the persisted members into the (already-created) sets.
// Uses `ipset restore -exist` to load the whole save-file in a single fork
// instead of `while read | ipset add` per entry — that fork-per-IP loop took
// minutes on a 30k-entry RU bypass set; bulk restore takes ~second.
func awgRestoreSets() {
	for _, s := range []string{awgSetInc, awgSetExc} {
		f := awgSetDir + "/" + s + ".ipset"
		_, _ = awgRun("[ -f " + f + " ] && ipset restore -exist < " + f + " 2>/dev/null; true")
	}
}

// awgSaveRecent persists the DNS proxy's recently-seen name→IPs cache so that after
// a panel restart / reboot the masks re-apply to every domain seen before, without
// waiting for the device to look it up again (its DNS cache wouldn't re-query it).
func (svc *Service) awgSaveRecent() {
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	if p == nil {
		return
	}
	m := p.SnapshotRecent()
	if len(m) == 0 {
		return
	}
	if b, err := json.Marshal(m); err == nil {
		_ = os.WriteFile(awgRecentFile, b, 0o644)
	}
}

// awgLoadRecent restores the persisted name→IPs cache into a freshly-created proxy.
func (svc *Service) awgLoadRecent(p *awg.DNSProxy) {
	b, err := os.ReadFile(awgRecentFile)
	if err != nil {
		return
	}
	var m map[string][]string
	if json.Unmarshal(b, &m) == nil && len(m) > 0 {
		p.LoadRecent(m)
	}
}
