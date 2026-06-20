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

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// ipset membership for split-routing + on-disk persistence so the learned IPs and
// the DNS proxy's seen-domains cache survive a panel restart / reboot.

const (
	awgSetDir     = "/opt/etc/nfqws2-strategy"
	awgRecentFile = awgSetDir + "/awg2_recent.json"
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
	if !force {
		if last := svc.route.lastZonesHash.Load(); last != nil && *last == h {
			return nil // zones unchanged since last build — leave the kernel ipsets alone
		}
	}
	defer svc.route.lastZonesHash.Store(&h)

	_, _ = awgRun("ipset create " + awgSetInc + " hash:net family inet -exist")
	_, _ = awgRun("ipset create " + awgSetExc + " hash:net family inet -exist")
	_, _ = awgRun("ipset create " + awgSetInc + "_6 hash:net family inet6 -exist")
	_, _ = awgRun("ipset create " + awgSetExc + "_6 hash:net family inet6 -exist")
	// When the DNS proxy is in use it adds matched mask IPs dynamically — don't flush
	// them here (the refresh path flushes explicitly when zones change), otherwise the
	// watchdog's periodic rebuild would wipe every proxy-learned IP between queries.
	if !awgUsesDNSProxy(cfg) {
		_, _ = awgRun("ipset flush " + awgSetInc)
		_, _ = awgRun("ipset flush " + awgSetExc)
		_, _ = awgRun("ipset flush " + awgSetInc + "_6")
		_, _ = awgRun("ipset flush " + awgSetExc + "_6")
	}

	// Build the whole load script and pipe it into a single `ipset restore`. With
	// catch-all zones (geosite:cn + geoip:cn) the entries can be > 30k; one
	// fork+exec saves minutes vs N invocations of `ipset add`.
	seen := map[string]struct{}{}
	var b strings.Builder
	addLine := func(set, entry string) bool {
		key := set + " " + entry
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
		b.WriteString("add ")
		b.WriteString(set)
		b.WriteByte(' ')
		b.WriteString(entry)
		b.WriteByte('\n')
		return true
	}

	nInc, nExc := 0, 0
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled {
			continue
		}
		// Source-bound zones get their own per-zone ipset built below — skip them
		// here so their destinations don't leak into the global include/exclude
		// sets that would apply to every device on the LAN.
		if len(z.SourceIPs) > 0 {
			continue
		}
		// Each zone feeds its OWN direction's set; v4 and v6 entries go to the
		// family-matching ipset (awg2_inc / awg2_inc_6 etc.) so ip6tables can
		// match them in the IPv6 chain.
		set4, set6 := awgSetInc, awgSetInc+"_6"
		if z.Mode == "exclude" {
			set4, set6 = awgSetExc, awgSetExc+"_6"
		}
		bump := func() {
			if z.Mode == "exclude" {
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
				if provider, ok := sharedCDNProvider(ip); ok {
					svc.awgNoteSharedCDNSkip("resolve", "", ip, provider)
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
	if b.Len() > 0 {
		if _, err := awgRunStdin("ipset restore -exist", b.String()); err != nil {
			logbuf.Append("awg2", "warn", "ipset restore (global): "+err.Error())
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("ipset: include=%d, exclude=%d записей", nInc, nExc))
	svc.awgBuildSourceSets(cfg)
	return nil
}

// awgBuildSourceSets creates one ipset per enabled source-bound zone and fills
// it with the zone's expanded domains/IPs. The firewall hook references these
// sets in the per-source mangle rules (see firewall_linux.go). Source-bound
// zones are intentionally isolated from awg2_inc/exc so they only affect the
// devices named in `source_ips`, never the rest of the LAN.
func (svc *Service) awgBuildSourceSets(cfg *awg.ServerConfig) {
	sb := sourceBoundZones(cfg.Routing.Zones)
	for i, z := range sb {
		set4 := sourceZoneSetName(i)
		set6 := sourceZoneSetName6(i)
		_, _ = awgRun("ipset create " + set4 + " hash:net family inet -exist")
		_, _ = awgRun("ipset create " + set6 + " hash:net family inet6 -exist")
		_, _ = awgRun("ipset flush " + set4)
		_, _ = awgRun("ipset flush " + set6)
		if len(z.Domains) == 0 && len(z.IPs) == 0 {
			continue // empty destinations = whole-source rule, no ipset entries needed
		}
		// Build the whole ipset script in memory and feed it to a SINGLE
		// `ipset restore` invocation. With a category like geosite:ru + geoip:ru
		// this can be 20–30k lines — one fork+exec instead of that many is the
		// difference between «apply takes 2 minutes» and «apply takes 1 second».
		expDomains, expIPs := svc.expandEntries(z.Domains)
		seen := map[string]struct{}{}
		var b strings.Builder
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
		if b.Len() == 0 {
			continue
		}
		if _, err := awgRunStdin("ipset restore -exist", b.String()); err != nil {
			logbuf.Append("awg2", "warn", fmt.Sprintf("ipset restore zone[%d]: %v", i, err))
		}
	}
}

func awgResetSNISet() {
	_, _ = awgRun("ipset create " + awgSetSNI + " hash:ip family inet timeout " + strconv.Itoa(awgSNITTL) + " -exist")
	_, _ = awgRun("ipset flush " + awgSetSNI + " 2>/dev/null")
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
func awgRestoreSets() {
	for _, s := range []string{awgSetInc, awgSetExc} {
		f := awgSetDir + "/" + s + ".ipset"
		_, _ = awgRun("[ -f " + f + " ] && grep '^add ' " + f + " 2>/dev/null | while read _a st ip _r; do ipset add \"$st\" \"$ip\" -exist 2>/dev/null; done; true")
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
