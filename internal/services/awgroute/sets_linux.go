//go:build linux

package awgroute

import (
	"encoding/json"
	"fmt"
	"os"
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

// awgEffectiveMode collapses the per-zone directions + global mode into the chain
// shape the firewall hook renders:
//
//	"full"    → mark everything (route all traffic)
//	"include" → whitelist: only include-zones tunnel; exclude-zones carve out
//	"exclude" → blacklist: everything tunnels except exclude-zones
//	""        → "zones" but no enabled zones with entries → nothing marked (all direct)
//	"off"     → routing disabled
//
// Rule: if ANY enabled include-zone has entries → whitelist (the user is selecting
// what goes through VPN). If there are only exclude-zones → blacklist (everything
// via VPN except them).
func awgEffectiveMode(r awg.RoutingConfig) string {
	switch r.Mode {
	case "off":
		return "off"
	case "full":
		return "full"
	}
	hasInc, hasExc := false, false
	for _, z := range r.Zones {
		if !z.Enabled || (len(z.Domains) == 0 && len(z.IPs) == 0) {
			continue
		}
		if z.Mode == "exclude" {
			hasExc = true
		} else {
			hasInc = true
		}
	}
	switch {
	case hasInc:
		return "include"
	case hasExc:
		return "exclude"
	default:
		return ""
	}
}

// isMaskEntry reports whether a zone domain entry is a glob/regex mask (which the
// DNS proxy resolves on the fly) rather than a plain resolvable hostname.
func isMaskEntry(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ContainsAny(s, "*#") || strings.HasPrefix(s, "[re]")
}

func (svc *Service) awgBuildSets(cfg *awg.ServerConfig) error {
	_, _ = awgRun("ipset create " + awgSetInc + " hash:net family inet -exist")
	_, _ = awgRun("ipset create " + awgSetExc + " hash:net family inet -exist")
	// In dnsproxy mode the proxy adds matched mask IPs dynamically — don't flush them
	// here (the refresh path flushes explicitly when zones change).
	if cfg.Routing.DomainSource != "dnsproxy" {
		_, _ = awgRun("ipset flush " + awgSetInc)
		_, _ = awgRun("ipset flush " + awgSetExc)
	}
	nInc, nExc := 0, 0
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled {
			continue
		}
		// Each zone feeds its OWN set by its direction: include → awg2_inc (tunnel),
		// exclude → awg2_exc (bypass).
		target := awgSetInc
		if z.Mode == "exclude" {
			target = awgSetExc
		}
		bump := func() {
			if z.Mode == "exclude" {
				nExc++
			} else {
				nInc++
			}
		}
		for _, ip := range z.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, err := awgRun("ipset add " + target + " " + ip + " -exist"); err == nil {
				bump()
			}
		}
		for _, d := range z.Domains {
			// Mask/regex entries (e.g. "2ip.*", "*ip*", "[re]…") can't be resolved as
			// a hostname — trying to (net.LookupHost on a bogus name) blocks on slow
			// DNS timeouts and would hang «Сохранить и применить». The DNS proxy is
			// what matches masks, so skip them here; only PLAIN domains get a direct
			// server-side resolve (which makes them tunnel/bypass immediately).
			if isMaskEntry(d) {
				continue
			}
			for _, ip := range resolveDomain(d) {
				_, _ = awgRun("ipset add " + target + " " + ip + "/32 -exist")
				bump()
			}
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("ipset: include=%d, exclude=%d записей", nInc, nExc))
	return nil
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
