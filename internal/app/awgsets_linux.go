//go:build linux

package app

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

// awgTargetSet is the ipset the active mode populates.
func awgTargetSet(mode string) string {
	if mode == "exclude" {
		return awgSetExc
	}
	return awgSetInc
}

// isMaskEntry reports whether a zone domain entry is a glob/regex mask (which the
// DNS proxy resolves on the fly) rather than a plain resolvable hostname.
func isMaskEntry(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ContainsAny(s, "*#") || strings.HasPrefix(s, "[re]")
}

func (a *App) awgBuildSets(cfg *awg.ServerConfig) error {
	_, _ = awgRun("ipset create " + awgSetInc + " hash:net family inet -exist")
	_, _ = awgRun("ipset create " + awgSetExc + " hash:net family inet -exist")
	target := awgSetInc
	if cfg.Routing.Mode == "exclude" {
		target = awgSetExc
	}
	// In dnsproxy mode the proxy adds matched IPs dynamically — don't flush them.
	if cfg.Routing.DomainSource != "dnsproxy" {
		_, _ = awgRun("ipset flush " + target)
	}
	n := 0
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled {
			continue
		}
		for _, ip := range z.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, err := awgRun("ipset add " + target + " " + ip + " -exist"); err == nil {
				n++
			}
		}
		for _, d := range z.Domains {
			// Mask/regex entries (e.g. "2ip.*", "*ip*", "[re]…") can't be resolved as
			// a hostname — trying to (net.LookupHost on a bogus name) blocks on slow
			// DNS timeouts and would hang «Сохранить и применить». The DNS proxy is
			// what matches masks, so skip them here; only PLAIN domains get a direct
			// server-side resolve (which makes them tunnel immediately).
			if isMaskEntry(d) {
				continue
			}
			for _, ip := range resolveDomain(d) {
				_, _ = awgRun("ipset add " + target + " " + ip + "/32 -exist")
				n++
			}
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("ipset %s: %d записей", target, n))
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
func (a *App) awgSaveRecent() {
	a.awgRoute.mu.Lock()
	p := a.awgRoute.dnsProxy
	a.awgRoute.mu.Unlock()
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
func (a *App) awgLoadRecent(p *awg.DNSProxy) {
	b, err := os.ReadFile(awgRecentFile)
	if err != nil {
		return
	}
	var m map[string][]string
	if json.Unmarshal(b, &m) == nil && len(m) > 0 {
		p.LoadRecent(m)
	}
}
