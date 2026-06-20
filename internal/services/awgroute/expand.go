package awgroute

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/geo"
	"nfqws2strategy/internal/tools/logbuf"
)

// nfqws2 hostlist/ipset directory — the same plain-text files the bypass engine
// uses for its DPI filters. Reusing them as AWG zone sources via `list:NAME` so
// the user doesn't maintain two copies of the same list.
const awgNfqwsListsDir = "/opt/etc/nfqws2/lists"

// expandEntries walks a zone's Domains slice and resolves any xray-style prefix
// (`domain:`, `full:`, `geosite:CATEGORY`, `geoip:CATEGORY`, `list:NAME`) into
// the flat (plain domains, plain IPs/CIDRs) pair the rest of the routing engine
// already knows how to consume. Plain entries pass through unchanged so existing
// zones keep working byte-for-byte; unknown prefixes likewise pass through so
// the user gets the same noisy failure they would today.
//
// The expansion is performed every time the firewall/ipset/DNS pipeline rebuilds
// (apply, watchdog, DNS-proxy reload). That keeps geosite/list edits picked up
// without the user having to retype zone contents.
func (svc *Service) expandEntries(in []string) (domains, ips []string) {
	seenDom := map[string]struct{}{}
	seenIP := map[string]struct{}{}
	pushDom := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seenDom[s]; ok {
			return
		}
		seenDom[s] = struct{}{}
		domains = append(domains, s)
	}
	pushIP := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seenIP[s]; ok {
			return
		}
		seenIP[s] = struct{}{}
		ips = append(ips, s)
	}
	pushAuto := func(s string) {
		if isIPish(s) {
			pushIP(s)
		} else {
			pushDom(s)
		}
	}

	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		lower := strings.ToLower(raw)
		switch {
		case strings.HasPrefix(lower, "domain:"):
			pushDom(strings.TrimSpace(raw[len("domain:"):]))
		case strings.HasPrefix(lower, "full:"):
			// "full" means exact match in xray. Our ipset engine resolves to IPs the
			// same way for suffix and exact, so it collapses to a plain domain here;
			// per-connection exact matching belongs in phase 3 (SNI sniffer).
			pushDom(strings.TrimSpace(raw[len("full:"):]))
		case strings.HasPrefix(lower, "geosite:"):
			cat := strings.TrimSpace(raw[len("geosite:"):])
			entries, _ := geo.LookupCategory(svc.store.Path("geo"), geo.KindGeoSite, cat)
			if len(entries) == 0 {
				logbuf.Append("awg2", "warn", "zone: geosite-категория \""+cat+"\" пустая или не найдена — загрузите geosite.dat или проверь имя")
			}
			for _, e := range entries {
				pushAuto(e)
			}
		case strings.HasPrefix(lower, "geoip:"):
			cat := strings.TrimSpace(raw[len("geoip:"):])
			entries, _ := geo.LookupCategory(svc.store.Path("geo"), geo.KindGeoIP, cat)
			if len(entries) == 0 {
				logbuf.Append("awg2", "warn", "zone: geoip-категория \""+cat+"\" пустая или не найдена — загрузите geoip.dat или проверь имя")
			}
			for _, e := range entries {
				pushAuto(e)
			}
		case strings.HasPrefix(lower, "list:"):
			name := strings.TrimSpace(raw[len("list:"):])
			entries := readNfqwsList(name)
			if len(entries) == 0 {
				logbuf.Append("awg2", "warn", "zone: список \""+name+"\" пустой или не найден в /opt/etc/nfqws2/lists/")
			}
			for _, e := range entries {
				pushAuto(e)
			}
		case strings.HasPrefix(lower, "regexp:"):
			// xray `regexp:` → the matcher's native `[re]` prefix (Go regexp over
			// the lowercased SNI / DNS query name). Runtime regex match happens in
			// the SNI sniffer / DNS proxy that's already wired into the routing
			// pipeline, so no extra infra is needed.
			expr := strings.TrimSpace(raw[len("regexp:"):])
			if expr != "" {
				pushDom("[re]" + expr)
			}
		case strings.HasPrefix(lower, "keyword:"):
			// xray `keyword:foo` → glob `*foo*` (substring) — same anchoring
			// semantics, picked up by the existing glob branch of NewDomainMatcher.
			kw := strings.TrimSpace(raw[len("keyword:"):])
			if kw != "" {
				pushDom("*" + kw + "*")
			}
		default:
			pushAuto(raw)
		}
	}
	return
}

// readNfqwsList reads /opt/etc/nfqws2/lists/<name>.list (.gz auto-detected and
// transparently decompressed), returning one entry per non-empty non-comment line.
// Returns an empty slice on any error — by design: a missing list is a soft fail
// that the apply path surfaces as "list is empty", not a hard error.
func readNfqwsList(name string) []string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || strings.ContainsAny(name, "/\\") {
		return nil
	}
	// Accept either a bare `user` (resolves to user.list / user.list.gz) or the
	// fully-spelled `user.list` from the user.
	if !strings.HasSuffix(name, ".list") && !strings.HasSuffix(name, ".gz") {
		name = name + ".list"
	}
	tryPaths := []string{
		filepath.Join(awgNfqwsListsDir, name),
		filepath.Join(awgNfqwsListsDir, name+".gz"),
	}
	var data []byte
	for _, p := range tryPaths {
		b, err := readMaybeGzipped(p)
		if err == nil {
			data = b
			break
		}
	}
	if data == nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func readMaybeGzipped(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if strings.HasSuffix(p, ".gz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	}
	return io.ReadAll(f)
}

// isIPish: a thin local copy of the helper in app_geo.go so awgroute does not
// take a dependency on the App package just for this.
func isIPish(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

// sourceBoundZones returns the enabled zones that carry a `source_ips` filter,
// in the same order they appear in cfg.Routing.Zones. Used by both the per-zone
// ipset builder (sets_linux.go) and the firewall hook renderer (firewall_linux.go)
// so each per-source rule references its own ipset by a deterministic index.
func sourceBoundZones(zones []awg.Zone) []awg.Zone {
	var out []awg.Zone
	for _, z := range zones {
		if z.Enabled && len(z.SourceIPs) > 0 {
			out = append(out, z)
		}
	}
	return out
}

// sourceZoneSetName names the per-zone ipset for the i-th source-bound zone.
// hash:net (IPv4) — same family as awg2_inc/exc so resolved domains and CIDRs
// both fit. The name is short enough to fit ipset's 31-char limit.
func sourceZoneSetName(idx int) string  { return fmt.Sprintf("awg2_z%d", idx) }
func sourceZoneSetName6(idx int) string { return fmt.Sprintf("awg2_z%d_6", idx) }

// isIPv6 reports whether s parses as an IPv6 literal (incl. mapped). Used by
// the DNS proxy onMatch to choose between hash:net inet vs inet6 ipsets.
func isIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}
