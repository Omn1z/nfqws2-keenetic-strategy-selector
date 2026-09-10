//go:build linux

package awgroute

import "strings"

// lookupMACBatch dumps the IPv4 AND IPv6 neighbour caches and returns a
// map[ip]mac. Hook generation calls this once and re-uses the map for every
// per-source-IP rule emit, replacing N forks with 2 (one per family).
//
// Stock busybox iproute2 prints only ONE family per invocation: `ip neigh show`
// without `-6` returns just the v4 table, so a source-bound zone whose
// source_ips entry is a real IPv6 address (e.g. a GUA from SLAAC) would never
// match a MAC and emitSourceRule6 would silently skip the rule. Run both
// families explicitly.
func lookupMACBatch() map[string]string {
	m := make(map[string]string, 64)
	for _, cmd := range []string{"ip -4 neigh show", "ip -6 neigh show"} {
		out, err := awgRun(cmd)
		if err != nil || out == "" {
			continue
		}
		for _, ln := range strings.Split(out, "\n") {
			fs := strings.Fields(ln)
			if len(fs) < 1 {
				continue
			}
			ip := fs[0]
			for i := 1; i < len(fs); i++ {
				if fs[i] == "lladdr" && i+1 < len(fs) {
					m[ip] = strings.ToLower(fs[i+1])
					break
				}
			}
		}
	}
	return m
}
