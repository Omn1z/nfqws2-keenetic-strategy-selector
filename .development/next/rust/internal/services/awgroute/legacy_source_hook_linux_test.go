//go:build linux

package awgroute

import (
	"slices"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestLegacyFullSourceMACsAndDestinationSets(t *testing.T) {
	zones := []awg.Zone{
		{Enabled: true, Route: "direct", SourceIPs: []string{"192.168.1.17"}, IPs: []string{"2001:db8:11::/48"}},
		{Enabled: true, Route: "tunnel", SourceIPs: []string{"192.168.1.17"}, IPs: []string{"2001:db8:12::/48"}},
		{Enabled: true, Route: "tunnel", SourceIPs: []string{"192.168.1.19"}},
	}
	var cfg awg.ServerConfig
	cfg.Routing.Zones = zones
	var svc Service
	sets := svc.awgPrepareSourceSetsWithLookup(&cfg, func(string) []string { t.Fatal("numeric fixture ran DNS"); return nil })
	for i, p := range []string{"2001:db8:11::/48", "2001:db8:12::/48"} {
		row := "add " + sourceZoneSetName6(i) + " " + p + "\n"
		if strings.Count(sets, row) != 1 || strings.Contains(sets, "add "+sourceZoneSetName(i)+" "+p) {
			t.Fatalf("wrong family/owner for %s", p)
		}
	}
	if strings.Contains(sets, "add "+sourceZoneSetName6(2)+" ") {
		t.Fatal("blanket cannot insert an address into its set")
	}
	src := "192.168.1.17"
	expected := func(t *testing.T, doc string, ordered ...string) {
		t.Helper()
		for _, line := range ordered {
			_, rest, ok := strings.Cut(doc, line+"\n")
			if !ok {
				t.Fatalf("missing or misordered rule %q", line)
			}
			doc = rest
		}
	}
	for _, scenario := range []struct {
		name        string
		known, dual bool
	}{
		{"resolved-dual", true, true}, {"resolved-reject", true, false}, {"unresolved-dual", false, true}, {"unresolved-reject", false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var reads []string
			neighbour := func() map[string]string {
				table := readMACBatch(func(cmd string) (string, error) {
					reads = append(reads, cmd)
					if !scenario.known {
						return "", nil
					}
					switch cmd {
					case "ip -4 neigh show":
						return src + " dev br0 lladdr 02:AA:BB:CC:DD:17 STALE\n192.168.1.19 dev br0 FAILED", nil
					case "ip -6 neigh show":
						return "2001:db8::19 dev br0 lladdr 02:AA:BB:CC:DD:19 REACHABLE", nil
					default:
						t.Fatalf("unexpected neighbour read %q", cmd)
						return "", nil
					}
				})
				if scenario.known && table["2001:db8::19"] != "02:aa:bb:cc:dd:19" {
					t.Fatal("IPv6 neighbour table must be read independently")
				}
				return table
			}
			hook := renderAWGFirewallHook(neighbour, "awg0", "full", "192.0.2.10", "eth0", 1280, false, scenario.dual, false, zones)
			if !slices.Equal(reads, []string{"ip -4 neigh show", "ip -6 neigh show"}) {
				t.Fatalf("unexpected neighbour reads %q", reads)
			}
			target := "MARK --set-xmark " + awgMarkRule
			expected(t, hook, "-A AWG2_MARK -s "+src+" -m set --match-set "+sourceZoneSetName(0)+" dst -j RETURN",
				"-A AWG2_MARK -s "+src+" -m set --match-set "+sourceZoneSetName(1)+" dst -j "+target,
				"-A AWG2_MARK -s 192.168.1.19 -j "+target)
			if scenario.known {
				p := "-A AWG2_MARK6 -m mac --mac-source 02:aa:bb:cc:dd:17 -m set --match-set "
				expected(t, hook, p+sourceZoneSetName6(0)+" dst -j RETURN", p+sourceZoneSetName6(1)+" dst -j "+target)
			} else if strings.Contains(hook, "-m mac --mac-source") {
				t.Fatal("unknown neighbour gained a source rule")
			}
			if strings.Contains(hook, "--mac-source 02:aa:bb:cc:dd:19") {
				t.Fatal("an unrelated IPv6 neighbour granted an IPv4 source selector")
			}
			mark := strings.Contains(hook, "-A AWG2_MARK6 -j "+target+"\n")
			reject := strings.Contains(hook, "-I FORWARD 1 -o eth0 -m comment --comment \""+awgV6LeakComment+"\" -j REJECT")
			if mark != scenario.dual || reject == scenario.dual {
				t.Fatalf("dual=%t global mark=%t WAN reject=%t", scenario.dual, mark, reject)
			}
		})
	}
}
