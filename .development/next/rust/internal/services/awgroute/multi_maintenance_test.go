package awgroute

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMultiMaintenanceHealthyAuditDoesNotBlockDNSOrDiscardLearnedMemo(t *testing.T) {
	svc := &Service{}
	svc.routingDNSGate.learned = map[string]time.Time{"awgm_000\x00192.0.2.1": time.Now().Add(time.Minute)}
	before := svc.routingDNSGate.writeEpoch
	release, err := svc.routingDNSGate.acquire(context.Background(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- svc.awgMaintainMultiPolicy(false, 1, func() bool { return true }, func() error { return errors.New("unnecessary refresh") }, func() error { return errors.New("unnecessary repair") })
	}()
	select {
	case err := <-done:
		release()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		release()
		<-done
		t.Fatal("healthy audit waited for a DNS reader")
	}
	if svc.routingDNSGate.writeEpoch != before || len(svc.routingDNSGate.learned) != 1 || !svc.RoutingDNSReadiness().Ready {
		t.Fatal("read-only audit changed the policy gate/cache")
	}
}

func TestMultiMaintenancePeriodicRefreshPreservesGenerationAndUsesBarrier(t *testing.T) {
	svc := &Service{}
	finish := svc.routingDNSGate.begin(true)
	finish(nil)
	generation := svc.routingDNSGate.version()
	called := false
	if err := svc.awgMaintainMultiPolicy(false, 15, func() bool { return true }, func() error {
		called = true
		if !svc.RoutingDNSReadiness().Applying {
			t.Fatal("set swap ran outside the DNS barrier")
		}
		return nil
	}, func() error { t.Fatal("healthy periodic refresh rebuilt the firewall/proxy"); return nil }); err != nil {
		t.Fatal(err)
	}
	if !called || svc.routingDNSGate.version() != generation || !svc.RoutingDNSReadiness().Ready {
		t.Fatal("periodic maintenance invalidated the learner generation")
	}
}

func TestMultiMaintenanceMissingStateAndFailedReadinessRetryCompleteRepair(t *testing.T) {
	for _, scenario := range []string{"missing hook", "firewall mismatch", "failed sets"} {
		t.Run(scenario, func(t *testing.T) {
			svc := &Service{}
			failure := errors.New("kernel install failed")
			if scenario == "failed sets" {
				finish := svc.routingDNSGate.begin(true)
				finish(failure)
			}
			repairCalls := 0
			for attempt := 0; attempt < 2; attempt++ {
				err := svc.awgMaintainMultiPolicy(scenario == "missing hook", 1, func() bool { return scenario != "firewall mismatch" }, func() error { t.Fatal("incomplete refresh used for failed state"); return nil }, func() error {
					repairCalls++
					if !svc.RoutingDNSReadiness().Applying {
						t.Fatal("repair outside the gate")
					}
					if attempt == 0 {
						return failure
					}
					return nil
				})
				if attempt == 0 && (!errors.Is(err, failure) || svc.RoutingDNSReadiness().Ready) {
					t.Fatal("failed repair was hidden")
				}
				if attempt == 1 && (err != nil || !svc.RoutingDNSReadiness().Ready) {
					t.Fatal("confirmed retry remained unavailable")
				}
			}
			if repairCalls != 2 {
				t.Fatal("failed readiness did not keep full recovery")
			}
		})
	}
}

func TestMultiFirewallAuditDetectsPartialResetAndOrderChanges(t *testing.T) {
	want := []string{"-A AWG2_MULTI -d 192.0.2.1/32 -j RETURN", "-A AWG2_MULTI -s 192.168.3.20 -m set --match-set awgm_000 dst -j MARK --set-xmark 0x10100000/0x1ff00000", "-A AWG2_MULTI -m set --match-set awgm_000 dst -j ACCEPT"}
	shared := map[string][]string{"nat/POSTROUTING": {"-A POSTROUTING -o awg0 -j MASQUERADE"}, "filter/FORWARD": {"-A FORWARD -i awg0 -j ACCEPT"}}
	saved := "*mangle\n:AWG2_MULTI - [0:0]\n-A PREROUTING -j AWG2_MULTI\n-A OUTPUT -j AWG2_MULTI\n" + strings.Join(want, "\n") + "\nCOMMIT\n*nat\n-A POSTROUTING -o awg0 -j MASQUERADE\nCOMMIT\n*filter\n-A FORWARD -i awg0 -j ACCEPT\nCOMMIT\n"
	// Real iptables-save renders host selectors /32 and canonical hex values.
	saved = strings.ReplaceAll(saved, "-s 192.168.3.20 ", "-s 192.168.3.20/32 ")
	if !awgMultiFirewallIntact(saved, "AWG2_MULTI", want, shared) {
		t.Fatal("complete policy not recognized")
	}
	for name, corrupt := range map[string]string{
		"empty": "", "missing mark": strings.Replace(saved, strings.ReplaceAll(want[1], "-s 192.168.3.20 ", "-s 192.168.3.20/32 "), "", 1),
		"missing source mark":      strings.Replace(saved, "--set-xmark 0x10100000/0x1ff00000", "--set-xmark 0x10200000/0x1ff00000", 1),
		"missing NAT":              strings.ReplaceAll(saved, "-A POSTROUTING -o awg0 -j MASQUERADE", ""),
		"missing forward":          strings.ReplaceAll(saved, "-A FORWARD -i awg0 -j ACCEPT", ""),
		"jump below other marking": strings.Replace(saved, "-A PREROUTING -j AWG2_MULTI", "-A PREROUTING -j OTHER\n-A PREROUTING -j AWG2_MULTI", 1),
		"rule reordered":           strings.Replace(saved, want[0]+"\n", "", 1) + "*mangle\n" + want[0] + "\nCOMMIT\n",
	} {
		t.Run(name, func(t *testing.T) {
			if awgMultiFirewallIntact(corrupt, "AWG2_MULTI", want, shared) {
				t.Fatal("incomplete policy skipped repair")
			}
		})
	}
}

func TestMultiRouteAuditRequiresEndpointEscapeDefaultAndKillswitch(t *testing.T) {
	want := []awgMultiRouteExpectation{{Table: 901, Iface: "awg0", EndpointIP: "198.51.100.1", Online: true, Killswitch: true}}
	saved := "default via 192.0.2.1 dev eth3\ndefault dev awg0 table 901 scope link\nblackhole default table 901 metric 1000\n198.51.100.1 via 192.0.2.1 dev eth3\n"
	if !awgMultiRoutesIntact(saved, "192.0.2.1", "eth3", want) {
		t.Fatal("complete routes not recognized")
	}
	for _, line := range []string{"default dev awg0 table 901 scope link\n", "blackhole default table 901 metric 1000\n", "198.51.100.1 via 192.0.2.1 dev eth3\n"} {
		if awgMultiRoutesIntact(strings.ReplaceAll(saved, line, ""), "192.0.2.1", "eth3", want) {
			t.Fatalf("missing %s skipped repair", line)
		}
	}
	want[0].Online = false
	if !awgMultiRoutesIntact(strings.ReplaceAll(saved, "default dev awg0 table 901 scope link\n", ""), "192.0.2.1", "eth3", want) {
		t.Fatal("offline client route kept requiring an interface default")
	}
}

func TestMultiFirewallAuditCanonicalizesTCPFlagsWithoutLosingMaskBits(t *testing.T) {
	named := "-A FORWARD -o awg1 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380"
	hex := strings.Replace(named, "SYN,RST SYN", "0x06 0x02", 1)
	if awgCanonicalFirewallRule(named) != awgCanonicalFirewallRule(hex) {
		t.Fatal("equivalent flag representations require unnecessary repair")
	}
	different := strings.Replace(named, "SYN,RST SYN", "0x17 0x02", 1)
	if awgCanonicalFirewallRule(named) == awgCanonicalFirewallRule(different) {
		t.Fatal("different TCP flag masks were treated as equivalent")
	}
}

func TestMultiPeriodicSetSwapRetainsLearnedAddressesAndRemainingTimeouts(t *testing.T) {
	sets := []awgMultiSetRefresh{{Name: "awgm_000", Entries: []string{"192.0.2.1/32", "198.51.100.0/24"}}, {Name: "awgm_001", Entries: []string{"203.0.113.1/32"}}}
	saved := "create awgm_000 hash:net family inet hashsize 1024 maxelem 65536 timeout 600 counters\nadd awgm_000 192.0.2.1 timeout 37 packets 9 bytes 512\nadd awgm_000 192.0.2.2 timeout 119 packets 2 bytes 64\ncreate awgm_001 hash:net family inet hashsize 1024 maxelem 65536\n"
	prepare, commit, err := awgMultiSetRefreshDocuments(sets, saved)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"create awgm_000_r hash:net family inet hashsize 1024 maxelem 65536 timeout 600 counters", "add awgm_000_r 192.0.2.1 timeout 37 packets 9 bytes 512", "add awgm_000_r 192.0.2.2 timeout 119 packets 2 bytes 64", "add awgm_000_r 198.51.100.0/24 -exist"} {
		if !strings.Contains(prepare, want) {
			t.Fatalf("lost live set option/member: %s", want)
		}
	}
	if strings.Contains(prepare, "add awgm_000_r 192.0.2.1/32 -exist") || strings.Contains(prepare, "flush ") || strings.Contains(commit, "flush ") {
		t.Fatal("refresh reset remaining TTL or flushed a live set")
	}
	if !strings.Contains(commit, "swap awgm_000_r awgm_000\ndestroy awgm_000_r\n") {
		t.Fatal("live set was not atomically swapped")
	}
	var applied []string
	if err := awgCommitMultiSetRefresh(prepare, commit, func(document string) error { applied = append(applied, document); return nil }); err != nil || !reflect.DeepEqual(applied, []string{prepare, commit}) {
		t.Fatal("swap ran before all sets were prepared")
	}
	failed := errors.New("fill failed")
	applied = nil
	if err := awgCommitMultiSetRefresh(prepare, commit, func(document string) error { applied = append(applied, document); return failed }); !errors.Is(err, failed) || !reflect.DeepEqual(applied, []string{prepare}) {
		t.Fatal("failed staging replaced a live set")
	}
}

func TestMultiPeriodicSetSwapRejectsMissingOrForeignDefinitions(t *testing.T) {
	for _, saved := range []string{"", "create awgm_000 hash:ip family inet", "create awgm_000 hash:net family inet\nadd awgm_000 invalid-address"} {
		if _, _, err := awgMultiSetRefreshDocuments([]awgMultiSetRefresh{{Name: "awgm_000"}}, saved); err == nil {
			t.Fatal("invalid kernel state produced a destructive refresh")
		}
	}
}

// Reads a captured snapshot only; never invokes router commands. Useful for
// verifying old iptables/iproute2 canonical forms before deployment.
func TestMultiAuditCapturedRouterSnapshot(t *testing.T) {
	path := os.Getenv("N2S_TEST_AWG_POLICY_SNAPSHOT")
	if path == "" {
		t.Skip("no captured router snapshot specified")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]struct {
		Output, Error string
		Exit          int
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"iptables", "ip6tables_nat", "routes", "rules", "sets", "hook", "bridges"} {
		if saved[name].Exit != 0 || saved[name].Output == "" {
			t.Fatalf("incomplete snapshot: %s", name)
		}
	}
	var expected []string
	for _, line := range strings.Split(saved["hook"].Output, "\n") {
		if strings.HasPrefix(line, "-A AWG2_MULTI ") {
			expected = append(expected, line)
		}
	}
	shared := map[string][]string{
		"nat/POSTROUTING": {"-A POSTROUTING -o awg1 -j MASQUERADE"},
		"filter/FORWARD":  {"-A FORWARD -i awg1 -j ACCEPT", "-A FORWARD -o awg1 -j ACCEPT"},
		"mangle/FORWARD":  {"-A FORWARD -i awg1 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380", "-A FORWARD -o awg1 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380"},
	}
	for _, bridge := range strings.Fields(saved["bridges"].Output) {
		for _, proto := range []string{"udp", "tcp"} {
			shared["nat/PREROUTING"] = append(shared["nat/PREROUTING"], "-A PREROUTING -i "+bridge+" -p "+proto+" -m "+proto+" --dport 53 -j REDIRECT --to-ports 5354")
		}
	}
	if !awgMultiFirewallIntact(saved["iptables"].Output, "AWG2_MULTI", expected, shared) {
		t.Fatal("captured healthy firewall did not pass audit")
	}
	if !awgMultiFirewallIntact(saved["ip6tables_nat"].Output, "", nil, map[string][]string{"nat/PREROUTING": shared["nat/PREROUTING"]}) {
		t.Fatal("captured IPv6 DNS redirects did not pass audit")
	}
	if !awgMultiRoutesIntact(saved["routes"].Output, "192.168.0.1", "eth3", []awgMultiRouteExpectation{{Table: 901, Iface: "awg1", EndpointIP: "138.124.229.182", Online: true}}) {
		t.Fatal("captured healthy endpoint/tunnel routes did not pass audit")
	}
}
