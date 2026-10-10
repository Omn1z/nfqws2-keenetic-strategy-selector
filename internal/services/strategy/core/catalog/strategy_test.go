package catalog

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// These checks constrain our own small catalog, not user-authored strategies.
// zapret-antidpi's fake splitters apply fooling to fake parts only. Plain
// multisplit/multidisorder apply it to real data, so damaging options belong
// only to the former. tcp_ts_up merely reorders an existing TCP option; it is
// not fooling on its own, nor does tcp_ack reliably protect timestamp-less
// clients. See upstream docs/manual.md#standard-fooling and #fakedsplit.
func TestCatalogProtectsEachTCPFake(t *testing.T) {
	for name, strategies := range map[string][]Strategy{"builtin": Builtin(), "auto": AutoCandidates()} {
		t.Run(name, func(t *testing.T) {
			seen := make(map[string]bool)
			for _, strategy := range strategies {
				t.Run(strategy.ID, func(t *testing.T) {
					if seen[strategy.ID] {
						t.Errorf("duplicate strategy ID %q", strategy.ID)
					}
					seen[strategy.ID] = true
					if err := Validate(strategy.ArgLine); err != nil {
						t.Fatalf("invalid catalog strategy: %v", err)
					}
					if strategy.L7 == "tls" || strategy.L7 == "http" {
						for _, issue := range catalogTCPFoolingIssues(strategy.ArgLine) {
							t.Error(issue)
						}
					}
				})
			}
		})
	}
}

func TestCatalogTCPFoolingGuardScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		ok   bool
	}{
		{"bare fake", "--lua-desync=fake:blob=tls_clienthello", false},
		{"TLS content is not fooling", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.microsoft.com", false},
		{"overlap is not fake fooling", "--lua-desync=fakedsplit:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello", false},
		{"timestamp reorder alone", "--lua-desync=hostfakesplit:tcp_ts_up", false},
		{"timestamp offset alone", "--lua-desync=fake:blob=tls_clienthello:tcp_ts=-600000", false},
		{"badack depends on timestamp layout", "--lua-desync=fake:blob=tls_clienthello:tcp_ack=-66000:tcp_ts_up", false},
		{"zero sequence shift", "--lua-desync=fake:blob=tls_clienthello:tcp_seq=0", false},
		{"future sequence may be buffered", "--lua-desync=fake:blob=tls_clienthello:tcp_seq=10000", false},
		{"short backward shift can overlap real data", "--lua-desync=fake:blob=tls_clienthello:tcp_seq=-1", false},
		{"catalog sequence margin boundary", "--lua-desync=fake:blob=tls_clienthello:tcp_seq=-9999", false},
		{"fooling does not carry forward", "--lua-desync=fake:blob=tls_clienthello:tcp_md5 --lua-desync=hostfakesplit:tcp_ts_up", false},
		{"fooling does not apply retroactively", "--lua-desync=fake:blob=tls_clienthello --lua-desync=fake:blob=tls_clienthello:tcp_seq=-10000", false},
		{"every fake protected separately", "--lua-desync=fake:blob=tls_clienthello:tcp_seq=-10000 --lua-desync=fakedsplit:pos=midsld:tcp_md5", true},
		{"timestamp absent but badseq remains", "--lua-desync=fake:blob=tls_clienthello:tcp_seq=-10000:tcp_ts_up", true},
		{"fixed TTL for both families", "--lua-desync=fake:blob=tls_clienthello:ip_ttl=4:ip6_ttl=4", true},
		{"IPv4 TTL does not protect IPv6", "--lua-desync=fake:blob=tls_clienthello:ip_ttl=4", false},
		{"unknown auto TTL needs a fallback", "--lua-desync=fake:blob=tls_clienthello:ip_autottl=0,3-20", false},
		{"badsum belongs on fake parts", "--lua-desync=fakeddisorder:pos=midsld:badsum:tcp_ts_up", true},
		{"badsum damages original", "--lua-desync=multidisorder:pos=midsld:badsum", false},
		{"MD5 damages original", "--lua-desync=multisplit:pos=midsld:tcp_md5", false},
		{"badack damages original", "--lua-desync=multidisorder:pos=midsld:tcp_ack=-66000", false},
		{"badseq damages original", "--lua-desync=multisplit:pos=midsld:tcp_seq=-10000", false},
		{"original timestamp reorder preserved", "--lua-desync=multisplit:pos=1,midsld:seqovl=1:tcp_ts_up", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues := catalogTCPFoolingIssues(tc.args)
			if (len(issues) == 0) != tc.ok {
				t.Fatalf("issues = %v, want accepted = %v", issues, tc.ok)
			}
		})
	}
}

func TestMicrosoftFakeCandidateKeepsRealPayloadIntact(t *testing.T) {
	// The previous auto-fake-msft-md was observed in a live router config with
	// GitHub avatars failing TLS. Keep its intended fake SNI/disorder behavior,
	// but ensure the sequence shift belongs to the fake, never the real split.
	for _, strategy := range AutoCandidates() {
		if strategy.ID != "auto-fake-msft-md" {
			continue
		}
		var fake, disorder bool
		for _, instance := range catalogInstances(strategy.ArgLine) {
			switch instance.method {
			case "fake":
				fake = instance.args["tcp_seq"] == "-10000" &&
					strings.Contains(instance.args["tls_mod"], "sni=www.microsoft.com")
			case "multidisorder":
				disorder = len(instance.args) == 1 && instance.args["pos"] == "1,midsld"
			}
		}
		if !fake || !disorder {
			t.Fatalf("fake protection or original disorder changed: %s", strategy.ArgLine)
		}
		return
	}
	t.Fatal("Microsoft fake candidate missing")
}

type catalogInstance struct {
	method string
	args   map[string]string
}

func catalogInstances(argLine string) []catalogInstance {
	var instances []catalogInstance
	for _, token := range strings.Fields(argLine) {
		value, ok := strings.CutPrefix(token, "--lua-desync=")
		if !ok {
			continue
		}
		parts := strings.Split(value, ":")
		instance := catalogInstance{method: parts[0], args: make(map[string]string)}
		for _, part := range parts[1:] {
			key, value, _ := strings.Cut(part, "=")
			instance.args[key] = value
		}
		instances = append(instances, instance)
	}
	return instances
}

func catalogTCPFoolingIssues(argLine string) []string {
	var issues []string
	for _, instance := range catalogInstances(argLine) {
		switch instance.method {
		case "fake", "fakedsplit", "fakeddisorder", "hostfakesplit":
			_, badsum := instance.args["badsum"]
			_, md5 := instance.args["tcp_md5"]
			seq, seqErr := strconv.ParseInt(instance.args["tcp_seq"], 10, 32)
			ttl4, ttl4Err := strconv.ParseUint(instance.args["ip_ttl"], 10, 8)
			ttl6, ttl6Err := strconv.ParseUint(instance.args["ip6_ttl"], 10, 8)
			// Constrain our known catalog payloads to a generous backwards margin;
			// a positive shift can still fall within the peer's receive window.
			// This is not a safety verdict for arbitrary user blobs or networks.
			if !badsum && !md5 && !(seqErr == nil && seq <= -10000) &&
				!(ttl4Err == nil && ttl4 > 0 && ttl6Err == nil && ttl6 > 0) {
				issues = append(issues, fmt.Sprintf("%s lacks its own timestamp-independent fake fooling", instance.method))
			}
		case "multisplit", "multidisorder":
			for _, forbidden := range []string{"badsum", "tcp_md5", "tcp_seq", "tcp_ack", "tcp_ts", "tcp_flags_set", "tcp_flags_unset", "ip_ttl", "ip6_ttl", "ip_autottl", "ip6_autottl"} {
				if _, exists := instance.args[forbidden]; exists {
					issues = append(issues, fmt.Sprintf("%s applies %s to the real payload", instance.method, forbidden))
				}
			}
		}
	}
	return issues
}
