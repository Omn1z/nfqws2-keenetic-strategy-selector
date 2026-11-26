//go:build linux

package awgroute

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in only. The test never touches a real service, route, firewall
// or configured set: all four reserved names must be absent before creation.
func TestMultiSetRefreshEntwareIntegration(t *testing.T) {
	if os.Getenv("N2S_TEST_AWG_MULTI_SETS") != "1" {
		t.Skip("set N2S_TEST_AWG_MULTI_SETS=1 to exercise isolated real ipset staging")
	}
	if os.Geteuid() != 0 {
		t.Skip("isolated kernel ipset integration requires root")
	}
	if _, err := exec.LookPath("ipset"); err != nil {
		t.Skip("ipset is unavailable")
	}
	const first, second = "awgm_998", "awgm_999"
	names, err := awgRun("ipset list -name")
	if err != nil {
		t.Skipf("kernel ipset access unavailable: %v", err)
	}
	for _, existing := range strings.Fields(names) {
		if existing == first || existing == second || existing == first+"_r" || existing == second+"_r" {
			t.Skipf("reserved test name %s already exists; leave it untouched", existing)
		}
	}
	created := []string{}
	refreshAttempted := false
	defer func() {
		for _, name := range created {
			if refreshAttempted {
				// This function's staging names were also proved absent above.
				_, _ = awgRun("ipset destroy " + name + "_r 2>/dev/null || true")
			}
			if output, err := awgRun("ipset destroy " + name); err != nil {
				t.Errorf("cleanup owned test set %s: %v: %s", name, err, strings.TrimSpace(output))
			}
		}
	}()
	started := time.Now()
	// No -exist: a concurrent owner cannot silently have its set reused.
	for _, setup := range []struct{ name, options string }{
		{first, "hash:net family inet timeout 37 counters"},
		{second, "hash:net family inet"},
	} {
		if output, err := awgRun("ipset create " + setup.name + " " + setup.options); err != nil {
			t.Skipf("test hash:net/options unsupported or unavailable: %v: %s", err, strings.TrimSpace(output))
		}
		created = append(created, setup.name)
	}
	if _, err := awgRunStdin("ipset restore", "add "+first+" 192.0.2.9 timeout 31 packets 7 bytes 280\nadd "+second+" 203.0.113.25\n"); err != nil {
		t.Fatalf("seed isolated learned members: %v", err)
	}
	refreshAttempted = true
	if err := awgRefreshMultiSets([]awgMultiRule{
		{SetName: first, HasDst: true, Entries: []string{"192.0.2.9/32", "198.51.100.0/24"}},
		{SetName: second, HasDst: true, Entries: []string{"203.0.113.26/32"}},
	}); err != nil {
		t.Fatalf("real staged restore/swap: %v", err)
	}
	for _, member := range []struct{ set, ip string }{
		{first, "192.0.2.9"}, {first, "198.51.100.1"},
		{second, "203.0.113.25"}, {second, "203.0.113.26"},
	} {
		if _, err := awgRun("ipset test " + member.set + " " + member.ip); err != nil {
			t.Fatalf("learned/static member missing from owned %s: %s: %v", member.set, member.ip, err)
		}
	}
	saved, err := awgRun("ipset save " + first)
	if err != nil {
		t.Fatal(err)
	}
	definitionOK, memberOK := false, false
	for _, line := range strings.Split(saved, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != first {
			continue
		}
		if fields[0] == "create" {
			definitionOK = fields[2] == "hash:net" && strings.Contains(line, "family inet") && strings.Contains(line, "timeout 37") && strings.Contains(line, "counters")
		}
		if fields[0] == "add" && (fields[2] == "192.0.2.9" || fields[2] == "192.0.2.9/32") {
			options := map[string]string{}
			for i := 3; i+1 < len(fields); i += 2 {
				options[fields[i]] = fields[i+1]
			}
			remaining, parseErr := strconv.Atoi(options["timeout"])
			memberOK = parseErr == nil && remaining > 0 && remaining <= 31 && options["packets"] == "7" && options["bytes"] == "280"
		}
	}
	if !definitionOK || !memberOK {
		t.Fatal("stage/swap lost the live definition, remaining timeout, or counters")
	}
	names, err = awgRun("ipset list -name")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Fields(names) {
		if name == first+"_r" || name == second+"_r" {
			t.Fatalf("owned staging set %s survived successful swap", name)
		}
	}
	t.Logf("isolated real ipset stage/swap completed in %s", time.Since(started))
}
