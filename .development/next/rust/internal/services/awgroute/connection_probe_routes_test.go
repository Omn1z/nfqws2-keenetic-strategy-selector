package awgroute

import (
	"errors"
	"strings"
	"testing"
)

func TestConnectionProbeRoutesArePrivateAndFailClosed(t *testing.T) {
	var calls []string
	run := func(cmd string) (string, error) { calls = append(calls, cmd); return "", nil }
	cleanup, err := prepareConnectionProbe("awg7", run)
	if err != nil {
		t.Fatal(err)
	}
	setup := strings.Join(calls, "\n")
	for _, required := range []string{"blackhole default table 997", "default dev awg7 table 997", "fwmark 0x60000000/0xe0000000 table 997"} {
		if !strings.Contains(setup, required) {
			t.Fatalf("missing isolation %q: %s", required, setup)
		}
	}
	if strings.Contains(setup, "table main") || strings.Contains(setup, "iptables") {
		t.Fatal("probe changed shared traffic policy")
	}
	cleanup()
	if !strings.Contains(strings.Join(calls, "\n"), "ip rule del "+connectionProbeRule) {
		t.Fatal("probe rule not removed")
	}
}

func TestConnectionProbePreservesUnrelatedTableAndRollsBackSetupFailure(t *testing.T) {
	var calls []string
	run := func(cmd string) (string, error) {
		calls = append(calls, cmd)
		if strings.HasPrefix(cmd, "ip route show") {
			return "default via 192.0.2.1 dev eth0", nil
		}
		return "", nil
	}
	if _, err := prepareConnectionProbe("awg1", run); err == nil {
		t.Fatal("occupied diagnostic table overwritten")
	}
	if len(calls) != 2 {
		t.Fatalf("occupied table was modified: %v", calls)
	}
	calls = nil
	run = func(cmd string) (string, error) {
		calls = append(calls, cmd)
		if strings.HasPrefix(cmd, "ip route add default dev") {
			return "interface missing", errors.New("failed")
		}
		return "", nil
	}
	if _, err := prepareConnectionProbe("awg1", run); err == nil {
		t.Fatal("route failure ignored")
	}
	if !strings.Contains(strings.Join(calls, "\n"), "ip route flush table 997") {
		t.Fatal("partial setup retained")
	}
	if _, err := prepareConnectionProbe("awg1;bad", run); err == nil {
		t.Fatal("unsafe interface accepted")
	}
}
