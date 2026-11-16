package awgroute

import (
	"strings"
	"testing"
)

func TestMultiActionAuditRequiresCompleteActionAndNoStaleChains(t *testing.T) {
	want := []string{
		"-A AWG2_MULTI -m mark --mark 0x20000000/0x20000000 -j RETURN",
		"-A AWG2_MULTI -m set --match-set awgm_000 dst -g AWG2_TO_10100000",
		"-A AWG2_TO_10100000 -j MARK --set-xmark 0x10100000/0x1ff00000",
		"-A AWG2_TO_10100000 -j ACCEPT",
	}
	saved := "*mangle\n:AWG2_MULTI - [0:0]\n:AWG2_TO_10100000 - [0:0]\n-A PREROUTING -j AWG2_MULTI\n-A OUTPUT -j AWG2_MULTI\n" + strings.Join(want, "\n") + "\nCOMMIT\n"
	if !awgMultiFirewallIntact(saved, "AWG2_MULTI", want, nil) {
		t.Fatal("complete root policy and action chain were not recognized")
	}
	if !awgMultiFirewallIntact(strings.ReplaceAll(saved, " -g ", " --goto "), "AWG2_MULTI", want, nil) {
		t.Fatal("equivalent --goto serialization required repair")
	}
	for name, broken := range map[string]string{
		"missing action mark":              strings.Replace(saved, want[2]+"\n", "", 1),
		"wrong action mark":                strings.Replace(saved, "--set-xmark 0x10100000/0x1ff00000", "--set-xmark 0x10200000/0x1ff00000", 1),
		"missing terminal verdict":         strings.Replace(saved, want[3]+"\n", "", 1),
		"action accepts before mark":       strings.Replace(saved, want[2]+"\n"+want[3], want[3]+"\n"+want[2], 1),
		"duplicate action":                 strings.Replace(saved, want[3], want[3]+"\n"+want[3], 1),
		"stale empty action":               strings.Replace(saved, ":AWG2_MULTI", ":AWG2_TO_10200000 - [0:0]\n:AWG2_MULTI", 1),
		"root references different action": strings.Replace(saved, "-g AWG2_TO_10100000", "-g AWG2_TO_10200000", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if awgMultiFirewallIntact(broken, "AWG2_MULTI", want, nil) {
				t.Fatal("incomplete/misordered action state skipped repair")
			}
		})
	}
}

func TestMultiActionOwnershipDoesNotIncludeForeignNames(t *testing.T) {
	for _, name := range []string{"AWG2_TO_10100000", "AWG2_TO_14000000"} {
		if !awgIsMultiActionChain(name) {
			t.Fatalf("owned action not recognized: %s", name)
		}
	}
	for _, name := range []string{"AWG2_TO_", "AWG2_TO_1010000", "AWG2_TO_101000000", "AWG2_TO_foreign", "AWG2_TO_1010000z", "FOREIGN_10100000"} {
		if awgIsMultiActionChain(name) {
			t.Fatalf("foreign action could be cleaned up: %s", name)
		}
	}
}
