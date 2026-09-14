//go:build linux

package awgroute

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// These tests execute the production cleanup against an in-memory rule table.
// The runner rejects unsupported shell commands and incomplete delete selectors;
// nothing invokes ip, changes routing, or writes to /opt.
type cleanupRule struct {
	pref       int
	mark, mask uint32
	table      int
}

type cleanupRuleTable struct {
	t       *testing.T
	rules   []cleanupRule
	flushed map[int]int
	deleted int
}

func (rt *cleanupRuleTable) run(command string) (string, error) {
	rt.t.Helper()
	if strings.HasPrefix(command, "ip route flush table ") {
		words := strings.Fields(command)
		if len(words) != 6 || words[5] != "2>/dev/null" {
			rt.t.Fatalf("unsupported route command: %q", command)
		}
		table, err := strconv.Atoi(words[4])
		if err != nil || table < 901 || table > 964 {
			rt.t.Fatalf("flush outside AWG tables: %q", command)
		}
		rt.flushed[table]++
		return "", nil
	}
	selector, hasPref, err := parseCleanupDelete(command)
	if err != nil {
		rt.t.Fatal(err)
	}
	// Each ip rule del removes only one match. The shell loop must continue
	// until the command reports no matching rule, including duplicate rules.
	for {
		index := -1
		for i, rule := range rt.rules {
			if (!hasPref || rule.pref == selector.pref) && rule.mark == selector.mark && rule.mask == selector.mask && rule.table == selector.table {
				index = i
				break
			}
		}
		if index < 0 {
			return "", nil
		}
		rt.rules = append(rt.rules[:index], rt.rules[index+1:]...)
		rt.deleted++
	}
}

func parseCleanupDelete(command string) (cleanupRule, bool, error) {
	var result cleanupRule
	const prefix, suffix = "while ip rule del ", " 2>/dev/null; do :; done"
	invalid := func() (cleanupRule, bool, error) {
		return cleanupRule{}, false, fmt.Errorf("unsafe or unsupported rule delete: %q", command)
	}
	if !strings.HasPrefix(command, prefix) || !strings.HasSuffix(command, suffix) {
		return invalid()
	}
	words := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(command, prefix), suffix))
	seen := map[string]bool{}
	for len(words) >= 2 {
		key, value := words[0], words[1]
		words = words[2:]
		if seen[key] {
			return invalid()
		}
		seen[key] = true
		switch key {
		case "pref", "table":
			number, err := strconv.Atoi(value)
			if err != nil || number <= 0 {
				return invalid()
			}
			if key == "pref" {
				result.pref = number
			} else {
				result.table = number
			}
		case "fwmark":
			parts := strings.Split(value, "/")
			if len(parts) != 2 {
				return invalid()
			}
			mark, markErr := strconv.ParseUint(parts[0], 0, 32)
			mask, maskErr := strconv.ParseUint(parts[1], 0, 32)
			if markErr != nil || maskErr != nil || mask == 0 {
				return invalid()
			}
			result.mark, result.mask = uint32(mark), uint32(mask)
		default:
			return invalid()
		}
	}
	if len(words) != 0 || !seen["fwmark"] || !seen["table"] {
		return invalid()
	}
	return result, seen["pref"], nil
}

func TestMultiRuleCleanupPreservesKeeneticAndForeignRules(t *testing.T) {
	var keep []cleanupRule
	// Keenetic access policies overlap the AWG priority range, including its
	// upper boundary. Priority alone must never establish rule ownership.
	for _, pref := range []int{100, 101, 102, 103, 104, 105, 134} {
		keep = append(keep, cleanupRule{pref, uint32(pref), 0xffff, pref})
	}
	for _, own := range []cleanupRule{
		{71, 0x10100000, 0x1ff00000, 901},
		{100, 0x11e00000, 0x1ff00000, 930},
		{134, 0x14000000, 0x1ff00000, 964},
	} {
		otherMark, otherMask, otherTable := own, own, own
		otherMark.mark ^= 0x00100000
		otherMask.mask = 0xffffffff
		otherTable.table += 1000
		keep = append(keep, otherMark, otherMask, otherTable)
	}
	rt := &cleanupRuleTable{t: t, rules: append([]cleanupRule(nil), keep...), flushed: map[int]int{}}
	for slot := 1; slot <= 64; slot++ {
		own := cleanupRule{70 + slot, 0x10000000 | uint32(slot)<<20, 0x1ff00000, 900 + slot}
		legacy := own
		legacy.pref = 1000 + slot
		rt.rules = append(rt.rules, own, own, own, legacy, legacy)
	}
	awgClearMultiRouteRules(rt.run)
	if !reflect.DeepEqual(rt.rules, keep) {
		t.Fatalf("foreign rules changed or AWG rules remain:\ngot  %#v\nwant %#v", rt.rules, keep)
	}
	if rt.deleted != 64*5 {
		t.Fatalf("removed %d rules, want all %d current/legacy duplicates", rt.deleted, 64*5)
	}
	for table := 901; table <= 964; table++ {
		if rt.flushed[table] != 1 {
			t.Fatalf("table %d flushed %d times, want once", table, rt.flushed[table])
		}
	}
	awgClearMultiRouteRules(rt.run)
	if !reflect.DeepEqual(rt.rules, keep) || rt.deleted != 64*5 {
		t.Fatal("repeating cleanup changed the remaining foreign rules")
	}
}

func TestMultiRuleCleanupWithoutConfiguredTunnels(t *testing.T) {
	var svc Service
	rules, tunnels := svc.awgBuildMultiPolicyCached()
	if len(rules) != 0 || len(tunnels) != 0 {
		t.Fatal("test fixture unexpectedly has configured routing")
	}
	// Removed tunnels can leave rules behind at both slot boundaries. Cleanup
	// must not depend on which tunnels are still present in configuration.
	rt := &cleanupRuleTable{t: t, flushed: map[int]int{}, rules: []cleanupRule{
		{71, 0x10100000, 0x1ff00000, 901},
		{250, 0x14000000, 0x1ff00000, 964},
	}}
	awgClearMultiRouteRules(rt.run)
	if len(rt.rules) != 0 || rt.deleted != 2 || len(rt.flushed) != 64 {
		t.Fatalf("stale cleanup incomplete: rules=%v, deleted=%d, tables=%d", rt.rules, rt.deleted, len(rt.flushed))
	}
}

func TestMultiRuleCleanupRunnerRejectsBroadDeletes(t *testing.T) {
	for _, command := range []string{
		"while ip rule del pref 100 2>/dev/null; do :; done",
		"while ip rule del table 930 2>/dev/null; do :; done",
		"while ip rule del fwmark 0x11e00000 table 930 2>/dev/null; do :; done",
		"while ip rule del fwmark 0x11e00000/0x1ff00000 2>/dev/null; do :; done",
		"while ip rule del fwmark 0x11e00000/0x1ff00000 table 930 unknown 1 2>/dev/null; do :; done",
		"while ip rule del fwmark 0x11e00000/0x1ff00000 table 930 2>/dev/null; do :; done; ip rule flush",
	} {
		if _, _, err := parseCleanupDelete(command); err == nil {
			t.Errorf("runner accepted unsafe command: %q", command)
		}
	}
}
