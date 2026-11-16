//go:build linux

package awgroute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDNSLearningFlushesOnlyNewKernelMembership(t *testing.T) {
	svc := new(Service)
	requests := []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}
	member := false
	var order []string
	run := func(_ context.Context, command, script string) (string, error) {
		switch command {
		case "sh":
			order = append(order, "check")
			if member {
				return "present", nil
			}
			return "missing", nil
		case "ipset restore -exist":
			order = append(order, "add")
			if !strings.Contains(script, "add awgm_001 203.0.113.19 -exist\n") {
				t.Fatalf("wrong restored reply: %q", script)
			}
			member = true
			return "", nil
		default:
			t.Fatalf("unexpected command %q", command)
			return "", nil
		}
	}
	invalidate := func() error {
		order = append(order, "flush")
		if !member || len(svc.routingDNSGate.learned) != 0 || !svc.routingDNSGate.accelerationDirty {
			t.Fatal("cache invalidation did not occur after add and before memo publication")
		}
		return nil
	}
	learn := func() error {
		return svc.awgIPSetLearnWithAcceleration(context.Background(), requests, run, func() bool { return true }, invalidate)
	}
	if err := learn(); err != nil {
		t.Fatal(err)
	}
	if err := learn(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"check", "add", "flush"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("repeated DNS hit changed kernel/cache: %v", order)
	}
	// Expiring the user-space memo does not remove the permanent kernel member.
	svc.routingDNSGate.learned["awgm_001 203.0.113.19"] = time.Now().Add(-time.Second)
	if err := learn(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"check", "add", "flush", "check"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("memo expiry flushed an unchanged route: %v", order)
	}
}

func TestDNSLearningRetriesFlushDebtBeforeCheckingExistingMember(t *testing.T) {
	svc := new(Service)
	requests := []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}
	member := false
	var order []string
	fault := errors.New("native cache could not be cleared")
	run := func(_ context.Context, command, _ string) (string, error) {
		if command == "sh" {
			order = append(order, "check")
			if member {
				return "present", nil
			}
			return "missing", nil
		}
		order = append(order, "add")
		member = true
		return "", nil
	}
	flushes := 0
	invalidate := func() error {
		order = append(order, "flush")
		flushes++
		if flushes == 1 {
			return fault
		}
		return nil
	}
	learn := func() error {
		return svc.awgIPSetLearnWithAcceleration(context.Background(), requests, run, func() bool { return true }, invalidate)
	}
	if err := learn(); !errors.Is(err, fault) {
		t.Fatalf("flush failure was hidden: %v", err)
	}
	if !svc.routingDNSGate.accelerationDirty || len(svc.routingDNSGate.learned) != 0 {
		t.Fatal("failed cache flush was memoized or its debt was lost")
	}
	if err := learn(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"check", "add", "flush", "flush", "check"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("existing member concealed outstanding invalidation: %v", order)
	}
	if svc.routingDNSGate.accelerationDirty || len(svc.routingDNSGate.learned) != 1 {
		t.Fatal("successful retry did not confirm the installed route")
	}
}

func TestDNSLearningPartialRestoreFailureStillInvalidatesAndStaysUnconfirmed(t *testing.T) {
	for _, flushFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cache cleared", true: "cache clear also failed"}[flushFails], func(t *testing.T) {
			svc := new(Service)
			addFault := errors.New("second add failed after first was installed")
			flushFault := errors.New("cache flush failed")
			var order []string
			err := svc.awgIPSetLearnWithAcceleration(context.Background(), []ipsetAddReq{
				{set: "awgm_001", ip: "203.0.113.19"}, {set: "awgm_001", ip: "203.0.113.20"},
			}, func(_ context.Context, command, _ string) (string, error) {
				if command == "sh" {
					order = append(order, "check")
					return "missing", nil
				}
				order = append(order, "partial add")
				return "kernel rejected a later member", addFault
			}, func() bool { return true }, func() error {
				order = append(order, "flush")
				if flushFails {
					return flushFault
				}
				return nil
			})
			if !errors.Is(err, addFault) || flushFails && !errors.Is(err, flushFault) {
				t.Fatalf("restore/flush errors were lost: %v", err)
			}
			if want := []string{"check", "partial add", "flush"}; !reflect.DeepEqual(order, want) {
				t.Fatalf("potential partial mutation escaped invalidation: %v", order)
			}
			if len(svc.routingDNSGate.learned) != 0 || svc.routingDNSGate.accelerationDirty != flushFails {
				t.Fatal("failed restore was memoized or dirty debt is incorrect")
			}
		})
	}
}

func TestDNSLearningMembershipErrorsDoNotWriteOrMemoize(t *testing.T) {
	for _, result := range []string{"command failure", "invalid response"} {
		t.Run(result, func(t *testing.T) {
			svc := new(Service)
			calls := 0
			err := svc.awgIPSetLearnWithAcceleration(context.Background(), []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}, func(_ context.Context, command, _ string) (string, error) {
				calls++
				if command != "sh" {
					t.Fatal("failed membership inspection reached restore")
				}
				if result == "command failure" {
					return "", errors.New("ipset failed")
				}
				return "unexpected", nil
			}, func() bool { return true }, func() error {
				t.Fatal("read-only membership failure flushed caches")
				return nil
			})
			if err == nil || calls != 1 || len(svc.routingDNSGate.learned) != 0 || svc.routingDNSGate.accelerationDirty {
				t.Fatalf("membership error was not fail-closed: err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestDNSLearningMissingSetCannotBeMistakenForConfirmedMembership(t *testing.T) {
	svc := new(Service)
	fault := errors.New("set does not exist")
	err := svc.awgIPSetLearnWithAcceleration(context.Background(), []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}, func(_ context.Context, command, _ string) (string, error) {
		if command == "sh" {
			return "missing", nil // Some ipset versions share exit 1 for this error.
		}
		return "set does not exist", fault
	}, func() bool { return true }, func() error { return nil })
	if !errors.Is(err, fault) || len(svc.routingDNSGate.learned) != 0 {
		t.Fatalf("missing set became a successful DNS route: %v", err)
	}
}

func TestDNSLearningDirtyDebtRequiresConfirmedConservativeState(t *testing.T) {
	svc := new(Service)
	svc.routingDNSGate.accelerationDirty = true
	svc.routingDNSGate.learned = map[string]time.Time{"awgm_001 203.0.113.19": time.Now().Add(time.Minute)}
	fault := errors.New("conservative state is not yet verified")
	flushErr := error(fault)
	learn := func() error {
		return svc.awgIPSetLearnWithAcceleration(context.Background(), []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}, func(context.Context, string, string) (string, error) {
			t.Fatal("a hot memo with invalidation debt executed an ipset command")
			return "", nil
		}, func() bool { return false }, func() error { return flushErr })
	}
	if err := learn(); !errors.Is(err, fault) || !svc.routingDNSGate.accelerationDirty {
		t.Fatalf("unverified conservative state erased debt: %v", err)
	}
	flushErr = nil
	if err := learn(); err != nil || svc.routingDNSGate.accelerationDirty {
		t.Fatalf("confirmed safe state did not clear debt: %v", err)
	}
}

func TestDNSLearnMembershipBatchUsesValidatedPairsAndExitCodes(t *testing.T) {
	bin := t.TempDir()
	logfile := filepath.Join(bin, "calls")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$3\" >> \"$N2S_DNS_MEMBERSHIP_TEST_LOG\"\ncase \"$3\" in\n203.0.113.19) exit 0 ;;\n203.0.113.20) exit 1 ;;\n*) exit 2 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "ipset"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("N2S_DNS_MEMBERSHIP_TEST_LOG", logfile)
	for _, tc := range []struct {
		name string
		ips  []string
		want string
		err  bool
	}{
		{"present", []string{"203.0.113.19"}, "present", false},
		{"missing stops later checks", []string{"203.0.113.19", "203.0.113.20", "203.0.113.21"}, "missing", false},
		{"kernel error", []string{"203.0.113.21"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make([]ipsetAddReq, 0, len(tc.ips))
			for _, ip := range tc.ips {
				requests = append(requests, ipsetAddReq{set: "awgm_001", ip: ip})
			}
			script, err := awgDNSLearnMembershipScript(requests)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out, err := awgRunShell(ctx, "sh", script)
			if (err != nil) != tc.err || out != tc.want {
				t.Fatalf("membership batch = %q, %v", out, err)
			}
		})
	}
	if _, err := awgDNSLearnMembershipScript([]ipsetAddReq{{set: "awgm_001; exit 0", ip: "203.0.113.19"}}); err == nil {
		t.Fatal("shell metacharacter in set name entered membership batch")
	}
}
