//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRouteTableMissingRecognizesOnlyExpectedFamily(t *testing.T) {
	exitErr := errors.New("exit status 2")
	for _, tc := range []struct {
		output, family string
		want           bool
	}{
		{"Error: ipv4: FIB table does not exist.\nDump terminated", "-4", true},
		{"Error: ipv6: FIB table does not exist.\nDump terminated", "-6", true},
		{"Error: FIB table does not exist.", "-6", true},
		{"Error: ipv4: FIB table does not exist.\r\nDump terminated\r\n", "-4", true},
		{"Error: ipv4: FIB table does not exist.\nDump terminated", "-6", false},
		{"Error: ipv6: FIB table does not exist.\nDump terminated", "-4", false},
		{"Error: ipv4: FIB table does not exist.", "invalid", false},
		{"", "-4", false},
		{"Dump terminated", "-4", false},
		{"Error: ipv4: FIB table does not exist.\nDump terminated\nDump terminated", "-4", false},
	} {
		if got := missingRouteTable(tc.output, tc.family, exitErr); got != tc.want {
			t.Errorf("missing(%q, %s)=%v, want %v", tc.output, tc.family, got, tc.want)
		}
	}
	if missingRouteTable("Error: ipv4: FIB table does not exist.", "-4", nil) {
		t.Fatal("diagnostic without failed command treated as absent table")
	}
}

func TestMissingDNSRouteTableCanBeCreated(t *testing.T) {
	for _, diagnostic := range []string{
		"Error: ipv4: FIB table does not exist.\nDump terminated",
		"Error: FIB table does not exist.\nDump terminated",
		"Error: ipv4: FIB table does not exist.",
	} {
		t.Run(diagnostic, func(t *testing.T) {
			prior := command
			t.Cleanup(func() { command = prior })
			var writes []string
			command = func(_ context.Context, name string, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				if name != "ip" {
					t.Fatalf("unexpected command: %s %s", name, joined)
				}
				switch joined {
				case "-4 route show table 701":
					return diagnostic, errors.New("exit status 2")
				case "-4 rule show":
					return "0: from all lookup local\n32766: from all lookup main", nil
				case "-4 rule add pref 40 fwmark 0x8000d501/0x8000ffff table 701",
					"-4 route replace blackhole default table 701 metric 32760",
					"-4 route replace default dev lo table 701":
					writes = append(writes, joined)
					return "", nil
				default:
					t.Fatalf("unexpected command: %s %s", name, joined)
					return "", nil
				}
			}
			a := New(nil, nil)
			route := &routeState{Route: Route{ID: "awg:test", Interface: "lo"}, slot: 1}
			if iface, err := a.ensureRouteLocked(context.Background(), route, "-4"); err != nil || iface != "lo" {
				t.Fatalf("absent table rejected: interface=%s error=%v", iface, err)
			}
			if len(writes) != 3 || !strings.Contains(writes[0], "rule add") || !strings.Contains(writes[1], "blackhole") || !strings.Contains(writes[2], "default dev lo") {
				t.Fatalf("route must be claimed then made fail-closed before dialing: %v", writes)
			}
		})
	}
}

func TestDNSRouteTableInspectionFailuresDoNotWrite(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		err          error
	}{
		{"permission", "RTNETLINK answers: Operation not permitted", errors.New("exit status 2")},
		{"device missing", "Cannot find device: interface does not exist", errors.New("exit status 1")},
		{"mixed routes and diagnostic", "default dev foreign0\nError: ipv4: FIB table does not exist.\nDump terminated", errors.New("exit status 2")},
		{"additional error", "Error: ipv4: FIB table does not exist.\nDump terminated\nRTNETLINK answers: Operation not permitted", errors.New("exit status 2")},
		{"canceled", "Error: ipv4: FIB table does not exist.\nDump terminated", context.Canceled},
		{"timeout", "Error: ipv4: FIB table does not exist.\nDump terminated", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := command
			t.Cleanup(func() { command = prior })
			command = func(_ context.Context, name string, args ...string) (string, error) {
				if name != "ip" || strings.Join(args, " ") != "-4 route show table 701" {
					t.Fatalf("inspection failure triggered another command: %s %v", name, args)
				}
				return tc.output, tc.err
			}
			a := New(nil, nil)
			route := &routeState{Route: Route{ID: "awg:test", Interface: "lo"}, slot: 1}
			if _, err := a.ensureRouteLocked(context.Background(), route, "-4"); !errors.Is(err, tc.err) {
				t.Fatalf("inspection error lost: %v", err)
			}
			if route.v4 != "" {
				t.Fatal("failed inspection marked route ready")
			}
		})
	}
}
