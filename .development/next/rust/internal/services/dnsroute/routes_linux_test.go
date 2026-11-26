//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVPNOnlyAdapterRefusesNFQWSDial(t *testing.T) {
	a := New(nil, nil)
	a.started = true
	a.listen.DisableNFQWS = true
	_, err := a.DialContext(context.Background(), "nfqws", "tcp", "1.1.1.1:443")
	if err == nil || !strings.Contains(err.Error(), "VPN only") {
		t.Fatalf("NFQWS dial not blocked by adapter: %v", err)
	}
	for _, route := range a.Routes() {
		if route.ID == "nfqws" && (route.Available || route.Error == "") {
			t.Fatalf("NFQWS route advertised in VPN-only mode: %+v", route)
		}
	}
}

func TestDNSCommandDeadlineKillsChildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := executeCommand(ctx, "sh", "-c", "sleep 5 & wait")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("command error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("DNS command waited for child after deadline: %s", elapsed)
	}
}

func TestDNSCommandOrphanCannotHoldOutputPipe(t *testing.T) {
	started := time.Now()
	_, err := executeCommand(context.Background(), "sh", "-c", "sleep 5 &")
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("command error = %v, want output-pipe wait limit", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("orphan held DNS command output for %s", elapsed)
	}
}

func TestInputFirewallRepairDoesNotDependOnNFQUEUE(t *testing.T) {
	prior := command
	defer func() { command = prior }()
	missingDrop := false
	command = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if name != "iptables" || strings.Contains(joined, "mangle") || strings.Contains(joined, "NFQUEUE") {
			t.Fatalf("LAN listener repair inspected NFQWS: %s %s", name, joined)
		}
		if missingDrop && strings.HasSuffix(joined, "-j DROP") {
			return "", errors.New("rule absent")
		}
		return "", nil
	}
	a := New(nil, nil)
	a.listen = ListenOptions{Host: "192.168.3.1", DNSPort: 5355, DisableNFQWS: true}
	a.lanIface, a.lanSubnet = "br0", "192.168.3.0/24"
	if !a.inputFirewallReady(context.Background()) {
		t.Fatal("LAN listener rejected because NFQWS was not checked")
	}
	missingDrop = true
	if a.inputFirewallReady(context.Background()) {
		t.Fatal("missing non-LAN drop rule did not trigger repair")
	}
}

func TestWANSelectionDoesNotFollowAWGDefault(t *testing.T) {
	out := "default dev awg1\ndefault via 192.168.0.1 dev eth3 metric 1000\n"
	iface, gw := pickWANDefault(out, []string{"eth3"})
	if iface != "eth3" || gw != "192.168.0.1" {
		t.Fatalf("wrong WAN path: %s %s", iface, gw)
	}
	if iface, _ = pickWANDefault("default dev awg1\n", []string{"eth3"}); iface != "" {
		t.Fatal("AWG mistaken for NFQWS WAN")
	}
}

func TestCleanupOwnershipRequiresExactMarkPriorityAndTable(t *testing.T) {
	valid := "40: from all fwmark 0x8000d501/0x8000ffff lookup 701"
	if !ownedRule(valid, 1) {
		t.Fatal("own rule not recognized")
	}
	for _, foreign := range []string{
		strings.Replace(valid, "40:", "41:", 1), strings.Replace(valid, "701", "702", 1), strings.Replace(valid, "0x8000ffff", "0xffffffff", 1),
		"71: from all fwmark 0x10100000/0x1ff00000 lookup 901",
	} {
		if ownedRule(foreign, 1) {
			t.Fatalf("would remove foreign policy: %s", foreign)
		}
	}
}

func TestOccupiedTableIsNeverModified(t *testing.T) {
	prior := command
	defer func() { command = prior }()
	command = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "-4 route show table 701":
			return "default dev foreign0", nil
		case "-4 rule show":
			return "32766: from all lookup main", nil
		default:
			t.Fatalf("foreign table was modified: %s %s", name, joined)
			return "", nil
		}
	}
	a := New(nil, nil)
	_, err := a.ensureRouteLocked(context.Background(), &routeState{Route: Route{ID: "awg:test", Interface: "lo"}, slot: 1}, "-4")
	if err == nil || !strings.Contains(err.Error(), "occupied") {
		t.Fatalf("expected collision error, got %v", err)
	}
}

func TestFailedAndRecreatedTunnelRoutesAreRetried(t *testing.T) {
	prior := command
	defer func() { command = prior }()
	owned := false
	deviceDefault := false
	failDefault := true
	blackhole := false
	adds := 0
	repairs := 0
	command = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "-4 route show table 701":
			if deviceDefault {
				return "default dev lo\nblackhole default metric 32760", nil
			}
			return "", nil
		case "-4 rule show":
			if owned {
				return "40: from all fwmark 0x8000d501/0x8000ffff lookup 701", nil
			}
			return "", nil
		case "-4 rule add pref 40 fwmark 0x8000d501/0x8000ffff table 701":
			owned = true
			adds++
			return "", nil
		case "-4 route replace blackhole default table 701 metric 32760":
			if !owned {
				t.Fatal("route created before ownership")
			}
			blackhole = true
			return "", nil
		case "-4 route replace default dev lo table 701":
			if !blackhole {
				t.Fatal("device route lacks fail-closed fallback")
			}
			if failDefault {
				failDefault = false
				return "", errors.New("interface restarted")
			}
			deviceDefault = true
			repairs++
			return "", nil
		default:
			t.Fatalf("unexpected command: %s %s", name, joined)
			return "", nil
		}
	}
	a := New(nil, nil)
	route := &routeState{Route: Route{ID: "awg:test", Interface: "lo"}, slot: 1}
	if _, err := a.ensureRouteLocked(context.Background(), route, "-4"); err == nil {
		t.Fatal("simulated route failure lost")
	}
	if _, err := a.ensureRouteLocked(context.Background(), route, "-4"); err != nil {
		t.Fatal("failed route was not retried:", err)
	}
	deviceDefault = false // ip link del removes only the interface route
	if _, err := a.ensureRouteLocked(context.Background(), route, "-4"); err != nil {
		t.Fatal("recreated tunnel was not repaired:", err)
	}
	if adds != 1 || repairs != 2 {
		t.Fatalf("unstable policy or missed repair: adds%d repairs%d", adds, repairs)
	}
}
