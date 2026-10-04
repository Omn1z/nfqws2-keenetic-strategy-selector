//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The firmware CLI and all DHCP exchanges are fake. Interface enumeration is
// read-only; this reproduces the captured known-peer timeout without touching WAN.
func shadowFallbackFixture(t *testing.T) (*Adapter, *string, *string) {
	t.Helper()
	device, client := "", ""
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if !validShadowWAN(iface.Name) || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, _ := net.ParseCIDR(address.String())
			if ip.To4() != nil && ip.IsGlobalUnicast() {
				device, client = iface.Name, ip.String()
				break
			}
		}
		if client != "" {
			break
		}
	}
	if client == "" {
		t.Skip("no read-only IPv4 WAN fixture available")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := command
	t.Cleanup(func() { command = old })
	native := strings.ReplaceAll(shadowBroadcastFixture, "192.0.2.10", client)
	log := "I [Oct  4 12:00:00] ndhcpc: ISP: received ACK for " + client + " from 1.1.1.2 lease 86400 sec."
	command = func(_ context.Context, name string, args ...string) (string, error) {
		switch filepath.Base(name) + " " + strings.Join(args, " ") {
		case "ndmc -c show ip name-server":
			return "server:\n address: " + client + "\n port: 5356\n service: Dns::Manager\n interface:\n", nil
		case "ndmc -c show log":
			return log, nil
		case "ndmc -c show interface", "ndmc -c show interface ISP", "ndmc -c show interface GigabitEthernet1":
			return native, nil
		case "ip -4 route show table main default":
			return "default via 192.0.2.1 dev " + device, nil
		case "date +%Y-%m-%dT%H:%M:%S%z":
			return "2026-10-04T12:10:00+0300", nil
		}
		return "", fmt.Errorf("unexpected read-only command %s %v", name, args)
	}
	a := New(nil, nil)
	a.cfg.WANIfaces, a.cfg.DataDir = []string{device}, t.TempDir()
	return a, &log, &native
}

func shadowFallbackRetryNow(a *Adapter) {
	a.shadow.discoveryUntil = time.Time{}
	for iface := range a.shadow.inform.retryAfter {
		a.shadow.inform.retryAfter[iface] = time.Time{}
	}
	a.shadow.inform.broadcastRetry = time.Time{}
}

func TestShadowKnownPeerTimeoutFallsBackWithoutLogReplay(t *testing.T) {
	a, log, _ := shadowFallbackFixture(t)
	unicast, broadcast := 0, 0
	var lastPeer net.IP
	a.shadow.inform.probe = func(_ context.Context, _ string, _, peer net.IP) ([]string, error) {
		unicast++
		lastPeer = append(net.IP(nil), peer...)
		return nil, fmt.Errorf("no matching ACK: %w", context.DeadlineExceeded)
	}
	broadcastFailure := true
	a.shadow.inform.probeDiscover = func(ctx context.Context, device string, client net.IP) (net.IP, []string, error) {
		broadcast++
		if device != a.cfg.WANIfaces[0] || !client.Equal(a.shadow.inform.targets["ISP"].clientIP) {
			t.Fatal("fallback left the verified WAN")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < time.Second {
			t.Fatal("fallback inherited a spent unicast deadline")
		}
		if broadcastFailure {
			return nil, nil, context.DeadlineExceeded
		}
		return net.ParseIP("192.0.2.2"), []string{"192.0.2.53"}, nil
	}
	for range 8 {
		if got, err := a.ShadowDNSServers(context.Background()); !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
			t.Fatal("known peer timeout missing", got, err)
		}
	}
	if unicast != 1 || broadcast != 0 || !lastPeer.Equal(net.ParseIP("1.1.1.2")) {
		t.Fatal("initial timeout multiplied probes", unicast, broadcast, lastPeer)
	}
	shadowFallbackRetryNow(a)
	for range 8 {
		if got, err := a.ShadowDNSServers(context.Background()); !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
			t.Fatal("broadcast timeout missing", got, err)
		}
	}
	if unicast != 1 || broadcast != 1 {
		t.Fatalf("known timeout did not transition to one cooled broadcast: unicast=%d broadcast=%d", unicast, broadcast)
	}
	broadcastFailure = false
	shadowFallbackRetryNow(a)
	if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatal("broadcast did not recover DNS", got, err)
	}
	state := &a.shadow.inform
	if len(state.targets) != 1 || !state.targets["ISP"].serverIP.Equal(net.ParseIP("192.0.2.2")) || state.targets["ISP"].stamp != "Oct  4 12:00:00" {
		t.Fatal("fallback duplicated interface alias or lost ACK watermark", state.targets)
	}
	expires := state.answers["ISP"].expires
	for range 3 {
		a.shadow.discoveryUntil = time.Time{} // force a fresh read of the SAME old ACK
		if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 {
			t.Fatal("old log overwrote live DNS discovery", got, err)
		}
	}
	if unicast != 1 || broadcast != 2 || !state.answers["ISP"].expires.Equal(expires) {
		t.Fatal("log replay multiplied probes or extended answer TTL", unicast, broadcast)
	}
	// Refresh by broadcast again; never return to the non-responsive unicast
	// path merely because the previous broadcast succeeded.
	answer := state.answers["ISP"]
	answer.expires = time.Now().Add(40 * time.Second)
	state.answers["ISP"] = answer
	broadcastFailure = true
	shadowFallbackRetryNow(a)
	if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || unicast != 1 || broadcast != 3 || !state.answers["ISP"].expires.Equal(answer.expires) {
		t.Fatal("failed refresh lost valid DNS, changed TTL or returned to unicast", got, err, unicast, broadcast)
	}
	// The remembered peer/watermark survives a service restart, without saving
	// the DNS answer as an invented DHCP address lease.
	b := New(nil, nil)
	b.cfg = a.cfg
	b.shadow.inform.probe = func(_ context.Context, _ string, _, peer net.IP) ([]string, error) {
		if !peer.Equal(net.ParseIP("192.0.2.2")) {
			t.Fatal("restart replayed old peer", peer)
		}
		return []string{"192.0.2.53"}, nil
	}
	if got, err := b.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 {
		t.Fatal("restart lost validated peer", got, err)
	}
	// A genuinely newer DHCP ACK can supersede live-discovered parameters.
	*log = strings.ReplaceAll(*log, "12:00:00", "12:01:00")
	*log = strings.ReplaceAll(*log, "1.1.1.2", "192.0.2.3")
	a.shadow.inform.probe = func(_ context.Context, _ string, _, peer net.IP) ([]string, error) {
		if !peer.Equal(net.ParseIP("192.0.2.3")) {
			t.Fatal("new DHCP ACK did not replace peer", peer)
		}
		return []string{"192.0.2.54"}, nil
	}
	shadowFallbackRetryNow(a)
	if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || got[0] != "192.0.2.54:53" {
		t.Fatal("new DHCP ACK could not refresh DNS", got, err)
	}
}

func TestShadowKnownPeerFallbackRequiresPublicDefaultWAN(t *testing.T) {
	a, _, native := shadowFallbackFixture(t)
	unicast, broadcast := 0, 0
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		unicast++
		return nil, context.DeadlineExceeded
	}
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		broadcast++
		return net.ParseIP("192.0.2.2"), []string{"192.0.2.53"}, nil
	}
	_, _ = a.ShadowDNSServers(context.Background())
	*native = strings.ReplaceAll(*native, "security-level: public", "security-level: private")
	shadowFallbackRetryNow(a)
	if got, err := a.ShadowDNSServers(context.Background()); err == nil || len(got) != 0 || unicast != 1 || broadcast != 0 {
		t.Fatal("fallback probed an ineligible interface", got, err, unicast, broadcast)
	}
}

func TestShadowKnownPeerCancellationDoesNotSelectBroadcast(t *testing.T) {
	a, _, _ := shadowFallbackFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		cancel()
		return nil, context.DeadlineExceeded
	}
	if _, err := a.ShadowDNSServers(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation lost", err)
	}
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		return []string{"192.0.2.53"}, nil
	}
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		t.Fatal("caller cancellation incorrectly selected broadcast")
		return nil, nil, nil
	}
	if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 {
		t.Fatal("cancellation poisoned next discovery", got, err)
	}
}

func TestShadowFallbackRefreshCannotReturnExpiredAnswer(t *testing.T) {
	a, _, _ := shadowFallbackFixture(t)
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		return nil, context.DeadlineExceeded
	}
	_, _ = a.ShadowDNSServers(context.Background())
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		return net.ParseIP("192.0.2.2"), []string{"192.0.2.53"}, nil
	}
	shadowFallbackRetryNow(a)
	if _, err := a.ShadowDNSServers(context.Background()); err != nil {
		t.Fatal(err)
	}
	answer := a.shadow.inform.answers["ISP"]
	answer.expires = time.Now().Add(5 * time.Millisecond)
	a.shadow.inform.answers["ISP"] = answer
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		time.Sleep(15 * time.Millisecond)
		return nil, nil, context.DeadlineExceeded
	}
	shadowFallbackRetryNow(a)
	if got, err := a.ShadowDNSServers(context.Background()); err == nil || len(got) != 0 {
		t.Fatal("DNS answer expired during failed broadcast but was returned", got, err)
	}
}

func TestShadowFallbackLogAliasSharesLivePeerWatermark(t *testing.T) {
	client := net.ParseIP("192.0.2.10")
	state := shadowInformState{targets: map[string]shadowDHCPTarget{
		"GigabitEthernet1": {wanKey: "wan", clientIP: client, serverIP: net.ParseIP("192.0.2.2"), stamp: "Oct  4 12:00:00", preferBroadcast: true},
	}}
	now := time.Date(2026, 10, 4, 12, 10, 0, 0, time.UTC)
	state.remember("ISP", shadowDHCPTarget{wanKey: "wan", clientIP: client, serverIP: net.ParseIP("1.1.1.2"), stamp: "Oct  4 12:00:00"}, now)
	if len(state.targets) != 1 || !state.targets["GigabitEthernet1"].serverIP.Equal(net.ParseIP("192.0.2.2")) || !state.targets["GigabitEthernet1"].preferBroadcast {
		t.Fatal("alias log replay duplicated or replaced discovered peer", state.targets)
	}
	state.remember("ISP", shadowDHCPTarget{wanKey: "wan", clientIP: client, serverIP: net.ParseIP("192.0.2.2"), stamp: "Oct  4 12:01:00"}, now)
	if !state.targets["GigabitEthernet1"].preferBroadcast {
		t.Fatal("same-server lease renewal lost working broadcast transport")
	}
}
