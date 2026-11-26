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

func TestShadowBroadcastStateRetryAndValidatedLearning(t *testing.T) {
	client, server := net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.1")
	wan := []shadowBroadcastWAN{{native: "ISP", device: "eth3", client: client}}
	state, calls := shadowInformState{}, 0
	state.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		calls++
		return server, []string{client.String()}, nil
	}
	if got, err := discoverShadowBroadcast(context.Background(), &state, "wan-a", wan, []net.IP{client}); err == nil || len(got) != 0 || len(state.targets) != 0 {
		t.Fatal("router-local DNS was learned", got, err)
	}
	for range 3 {
		_, _ = discoverShadowBroadcast(context.Background(), &state, "wan-a", wan, []net.IP{client})
	}
	if calls != 1 {
		t.Fatal("failed discovery bypassed cooldown", calls)
	}
	state.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		calls++
		return server, []string{"192.0.2.53"}, nil
	}
	// A real WAN change invalidates the old cooldown.
	got, err := discoverShadowBroadcast(context.Background(), &state, "wan-b", wan, []net.IP{client})
	if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" || calls != 2 {
		t.Fatal("new WAN not discovered", got, err, calls)
	}
	target := state.targets["ISP"]
	if target.wanKey != "wan-b" || !target.serverIP.Equal(server) || !target.clientIP.Equal(client) || target.stamp != "" {
		t.Fatal("live INFORM invented lease evidence", target)
	}
	if remaining := time.Until(state.answers["ISP"].expires); remaining < 299*time.Second || remaining > 300*time.Second {
		t.Fatal("wrong parameter cache lifetime", remaining)
	}
	state.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		t.Fatal("fresh learned answer triggered unicast")
		return nil, nil
	}
	if got, err = discoverShadowInform(context.Background(), &state, "wan-b", []net.IP{client}, []net.IP{client}, map[string]string{client.String(): "eth3"}, func(string, net.IP) bool { return true }); err != nil || len(got) != 1 {
		t.Fatal("learned answer not reused", got, err)
	}
	// Caller cancellation must not create cooldown or trusted peer state.
	ctx, cancel := context.WithCancel(context.Background())
	state = shadowInformState{probeDiscover: func(context.Context, string, net.IP) (net.IP, []string, error) {
		cancel()
		return server, []string{"192.0.2.53"}, nil
	}}
	if _, err := discoverShadowBroadcast(ctx, &state, "wan-c", wan, []net.IP{client}); !errors.Is(err, context.Canceled) || state.broadcastKey != "" || len(state.targets) != 0 {
		t.Fatal("cancellation installed discovery state", err)
	}
}

func TestShadowCleanDiscoveryWithoutHistoricalACK(t *testing.T) {
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
	nameservers := "server:\n address: " + client + "\n port: 5356\n service: Dns::Manager\n interface:\n"
	command = func(_ context.Context, name string, args ...string) (string, error) {
		switch filepath.Base(name) + " " + strings.Join(args, " ") {
		case "ndmc -c show ip name-server":
			return nameservers, nil
		case "ndmc -c show log":
			return "I [Oct  4 12:00:00] ndm: unrelated event", nil
		case "ndmc -c show interface":
			return native, nil
		case "ndmc -c show interface GigabitEthernet1":
			return native, nil
		case "ip -4 route show table main default":
			return "default via 192.0.2.1 dev " + device, nil
		case "date +%Y-%m-%dT%H:%M:%S%z":
			return "2026-10-04T12:00:00+0300", nil
		}
		return "", fmt.Errorf("unexpected read-only command %s %v", name, args)
	}
	calls := 0
	state := shadowInformState{probeDiscover: func(_ context.Context, gotDevice string, ip net.IP) (net.IP, []string, error) {
		calls++
		if gotDevice != device || ip.String() != client {
			t.Fatal("lost kernel WAN binding")
		}
		return net.ParseIP("192.0.2.1"), []string{"192.0.2.53"}, nil
	}}
	for range 2 {
		got, err := discoverShadowServersWithState(context.Background(), []string{device}, map[string]shadowRememberedLease{}, &state)
		if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
			t.Fatal("clean installation remained dependent on ring log", got, err)
		}
	}
	if calls != 1 {
		t.Fatal("cached clean discovery broadcast repeatedly", calls)
	}
	nameservers = "server:\n address: 192.0.2.54\n port: 53\n service: Dhcp::Client-GigabitEthernet1\n interface: GigabitEthernet1\n"
	state = shadowInformState{probeDiscover: func(context.Context, string, net.IP) (net.IP, []string, error) {
		t.Fatal("authoritative DNS triggered broadcast")
		return nil, nil, nil
	}}
	if got, err := discoverShadowServersWithState(context.Background(), []string{device}, nil, &state); err != nil || len(got) != 1 || got[0] != "192.0.2.54:53" {
		t.Fatal("authoritative DNS lost", got, err)
	}
}

func TestShadowInternalDiscoveryTimeoutHasNegativeCache(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := command
	t.Cleanup(func() { command = old })
	calls := 0
	command = func(ctx context.Context, _ string, _ ...string) (string, error) {
		calls++
		<-ctx.Done()
		return "", ctx.Err()
	}
	a := New(nil, nil)
	a.cfg.DataDir = t.TempDir()
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	if got, err := a.ShadowDNSServers(caller); !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 || caller.Err() != nil {
		t.Fatal("internal timeout incorrectly became caller cancellation", got, err, caller.Err())
	}
	firstCalls := calls
	if firstCalls == 0 || time.Until(a.shadow.discoveryUntil) < 29*time.Second {
		t.Fatal("internal discovery timeout missed negative cache", firstCalls, a.shadow.discoveryUntil)
	}
	for range 3 {
		if _, err := a.ShadowDNSServers(caller); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("cached timeout was not returned", err)
		}
	}
	if calls != firstCalls {
		t.Fatal("each DNS query repeated timed-out native discovery", firstCalls, calls)
	}
	cancel()
	if _, err := a.ShadowDNSServers(caller); !errors.Is(err, context.Canceled) || calls != firstCalls {
		t.Fatal("negative cache hid caller cancellation", err, calls)
	}
}
