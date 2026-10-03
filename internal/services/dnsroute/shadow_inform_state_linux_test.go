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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestShadowInformCacheRetryCancellationAndRenewal(t *testing.T) {
	client, server := net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.1")
	target := shadowDHCPTarget{wanKey: "same-wan", clientIP: client, serverIP: server, stamp: "Oct  3 01:00:00"}
	state := shadowInformState{targets: map[string]shadowDHCPTarget{"ISP": target}}
	calls := 0
	var failure error
	state.probe = func(ctx context.Context, device string, gotClient, gotServer net.IP) ([]string, error) {
		calls++
		if device != "eth3" || !gotClient.Equal(client) || !gotServer.Equal(server) {
			t.Fatal("probe lost verified WAN identity")
		}
		return []string{"192.0.2.53"}, failure
	}
	discover := func(ctx context.Context) ([]string, error) {
		return discoverShadowInform(ctx, &state, "same-wan", []net.IP{client}, []net.IP{client}, map[string]string{client.String(): "eth3"}, func(iface string, ip net.IP) bool { return iface == "ISP" && ip.Equal(client) })
	}
	for range 10 {
		if got, err := discover(context.Background()); err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
			t.Fatalf("discovery: %v %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("cached DNS caused %d DHCP probes", calls)
	}
	answer := state.answers["ISP"]
	if left := time.Until(answer.expires); left < 4*time.Minute+59*time.Second || left > 5*time.Minute {
		t.Fatal("INFORM options did not use a separate five-minute validity", left)
	}
	// Bare renewal requests fresh options but preserves a still-valid answer.
	renewed := target
	renewed.stamp = "Oct  3 12:00:00"
	state.remember("ISP", renewed, time.Date(2026, 10, 3, 12, 0, 1, 0, time.UTC))
	state.retryAfter["ISP"] = time.Time{}
	failure = errors.New("test DHCP timeout")
	if got, err := discover(context.Background()); err != nil || len(got) != 1 || calls != 2 || !state.answers["ISP"].expires.Equal(answer.expires) {
		t.Fatalf("failed renewal lost valid information: %v %v calls=%d", got, err, calls)
	}
	if until := time.Until(state.retryAfter["ISP"]); until < 29*time.Second {
		t.Fatal("missing failure cooldown")
	}
	if _, err := discover(context.Background()); err != nil || calls != 2 {
		t.Fatal("cooled failure retried immediately", err, calls)
	}
	// Expired parameter information cannot be served during retry cooldown.
	state.answers["ISP"] = shadowInformAnswer{servers: answer.servers, expires: time.Now().Add(-time.Second)}
	if got, err := discover(context.Background()); err == nil || len(got) != 0 || calls != 2 {
		t.Fatal("expired parameter cache reused", got, err, calls)
	}
	state.retryAfter["ISP"] = time.Time{}
	ctx, cancel := context.WithCancel(context.Background())
	state.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		cancel()
		return nil, context.Canceled
	}
	if _, err := discover(ctx); !errors.Is(err, context.Canceled) || !state.retryAfter["ISP"].IsZero() {
		t.Fatal("cancellation poisoned retry cache", err)
	}
	// An answer which expires during a failed probe must not escape the TTL.
	state.answers["ISP"] = shadowInformAnswer{servers: answer.servers, expires: time.Now().Add(5 * time.Millisecond)}
	state.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		time.Sleep(15 * time.Millisecond)
		return nil, failure
	}
	if got, err := discover(context.Background()); err == nil || len(got) != 0 {
		t.Fatal("probe used pre-I/O time to serve expired DNS", got, err)
	}
	// A different verified server cannot inherit the previous peer's answer or cooldown.
	changed := renewed
	changed.serverIP = net.ParseIP("192.0.2.2")
	state.remember("ISP", changed, time.Date(2026, 10, 3, 12, 0, 2, 0, time.UTC))
	if len(state.answers) != 0 || len(state.retryAfter) != 0 {
		t.Fatal("changed DHCP peer retained old options or failure cooldown")
	}
}

func TestShadowInformRequiresExactNativeWANOwner(t *testing.T) {
	client, other := net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.10")
	state := shadowInformState{targets: map[string]shadowDHCPTarget{"ISP": {wanKey: "two-wans", clientIP: client, serverIP: net.ParseIP("192.0.2.1")}}}
	state.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		t.Fatal("DHCP probed through mismatched native WAN identity")
		return nil, nil
	}
	state.answers = map[string]shadowInformAnswer{"ISP": {servers: []string{"192.0.2.53:53"}, expires: time.Now().Add(time.Minute)}}
	got, err := discoverShadowInform(context.Background(), &state, "two-wans", []net.IP{client, other}, nil, map[string]string{client.String(): "eth3", other.String(): "eth4"}, func(_ string, targetIP net.IP) bool {
		return keeneticInterfaceOwnsWAN("connected: yes\naddress: "+other.String(), []net.IP{targetIP})
	})
	if err != nil || len(got) != 0 {
		t.Fatal("cached options were accepted from another active WAN", got, err)
	}
}

// Real interface inspection is read-only. Every firmware/ip command and DHCP
// packet exchange is fake; state writes are confined to t.TempDir().
func TestShadowInformDiscoverySurvivesLeaseExpiryLogRotationAndRestart(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	device, client := "", net.IP(nil)
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || !validShadowWAN(iface.Name) {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, addr := range addresses {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil && ip.IsGlobalUnicast() {
				device, client = iface.Name, ip
				break
			}
		}
		if device != "" {
			break
		}
	}
	if device == "" {
		t.Skip("no WAN-like IPv4 interface for read-only inspection")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := command
	t.Cleanup(func() { command = previous })
	log := "I [Oct  3 12:00:00] ndhcpc: ISP: received ACK for " + client.String() + " from 192.0.2.1 lease 86400 sec."
	gateway, connected := "192.0.2.1", "yes"
	command = func(_ context.Context, name string, args ...string) (string, error) {
		switch filepath.Base(name) + " " + strings.Join(args, " ") {
		case "ndmc -c show ip name-server":
			return "", nil
		case "ndmc -c show log":
			return log, nil
		case "ndmc -c show interface ISP":
			return "connected: " + connected + "\naddress: " + client.String(), nil
		case "ip -4 route show table main default":
			return "default via " + gateway + " dev " + device, nil
		case "date +%Y-%m-%dT%H:%M:%S%z":
			return "2026-10-03T12:00:01+0300", nil
		}
		return "", fmt.Errorf("unexpected command %s %v", name, args)
	}
	var probes atomic.Int32
	probe := func(_ context.Context, gotDevice string, gotClient, gotServer net.IP) ([]string, error) {
		probes.Add(1)
		if gotDevice != device || !gotClient.Equal(client) || !gotServer.Equal(net.ParseIP("192.0.2.1")) {
			t.Error("wrong WAN/DHCP server identity")
		}
		return []string{"192.0.2.54"}, nil
	}
	a := New(nil, nil)
	a.cfg.WANIfaces, a.cfg.DataDir = []string{device}, t.TempDir()
	a.shadow.leasesLoaded = true
	key := shadowWANKey("default via "+gateway+" dev "+device, []string{device}, []net.IP{client})
	oldExpiry := time.Now().Add(time.Hour)
	a.shadow.leases = map[string]shadowRememberedLease{"ISP": {wanKey: key, clientIP: client, servers: []string{"192.0.2.53:53"}, expires: oldExpiry, stamp: "Oct  3 01:00:00", leaseSeconds: 86400}}
	a.shadow.inform.probe = probe
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := a.ShadowDNSServers(context.Background())
			if err != nil || len(got) != 1 || got[0] != "192.0.2.54:53" {
				t.Errorf("fresh DHCP options %v %v", got, err)
			}
		}()
	}
	wg.Wait()
	if probes.Load() != 1 || !a.shadow.leases["ISP"].expires.Equal(oldExpiry) {
		t.Fatal("burst duplicated DHCP or invented a new lease", probes.Load())
	}
	// Original DNS lease expires and the ACK leaves the firmware ring. The
	// independently retained target still obtains current options on demand.
	log = ""
	expired := a.shadow.leases["ISP"]
	expired.expires = time.Now().Add(-time.Second)
	a.shadow.leases["ISP"] = expired
	a.shadow.discoveryUntil = time.Time{}
	a.shadow.inform.answers["ISP"] = shadowInformAnswer{}
	a.shadow.inform.retryAfter["ISP"] = time.Time{}
	if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || got[0] != "192.0.2.54:53" || probes.Load() != 2 || len(a.shadow.leases) != 0 {
		t.Fatal("lease expiry lost independent DHCP discovery", got, err, probes.Load())
	}
	b := New(nil, nil)
	b.cfg.WANIfaces = []string{device}
	b.cfg.DataDir = a.cfg.DataDir
	b.shadow.inform.probe = probe
	if got, err := b.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || probes.Load() != 3 || len(b.shadow.leases) != 0 {
		t.Fatal("restart/log rotation lost persisted DHCP target", got, err, probes.Load())
	}
	// A failed early refresh can serve only the remaining parameter TTL.
	answer := b.shadow.inform.answers["ISP"]
	answer.expires = time.Now().Add(20 * time.Second)
	b.shadow.inform.answers["ISP"] = answer
	b.shadow.inform.retryAfter["ISP"] = time.Time{}
	b.shadow.discoveryUntil = time.Time{}
	b.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		return nil, errors.New("test timeout")
	}
	if got, err := b.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || b.shadow.discoveryUntil.After(answer.expires) {
		t.Fatal("outer cache outlived INFORM TTL", got, err, b.shadow.discoveryUntil, answer.expires)
	}
	connected = "no"
	b.shadow.discoveryUntil = time.Time{}
	if got, err := b.ShadowDNSServers(context.Background()); err == nil || len(got) != 0 {
		t.Fatal("disconnected WAN reused cached options", got, err)
	}
	connected = "yes"
	gateway = "192.0.2.2"
	b.shadow.discoveryUntil = time.Time{}
	if got, err := b.ShadowDNSServers(context.Background()); err == nil || len(got) != 0 || len(b.shadow.inform.targets) != 0 {
		t.Fatal("changed WAN reused DHCP target", got, err)
	}
}
