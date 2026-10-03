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

	"github.com/miekg/dns"
)

func shadowDiscoveryTestWAN(t *testing.T) (string, net.IP) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifs {
		if !validShadowWAN(iface.Name) || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil && ip.IsGlobalUnicast() {
				return iface.Name, ip
			}
		}
	}
	t.Skip("no IPv4 WAN-like interface for read-only lookup")
	return "", nil
}

func TestShadowDiscoveryNativeControlFailuresAndIgnoredDNS(t *testing.T) {
	device, ip := shadowDiscoveryTestWAN(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := command
	t.Cleanup(func() { command = previous })
	const failure = "[C] Oct 4 00:39:03 ndm: ndmc: system failed [0xcffd0062].\nndmc: initialization failure."
	current := "server:\n address: 192.0.2.53\n service: DHCP client\n interface: ISP\n"
	ignored := "I [Oct 3 01:00:00] ndhcpc: ISP: received ACK for " + ip.String() + " from 192.0.2.1 lease 86400 sec.\nI [Oct 3 01:00:00] ndm: Dhcp::Client: obtained IP address " + ip.String() + "/24.\nW [Oct 3 01:00:00] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored."
	for _, tc := range []struct {
		name, failedOperation, current, log, wantStage string
		exitErr                                        error
		remember, wantDNS                              bool
	}{
		{name: "initialization failure with nonzero exit", failedOperation: "all", exitErr: errors.New("exit status 1"), wantStage: "show ip name-server"},
		{name: "initialization failure with zero exit", failedOperation: "all", wantStage: "show ip name-server"},
		{name: "current DNS cannot verify WAN owner", failedOperation: "show interface ISP", current: current, wantStage: "show interface ISP"},
		{name: "empty current DNS cannot read lease log", failedOperation: "show log", wantStage: "show log"},
		{name: "normal ignored DNS", log: ignored, wantDNS: true},
		{name: "failed DNS command still allows verified log", failedOperation: "show ip name-server", log: ignored, wantDNS: true},
		{name: "historical ndmc failure is not current failure", log: "I [Oct 3 00:39:03] ndm: ndmc: initialization failure.\n" + ignored, wantDNS: true},
		{name: "failed log still allows valid remembered lease", failedOperation: "show log", remember: true, wantDNS: true},
		{name: "failed WAN verification rejects remembered lease", failedOperation: "show interface ISP", remember: true, wantStage: "show interface ISP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := "default via 192.0.2.1 dev " + device
			command = func(_ context.Context, name string, args ...string) (string, error) {
				if filepath.Base(name) == "ndmc" && (tc.failedOperation == "all" || args[1] == tc.failedOperation) {
					return failure, tc.exitErr
				}
				switch filepath.Base(name) + " " + strings.Join(args, " ") {
				case "ndmc -c show ip name-server":
					return tc.current, nil
				case "ndmc -c show log":
					return tc.log, nil
				case "ndmc -c show interface ISP":
					return "connected: yes\naddress: " + ip.String(), nil
				case "ip -4 route show table main default":
					return route, nil
				case "date +%Y-%m-%dT%H:%M:%S%z":
					return "2026-10-03T12:00:00+0300", nil
				}
				t.Fatalf("unexpected command: %s %v", name, args)
				return "", errors.New("unexpected command")
			}
			remembered := map[string]shadowRememberedLease{}
			expires := time.Now().Add(time.Hour)
			if tc.remember {
				remembered["ISP"] = shadowRememberedLease{wanKey: shadowWANKey(route, []string{device}, []net.IP{ip}), clientIP: ip, servers: []string{"192.0.2.53:53"}, expires: expires}
			}
			got, err := discoverShadowServersWithLeases(context.Background(), []string{device}, remembered)
			if tc.wantDNS {
				if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
					t.Fatalf("verified DNS lost: servers=%v err=%v", got, err)
				}
			} else if len(got) != 0 || err == nil || !strings.Contains(err.Error(), tc.wantStage) || !strings.Contains(err.Error(), "initialization failure") || strings.Contains(err.Error(), "ожидается информация DHCP/PPP") {
				t.Fatalf("native failure misreported: servers=%v err=%v", got, err)
			}
			if tc.remember && !remembered["ISP"].expires.Equal(expires) {
				t.Fatal("native command failure extended or removed valid remembered evidence")
			}
		})
	}
}

func TestShadowDiscoveryNativeCancellationDoesNotPoisonCache(t *testing.T) {
	device, _ := shadowDiscoveryTestWAN(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := command
	t.Cleanup(func() { command = previous })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command = func(context.Context, string, ...string) (string, error) {
		cancel()
		return "ndmc: initialization failure.", errors.New("signal: killed")
	}
	a := New(nil, nil)
	a.cfg.WANIfaces, a.cfg.DataDir = []string{device}, t.TempDir()
	if got, err := a.shadowServersOS(ctx); !errors.Is(err, context.Canceled) || len(got) != 0 {
		t.Fatalf("caller cancellation replaced by native failure: %v %v", got, err)
	}
	if !a.shadow.discoveryUntil.IsZero() || a.shadow.discoveryErr != nil {
		t.Fatal("cancellation installed a negative discovery cache")
	}
}

func TestKeeneticShadowInterfaceMustOwnActiveWANAddress(t *testing.T) {
	wan := []net.IP{net.ParseIP("192.168.0.10")}
	if !keeneticInterfaceOwnsWAN("connected: yes\naddress: 192.168.0.10\n", wan) {
		t.Fatal("missed active WAN")
	}
	for _, output := range []string{"connected: no\naddress: 192.168.0.10", "connected: yes\naddress: 192.168.3.1", "connected: yes\naddress: not-ip"} {
		if keeneticInterfaceOwnsWAN(output, wan) {
			t.Errorf("accepted non-WAN interface %q", output)
		}
	}
}

func TestShadowRouteHasIsolatedWANTableAndBlackhole(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	iface := ""
	for _, x := range ifs {
		if x.Flags&net.FlagUp != 0 && validShadowWAN(x.Name) {
			iface = x.Name
			break
		}
	}
	if iface == "" {
		t.Skip("no suitable interface for read-only interface lookup")
	}
	a := New(nil, nil)
	a.cfg.WANIfaces = []string{iface}
	previous := command
	t.Cleanup(func() { command = previous })
	var calls []string
	command = func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "ip -4 route show table main default":
			return "default via 192.0.2.1 dev " + iface, nil
		case "ip -4 route show table 827", "ip -4 rule show":
			return "", nil
		}
		if strings.Contains(call, "route replace") || strings.Contains(call, "rule add") {
			return "", nil
		}
		return "", fmt.Errorf("unexpected command: %s", call)
	}
	r := &routeState{Route: Route{ID: "shadow"}, slot: shadowRouteSlot}
	got, err := a.ensureRouteLocked(context.Background(), r, "-4")
	if err != nil || got != iface {
		t.Fatalf("iface=%q err=%v", got, err)
	}
	all := strings.Join(calls, "\n")
	for _, want := range []string{"fwmark 0x8000d57f/0x8000ffff table 827", "blackhole default table 827 metric 32760", "192.0.2.1/32 dev " + iface, "default via 192.0.2.1 dev " + iface + " table 827"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in %s", want, all)
		}
	}
	if strings.Contains(all, "iptables") || strings.Contains(all, "table 901") {
		t.Fatal("Shadow touched NFQUEUE/AWG")
	}
}

func TestShadowCachedDiscoveryIsCopiedAndHonorsCancellation(t *testing.T) {
	a := New(nil, nil)
	a.cfg.DataDir = t.TempDir()
	a.shadow.servers = []string{"192.0.2.53:53"}
	a.shadow.discoveryUntil = time.Now().Add(time.Minute)
	got, err := a.ShadowDNSServers(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	got[0] = "poisoned"
	if a.shadow.servers[0] != "192.0.2.53:53" {
		t.Fatal("returned shared mutable discovery cache")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ShadowDNSServers(ctx); err != context.Canceled {
		t.Fatalf("%v", err)
	}
}

func TestShadowUDPWrapperPreservesPacketConn(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	var conn net.Conn = &shadowPacketConn{routedConn: &routedConn{Conn: udp, closed: func() { closed++ }}, packet: udp}
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatal("DNS library would misinterpret UDP as TCP framing")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if closed != 1 {
		t.Fatalf("close tracked %d times", closed)
	}
}

func TestShadowUDPWrapperMiekgWireRoundTrip(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	serverDone := make(chan error, 1)
	go func() {
		data := make([]byte, 4096)
		n, peer, err := server.ReadFromUDP(data)
		if err != nil {
			serverDone <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(data[:n]); err != nil {
			serverDone <- fmt.Errorf("UDP unexpectedly got TCP prefix: %w", err)
			return
		}
		if len(query.Question) != 1 || query.Question[0].Name != "shadow.example." {
			serverDone <- fmt.Errorf("wrong query: %s", query)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(query)
		answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "shadow.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 9)}}
		wire, err := answer.Pack()
		if err == nil {
			_, err = server.WriteToUDP(wire, peer)
		}
		serverDone <- err
	}()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &shadowPacketConn{routedConn: &routedConn{Conn: client, closed: func() {}}, packet: client}
	defer wrapped.Close()
	_ = wrapped.SetDeadline(time.Now().Add(2 * time.Second))
	dc := &dns.Conn{Conn: wrapped, UDPSize: 4096}
	question := new(dns.Msg)
	question.SetQuestion("shadow.example.", dns.TypeA)
	if err := dc.WriteMsg(question); err != nil {
		t.Fatal(err)
	}
	answer, err := dc.ReadMsg()
	if err != nil || answer == nil || answer.Id != question.Id || len(answer.Answer) != 1 {
		t.Fatalf("answer=%v err=%v", answer, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestShadowSlowRoutePreparationDoesNotBlockOrdinaryRoutes(t *testing.T) {
	a, _ := maintenanceTestAdapter(t)
	previous := command
	t.Cleanup(func() { command = previous })
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "ip" && strings.Join(args, " ") == "-4 route show table main default" {
			close(entered)
			<-ctx.Done()
			return "", ctx.Err()
		}
		return "", fmt.Errorf("unexpected command")
	}
	dialDone := make(chan struct{})
	go func() { defer close(dialDone); _, _ = a.dialShadowOS(ctx, "udp", "192.0.2.53:53") }()
	waitMaintenanceTest(t, entered, "blocked Shadow WAN inspection")
	routesDone := make(chan struct{})
	go func() { defer close(routesDone); a.Routes() }()
	select {
	case <-routesDone:
	case <-time.After(250 * time.Millisecond):
		cancel()
		waitMaintenanceTest(t, dialDone, "Shadow cancellation")
		t.Fatal("Shadow WAN command blocked ordinary DNS route lookup")
	}
	cancel()
	waitMaintenanceTest(t, dialDone, "Shadow dial cancellation")
}

func TestShadowLeaseCacheSurvivesLogRotationAndRejectsChangedWAN(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	device, ip := "", ""
	for _, iface := range ifs {
		if !validShadowWAN(iface.Name) || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			parsed, _, _ := net.ParseCIDR(addr.String())
			if parsed.To4() != nil && parsed.IsGlobalUnicast() {
				device, ip = iface.Name, parsed.String()
				break
			}
		}
		if device != "" {
			break
		}
	}
	if device == "" {
		t.Skip("no IPv4 WAN-like interface for read-only lookup")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := command
	t.Cleanup(func() { command = previous })
	fixture := "I [Oct  3 01:00:00] ndhcpc: ISP: received ACK for " + ip + " from 192.0.2.1 lease 86400 sec.\nI [Oct  3 01:00:00] ndm: Dhcp::Client: obtained IP address " + ip + "/24.\nW [Oct  3 01:00:00] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored."
	log, gateway, connected := fixture, "192.0.2.1", "yes"
	command = func(_ context.Context, name string, args ...string) (string, error) {
		switch filepath.Base(name) + " " + strings.Join(args, " ") {
		case "ndmc -c show ip name-server":
			return "", nil
		case "ndmc -c show log":
			return log, nil
		case "ndmc -c show interface ISP":
			return "connected: " + connected + "\naddress: " + ip, nil
		case "ip -4 route show table main default":
			return "default via " + gateway + " dev " + device, nil
		case "date +%Y-%m-%dT%H:%M:%S%z":
			return "2026-10-03T12:00:00+0300", nil
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	}
	cache := map[string]shadowRememberedLease{}
	discover := func() ([]string, error) {
		return discoverShadowServersWithLeases(context.Background(), []string{device}, cache)
	}
	if got, err := discover(); err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" || len(cache) != 1 {
		t.Fatalf("initial discovery: %v %v %+v", got, err, cache)
	}
	saved := cache["ISP"]
	if remaining := time.Until(saved.expires); remaining < 12*time.Hour+59*time.Minute || remaining > 13*time.Hour {
		t.Fatalf("invented lease lifetime: %s", remaining)
	}
	log = "I [Oct  3 12:00:00] ndm: unrelated later event"
	if got, err := discover(); err != nil || len(got) != 1 {
		t.Fatalf("ring rotation lost valid lease: %v %v", got, err)
	}
	if !cache["ISP"].expires.Equal(saved.expires) {
		t.Fatal("cache fallback extended real lease")
	}
	localResolver := saved
	localResolver.servers = []string{net.JoinHostPort(ip, "53")}
	cache["ISP"] = localResolver
	if got, err := discover(); err == nil || len(got) != 0 {
		t.Fatal("restored router-local resolver was not revalidated", got, err)
	}
	cache["ISP"] = saved
	connected = "no"
	if got, err := discover(); err == nil || len(got) != 0 {
		t.Fatal("disconnected WAN reused lease", got, err)
	}
	connected = "yes"
	gateway = "192.0.2.2"
	if got, err := discover(); err == nil || len(got) != 0 || len(cache) != 0 {
		t.Fatal("new gateway reused lease", got, err, cache)
	}
	gateway = "192.0.2.1"
	cache["ISP"] = saved
	log = "I [Oct  3 12:00:00] ndhcpc: ISP: received ACK for " + ip + " from 192.0.2.1 lease 86400 sec."
	if got, err := discover(); err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" || !sameShadowLease(cache["ISP"], saved) || !cache["ISP"].expires.Equal(saved.expires) {
		t.Fatal("ACK-only renewal lost valid DNS or extended its original expiry", got, err, cache)
	}
	// An old complete ACK may remain in the ring; it must neither replace
	// current DNS nor clear it merely because its timestamp differs.
	log = strings.ReplaceAll(strings.ReplaceAll(fixture, "01:00:00", "00:30:00"), "192.0.2.53", "192.0.2.54")
	if got, err := discover(); err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" || !cache["ISP"].expires.Equal(saved.expires) {
		t.Fatal("older ACK replaced current DNS", got, err, cache)
	}
	log = strings.ReplaceAll(log, ip, "192.0.2.200")
	if got, err := discover(); err != nil || len(got) != 1 || !sameShadowLease(cache["ISP"], saved) || !cache["ISP"].expires.Equal(saved.expires) {
		t.Fatal("older different-address ACK invalidated current lease", got, err, cache)
	}
	// Complete, current DNS evidence does replace the previous lease.
	log = strings.ReplaceAll(strings.ReplaceAll(fixture, "01:00:00", "12:00:00"), "192.0.2.53", "192.0.2.54")
	if got, err := discover(); err != nil || len(got) != 1 || got[0] != "192.0.2.54:53" || cache["ISP"].stamp != "Oct  3 12:00:00" {
		t.Fatal("complete new DHCP DNS did not replace previous evidence", got, err, cache)
	}
	cache["ISP"] = saved
	log = "I [Oct  3 12:00:00] ndhcpc: ISP: received ACK for 192.0.2.200 from 192.0.2.1 lease 86400 sec."
	if got, err := discover(); err == nil || len(got) != 0 || len(cache) != 0 {
		t.Fatal("changed-address ACK reused previous DNS", got, err, cache)
	}
	log = "I [Oct  3 12:00:00] ndhcpc: ISP: received ACK for " + ip + " from 192.0.2.1 lease 86400 sec."
	saved.expires = time.Now().Add(-time.Second)
	cache["ISP"] = saved
	if got, err := discover(); err == nil || len(got) != 0 || len(cache) != 0 {
		t.Fatal("expired lease used", got, err, cache)
	}
}
