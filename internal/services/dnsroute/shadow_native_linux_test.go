//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type shadowNativeFakeReader struct {
	state   shadowNativeSnapshot
	stopped bool
}

func (f *shadowNativeFakeReader) snapshot() shadowNativeSnapshot { return f.state }
func (f *shadowNativeFakeReader) close()                         { f.stopped = true }

func shadowNativeFixture(t *testing.T) (*Adapter, *shadowNativeFakeReader, shadowBroadcastWAN) {
	t.Helper()
	a, _, _ := shadowFallbackFixture(t)
	a.started = true
	a.loadShadowLeases()
	nic, err := net.InterfaceByName(a.cfg.WANIfaces[0])
	if err != nil {
		t.Fatal(err)
	}
	addrs, _ := nic.Addrs()
	var ips []net.IP
	var client net.IP
	for _, addr := range addrs {
		ip, _, _ := net.ParseCIDR(addr.String())
		ips = append(ips, ip)
		if client == nil && ip.To4() != nil {
			client = ip
		}
	}
	wan := shadowBroadcastWAN{native: "GigabitEthernet1", device: nic.Name, client: client}
	key := shadowWANKey("default via 192.0.2.1 dev "+nic.Name, a.cfg.WANIfaces, ips)
	r := &shadowNativeFakeReader{state: shadowNativeSnapshot{started: time.Now()}}
	a.shadow.native = shadowNativeState{reader: r, key: key, iface: wan.native, device: wan.device, client: client, identity: fmt.Sprintf("%d/%s", nic.Index, nic.HardwareAddr)}
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) { return nil, context.DeadlineExceeded }
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		return nil, nil, context.DeadlineExceeded
	}
	t.Cleanup(a.closeShadowNative)
	return a, r, wan
}

func shadowNativeTestACK(r *shadowNativeFakeReader, now time.Time) {
	r.state.sequence++
	r.state.observedAt = now
	r.state.observation = shadowNativeDHCPObservation{Kind: "ack", ServerIP: net.ParseIP("1.1.1.2"), Servers: []string{"192.0.2.53"}, LeaseSeconds: 3600, LeaseExpires: now.Add(time.Hour)}
}

func TestShadowNativeLeaseInvalidatesNegativeCacheWithoutInform(t *testing.T) {
	a, reader, _ := shadowNativeFixture(t)
	if _, err := a.ShadowDNSServers(context.Background()); err == nil {
		t.Fatal("expected original INFORM timeout")
	}
	shadowNativeTestACK(reader, time.Now())
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		t.Fatal("valid native lease triggered INFORM")
		return nil, nil
	}
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		t.Fatal("valid native lease triggered broadcast")
		return nil, nil, nil
	}
	got, err := a.ShadowDNSServers(context.Background())
	if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatal(got, err)
	}
	if a.shadow.native.changed() {
		t.Fatal("revision not consumed")
	}
	first := a.shadow.leases["GigabitEthernet1"].expires
	shadowFallbackRetryNow(a)
	if _, err := a.ShadowDNSServers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.shadow.leases["GigabitEthernet1"].expires.Equal(first) {
		t.Fatal("snapshot replay extended lease")
	}
	// A service restart restores only the lease; no new INFORM is needed.
	a.closeShadowNative()
	a.shadow.leasesLoaded = false
	a.shadow.discoveryUntil = time.Time{}
	a.started = false // do not open an actual capture socket in this unit test
	if _, err := a.ShadowDNSServers(context.Background()); err != nil {
		t.Fatal("restored native lease unusable", err)
	}
}

func TestShadowNativeCaptureCannotOverrideNewerLogOrLease(t *testing.T) {
	a, reader, wan := shadowNativeFixture(t)
	observed := time.Now().Add(-time.Minute)
	shadowNativeTestACK(reader, observed)
	newer := shadowRememberedLease{wanKey: a.shadow.native.key, clientIP: wan.client, servers: []string{"192.0.2.54:53"}, observedAt: observed.Add(30 * time.Second), expires: time.Now().Add(time.Hour), leaseSeconds: 3600}
	for _, kind := range []string{"ack", "nak", "ack_no_dns"} {
		reader.state.observation.Kind = kind
		a.shadow.leases[wan.native] = newer
		if a.observeShadowNative(context.Background(), a.shadow.native.key, []shadowBroadcastWAN{wan}, nil, time.Now()) {
			t.Fatal("old observation superseded newer evidence", kind)
		}
		if got := a.shadow.leases[wan.native]; got.servers[0] != "192.0.2.54:53" {
			t.Fatal("newer native lease lost")
		}
	}
	// Log stamps use the router timezone, not Go's local timezone.
	routerNow := time.Now().In(time.FixedZone("router", 3*3600))
	newer.observedAt = time.Time{}
	newer.stamp = routerNow.Add(-10 * time.Second).Format("Jan _2 15:04:05")
	a.shadow.leases[wan.native] = newer
	if a.observeShadowNative(context.Background(), a.shadow.native.key, []shadowBroadcastWAN{wan}, nil, routerNow) {
		t.Fatal("newer firmware log suppressed")
	}
}

func TestShadowNativeWithdrawalAndWANLoss(t *testing.T) {
	for _, kind := range []string{"nak", "ack_no_dns", "expired"} {
		t.Run(kind, func(t *testing.T) {
			a, reader, wan := shadowNativeFixture(t)
			shadowNativeTestACK(reader, time.Now())
			key := a.shadow.native.key
			if !a.observeShadowNative(context.Background(), key, []shadowBroadcastWAN{wan}, nil, time.Now()) {
				t.Fatal("ACK not applied")
			}
			reader.state.sequence++
			reader.state.observedAt = time.Now()
			if kind == "expired" {
				reader.state.observation.LeaseExpires = time.Now().Add(-time.Second)
			} else {
				reader.state.observation.Kind = kind
			}
			if !a.observeShadowNative(context.Background(), key, []shadowBroadcastWAN{wan}, nil, time.Now()) || len(a.shadow.leases) != 0 {
				t.Fatal("withdrawal kept native lease")
			}
			if a.observeShadowNative(context.Background(), "", nil, nil, time.Now()) || !reader.stopped {
				t.Fatal("lost WAN left capture running")
			}
		})
	}
}

func TestShadowNativeRevisionDoesNotBypassErrorCache(t *testing.T) {
	a, reader, _ := shadowNativeFixture(t)
	a.SetShadowDiagnostics(true)
	shadowNativeTestACK(reader, time.Now())
	previous := command
	calls := 0
	command = func(context.Context, string, ...string) (string, error) { calls++; return "", errors.New("offline") }
	t.Cleanup(func() { command = previous })
	for range 10 {
		_, _ = a.ShadowDNSServers(context.Background())
	}
	if len(a.ShadowDiagnostics().Attempts) != 1 || calls > 4 {
		t.Fatal("native revision bypassed error cooldown", calls)
	}
	if !reader.stopped {
		t.Fatal("unverified WAN kept capture running")
	}
}

func TestShadowNativeSocketShutdownWakesIdlePoll(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	pipes := []int{-1, -1}
	if err := unix.Pipe2(pipes, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fds[0])
		t.Fatal(err)
	}
	s := &shadowNativeSocket{wake: pipes[1], done: make(chan struct{})}
	tracker, _ := newShadowNativeDHCPTracker(net.ParseIP("192.0.2.10"), net.HardwareAddr{2, 0, 0, 0, 0, 1})
	go s.read(fds[0], pipes[0], 1, tracker)
	closed := make(chan struct{})
	go func() { s.close(); s.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("idle capture did not stop")
	}
	if !s.snapshot().closed {
		t.Fatal("missing closed state")
	}
}

func TestShadowNativeDiagnosticsExplainWaiting(t *testing.T) {
	a, _, wan := shadowNativeFixture(t)
	a.SetShadowDiagnostics(true)
	ctx, finish := a.shadow.diagnostics.begin(context.Background())
	a.observeShadowNative(ctx, a.shadow.native.key, []shadowBroadcastWAN{wan}, nil, time.Now())
	finish(nil, nil, time.Time{})
	text := a.ShadowDiagnostics().Attempts[0].Events[0].Message
	if !strings.Contains(text, "штатное обновление") || !strings.Contains(text, "REQUEST=0") {
		t.Fatal(text)
	}
}

func TestShadowNativeDNSWorksWithDiagnosticsOffAndToggleHasNoSideEffects(t *testing.T) {
	a, reader, _ := shadowNativeFixture(t)
	fallback := command
	calls := 0
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		calls++
		return fallback(ctx, name, args...)
	}
	if diagnostics := a.ShadowDiagnostics(); diagnostics.Enabled || len(diagnostics.Attempts) != 0 {
		t.Fatal("diagnostics must start disabled", diagnostics)
	}
	if _, err := a.ShadowDNSServers(context.Background()); err == nil {
		t.Fatal("expected initial missing-DNS error")
	}
	beforeCalls, beforeCache, beforeReader := calls, a.shadow.discoveryUntil, a.shadow.native.reader
	for _, enabled := range []bool{true, false, true, false} {
		a.SetShadowDiagnostics(enabled)
		if a.ShadowDiagnostics().Enabled != enabled {
			t.Fatal("diagnostic switch not applied")
		}
		if calls != beforeCalls || a.shadow.native.reader != beforeReader || reader.stopped || !a.shadow.discoveryUntil.Equal(beforeCache) {
			t.Fatal("diagnostic switch changed discovery, capture, or cache")
		}
	}
	// The functional DHCP observer remains alive even when optional diagnostic
	// history and additional packet diagnostics are disabled.
	shadowNativeTestACK(reader, time.Now())
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		t.Fatal("valid observed lease triggered another INFORM")
		return nil, nil
	}
	servers, err := a.ShadowDNSServers(context.Background())
	if err != nil || len(servers) != 1 || servers[0] != "192.0.2.53:53" {
		t.Fatal("native DHCP DNS not applied while diagnostics disabled", servers, err)
	}
	if diagnostics := a.ShadowDiagnostics(); diagnostics.Enabled || len(diagnostics.Attempts) != 0 || diagnostics.InProgress {
		t.Fatal("disabled diagnostics collected discovery history", diagnostics)
	}
	beforeCalls, beforeCache = calls, a.shadow.discoveryUntil
	expires, revision := a.shadow.leases["GigabitEthernet1"].expires, a.shadow.native.applied
	a.SetShadowDiagnostics(true)
	a.SetShadowDiagnostics(false)
	servers, err = a.ShadowDNSServers(context.Background())
	if err != nil || len(servers) != 1 || calls != beforeCalls || !a.shadow.discoveryUntil.Equal(beforeCache) || !a.shadow.leases["GigabitEthernet1"].expires.Equal(expires) || a.shadow.native.applied != revision || reader.stopped {
		t.Fatal("toggling diagnostics invalidated an already learned DNS lease", servers, err)
	}
}

func TestShadowNativeSavedCanonicalLeaseBeatsOlderAliasLog(t *testing.T) {
	a, reader, wan := shadowNativeFixture(t)
	shadowNativeTestACK(reader, time.Now())
	if _, err := a.ShadowDNSServers(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.closeShadowNative()
	a.started = false
	a.shadow.leasesLoaded = false
	a.shadow.discoveryUntil = time.Time{}
	routerNow := time.Now().In(time.FixedZone("router", 3*3600))
	stamp := routerNow.Add(-5 * time.Minute).Format("Jan _2 15:04:05")
	old := command
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-c show log":
			return fmt.Sprintf("I [%s] ndhcpc: ISP: received ACK for %s from 1.1.1.2 lease 86400 sec.\nI [%s] ndm: Dhcp::Client: obtained IP address %s/24.\nI [%s] ndm: Dns::InterfaceSpecific: name server 192.0.2.99 is ignored.", stamp, wan.client, stamp, wan.client, stamp), nil
		case "+%Y-%m-%dT%H:%M:%S%z":
			return routerNow.Format("2006-01-02T15:04:05-0700"), nil
		}
		return old(ctx, name, args...)
	}
	t.Cleanup(func() { command = old })
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		t.Fatal("stale alias forced INFORM")
		return nil, nil
	}
	got, err := a.ShadowDNSServers(context.Background())
	if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatal("old alias overwrote fresh persisted DNS", got, err)
	}
}

func TestShadowNativeCanceledDiscoveryPreservesNewRevision(t *testing.T) {
	a, reader, _ := shadowNativeFixture(t)
	a.shadow.discoveryErr = errors.New("previous failure")
	a.shadow.discoveryUntil = time.Now().Add(time.Minute)
	shadowNativeTestACK(reader, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := command
	command = func(context.Context, string, ...string) (string, error) { cancel(); return "", context.Canceled }
	t.Cleanup(func() { command = old })
	if _, err := a.ShadowDNSServers(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if reader.stopped || !a.shadow.native.changed() {
		t.Fatal("canceled discovery lost new DHCP observation")
	}
	command = old
	got, err := a.ShadowDNSServers(context.Background())
	if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatal("new query reused stale error cache", got, err)
	}
}

func TestShadowNativeKernelCaptureOpensAndStops(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var nic *net.Interface
	var client net.IP
	for _, candidate := range interfaces {
		if len(candidate.HardwareAddr) != 6 || candidate.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := candidate.Addrs()
		for _, address := range addresses {
			ip, _, _ := net.ParseCIDR(address.String())
			if ip.To4() != nil && ip.IsGlobalUnicast() {
				nic = &candidate
				client = ip
				break
			}
		}
		if nic != nil {
			break
		}
	}
	if nic == nil {
		t.Skip("no Ethernet test interface")
	}
	reader, err := startShadowNativeReader(nic, client)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip("CAP_NET_RAW unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	reader.close()
	if !reader.snapshot().closed {
		t.Fatal("kernel capture stayed open")
	}
}

func TestShadowNativeOldWithdrawalPreservesNewInformCache(t *testing.T) {
	a, reader, wan := shadowNativeFixture(t)
	shadowNativeTestACK(reader, time.Now())
	reader.state.observation.Kind = "ack_no_dns"
	key := a.shadow.native.key
	a.shadow.inform.targets = map[string]shadowDHCPTarget{wan.native: {wanKey: key, clientIP: wan.client, serverIP: net.ParseIP("1.1.1.2")}}
	a.observeShadowNative(context.Background(), key, []shadowBroadcastWAN{wan}, nil, time.Now())
	a.shadow.inform.answers = map[string]shadowInformAnswer{wan.native: {servers: []string{"192.0.2.54:53"}, expires: time.Now().Add(5 * time.Minute)}}
	a.observeShadowNative(context.Background(), key, []shadowBroadcastWAN{wan}, nil, time.Now())
	if len(a.shadow.inform.answers) != 1 {
		t.Fatal("replayed native withdrawal deleted newer INFORM cache")
	}
	reader.state.sequence++
	a.observeShadowNative(context.Background(), key, []shadowBroadcastWAN{wan}, nil, time.Now())
	if len(a.shadow.inform.answers) != 0 {
		t.Fatal("new native withdrawal kept older INFORM cache")
	}
}

func TestShadowNativeExpiryDuringWANVerification(t *testing.T) {
	a, _, wan := shadowNativeFixture(t)
	now := time.Now()
	a.shadow.leases[wan.native] = shadowRememberedLease{wanKey: a.shadow.native.key, clientIP: wan.client, servers: []string{"192.0.2.53:53"}, observedAt: now, expires: now.Add(25 * time.Millisecond), leaseSeconds: 1}
	old := command
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-c show interface GigabitEthernet1" {
			time.Sleep(40 * time.Millisecond)
		}
		return old(ctx, name, args...)
	}
	t.Cleanup(func() { command = old })
	if got, err := a.ShadowDNSServers(context.Background()); err == nil || len(got) != 0 {
		t.Fatal("expired native DNS served after slow WAN check", got, err)
	}
}

func TestShadowNativeCancellationAfterObservationKeepsRevision(t *testing.T) {
	a, reader, _ := shadowNativeFixture(t)
	a.shadow.discoveryErr = errors.New("previous failure")
	a.shadow.discoveryUntil = time.Now().Add(time.Minute)
	shadowNativeTestACK(reader, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := command
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-c show interface GigabitEthernet1" {
			cancel()
		}
		return old(ctx, name, args...)
	}
	t.Cleanup(func() { command = old })
	if _, err := a.ShadowDNSServers(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !a.shadow.native.changed() {
		t.Fatal("late cancellation consumed observation before committing cache")
	}
	command = old
	if got, err := a.ShadowDNSServers(context.Background()); err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatal(got, err)
	}
}
