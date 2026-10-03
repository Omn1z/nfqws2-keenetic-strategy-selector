package arpblock

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type nativeFixture struct {
	enabled     bool
	calls       []string
	failSave    bool
	ignoreWrite bool
	failRestore bool
}

func fixtureConfig(enabled bool) string {
	flag := ""
	if enabled {
		flag = "    peer-isolation\n"
	}
	return "! automatically generated configuration\ninterface WifiMaster1/AccessPoint1\n    rename GuestWiFi_5G\n    ssid Keenetic\n    authentication wpa-psk very-secret-password\n    up\n!\ninterface Bridge0\n    rename Home\n    description \"Home network\"\n    include GuestWiFi_5G\n    security-level private\n    ip address 192.168.3.1 255.255.255.0\n" + flag + "    up\n!\n"
}

func (f *nativeFixture) run(ctx context.Context, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.calls = append(f.calls, command)
	switch command {
	case "show running-config":
		return fixtureConfig(f.enabled), nil
	case "show interface Bridge0":
		return "              id: Bridge0\n  interface-name: Home\n            type: Bridge\n           state: up\n          global: no\n  security-level: private\n         address: 192.168.3.1\n            mask: 255.255.255.0\n", nil
	case "show associations":
		return "          station: \n              mac: ac:ba:c0:48:8a:8e\n               ap: WifiMaster1/AccessPoint1\n", nil
	case "show ip dhcp bindings":
		return "            lease: \n               ip: 192.168.3.127\n              mac: ac:ba:c0:48:8a:8e\n         hostname: Yandex-Station-Max\n", nil
	case "interface Bridge0 peer-isolation":
		if !f.ignoreWrite {
			f.enabled = true
		}
		return "", nil
	case "interface Bridge0 no peer-isolation":
		if f.failRestore {
			return "", errors.New("restore failed")
		}
		f.enabled = false
		return "", nil
	case "system configuration save":
		if f.failSave {
			f.failSave = false
			return "", errors.New("save failed")
		}
		return "", nil
	default:
		return "", errors.New("unexpected command")
	}
}

func testService(f *nativeFixture) *Service {
	return &Service{gate: make(chan struct{}, 1), platform: "keenetic", run: f.run}
}

func TestReadOnlyInventoryAndCache(t *testing.T) {
	f := &nativeFixture{}
	s := testService(f)
	v, err := s.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Segments) != 1 || !v.Segments[0].Home || !v.Segments[0].Eligible || v.Segments[0].Enabled {
		t.Fatalf("segments: %+v", v.Segments)
	}
	if len(v.Clients) != 1 || v.Clients[0].Hostname != "Yandex-Station-Max" || v.Clients[0].Segment != "Bridge0" || v.Clients[0].IP != "192.168.3.127" {
		t.Fatalf("clients: %+v", v.Clients)
	}
	if strings.Contains(v.Revision, "secret") || len(v.Revision) != 64 {
		t.Fatalf("invalid revision %q", v.Revision)
	}
	_, err = s.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 3 {
		t.Fatalf("cached read issued commands: %v", f.calls)
	}
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "show ") {
			t.Fatalf("read mutated router: %s", c)
		}
	}
}

func TestChangeIsVerifiedAndPersisted(t *testing.T) {
	f := &nativeFixture{}
	s := testService(f)
	v, _ := s.View(context.Background())
	after, err := s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: true, Revision: v.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if !f.enabled || !after.Segments[0].Enabled || after.Revision == v.Revision {
		t.Fatalf("not applied: %+v", after)
	}
	if !contains(f.calls, "system configuration save") {
		t.Fatal("not persisted")
	}
	// Disable is the symmetric native command, not removal of a whole segment.
	after, err = s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: false, Revision: after.Revision})
	if err != nil || f.enabled || after.Segments[0].Enabled {
		t.Fatalf("disable: %v %+v", err, after)
	}
}

func TestStaleRevisionAndCommandInjectionCannotMutate(t *testing.T) {
	for _, change := range []Change{{Segment: "Bridge0", Enabled: true, Revision: "stale"}, {Segment: "Bridge0; reboot", Enabled: true}} {
		f := &nativeFixture{}
		s := testService(f)
		v, _ := s.View(context.Background())
		if change.Revision == "" {
			change.Revision = v.Revision
		}
		_, err := s.SetIsolation(context.Background(), change)
		if err == nil {
			t.Fatal("accepted unsafe change")
		}
		for _, c := range f.calls {
			if !strings.HasPrefix(c, "show ") {
				t.Fatalf("unexpected mutation: %s", c)
			}
		}
	}
}

func TestPersistenceFailureRestoresOriginalValue(t *testing.T) {
	f := &nativeFixture{failSave: true}
	s := testService(f)
	v, _ := s.View(context.Background())
	_, err := s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: true, Revision: v.Revision})
	if err == nil || !strings.Contains(err.Error(), "предыдущая настройка восстановлена") {
		t.Fatalf("error: %v", err)
	}
	if f.enabled {
		t.Fatal("rollback left isolation enabled")
	}
	if !contains(f.calls, "interface Bridge0 no peer-isolation") {
		t.Fatal("no rollback")
	}
	view, err := s.View(context.Background())
	if err != nil || view.Segments[0].Enabled {
		t.Fatalf("stale cache after rollback: %v %+v", err, view)
	}
}

func TestIgnoredCommandNeverReportsApplied(t *testing.T) {
	f := &nativeFixture{ignoreWrite: true}
	s := testService(f)
	v, _ := s.View(context.Background())
	_, err := s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: true, Revision: v.Revision})
	if err == nil {
		t.Fatal("unverified isolation reported as applied")
	}
}

func TestRollbackFailureIsExplicit(t *testing.T) {
	f := &nativeFixture{failSave: true, failRestore: true}
	s := testService(f)
	v, _ := s.View(context.Background())
	_, err := s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: true, Revision: v.Revision})
	if err == nil || !strings.Contains(err.Error(), "возврат настройки не подтверждён") {
		t.Fatalf("hidden rollback failure: %v", err)
	}
}

func TestWaitingRequestHonoursCancellation(t *testing.T) {
	s := testService(&nativeFixture{})
	s.gate <- struct{}{}
	defer func() { <-s.gate }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := s.View(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error: %v", err)
	}
}

func TestUnavailableBackendDoesNotPretendToIsolate(t *testing.T) {
	s := &Service{gate: make(chan struct{}, 1), platform: "openwrt", reason: "unsupported"}
	v, err := s.View(context.Background())
	if err != nil || v.Supported || len(v.Segments) != 0 {
		t.Fatalf("view: %v %+v", err, v)
	}
	_, err = s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: true})
	if err == nil {
		t.Fatal("unsupported backend accepted changes")
	}
}

func TestClientRefreshFailureDoesNotUndoConfirmedSuccess(t *testing.T) {
	f := &nativeFixture{}
	s := testService(f)
	v, _ := s.View(context.Background())
	s.run = func(ctx context.Context, command string) (string, error) {
		if command == "show associations" {
			return "", errors.New("inventory unavailable")
		}
		return f.run(ctx, command)
	}
	after, err := s.SetIsolation(context.Background(), Change{Segment: "Bridge0", Enabled: true, Revision: v.Revision})
	if err != nil || !after.Segments[0].Enabled || !strings.Contains(after.Reason, "inventory unavailable") {
		t.Fatalf("lost confirmed successful mutation: %v %+v", err, after)
	}
}

func TestBrowserCancellationAfterWriteStillCompletesVerification(t *testing.T) {
	f := &nativeFixture{}
	s := testService(f)
	v, _ := s.View(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.run = func(commandCtx context.Context, command string) (string, error) {
		out, err := f.run(commandCtx, command)
		if command == "interface Bridge0 peer-isolation" {
			cancel()
		}
		return out, err
	}
	after, err := s.SetIsolation(ctx, Change{Segment: "Bridge0", Enabled: true, Revision: v.Revision})
	if err != nil || !after.Segments[0].Enabled || !contains(f.calls, "system configuration save") {
		t.Fatalf("browser cancellation interrupted applied change: %v %+v", err, after)
	}
}
