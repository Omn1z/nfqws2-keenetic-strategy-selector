package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

func importTestService(t *testing.T) *Service {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	return s
}
func TestDNSImportPreviewValidationIsReadOnly(t *testing.T) {
	s := importTestService(t)
	before := s.Config()
	hash := ConfigDigest(before)
	candidate := s.Config()
	candidate.Enabled = true
	candidate.ListenHost = "127.0.0.1"
	candidate.DNSPort = protocolTestPort(t)
	candidate.LoggingEnabled = false
	candidate.SchedulerEnabled = false
	normalized, host, err := s.ValidateImportedConfig(candidate)
	if err != nil || host != "127.0.0.1" || normalized.SchedulerEnabled {
		t.Fatalf("preview=%+v host=%q error=%v", normalized, host, err)
	}
	var persisted Config
	if err := s.store.Load(configFile, &persisted); err != nil {
		t.Fatal(err)
	}
	if ConfigDigest(s.Config()) != hash || ConfigDigest(persisted) != hash || s.Status().Running {
		t.Fatal("preview changed persisted/runtime configuration")
	}
	candidate.DefaultUpstream.Address = "https://127.0.0.1:" + strconv.Itoa(candidate.DNSPort) + "/dns-query"
	if _, _, err := s.ValidateImportedConfig(candidate); err == nil {
		t.Fatal("self upstream passed preview")
	}
	if !reflect.DeepEqual(before, s.Config()) {
		t.Fatal("rejected preview changed current config")
	}
}

func TestDNSImportPreparesForeignLANListenerWithoutChangingSavedSettings(t *testing.T) {
	for _, currentListener := range []string{"auto", "192.168.1.1", "192.168.2.1"} {
		t.Run(currentListener, func(t *testing.T) {
			s := importTestService(t)
			current := s.Config()
			current.ListenHost = currentListener
			if err := s.SetConfig(current); err != nil {
				t.Fatal(err)
			}
			s.resolveHost = func(host string) (string, error) {
				if host == "auto" || host == "192.168.1.1" {
					return "192.168.1.1", nil
				}
				return "", fmt.Errorf("address %s is not owned by this router", host)
			}
			before := ConfigDigest(s.Config())
			candidate := s.Config()
			candidate.ListenHost = "192.168.3.1"
			candidate.RouteMode, candidate.AWGFallback = RouteModeVPNOnly, "auto"
			if _, _, err := s.ValidateImportedConfig(candidate); err == nil {
				t.Fatal("strict validation silently changed an unavailable listener")
			}
			prepared, host, err := s.PrepareImportedConfig(candidate)
			wantListener := currentListener
			if currentListener == "192.168.2.1" {
				wantListener = "auto"
			}
			if err != nil || host != "192.168.1.1" || prepared.ListenHost != wantListener || prepared.RouteMode != RouteModeVPNOnly || prepared.AWGFallback != "auto" {
				t.Fatalf("listener preparation=%+v host=%q err=%v", prepared, host, err)
			}
			if candidate.ListenHost != "192.168.3.1" || ConfigDigest(s.Config()) != before || s.Status().Running {
				t.Fatal("preview mutated source, saved config or runtime")
			}
			var persisted Config
			if err := s.store.Load(configFile, &persisted); err != nil || ConfigDigest(persisted) != before {
				t.Fatalf("preview changed disk config: %v", err)
			}
		})
	}
}

func TestDNSImportListenerPreparationPreservesValidHostAndRejectsUnsafeConfig(t *testing.T) {
	s := importTestService(t)
	var resolved []string
	s.resolveHost = func(host string) (string, error) {
		resolved = append(resolved, host)
		if host == "auto" {
			return "192.168.1.1", nil
		}
		if host == "192.168.1.2" {
			return host, nil
		}
		return "", errors.New("listener unavailable")
	}
	cfg := s.Config()
	cfg.ListenHost = "192.168.1.2"
	prepared, host, err := s.PrepareImportedConfig(cfg)
	if err != nil || prepared.ListenHost != cfg.ListenHost || host != cfg.ListenHost || !reflect.DeepEqual(resolved, []string{cfg.ListenHost}) {
		t.Fatalf("valid owned listener replaced: %+v host=%q resolved=%v err=%v", prepared, host, resolved, err)
	}
	for _, invalid := range []string{"0.0.0.0", "::", "8.8.8.8", "not-an-address"} {
		resolved = nil
		cfg.ListenHost = invalid
		if _, _, err := s.PrepareImportedConfig(cfg); err == nil || len(resolved) != 0 {
			t.Fatalf("malformed listener %q was adapted instead of rejected: %v %v", invalid, resolved, err)
		}
	}
	// Validation must use the effective destination listener, never the foreign
	// address, or an imported DoH endpoint could become a DNS forwarding loop.
	cfg.ListenHost = "192.168.3.1"
	cfg.DefaultUpstream.Address = "https://192.168.1.1:" + strconv.Itoa(cfg.DNSPort) + "/dns-query"
	if _, _, err := s.PrepareImportedConfig(cfg); err == nil {
		t.Fatal("self upstream accepted after listener adaptation")
	}
	cfg.DefaultUpstream = s.Config().DefaultUpstream
	s.resolveHost = func(string) (string, error) { return "", errors.New("no local LAN address") }
	if _, _, err := s.PrepareImportedConfig(cfg); err == nil {
		t.Fatal("unavailable target listener accepted")
	}
}

func TestDNSImportConflictPreservesLaterEdits(t *testing.T) {
	s := importTestService(t)
	candidate := s.Config()
	hash := ConfigDigest(candidate)
	candidate.CacheTTLSeconds = 42
	if err := s.SetLoggingEnabled(false); err != nil {
		t.Fatal(err)
	}
	edited := s.Config()
	if err := s.ImportConfig(candidate, hash); !errors.Is(err, ErrImportConfigConflict) {
		t.Fatalf("stale import=%v", err)
	}
	if !reflect.DeepEqual(s.Config(), edited) {
		t.Fatal("stale import overwrote later settings")
	}
}
func TestDNSImportCommitsCompleteConfigAndRetryIsReadOnly(t *testing.T) {
	s := importTestService(t)
	candidate := s.Config()
	hash := ConfigDigest(candidate)
	candidate.DNSPort = protocolTestPort(t)
	candidate.ListenHost = "127.0.0.1"
	candidate.LoggingEnabled = false
	candidate.FastDNS = false
	candidate.SchedulerEnabled = false
	candidate.CacheTTLSeconds = 42
	candidate.DefaultPool = []Upstream{{Address: "https://9.9.9.9/dns-query", BootstrapIPs: []string{"9.9.9.9"}}}
	candidate.Filtering = &FilteringConfig{Enabled: false, Lists: []string{}, CustomRules: []BlockingRule{{Domain: "ads.example", Category: "ads"}}, Allowlist: []string{"allowed.example"}}
	candidate.DisabledMethods = []DisabledMethod{{Upstream: candidate.DefaultUpstream.Address, Route: "nfqws"}}
	candidate.ShadowDNS.Enabled = true
	candidate.ShadowDNS.Servers = []string{"192.0.2.53:53"}
	candidate.ShadowDNS.Domains = []ShadowDomain{{Domain: "ru", IncludeSubdomains: true}, {Domain: "exact.example"}}
	if err := s.ImportConfig(candidate, hash); err != nil {
		t.Fatal(err)
	}
	normalized, _, err := s.ValidateImportedConfig(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Config(), normalized) {
		t.Fatalf("full config not applied: %+v", s.Config())
	}
	var persisted Config
	if err := s.store.Load(configFile, &persisted); err != nil || ConfigDigest(persisted) != ConfigDigest(normalized) {
		t.Fatalf("disk mismatch %v %+v", err, persisted)
	}
	if err := s.ImportConfig(candidate, hash); err != nil {
		t.Fatalf("lost ACK retry=%v", err)
	}
	candidate.Filtering.Allowlist[0] = "mutated.example"
	if s.Config().Filtering.Allowlist[0] != "allowed.example" {
		t.Fatal("import retained caller-owned slices")
	}
}
func TestDNSConcurrentImportsUseOnePreviewGeneration(t *testing.T) {
	s := importTestService(t)
	base := s.Config()
	hash := ConfigDigest(base)
	a, b := base, base
	a.CacheTTLSeconds = 42
	b.CacheTTLSeconds = 43
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, cfg := range []Config{a, b} {
		wg.Add(1)
		go func(cfg Config) { defer wg.Done(); <-start; results <- s.ImportConfig(cfg, hash) }(cfg)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrImportConfigConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}
func TestDNSImportStartupFailureRestoresSavedAndRunningConfig(t *testing.T) {
	s, _, client := newDNSServiceFixture(t, 8)
	old := s.Config()
	oldEndpoint := s.Status().Endpoints.DNS
	s.mu.RLock()
	original := s.active
	s.mu.RUnlock()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	_, rawPort, _ := net.SplitHostPort(occupied.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	candidate := s.Config()
	candidate.DNSPort = port
	candidate.LoggingEnabled = false
	candidate.SchedulerEnabled = false
	if err := s.ImportConfig(candidate, ConfigDigest(old)); err == nil {
		t.Fatal("occupied TCP listener import succeeded")
	}
	if !reflect.DeepEqual(s.Config(), old) || !s.Status().Running || s.Status().Endpoints.DNS != oldEndpoint {
		t.Fatalf("failed import did not restore old DNS: %+v", s.Status())
	}
	s.mu.RLock()
	kept := s.active == original
	s.mu.RUnlock()
	if !kept {
		t.Fatal("known port collision interrupted the original listener before preflight")
	}
	var persisted Config
	if err := s.store.Load(configFile, &persisted); err != nil || ConfigDigest(persisted) != ConfigDigest(old) {
		t.Fatalf("rollback disk mismatch=%v", err)
	}
	queryDNSService(t, client, oldEndpoint, 201)
}

type dnsImportFailOnceBackend struct {
	*resolverTestBackend
	failNext atomic.Bool
}

func (b *dnsImportFailOnceBackend) Prepare(ctx context.Context, opts dnsroute.ListenOptions) error {
	if b.failNext.Swap(false) {
		return errors.New("test imported firewall preparation failed")
	}
	return b.resolverTestBackend.Prepare(ctx, opts)
}

func TestDNSImportRuntimePreparationFailureRollsBack(t *testing.T) {
	s := importTestService(t)
	backend := &dnsImportFailOnceBackend{resolverTestBackend: s.backend.(*resolverTestBackend)}
	s.backend = backend // fixture is still disabled; no runtime can read this field.
	old := s.Config()
	old.ListenHost = "127.0.0.1"
	old.Enabled = true
	old.DNSPort = protocolTestPort(t)
	if err := s.SetConfig(old); err != nil || !s.Status().Running {
		t.Fatalf("fixture start = %v %+v", err, s.Status())
	}
	old = s.Config()
	candidate := s.Config()
	candidate.SchedulerEnabled = false
	backend.failNext.Store(true)
	if err := s.ImportConfig(candidate, ConfigDigest(old)); err == nil {
		t.Fatal("failed firewall preparation import succeeded")
	}
	if !reflect.DeepEqual(s.Config(), old) || !s.Status().Running {
		t.Fatalf("runtime failure did not roll back: %+v", s.Status())
	}
	var persisted Config
	if err := s.store.Load(configFile, &persisted); err != nil || ConfigDigest(persisted) != ConfigDigest(old) {
		t.Fatalf("rollback persisted wrong config: %v", err)
	}
}
func TestDNSImportInvalidConfigAndHashDoNotMutate(t *testing.T) {
	s := importTestService(t)
	old := s.Config()
	bad := s.Config()
	bad.DNSPort = 0
	if err := s.ImportConfig(bad, ConfigDigest(old)); err == nil {
		t.Fatal("invalid config imported")
	}
	good := s.Config()
	good.LoggingEnabled = false
	if err := s.ImportConfig(good, ""); err == nil {
		t.Fatal("missing preview hash accepted")
	}
	if !reflect.DeepEqual(s.Config(), old) {
		t.Fatal("invalid import changed settings")
	}
}

func TestDNSImportRetryKeepsHealthyRunAndRebindsChangedAutoLAN(t *testing.T) {
	s, _, _ := newDNSServiceFixture(t, 8)
	var moved atomic.Bool
	s.resolveHost = func(string) (string, error) {
		if moved.Load() {
			return "127.0.0.2", nil
		}
		return "127.0.0.1", nil
	}
	cfg := s.Config()
	cfg.ListenHost = "auto"
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	original := s.active
	s.mu.RUnlock()
	if err := s.ImportConfig(cfg, ConfigDigest(cfg)); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	same := s.active == original
	s.mu.RUnlock()
	if !same {
		t.Fatal("retry discarded a healthy listener")
	}
	moved.Store(true)
	if err := s.ImportConfig(cfg, ConfigDigest(cfg)); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	rebound := s.active != original
	host := s.host
	s.mu.RUnlock()
	if !rebound || host != "127.0.0.2" || !s.Status().Running {
		t.Fatal("same settings ignored a changed resolved LAN bind address")
	}
}
