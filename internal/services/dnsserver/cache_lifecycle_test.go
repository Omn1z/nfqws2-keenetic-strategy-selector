package dnsserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/tools/store"
)

func TestDNSIdenticalConfigAndRepeatedStartPreserveLiveCache(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	for _, id := range []uint16{810, 811} {
		if answer := queryDNSService(t, client, s.Status().Endpoints.DNS, id); answer.Rcode != mdns.RcodeSuccess {
			t.Fatal("could not prime live DNS cache")
		}
	}
	before := s.Status()
	run := activeDNSRun(s)
	backend.mu.Lock()
	prepares, closes := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if before.Cache.Entries != 1 || before.Stats.CacheHits != 1 || !before.Stats.LastCached {
		t.Fatal("fixture did not populate and reuse its DNS cache")
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "same config", run: func() error { return s.SetConfig(s.Config()) }},
		{name: "equivalent spelling", run: func() error {
			cfg := s.Config()
			cfg.ListenHost = " " + cfg.ListenHost + " "
			cfg.DefaultUpstream.Address = " " + cfg.DefaultUpstream.Address + " "
			cfg.RouteMode = " " + cfg.RouteMode + " "
			for i := range cfg.Rules {
				cfg.Rules[i].Domain = strings.ToUpper(cfg.Rules[i].Domain) + "."
			}
			return s.SetConfig(cfg)
		}},
		{name: "repeated start", run: func() error { return s.SetEnabled(true) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); err != nil {
				t.Fatal(err)
			}
			after := s.Status()
			if activeDNSRun(s) != run || !after.Running || !reflect.DeepEqual(after.Stats, before.Stats) || after.Cache != before.Cache || !reflect.DeepEqual(after.Config, before.Config) {
				t.Fatal("identical normalized save discarded the resolver, cache, counters or configuration")
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			if backend.prepareCount != prepares || backend.closeCount != closes {
				t.Fatal("identical save or repeated start changed backend routing")
			}
		})
	}
	if result := s.Test(context.Background(), "example.com", "A"); !result.OK || !result.Cached || result.Error != "" || result.Route == "" || result.Upstream == "" {
		t.Fatalf("preserved cache did not serve the next diagnostic query: %+v", result)
	}
	if after := s.Status(); after.Stats.Queries != before.Stats.Queries+1 || after.Stats.CacheHits != before.Stats.CacheHits+1 || !after.Stats.LastCached {
		t.Fatal("same-config save lost the cached answer or its delivery metadata")
	}
}

func TestDNSChangedConfigStillReplacesResolverAndInvalidatesCache(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	queryDNSService(t, client, s.Status().Endpoints.DNS, 820)
	run := activeDNSRun(s)
	before := s.Status()
	backend.mu.Lock()
	prepares, closes := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	cfg := s.Config()
	cfg.CacheSize++
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	after := s.Status()
	if !after.Running || activeDNSRun(s) == run || run.resolver.lifetime.Err() == nil || after.Cache.Entries != 0 || after.Cache.Capacity != before.Cache.Capacity+1 || after.Stats != (Stats{}) {
		t.Fatal("real resolver setting change retained stale answers or the old run")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.prepareCount != prepares+1 || backend.closeCount != closes+1 {
		t.Fatal("real resolver setting change did not reinstall its backend")
	}
}

func TestDNSSameConfigResolvedHostChangeStillRestarts(t *testing.T) {
	s, _, client := newDNSServiceFixture(t, 8)
	queryDNSService(t, client, s.Status().Endpoints.DNS, 830)
	run := activeDNSRun(s)
	s.opMu.Lock()
	s.resolveHost = func(string) (string, error) { return "127.0.0.2", nil }
	s.opMu.Unlock()
	if err := s.SetConfig(s.Config()); err != nil {
		t.Fatal(err)
	}
	after := s.Status()
	if !after.Running || activeDNSRun(s) == run || after.ListenHost != "127.0.0.2" || after.Cache.Entries != 0 || after.Stats != (Stats{}) {
		t.Fatal("changed concrete LAN host was mistaken for an identical live listener")
	}
}

func TestDNSFailedStartSameConfigAndRepeatedStartRetryRecovery(t *testing.T) {
	for _, operation := range []string{"same config", "repeated start"} {
		t.Run(operation, func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cfg := Default()
			cfg.Enabled = true
			cfg.ListenHost = "127.0.0.1"
			cfg.DNSPort = protocolTestPort(t)
			cfg.FastDNS = false
			cfg.Rules = []Rule{}
			if err := st.Save(configFile, cfg); err != nil {
				t.Fatal(err)
			}
			backend := &resolverTestBackend{prepareErr: errors.New("fixture routes unavailable")}
			s := New(st, backend, func(string) (string, error) { return "127.0.0.1", nil })
			t.Cleanup(s.Close)
			s.StartEnabled()
			if status := s.Status(); status.Running || status.LastError == "" || !status.Config.Enabled {
				t.Fatal("fixture failed start did not preserve desired enabled state and error")
			}
			backend.mu.Lock()
			backend.prepareErr = nil
			prepares := backend.prepareCount
			backend.mu.Unlock()
			if operation == "same config" {
				err = s.SetConfig(s.Config())
			} else {
				err = s.SetEnabled(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			if status := s.Status(); !status.Running || status.LastError != "" || !status.Config.Enabled {
				t.Fatal("identical config masked a failed start instead of retrying")
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			if backend.prepareCount != prepares+1 {
				t.Fatal("failed start recovery did not prepare routes again")
			}
		})
	}
}

func TestDNSUnhealthyLiveRunDoesNotTakeIdenticalConfigShortcut(t *testing.T) {
	for _, failure := range []string{"service error", "listener canceled"} {
		t.Run(failure, func(t *testing.T) {
			s, _, client := newDNSServiceFixture(t, 8)
			queryDNSService(t, client, s.Status().Endpoints.DNS, 840)
			run := activeDNSRun(s)
			if failure == "service error" {
				s.setError(errors.New("fixture service failure"))
			} else {
				run.listeners.cancel()
			}
			if err := s.SetEnabled(true); err != nil {
				t.Fatal(err)
			}
			if status := s.Status(); !status.Running || status.LastError != "" || activeDNSRun(s) == run || status.Cache.Entries != 0 {
				t.Fatal("unhealthy live run was preserved instead of retried")
			}
		})
	}
}

func TestDNSCacheDeliveryFlagsRejectBlockedAndObserverFailure(t *testing.T) {
	s, backend, _ := newDNSServiceFixture(t, 8)
	cacheResponseServiceAnswer(t, s, "delivery.example", mdns.TypeA, "delivery.example. 60 IN A 203.0.113.20")
	assertFlags := func(wantCached, wantBlocked, wantOK bool, wantEvent string) {
		t.Helper()
		cursor := s.Logs(0).LastID
		result := s.Test(context.Background(), "delivery.example", "A")
		if result.Cached != wantCached || result.Shared || result.Blocked != wantBlocked || result.OK != wantOK || s.Status().Stats.LastCached != wantCached || s.Status().Stats.LastShared {
			t.Fatalf("wrong cache delivery metadata: cached=%v last=%v blocked=%v ok=%v error=%q", result.Cached, s.Status().Stats.LastCached, result.Blocked, result.OK, result.Error)
		}
		entries := s.Logs(cursor).Entries
		if len(entries) != 1 || entries[0].Event != wantEvent {
			t.Fatal("delivery outcome received an incorrect cache/error/block log event")
		}
		for _, item := range []struct {
			value any
			key   string
			want  bool
		}{{result, "cached", wantCached}, {s.Status().Stats, "last_cached", wantCached}, {result, "shared", false}, {s.Status().Stats, "last_shared", false}} {
			wire, err := json.Marshal(item.value)
			var fields map[string]any
			if err != nil || json.Unmarshal(wire, &fields) != nil || fields[item.key] != item.want {
				t.Fatal("public cache delivery flag was omitted or changed")
			}
		}
	}
	assertFlags(true, false, true, "cache")
	backend.mu.Lock()
	backend.observe = func(context.Context, string, []byte, net.IP) ([]byte, error) {
		return nil, errors.New("fixture routing policy is unavailable")
	}
	backend.mu.Unlock()
	assertFlags(false, false, false, "error")
	if stats := s.Status().Stats; stats.CacheHits != 1 || stats.Failures != 1 {
		t.Fatal("observer failure was counted as a delivered cache hit")
	}
	backend.mu.Lock()
	backend.observe = nil
	backend.mu.Unlock()
	assertFlags(true, false, true, "cache")
	blocker, err := NewBlockMatcher(nil, []BlockingRule{{Domain: "delivery.example", Category: BlockCategoryAds}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	activeDNSRun(s).resolver.SetBlocker(blocker)
	assertFlags(false, true, true, "blocked")
	if stats := s.Status().Stats; stats.CacheHits != 2 || stats.BlockedTotal != 1 || stats.LastCached {
		t.Fatal("block policy retained a previous delivered-cache status")
	}
}
