package awgroute

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func discoveryServiceFixture(t *testing.T, zones []awg.Zone) *Service {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := awg.Default()
	cfg.Endpoint = "192.0.2.10:51820"
	cfg.PrivateKey = "must-never-be-in-discoveries"
	cfg.Client.Enabled = true
	cfg.Routing = awg.RoutingConfig{Mode: "zones", Active: true, DomainSource: "dnsproxy", Zones: zones}
	m := awg.NewManager(cfg)
	svc := &Service{store: st, activeID: "primary", order: []string{"primary"}, awg: m, servers: map[string]*managedServer{"primary": {ID: "primary", Name: "Test", Manager: m}}}
	t.Cleanup(svc.CloseRoutingDiscoveries)
	return svc
}

func TestRoutingDiscoveriesRemainReadOnlyAndSeparateFromRuleSources(t *testing.T) {
	on := true
	z := awg.Zone{Name: "Video", TunnelID: "primary", Domains: []string{"example.org"}, IncludeSubdomains: &on, Enabled: true, Route: "tunnel"}
	svc := discoveryServiceFixture(t, []awg.Zone{z})
	svc.recordRoutingDiscovery(z, "media.example.org", "192.168.1.5", []string{"198.51.100.7"}, "dns", 0)
	svc.recordRoutingDiscovery(z, "example.org", "192.168.1.5", []string{"198.51.100.8"}, "dns", 0)
	svc.CloseRoutingDiscoveries()
	before, err := os.ReadFile(svc.store.Path(routingLearnedFile))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := svc.AWG2DiscoveredRoutes()
	if !snapshot.Active || !snapshot.Ready || len(snapshot.Rules) != 1 || len(snapshot.Rules[0].Entries) != 2 {
		t.Fatalf("invalid snapshot: %+v", snapshot)
	}
	for _, entry := range snapshot.Rules[0].Entries {
		if !entry.Confirmed {
			t.Fatal("confirmed installation missing")
		}
		if entry.Additional != (entry.Domain == "media.example.org") {
			t.Fatalf("source/subdomain classification: %+v", entry)
		}
	}
	if !reflect.DeepEqual(svc.awgRoutingRules()[0].Domains, []string{"example.org"}) {
		t.Fatal("observation edited manual source")
	}
	for i := 0; i < 3; i++ {
		svc.AWG2DiscoveredRoutes()
	}
	after, _ := os.ReadFile(svc.store.Path(routingLearnedFile))
	if !bytes.Equal(before, after) {
		t.Fatal("read-only snapshot wrote history")
	}
	wire, err := json.Marshal(snapshot)
	if err != nil || bytes.Contains(wire, []byte("must-never")) {
		t.Fatal("snapshot exposed connection secret")
	}
	restored := discoveryServiceFixture(t, []awg.Zone{z})
	restored.store = svc.store
	restored.loadRoutingDiscoveries()
	loaded := restored.AWG2DiscoveredRoutes()
	if len(loaded.Rules[0].Entries) != 2 || loaded.Rules[0].Entries[0].Confirmed {
		t.Fatal("restored history claimed live kernel state")
	}
}

func TestRoutingDiscoveriesRespectScopeSourcesAndPolicyReadiness(t *testing.T) {
	on, off := true, false
	z := awg.Zone{Name: "Scoped", TunnelID: "primary", Domains: []string{"example.org"}, IncludeSubdomains: &on, SourceIPs: []string{"192.168.1.0/24"}, Enabled: true, Route: "tunnel"}
	svc := discoveryServiceFixture(t, []awg.Zone{z})
	for _, test := range []struct{ name, src string }{
		{"outside.org", "192.168.1.5"}, {"evil-example.org", "192.168.1.5"}, {"cdn.example.org", "192.168.2.5"}, {"cdn.example.org", ""},
	} {
		svc.recordRoutingDiscovery(z, test.name, test.src, []string{"198.51.100.7"}, "dns", 0)
	}
	if entries := svc.discovered.Snapshot(AWGRoutingLearnedRuleKey(z), 0, 0, true); len(entries) != 0 {
		t.Fatal("out-of-scope request entered history")
	}
	svc.recordRoutingDiscovery(z, "cdn.example.org", "192.168.1.5", []string{"198.51.100.7"}, "dns", 0)
	if got := svc.AWG2DiscoveredRoutes().Rules[0].Entries; len(got) != 1 || !got[0].Confirmed {
		t.Fatalf("matching source not recorded: %+v", got)
	}
	finish := svc.routingDNSGate.begin(false)
	svc.recordRoutingDiscovery(z, "new.example.org", "192.168.1.5", []string{"198.51.100.8"}, "dns", 0)
	if got := svc.AWG2DiscoveredRoutes(); got.Ready || got.Rules[0].Entries[0].Confirmed || len(got.Rules[0].Entries) != 1 {
		t.Fatal("applying policy published new confirmation")
	}
	finish(nil)
	if got := svc.AWG2DiscoveredRoutes().Rules[0].Entries; got[0].Confirmed {
		t.Fatal("old confirmation survived kernel epoch replacement")
	}
	z.IncludeSubdomains = &off
	svc.recordRoutingDiscovery(z, "cdn.example.org", "192.168.1.5", []string{"198.51.100.7"}, "dns", 0)
	if got := svc.discovered.Snapshot(AWGRoutingLearnedRuleKey(z), 0, 1, true); len(got) != 0 {
		t.Fatal("exact rule captured subdomain")
	}
}

func TestRoutingDiscoveriesRevalidateExpandedListContent(t *testing.T) {
	on := true
	z := awg.Zone{Name: "List", TunnelID: "primary", Domains: []string{"list:video"}, IncludeSubdomains: &on, Enabled: true, Route: "tunnel"}
	svc := discoveryServiceFixture(t, []awg.Zone{z})
	svc.expandCache = map[string]expandCacheEntry{"list:video": {rev: 0, domains: []string{"old.example"}}}
	svc.recordRoutingDiscovery(z, "cdn.old.example", "", []string{"198.51.100.7"}, "dns", 0)
	if len(svc.AWG2DiscoveredRoutes().Rules[0].Entries) != 1 {
		t.Fatal("expanded list did not match")
	}
	svc.BumpZonesRevision()
	svc.expandCache["list:video"] = expandCacheEntry{rev: svc.zonesRevision.Load(), domains: []string{"new.example"}}
	if len(svc.AWG2DiscoveredRoutes().Rules[0].Entries) != 0 {
		t.Fatal("changed list kept obsolete discoveries visible")
	}
	svc.recordRoutingDiscovery(z, "cdn.old.example", "", []string{"198.51.100.7"}, "dns", 0)
	svc.recordRoutingDiscovery(z, "cdn.new.example", "", []string{"198.51.100.8"}, "dns", 0)
	if got := svc.AWG2DiscoveredRoutes().Rules[0].Entries; len(got) != 1 || got[0].Domain != "cdn.new.example" {
		t.Fatalf("list cache not invalidated: %+v", got)
	}
}
