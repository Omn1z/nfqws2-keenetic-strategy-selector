package awgroute

import (
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func TestFallbackCandidatesKeepPriorityAndRemoveDuplicates(t *testing.T) {
	got := fallbackCandidates("primary", []string{" backup ", "primary", "backup", "last", ""})
	want := []string{"primary", "backup", "last"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}

func TestNormalizeFallbackTunnelIDsValidatesAndPreservesOrder(t *testing.T) {
	exists := func(id string) bool { return id == "a" || id == "b" || id == "c" }
	got, err := normalizeFallbackTunnelIDs("a", []string{"b", "a", " b ", "c"}, exists)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "b,c" {
		t.Fatalf("normalized = %#v", got)
	}
	if _, err := normalizeFallbackTunnelIDs("a", []string{"missing"}, exists); err == nil {
		t.Fatal("unknown fallback must be rejected")
	}
}

func TestSelectFallbackTunnelID(t *testing.T) {
	usable := map[string]bool{"primary": true, "backup": true, "last": true}
	healthy := map[string]bool{"primary": false, "backup": true, "last": true}
	canUse := func(id string) bool { return usable[id] }
	isUp := func(id string) bool { return healthy[id] }
	if got := selectFallbackTunnelID("primary", []string{"backup", "last"}, canUse, isUp); got != "backup" {
		t.Fatalf("down primary should select backup, got %q", got)
	}
	healthy["primary"] = true
	if got := selectFallbackTunnelID("primary", []string{"backup", "last"}, canUse, isUp); got != "primary" {
		t.Fatalf("recovered primary should regain priority, got %q", got)
	}
	healthy["primary"], healthy["backup"], healthy["last"] = false, false, false
	if got := selectFallbackTunnelID("primary", []string{"backup", "last"}, canUse, isUp); got != "primary" {
		t.Fatalf("all-down policy must retain primary killswitch, got %q", got)
	}
	usable["primary"] = false
	if got := selectFallbackTunnelID("primary", []string{"backup"}, canUse, isUp); got != "backup" {
		t.Fatalf("disabled primary should use usable backup, got %q", got)
	}
}

func TestSetRoutingRulesNormalizesFallbackList(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	primary := awg.NewManager(importedLikeConfig())
	backupCfg := importedLikeConfig()
	backupCfg.Endpoint = "188.114.97.101:2408"
	backup := awg.NewManager(backupCfg)
	svc := &Service{
		store:    st,
		activeID: "primary",
		order:    []string{"primary", "backup"},
		servers: map[string]*managedServer{
			"primary": {ID: "primary", Name: "primary", Manager: primary},
			"backup":  {ID: "backup", Name: "backup", Manager: backup},
		},
		awg: primary,
	}
	err = svc.AWG2SetRoutingRules(awg.RoutingConfig{Mode: "off", Zones: []awg.Zone{{
		Name:              "fallback",
		TunnelID:          "primary",
		FallbackTunnelIDs: []string{"backup", "backup"},
		Route:             "tunnel",
		// Keep the rule match empty: this test exercises persistence and
		// activation without asking the host running the test to install ipsets.
		Domains: []string{},
		Enabled: true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got := primary.Config().Routing.Zones
	if len(got) != 1 || len(got[0].FallbackTunnelIDs) != 1 || got[0].FallbackTunnelIDs[0] != "backup" {
		t.Fatalf("unexpected stored fallback list: %#v", got)
	}
}
