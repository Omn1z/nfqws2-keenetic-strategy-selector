package awgroute

import (
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func importedLikeConfig() *awg.ServerConfig {
	cfg := awg.Default()
	cfg.Install = "apt"
	cfg.Conn.Host = ""
	cfg.Endpoint = "188.114.97.100:2408"
	cfg.PrivateKey = ""
	cfg.PublicKey = "server-public-key"
	cfg.DeployedAt = 1
	cfg.Client.Enabled = true
	cfg.Peers = []awg.Peer{{
		ID:         "router",
		Name:       "router",
		PublicKey:  "router-public-key",
		PrivateKey: "router-private-key",
		Address:    "172.16.0.2/32",
		AllowedIPs: "0.0.0.0/0",
		Keepalive:  25,
		IsRouter:   true,
	}}
	return cfg
}

func TestSetRoutingRulesDoesNotRequireVPSHostForImportedLikeProfile(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := importedLikeConfig()
	m := awg.NewManager(cfg)
	svc := &Service{
		store:    st,
		activeID: "warp",
		order:    []string{"warp"},
		servers: map[string]*managedServer{
			"warp": {ID: "warp", Name: "WARP", Manager: m},
		},
		awg: m,
	}

	err = svc.AWG2SetRoutingRules(awg.RoutingConfig{
		Mode:         "zones",
		DomainSource: "dnsproxy",
		Killswitch:   true,
		Zones:        []awg.Zone{},
	})
	if err != nil {
		t.Fatalf("route-only save should not validate VPS host: %v", err)
	}
	got := m.Config().Routing
	if got.Mode != "zones" || len(got.Zones) != 0 || got.Active {
		t.Fatalf("unexpected routing after empty rules save: mode=%q zones=%d active=%v", got.Mode, len(got.Zones), got.Active)
	}
	if got.DomainSource != "dnsproxy" || !got.Killswitch {
		t.Fatalf("routing flags were not preserved: domain_source=%q killswitch=%v", got.DomainSource, got.Killswitch)
	}
}

func TestNormalizeAWGStateRepairsImportedInstallMarker(t *testing.T) {
	cfg := importedLikeConfig()
	st := normalizeAWGState(awgPersisted{
		ActiveID: "warp",
		Servers:  []awgPersistedServer{{ID: "warp", Name: "WARP", Config: *cfg}},
	})
	got := st.Servers[0].Config
	if got.Install != "imported" {
		t.Fatalf("expected imported marker to be repaired, got %q", got.Install)
	}
	if got.Conn.Host != "" || got.Conn.Port != 0 || got.Conn.User != "" {
		t.Fatalf("imported profile must not keep SSH credentials: %+v", got.Conn)
	}
}
