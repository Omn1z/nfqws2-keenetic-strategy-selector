package tgws

import (
	"encoding/json"
	"testing"
)

func TestH2ConfigMigrationPreservesExplicitChoiceAndEligibility(t *testing.T) {
	for _, test := range []struct {
		name          string
		json          string
		want, enabled bool
	}{
		{"legacy", `{"cfproxy":true,"secret":"0123456789abcdef0123456789abcdef","pool_size":0}`, true, true},
		{"disabled", `{"cfproxy":true,"cfproxy_h2_media":false}`, false, false},
		{"enabled", `{"cfproxy":true,"cfproxy_h2_media":true}`, true, true},
		{"CF disabled", `{"cfproxy":false}`, true, false},
		{"plain WS", `{"cfproxy":true,"disable_secure":true}`, true, false},
		{"test DC", `{"cfproxy":true,"force_test_dc":true}`, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cfg Config
			if err := json.Unmarshal([]byte(test.json), &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.Normalize()
			if cfg.CFProxyH2Media != test.want || cfg.h2Enabled() != test.enabled {
				t.Fatalf("choice=%t effective=%t", cfg.CFProxyH2Media, cfg.h2Enabled())
			}
			wire, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			copy := Default()
			if err := json.Unmarshal(wire, copy); err != nil {
				t.Fatal(err)
			}
			if copy.h2Enabled() != test.enabled || copy.Secret != cfg.Secret || copy.PoolSize != cfg.PoolSize {
				t.Fatal("round trip changed settings")
			}
		})
	}
	if !Default().h2Enabled() {
		t.Fatal("fresh install lost upstream H2 default")
	}
}

func TestH2StatsAreVisibleInSnapshot(t *testing.T) {
	s := &Stats{}
	s.connectionsH2.Store(3)
	s.h2TCPConnections.Store(1)
	s.h2Requests.Store(12)
	s.h2Errors.Store(2)
	s.h2Replays.Store(4)
	v := s.snapshot()
	if v.Connections.H2 != 3 || v.H2.TCPConnections != 1 || v.H2.Requests != 12 || v.H2.Errors != 2 || v.H2.Replays != 4 {
		t.Fatalf("lost H2 counters: %+v", v)
	}
}
