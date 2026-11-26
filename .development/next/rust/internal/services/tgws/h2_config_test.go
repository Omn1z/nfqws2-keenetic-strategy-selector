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

func TestLegacyMixedCaseTGWSConfigRetainsOptionalControls(t *testing.T) {
	cfg := Default()
	if err := json.Unmarshal([]byte(`{
		"port":1431,"PORT":1430,"PoRt":null,
		"disable_secure":false,"DISABLE_SECURE":true,"CFPROXY":true,
		"CFPROXY_H2_MEDIA":false,"cfProxy_h2_media":null,"PROXY_PROTOCOL":true,
		"DC_REDIRECTS":null,"dc_redirects":{"3":"192.0.2.3"},
		"Dc_Redirects":{"5":"192.0.2.5"}
	}`), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Normalize()
	if cfg.Port != 1430 || !cfg.DisableSecure || !cfg.CFProxy || !cfg.ProxyProtocol || cfg.CFProxyH2Media || cfg.h2Enabled() {
		t.Fatal("mixed-case startup changed the configured transport or port")
	}
	if len(cfg.DCRedirects) != 2 || cfg.DCRedirects[3] != "192.0.2.3" || cfg.DCRedirects[5] != "192.0.2.5" {
		t.Fatal("map was not cleared and overlaid in wire order")
	}

	var replacement Config
	if err := json.Unmarshal([]byte(`{
		"port":1430,"PORT":1440,"PoRt":null,"DISABLE_SECURE":false,"CFPROXY":true,
		"CFPROXY_H2_MEDIA":true,"cfProxy_h2_media":null,"PROXY_PROTOCOL":false
	}`), &replacement); err != nil {
		t.Fatal(err)
	}
	replacement.Normalize()
	if replacement.Port != 1440 || replacement.DisableSecure || replacement.ProxyProtocol || !replacement.h2Enabled() {
		t.Fatal("mixed-case replacement changed the requested transport or port")
	}
}

func TestLegacyTGWSJSONFoldAndEarlierDuplicateType(t *testing.T) {
	valid := []byte(`{
		"PORT":-1,"port":1430,"ſni_fronting":true,
		"Cfproxy_worKer_domain":"worker.example",
		"dİsable_secure":true,"tranſport":"extension"
	}`)
	for _, cfg := range []*Config{Default(), {}} {
		if err := json.Unmarshal(valid, cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Port != 1430 || !cfg.SNIFronting || cfg.CFProxyWorkerDomain != "worker.example" || cfg.DisableSecure {
			t.Fatal("known field casing did not follow Unicode SimpleFold")
		}
	}
	for _, invalid := range []string{
		`{"PORT":"wrong","port":1430}`,
		`{"ſni_fronting":"wrong","SNI_FRONTING":false}`,
		`{"LinK_host":false,"link_host":"proxy.example"}`,
	} {
		var cfg Config
		if err := json.Unmarshal([]byte(invalid), &cfg); err == nil {
			t.Fatal("accepted an earlier non-null scalar of the wrong type")
		}
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
