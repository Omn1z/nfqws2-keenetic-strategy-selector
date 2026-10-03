package awg

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicConnectionIdentityHasNoSecretsAndCannotMutateManager(t *testing.T) {
	cfg := Default()
	cfg.Endpoint, cfg.ClientIface, cfg.ProtocolVersion, cfg.PublicKey = "server.example:443", "awg2", "3.1", "public-server-key"
	cfg.PrivateKey, cfg.Conn.Password, cfg.Conn.KeyPEM = "private-secret", "password-secret", "ssh-key-secret"
	cfg.Peers = []Peer{{Name: "Router", PrivateKey: "peer-secret", PSK: "psk-secret"}}
	cfg.Routing.Zones = []Zone{{Domains: []string{"private-routing.example"}}}
	manager := NewManager(cfg)
	identity := manager.PublicConnectionIdentity()
	if identity.Endpoint != cfg.Endpoint || identity.ClientIface != cfg.ClientIface || identity.Protocol != cfg.Protocol || identity.ProtocolVersion != "3.1" || identity.ServerPublicKey != cfg.PublicKey {
		t.Fatal("public identity changed the configured wire fields")
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-secret", "password-secret", "ssh-key-secret", "peer-secret", "psk-secret", "private-routing.example", "PrivateKey", "Password", "Peers", "Routing"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("public identity exposed secret or routing state")
		}
	}
	identity.Endpoint = "changed.example:1"
	identity.ServerPublicKey = "changed-public-key"
	if manager.PublicConnectionIdentity().Endpoint != "server.example:443" || manager.PublicConnectionIdentity().ServerPublicKey != "public-server-key" {
		t.Fatal("changing a returned identity changed the manager")
	}
}

func TestPublicConnectionIdentityDoesNotAllocateForLargeRoutingLists(t *testing.T) {
	cfg := Default()
	cfg.Routing.Zones = []Zone{{Domains: make([]string, 10000)}}
	manager := NewManager(cfg)
	var result ConnectionIdentity
	if allocations := testing.AllocsPerRun(100, func() { result = manager.PublicConnectionIdentity() }); allocations != 0 {
		t.Fatal("public identity allocated while reading a large routing config")
	}
	if result.Protocol == "" {
		t.Fatal("public identity was not read")
	}
}

func TestRuntimeLocalClientIdentityUsesCommittedEndpointAndDesiredLocalFlags(t *testing.T) {
	cfg := Default()
	cfg.Enabled, cfg.Client.Enabled = true, true
	cfg.Endpoint, cfg.ClientIface = "desired.example:443", "awg2"
	cfg.PrivateKey, cfg.Conn.Password = "private-secret", "password-secret"
	cfg.Routing.Zones = []Zone{{Domains: make([]string, 10000)}}
	manager := NewManager(cfg)
	applied := cfg.clone()
	applied.Endpoint, applied.ClientIface = "committed.example:443", "awg0"
	applied.Enabled, applied.Client.Enabled = false, false
	manager.SetAppliedConfig(&applied)
	got := manager.RuntimeLocalClientIdentity()
	full := manager.RuntimeConfig()
	if !got.Enabled || !got.ClientEnabled || got.Endpoint != full.Endpoint || got.ClientIface != full.ClientIface {
		t.Fatal("local DNS identity ignored committed endpoint or desired local controls")
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "Routing") || strings.Contains(string(encoded), "Peers") {
		t.Fatal("local DNS identity exposed unrelated or secret state")
	}
	got.Endpoint = "mutated.example:1"
	if manager.RuntimeLocalClientIdentity().Endpoint != "committed.example:443" {
		t.Fatal("returned identity aliased manager state")
	}
	if allocations := testing.AllocsPerRun(100, func() { got = manager.RuntimeLocalClientIdentity() }); allocations != 0 {
		t.Fatal("DNS client identity cloned a large routing config")
	}
}
