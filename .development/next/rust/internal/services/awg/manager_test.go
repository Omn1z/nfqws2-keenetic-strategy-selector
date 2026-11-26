package awg

import (
	"context"
	"strings"
	"testing"
)

// fakeRunner records commands/puts and replies based on substring matches.
type fakeRunner struct {
	cmds      []string
	puts      []string
	responses []kv
}

type kv struct{ match, out string }

func (f *fakeRunner) Run(_ context.Context, cmd string) (string, string, error) {
	f.cmds = append(f.cmds, cmd)
	for _, r := range f.responses {
		if strings.Contains(cmd, r.match) {
			return r.out, "", nil
		}
	}
	if strings.Contains(cmd, "echo previous=1") {
		return "previous=1", "", nil
	}
	return "", "", nil
}

func (f *fakeRunner) Put(_ context.Context, path string, _ uint32, _ []byte) error {
	f.puts = append(f.puts, path)
	return nil
}

func (f *fakeRunner) Close() error { return nil }

func newManagerWithFake(f *fakeRunner) (*Manager, *string) {
	cfg := Default()
	cfg.ProtocolVersion = "2" // this fixture exercises the legacy apt/DKMS path
	cfg.TrafficObfuscation = nil
	cfg.Conn.Host = "vps.example.com"
	cfg.Conn.Password = "secret"
	m := NewManager(cfg)
	learned := "ssh-ed25519 AAAATESTKEY"
	m.dial = func(_ context.Context, _ Credentials) (runner, string, error) {
		return f, learned, nil
	}
	return m, &learned
}

func TestDeployFlow(t *testing.T) {
	f := &fakeRunner{responses: []kv{
		{"ip route show default", "eth0\n===\nubuntu 22.04\nkvm"},
		{"modinfo amneziawg", "loaded"},
		{"awg show awg0 2>&1", "interface: awg0\n  listening port: 51820\n  latest handshake: 5 seconds ago\n==LISTEN==\nUNCONN 0 0 0.0.0.0:51820 0.0.0.0:*"},
	}}
	m, _ := newManagerWithFake(f)
	if _, err := m.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	res, err := m.Deploy(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Listening {
		t.Fatalf("expected OK+listening, got %+v", res)
	}
	if res.Method != "apt" {
		t.Fatalf("expected apt method, got %q", res.Method)
	}
	foundConf := false
	for _, p := range f.puts {
		if strings.Contains(p, "/etc/amnezia/amneziawg/.nfqws-deploy-awg0-") && strings.HasSuffix(p, "/new.conf") {
			foundConf = true
		}
	}
	if !foundConf {
		t.Fatalf("conf was never written; puts=%v", f.puts)
	}
	// host key got pinned (TOFU) and deploy timestamp set
	if m.Config().Conn.KnownKey == "" {
		t.Fatal("expected host key to be pinned")
	}
	if m.Config().DeployedAt == 0 {
		t.Fatal("expected DeployedAt set after successful deploy")
	}
	// server keys generated and randomized obfuscation is non-vanilla
	if m.Config().Obf.H1 == "1" {
		t.Fatal("expected randomized H1")
	}
}

func TestDeployUserspaceFallback(t *testing.T) {
	f := &fakeRunner{responses: []kv{
		{"ip route show default", "ens3"},
		{"modinfo amneziawg", "missing"},
		{"awg show awg0 2>&1", "interface: awg0\n==LISTEN==\n0.0.0.0:51820"},
	}}
	m, _ := newManagerWithFake(f)
	_, _ = m.EnsureKeys()
	res, err := m.Deploy(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != "userspace" {
		t.Fatalf("expected userspace fallback, got %q", res.Method)
	}
}

func TestAddPeerSyncsWhenDeployed(t *testing.T) {
	f := &fakeRunner{}
	m, _ := newManagerWithFake(f)
	_, _ = m.EnsureKeys()
	m.cfg.DeployedAt = 1 // pretend already deployed
	p, err := m.AddPeer(context.Background(), Peer{Name: "router", IsRouter: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.PublicKey == "" || p.PrivateKey == "" || p.PSK == "" {
		t.Fatal("expected generated keys/PSK")
	}
	if p.Address != "10.13.13.2/32" {
		t.Fatalf("expected first peer addr .2, got %q", p.Address)
	}
	syncd := false
	forwarding := false
	for _, c := range f.cmds {
		if strings.Contains(c, "awg syncconf awg0") {
			syncd = true
		}
		if strings.Contains(c, "iptables -t nat -C POSTROUTING") && strings.Contains(c, "iptables -C FORWARD -i awg0") {
			forwarding = true
		}
	}
	if !syncd {
		t.Fatalf("expected live syncconf; cmds=%v", f.cmds)
	}
	if !forwarding {
		t.Fatalf("expected live sync to re-assert server forwarding/NAT; cmds=%v", f.cmds)
	}
	// client config renders and contains the endpoint + private key
	text, name, err := m.ClientConfig(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "PrivateKey = "+p.PrivateKey) || !strings.HasSuffix(name, ".conf") {
		t.Fatalf("unexpected client config:\n%s", text)
	}
}

func TestEnsureRouterPeerCreatesOnlyOnce(t *testing.T) {
	f := &fakeRunner{}
	m, _ := newManagerWithFake(f)
	p, created, err := m.EnsureRouterPeer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !created || !p.IsRouter || p.PrivateKey == "" || p.Address == "" {
		t.Fatalf("expected created router peer with secrets/address, got created=%v peer=%+v", created, p)
	}
	p2, created, err := m.EnsureRouterPeer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if created || p2.ID != p.ID || len(m.Config().Peers) != 1 {
		t.Fatalf("expected idempotent router peer, created=%v p1=%s p2=%s peers=%d", created, p.ID, p2.ID, len(m.Config().Peers))
	}
}

func TestConfigClonePreservesEmptyZoneSlices(t *testing.T) {
	cfg := Default()
	cfg.Routing.Zones = []Zone{{Name: "empty", Mode: "include", Domains: []string{}, IPs: []string{}, Enabled: true}}
	cp := cfg.clone()
	if cp.Routing.Zones[0].Domains == nil {
		t.Fatal("expected empty Domains to stay []")
	}
	if cp.Routing.Zones[0].IPs == nil {
		t.Fatal("expected empty IPs to stay []")
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	f := &fakeRunner{}
	m, _ := newManagerWithFake(f)
	_, _ = m.EnsureKeys()
	_, _ = m.AddPeer(context.Background(), Peer{Name: "p1"})
	r := m.Redacted()
	if r.PrivateKey != "" || r.Conn.Password != "" {
		t.Fatal("server secrets not redacted")
	}
	for _, p := range r.Peers {
		if p.PrivateKey != "" || p.PSK != "" {
			t.Fatal("peer secrets not redacted")
		}
		if !p.HasPrivate {
			t.Fatal("expected HasPrivate flag preserved")
		}
	}
	// original still has secrets
	if m.Config().PrivateKey == "" {
		t.Fatal("redaction mutated the original config")
	}
}
