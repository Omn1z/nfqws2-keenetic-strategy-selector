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
	return "", "", nil
}

func (f *fakeRunner) Put(_ context.Context, path string, _ uint32, _ []byte) error {
	f.puts = append(f.puts, path)
	return nil
}

func (f *fakeRunner) Close() error { return nil }

func newManagerWithFake(f *fakeRunner) (*Manager, *string) {
	cfg := Default()
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
		if strings.Contains(p, "/etc/amnezia/amneziawg/awg0.conf") {
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
	for _, c := range f.cmds {
		if strings.Contains(c, "awg syncconf awg0") {
			syncd = true
		}
	}
	if !syncd {
		t.Fatalf("expected live syncconf; cmds=%v", f.cmds)
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
