package awg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestEndpointBackupsCanonicalBoundedIPPolicy(t *testing.T) {
	got, err := NormalizeEndpointBackups("vpn.example:51820", []string{" 192.0.2.2 ", "192.0.2.2:51820", "2001:0db8:0::2", "[2001:db8::2]:51820", "192.0.2.3:00443", "10.0.0.2"})
	want := []string{"192.0.2.2:51820", "[2001:db8::2]:51820", "192.0.2.3:443", "10.0.0.2:51820"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical pool=%v err=%v", got, err)
	}
	got, err = NormalizeEndpointBackups("[2001:db8::1]:443", []string{"2001:db8::1", "2001:db8::2"})
	if err != nil || !reflect.DeepEqual(got, []string{"[2001:db8::2]:443"}) {
		t.Fatalf("primary duplicate/port inheritance: %v %v", got, err)
	}
	for _, raw := range []string{"vpn.example:443", "192.0.2.1:0", "192.0.2.1:65536", "[fe80::1%eth0]:443", "0.0.0.0", "ff02::1", "192.0.2.1/32", "192.0.2.1:443\nendpoint=x"} {
		if _, err := NormalizeEndpointBackups("vpn.example:51820", []string{raw}); err == nil {
			t.Fatalf("accepted invalid backup %q", raw)
		}
	}
	if _, err := NormalizeEndpointBackups("vpn.example", []string{"192.0.2.2"}); err == nil {
		t.Fatal("missing primary port accepted")
	}
	if _, err := NormalizeEndpointBackups("vpn.example:443", make([]string, MaxEndpointBackups+1)); err == nil {
		t.Fatal("unbounded pool accepted")
	}
}

func endpointTestConfig() *ServerConfig {
	c := Default()
	c.Install = "imported"
	c.Endpoint = "vpn.example:51820"
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	c.PublicKey = key(1)
	c.Peers = []Peer{{ID: "router", Name: "router", IsRouter: true, PublicKey: key(2), PrivateKey: key(3), Address: "10.13.13.2/32", Keepalive: 25}}
	c.Client.EndpointBackups = []string{"192.0.2.2"}
	return c
}

func TestEndpointRuntimeSelectionNeverChangesConfigOrExports(t *testing.T) {
	m := NewManager(endpointTestConfig())
	if !m.SelectClientEndpoint(1) || m.RuntimeConfig().Endpoint != "192.0.2.2:51820" || m.RuntimeLocalClientIdentity().Endpoint != "192.0.2.2:51820" {
		t.Fatal("runtime did not use selected candidate")
	}
	if m.Config().Endpoint != "vpn.example:51820" || m.Redacted().Endpoint != "vpn.example:51820" || m.PublicConnectionIdentity().Endpoint != "vpn.example:51820" {
		t.Fatal("runtime choice changed stored/public identity")
	}
	text, _, err := m.ClientConfig("router")
	if err != nil || !strings.Contains(text, "Endpoint = vpn.example:51820") {
		t.Fatal("export lost configured primary")
	}
	cfg := m.Config()
	cfg.Routing.TraceEnabled = !cfg.Routing.TraceEnabled
	if err := m.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if m.RuntimeConfig().Endpoint != "192.0.2.2:51820" {
		t.Fatal("routing-only save displaced healthy backup")
	}
	m.SetAppliedConfig(&cfg)
	cfg.Endpoint = "vpn-new.example:443"
	if err := m.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if m.RuntimeConfig().Endpoint != "192.0.2.2:51820" {
		t.Fatal("desired pending wire update changed active endpoint")
	}
	m.SetAppliedConfig(nil)
	if m.RuntimeConfig().Endpoint != "vpn-new.example:443" {
		t.Fatal("new wire identity retained stale override")
	}
}

func TestEndpointPoolCloneAndJSONKeepPolicyButNotRuntime(t *testing.T) {
	m := NewManager(endpointTestConfig())
	before := m.Config()
	m.SetAppliedConfig(&before)
	m.SelectClientEndpoint(1)
	copy := m.Config()
	copy.Client.EndpointBackups[0] = "192.0.2.99:443"
	applied := m.AppliedConfig()
	applied.Client.EndpointBackups[0] = "192.0.2.98:443"
	if m.Config().Client.EndpointBackups[0] != "192.0.2.2:51820" || m.AppliedConfig().Client.EndpointBackups[0] != "192.0.2.2:51820" {
		t.Fatal("pool slice aliases manager state")
	}
	data, err := json.Marshal(m.Config())
	if err != nil {
		t.Fatal(err)
	}
	var decoded ServerConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Client.EndpointBackups, m.Config().Client.EndpointBackups) || NewManager(&decoded).RuntimeConfig().Endpoint != "vpn.example:51820" {
		t.Fatal("JSON roundtrip lost policy or persisted runtime override")
	}
	if err := m.SetEndpointBackups([]string{}); err != nil {
		t.Fatal(err)
	}
	if m.RuntimeConfig().Endpoint != "vpn.example:51820" {
		t.Fatal("removed active candidate remained selected")
	}
}

func TestRenderUAPIIPv6EndpointUsesBrackets(t *testing.T) {
	c := endpointTestConfig()
	text, err := RenderUAPISet(c, c.Peers[0], "2001:db8::2", 443)
	if err != nil || !strings.Contains(text, "endpoint=[2001:db8::2]:443\n") {
		t.Fatal("IPv6 UAPI endpoint is not bracketed")
	}
}
