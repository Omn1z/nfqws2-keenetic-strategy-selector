package awgroute

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestPublicConnectionReferenceValidationMatchesPortableRules(t *testing.T) {
	ref := portableReference("live", "server.example:443", "awg1", 7)
	if err := ValidateAWGConnectionReference(ref); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAWGConnectionReference(AWG2ConnectionRef{Ref: "missing", Label: "Waiting"}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []AWG2ConnectionRef{
		{Ref: "../invalid"},
		{Ref: "live", Endpoint: "server.example:70000"},
		{Ref: "live", ServerPublicKey: "private-not-a-public-key"},
		{Ref: "live", ClientIface: "eth3"},
		{Ref: "live", Protocol: "unknown"},
		{Ref: ref.Ref, Endpoint: ref.Endpoint, ClientIface: ref.ClientIface, Protocol: ref.Protocol, ServerPublicKey: ref.ServerPublicKey, Fingerprint: "incorrect"},
	} {
		if err := ValidateAWGConnectionReference(invalid); err == nil {
			t.Fatal("invalid connection reference accepted")
		}
	}
}

func TestPublicConnectionsOnlyExposeIsolatedLiveConfigIdentity(t *testing.T) {
	ref := portableReference("live", "server.example:443", "awg1", 7)
	cfg := awg.Default()
	cfg.Endpoint, cfg.ClientIface, cfg.PublicKey, cfg.ProtocolVersion = ref.Endpoint, ref.ClientIface, ref.ServerPublicKey, "3.1"
	cfg.PrivateKey, cfg.Conn.Password = "private-secret", "password-secret"
	cfg.Peers = []awg.Peer{{PrivateKey: "peer-secret", PSK: "psk-secret"}}
	cfg.Routing.Zones = []awg.Zone{{Domains: []string{"private-rule.example"}}}
	svc := &Service{order: []string{"live"}, servers: map[string]*managedServer{"live": {ID: "live", Name: "Live", Manager: awg.NewManager(cfg)}}, connectionRefs: map[string]AWG2ConnectionRef{"missing": {Ref: "missing"}}}
	refs := svc.AWG2PublicConnections()
	if len(refs) != 1 || refs[0].Ref != "live" || refs[0].Fingerprint != ref.Fingerprint {
		t.Fatal("public getter lost live identity or included detached references")
	}
	data, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-secret", "password-secret", "peer-secret", "psk-secret", "private-rule.example"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("public getter exposed secret or routing data")
		}
	}
	refs[0].Label, refs[0].Endpoint = "mutated", "mutated.example:1"
	again := svc.AWG2PublicConnections()
	if again[0].Label != "Live" || again[0].Endpoint != ref.Endpoint {
		t.Fatal("returned metadata aliased service/manager state")
	}
}

func TestPublicConnectionCommitSerializesConcurrentIdentityEdit(t *testing.T) {
	svc := pendingRuleFixture(t, "live")
	m := svc.awgActive()
	cfg := m.Config()
	cfg.Client.Enabled = false // a config edit must never start a real interface
	cfg.Peers = nil
	if err := m.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	failure := errors.New("dependent commit rejected")
	result := make(chan error, 1)
	go func() {
		result <- svc.WithAWG2PublicConnections(func(refs []AWG2ConnectionRef) error {
			if len(refs) != 1 || refs[0].Endpoint != "live.example:443" {
				return errors.New("snapshot lost original identity")
			}
			close(entered)
			<-release
			return failure
		})
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("callback did not start: %v", err)
	case <-time.After(time.Second):
		t.Fatal("callback blocked before taking snapshot")
	}
	edited := cfg
	edited.Endpoint = "changed.example:443"
	editResult := make(chan error, 1)
	go func() { editResult <- svc.AWG2SetConfig(&edited) }()
	deadline := time.Now().Add(time.Second)
	for svc.clients.waiters.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if svc.clients.waiters.Load() == 0 {
		t.Fatal("identity edit did not reach lifecycle boundary")
	}
	select {
	case err := <-editResult:
		t.Fatalf("identity changed during dependent commit: %v", err)
	default:
	}
	if refs := svc.AWG2PublicConnections(); refs[0].Endpoint != "live.example:443" {
		t.Fatal("callback failed to keep configured identity stable")
	}
	unblock()
	if err := <-result; !errors.Is(err, failure) {
		t.Fatalf("callback error swallowed: %v", err)
	}
	select {
	case err := <-editResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback return retained lifecycle lock")
	}
	if err := svc.WithAWG2PublicConnections(func(refs []AWG2ConnectionRef) error {
		if refs[0].Endpoint != "changed.example:443" {
			return errors.New("later snapshot missed committed identity edit")
		}
		refs[0].Endpoint = "caller-mutated.example:443"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if svc.AWG2PublicConnections()[0].Endpoint != "changed.example:443" {
		t.Fatal("callback metadata aliased manager config")
	}
}
