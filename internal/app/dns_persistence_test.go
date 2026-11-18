package app

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/tools/dns"
	"nfqws2strategy/internal/tools/store"
)

func dnsListFixture(t *testing.T, raw []byte) *App {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		if err := os.WriteFile(st.Path(dnsConfigFile), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{store: st}
	a.initDNS()
	return a
}

func TestDNSListExplicitEmptySurvivesRestart(t *testing.T) {
	a := dnsListFixture(t, []byte("[]"))
	if a.DNSConfigError() != nil || len(a.DNSServers()) != 0 {
		t.Fatal("an intentionally empty list was reset")
	}
	restarted := &App{store: a.store}
	restarted.initDNS()
	if restarted.DNSConfigError() != nil || len(restarted.DNSServers()) != 0 {
		t.Fatal("restart reintroduced default providers")
	}
	after, _ := os.ReadFile(a.store.Path(dnsConfigFile))
	if !bytes.Equal(after, []byte("[]")) {
		t.Fatal("empty saved list was rewritten")
	}
}

func TestDNSListCorruptionPreservedUntilExplicitReset(t *testing.T) {
	for name, raw := range map[string][]byte{"null": []byte("null"), "object": []byte("{}"), "truncated": []byte("[{"), "zeroed": make([]byte, 32)} {
		t.Run(name, func(t *testing.T) {
			a := dnsListFixture(t, raw)
			if a.DNSConfigError() == nil {
				t.Fatal("corruption was silently treated as a fresh install")
			}
			if _, err := a.SaveDNSServer(dns.Server{Name: "Fixture", Type: dns.DoH, Addr: "https://example.invalid/dns-query"}); err == nil {
				t.Fatal("ordinary save replaced unreadable settings")
			}
			if err := a.DeleteDNSServer("missing"); err == nil {
				t.Fatal("ordinary delete replaced unreadable settings")
			}
			after, _ := os.ReadFile(a.store.Path(dnsConfigFile))
			if !bytes.Equal(after, raw) {
				t.Fatal("startup or an ordinary control changed original bytes")
			}
			if _, err := a.ResetDNSServers(); err != nil {
				t.Fatal(err)
			}
			if a.DNSConfigError() != nil || len(a.DNSServers()) == 0 {
				t.Fatal("explicit validated reset did not recover the list")
			}
		})
	}
}

func TestDNSListFailedWritesDoNotPublishUnsavedMemory(t *testing.T) {
	a := dnsListFixture(t, nil)
	before := a.DNSServers()
	path, saved := a.store.Path(dnsConfigFile), a.store.Path(dnsConfigFile+".fixture-before")
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		_ = os.Rename(saved, path)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path); _ = os.Rename(saved, path) })
	if _, err := a.SaveDNSServer(dns.Server{Name: "Fixture", Type: dns.DoH, Addr: "https://example.invalid/dns-query"}); err == nil {
		t.Fatal("blocked add succeeded")
	}
	if !reflect.DeepEqual(a.DNSServers(), before) {
		t.Fatal("failed add published unsaved settings")
	}
	if err := a.DeleteDNSServer(before[0].ID); err == nil {
		t.Fatal("blocked delete succeeded")
	}
	if !reflect.DeepEqual(a.DNSServers(), before) {
		t.Fatal("failed delete published unsaved settings")
	}
	if _, err := a.ResetDNSServers(); err == nil {
		t.Fatal("blocked reset succeeded")
	}
	if !reflect.DeepEqual(a.DNSServers(), before) {
		t.Fatal("failed reset published unsaved settings")
	}
}

func TestDNSListRecoveryLoadsVerifiedProviderList(t *testing.T) {
	a := dnsListFixture(t, nil)
	provider := dns.Server{Name: "Fixture", Type: dns.DoH, Addr: "https://example.invalid/dns-query"}
	if _, err := a.SaveDNSServer(provider); err != nil {
		t.Fatal(err)
	}
	want := a.DNSServers()
	if err := os.WriteFile(a.store.Path(dnsConfigFile), []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	restarted := &App{store: a.store}
	restarted.initDNS()
	if restarted.DNSConfigError() != nil || !reflect.DeepEqual(restarted.DNSServers(), want) {
		t.Fatal("verified recovery lost custom providers")
	}
}
