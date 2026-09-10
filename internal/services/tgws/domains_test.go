package tgws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyCFDomainsMigrateWithoutChangingConnection(t *testing.T) {
	cfg := Default()
	const secret = "00112233445566778899aabbccddeeff"
	if err := json.Unmarshal([]byte(`{"port":1430,"secret":"`+secret+`","enabled":true,"cfproxy_user_domain":"One.example; TWO.example one.EXAMPLE","cfproxy_worker_domain":"worker.example"}`), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Normalize()
	if cfg.Port != 1430 || cfg.Secret != secret || !cfg.Enabled {
		t.Fatal("migration changed connection identity")
	}
	if !reflect.DeepEqual(cfg.CFProxyUserDomains, []string{"one.example", "two.example"}) {
		t.Fatal(cfg.CFProxyUserDomains)
	}
	if !reflect.DeepEqual(cfg.CFProxyWorkerDomains, []string{"worker.example"}) {
		t.Fatal(cfg.CFProxyWorkerDomains)
	}
	if errors := cfg.Validate(); len(errors) != 0 {
		t.Fatal(errors)
	}
	data, _ := json.Marshal(cfg)
	var reloaded Config
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	reloaded.Normalize()
	if !reflect.DeepEqual(cfg, &reloaded) {
		t.Fatal("migration does not survive save/reload")
	}
}

func TestEmptyDomainListsClearLegacyValues(t *testing.T) {
	cfg := Default()
	cfg.CFProxyUserDomain = "old.example"
	cfg.CFProxyWorkerDomain = "old-worker.example"
	cfg.CFProxyUserDomains, cfg.CFProxyWorkerDomains = []string{}, []string{}
	cfg.Normalize()
	if cfg.CFProxyUserDomain != "" || cfg.CFProxyWorkerDomain != "" {
		t.Fatal("legacy domains reappeared")
	}
}

func TestDomainValidation(t *testing.T) {
	for _, domain := range []string{"proxy.example", "A-1.example", "xn--p1ai.example"} {
		if !validDomain(domain) {
			t.Fatalf("rejected %q", domain)
		}
	}
	for _, domain := range []string{"", "https://a.example", "a.example:443", "a.example/x", "a..example", "-a.example", "a-.example", "127.0.0.1", "a.example\r\nHeader: yes", strings.Repeat("a", 64) + ".example"} {
		cfg := Default()
		cfg.CFProxyWorkerDomains = []string{domain}
		cfg.EnsureSecret()
		if validDomain(domain) || len(cfg.Validate()) == 0 {
			t.Fatalf("accepted %q", domain)
		}
	}
}

func TestCFDomainRefreshKeepsWorkingPoolOnBadPayload(t *testing.T) {
	for _, response := range []struct {
		name, body string
		status     int
		replace    bool
	}{
		{"valid", "# comment\nOne.example\ntwo.example\nthree.example\nONE.example", 200, true},
		{"duplicates", "one.example\nONE.example\none.example", 200, false},
		{"html", "<html>error</html>", 200, false},
		{"status", "one.example\ntwo.example\nthree.example", 503, false},
		{"oversize", strings.Repeat("a", 65537), 200, false},
	} {
		t.Run(response.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(response.status)
				_, _ = w.Write([]byte(response.body))
			}))
			defer srv.Close()
			bal := newDomainBalancer()
			bal.updatePool([]string{"known.example"})
			err := refreshCFDomains(context.Background(), srv.Client(), srv.URL, bal)
			if (err == nil) != response.replace {
				t.Fatalf("replace=%v err=%v", response.replace, err)
			}
			if response.replace {
				if len(bal.candidatesFor(1)) != 3 {
					t.Fatal("pool not updated")
				}
			} else if !reflect.DeepEqual(bal.candidatesFor(1), []string{"known.example"}) {
				t.Fatal("working pool lost")
			}
		})
	}
}

func TestCensorDomainsKeepsTelegramAndMasksFallback(t *testing.T) {
	want := "DC1 kws1.web.telegram.org pr***.example:443 149.154.167.220 proxy.log"
	if got := censorDomains("DC1 kws1.web.telegram.org proxy.example:443 149.154.167.220 proxy.log"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCFRefreshRetriesAfterTLSFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("one.example\ntwo.example\nthree.example"))
	}))
	defer srv.Close()
	bal := newDomainBalancer()
	// The first client does not trust the certificate. The normal path does.
	err := refreshCFWithFallback(context.Background(), &http.Client{}, srv.Client(), srv.URL, bal)
	if err != nil {
		t.Fatal(err)
	}
	if len(bal.candidatesFor(1)) != 3 {
		t.Fatal("DNS fallback was not applied after TLS failure")
	}
}
