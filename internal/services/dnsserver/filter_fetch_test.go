package dnsserver

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
)

func TestFetchFilteringSourceRejectsUnknownURLAndDoesNotUseWANWithoutVPN(t *testing.T) {
	cfg := Default()
	cfg.RouteMode = RouteModeVPNOnly
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: false}}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	if _, err := r.FetchFilteringSource(context.Background(), "https://127.0.0.1/filter.txt"); err == nil || !strings.Contains(err.Error(), "каталоге") {
		t.Fatalf("arbitrary URL accepted: %v", err)
	}
	if _, err := r.FetchFilteringSource(context.Background(), filteringCatalog[0].URL); err == nil || !strings.Contains(err.Error(), "только VPN") {
		t.Fatalf("missing VPN-only fail-closed error: %v", err)
	}
	if calls := backend.dialCalls(); len(calls) != 0 {
		t.Fatalf("download attempted WAN route: %v", calls)
	}
}

func TestFetchFilteringSourceRejectsRetiredPublisherURLs(t *testing.T) {
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}}
	r := NewResolver(Default(), backend)
	defer r.Close()
	for _, sourceURL := range []string{
		"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
		"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
		"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
		"https://small.oisd.nl/domainswild2",
		"https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
		"https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt",
	} {
		if _, err := r.FetchFilteringSource(context.Background(), sourceURL); err == nil || !strings.Contains(err.Error(), "каталоге") {
			t.Fatalf("retired source URL accepted: %s: %v", sourceURL, err)
		}
	}
	if calls := backend.dialCalls(); len(calls) != 0 {
		t.Fatalf("retired publisher contacted network: %v", calls)
	}
}

func TestFetchFilteringIPRejectsPrivateEndpointBeforeDial(t *testing.T) {
	backend := &resolverTestBackend{}
	r := NewResolver(Default(), backend)
	defer r.Close()
	endpoint, _ := url.Parse("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
	if _, err := r.fetchFilteringIP(context.Background(), "awg:warp", endpoint, "127.0.0.1", nil); err == nil || !strings.Contains(err.Error(), "публичного IP") {
		t.Fatalf("private endpoint accepted: %v", err)
	}
	if len(backend.dialCalls()) != 0 {
		t.Fatal("private endpoint reached network")
	}
}

func TestFetchFilteringIPPinsSocketAndValidatesResponse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{"list", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("||ads.example^\n"))
		}, ""},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, "HTTP 302"},
		{"html", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>wrong</html>"))
		}, "HTML"},
		{"too large", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(maxFilteringSourceBytes+1))
			w.WriteHeader(http.StatusOK)
		}, "8 МиБ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tc.handler)
			defer server.Close()
			endpoint, err := url.Parse(server.URL + "/filter.txt")
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			backend := &resolverTestBackend{}
			backend.dialHook = func(ctx context.Context, route, network, address string) (net.Conn, error) {
				if route != "awg:warp" {
					return nil, fmt.Errorf("wrong route %s", route)
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			r := NewResolver(Default(), backend)
			defer r.Close()
			data, err := r.fetchFilteringIP(context.Background(), "awg:warp", endpoint, "203.0.113.9", roots)
			if tc.wantErr == "" {
				if err != nil || string(data) != "||ads.example^\n" {
					t.Fatalf("download = %q, %v", data, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("download error = %v, want %q", err, tc.wantErr)
			}
			backend.mu.Lock()
			addresses := append([]string{}, backend.addresses...)
			backend.mu.Unlock()
			if len(addresses) != 1 || addresses[0] != net.JoinHostPort("203.0.113.9", endpoint.Port()) {
				t.Fatalf("HTTPS socket was not pinned to route IP: %v", addresses)
			}
		})
	}
}

func TestFetchFilteringIPStopsOnContextCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL + "/filter.txt")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	backend := &resolverTestBackend{}
	backend.dialHook = func(ctx context.Context, _, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	r := NewResolver(Default(), backend)
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.fetchFilteringIP(ctx, "awg:warp", endpoint, "203.0.113.9", roots)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS request did not reach handler")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("canceled fetch returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled fetch did not stop")
	}
}
