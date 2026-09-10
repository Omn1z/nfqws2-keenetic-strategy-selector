package dnsserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/tools/store"
)

func newDNSServiceFixture(t *testing.T, cacheSize int) (*Service, *resolverTestBackend, *mdns.Client) {
	t.Helper()
	fixture, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := fixture.cfg
	cfg.Enabled = false
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = protocolTestPort(t)
	cfg.CacheSize = cacheSize
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if !s.Status().Running {
		t.Fatal("service did not start:", s.Status().LastError)
	}
	// Copy only the fixture trust roots into the service's real upstream pools.
	fixture.mu.Lock()
	var upstreamRoots *x509.CertPool
	for _, c := range fixture.clients {
		upstreamRoots = c.Transport.(*http.Transport).TLSClientConfig.RootCAs
		break
	}
	fixture.mu.Unlock()
	s.mu.RLock()
	run := s.active
	s.mu.RUnlock()
	trustResolverFixture(t, run.resolver, cfg.DefaultUpstream, upstreamRoots)
	b.setFailures()
	return s, b, &mdns.Client{Net: "udp", Timeout: 4 * time.Second}
}

func queryDNSService(t *testing.T, client *mdns.Client, endpoint string, id uint16) *mdns.Msg {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion("example.com.", mdns.TypeA)
	query.Id = id
	msg, _, err := client.Exchange(query, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Id != id {
		t.Fatalf("response ID=%d want %d", msg.Id, id)
	}
	return msg
}

func TestDNSServiceStartsDisabledWithoutNetworkChanges(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &resolverTestBackend{}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	defer s.Close()
	s.StartEnabled()
	status := s.Status()
	if status.Config.Enabled || status.Running {
		t.Fatalf("unexpected default status: %+v", status)
	}
	b.mu.Lock()
	prepared := b.prepareCount
	b.mu.Unlock()
	if prepared != 0 {
		t.Fatal("disabled service altered network routing")
	}
	if len(status.Config.Rules) != 3 {
		t.Fatal("missing requested default domain rules")
	}
	var saved Config
	if err := st.Load(configFile, &saved); err != nil || saved.Enabled {
		t.Fatalf("disabled default not persisted: %v", err)
	}
	if _, err := os.Stat(st.Path("dnsserver-tls")); !os.IsNotExist(err) {
		t.Fatalf("plain DNS created a certificate directory: %v", err)
	}
}

func TestDNSServiceMigratesLegacyTLSConfigPreservingRulesAndEnabledState(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		st, err := store.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cfg := Default()
		cfg.Enabled = enabled
		cfg.ListenHost = "127.0.0.1"
		cfg.Rules = []Rule{{ID: "saved-rule", Enabled: true, Domain: "custom.example", IncludeSubdomains: true, Upstream: Upstream{Address: "https://9.9.9.9/dns-query", BootstrapIPs: []string{"9.9.9.9"}}}}
		raw, _ := json.Marshal(cfg)
		var legacy map[string]any
		if err := json.Unmarshal(raw, &legacy); err != nil {
			t.Fatal(err)
		}
		delete(legacy, "dns_port")
		legacy["doh_port"] = 8443
		legacy["dot_port"] = 853
		legacy["doq_port"] = 853
		legacy["tls_host"] = "old.home.arpa"
		legacy["certificate_mode"] = "custom"
		if err := st.Save(configFile, legacy); err != nil {
			t.Fatal(err)
		}
		backend := &resolverTestBackend{}
		s := New(st, backend, func(string) (string, error) { return "127.0.0.1", nil })
		status := s.Status()
		if status.Config.Enabled != enabled || status.Config.DNSPort != 5355 || len(status.Config.Rules) != 1 || status.Config.Rules[0].Domain != "custom.example" || status.Config.Rules[0].Upstream.Address != "https://9.9.9.9/dns-query" {
			t.Fatalf("migration lost saved DNS configuration: %+v", status.Config)
		}
		if status.Running || backend.prepareCount != 0 {
			t.Fatal("loading saved settings altered network routing")
		}
		raw, err = os.ReadFile(st.Path(configFile))
		if err != nil {
			t.Fatal(err)
		}
		for _, removed := range []string{"tls_host", "doh_port", "dot_port", "doq_port", "certificate_mode"} {
			if strings.Contains(string(raw), removed) {
				t.Errorf("persisted legacy field %s", removed)
			}
		}
		public, _ := json.Marshal(status)
		if strings.Contains(string(public), "certificate") || status.Endpoints.DNS != "127.0.0.1:5355" {
			t.Fatalf("unexpected plain DNS status: %s", public)
		}
		s.Close()
	}
}

func TestDNSServiceReturnsSERVFAILThenRecoversWithoutRestart(t *testing.T) {
	s, b, client := newDNSServiceFixture(t, 0)
	b.setFailures("nfqws", "awg:first", "awg:warp")
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 100); msg.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("all-route failure returned %s", mdns.RcodeToString[msg.Rcode])
	}
	status := s.Status()
	if !status.Running || status.Stats.Failures != 1 {
		t.Fatalf("query failure stopped service: %+v", status.Stats)
	}
	b.setFailures()
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 101); msg.Rcode != mdns.RcodeSuccess || len(msg.Answer) == 0 {
		t.Fatalf("recovery returned %v", msg)
	}
	status = s.Status()
	if status.Stats.NFQWSSuccess+status.Stats.AWGSuccess != 1 || status.Stats.Failures != 1 || status.Stats.Queries != 2 || status.Stats.LastError != "" {
		t.Fatalf("recovery statistics: %+v", status.Stats)
	}
	port := status.Config.DNSPort
	if err := s.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if s.Status().Running || s.Config().Enabled {
		t.Fatal("disable did not stop service")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("disable leaked listener: %v", err)
	}
	ln.Close()
}

func TestDNSServiceAppliesClientPolicyToEveryCacheHit(t *testing.T) {
	s, b, _ := newDNSServiceFixture(t, 8)
	var mu sync.Mutex
	observations := []string{}
	b.mu.Lock()
	b.observe = func(_ context.Context, domain string, wire []byte, ip net.IP) ([]byte, error) {
		mu.Lock()
		observations = append(observations, ip.String())
		mu.Unlock()
		if domain != "example.com" {
			return nil, fmt.Errorf("wrong policy domain %s", domain)
		}
		var msg mdns.Msg
		if err := msg.Unpack(wire); err != nil {
			return nil, err
		}
		if ip.Equal(net.ParseIP("192.168.3.21")) {
			msg.Answer = nil
			msg.Rcode = mdns.RcodeRefused
		}
		return msg.Pack()
	}
	b.mu.Unlock()
	s.mu.RLock()
	run := s.active
	s.mu.RUnlock()
	for i, ip := range []string{"192.168.3.20", "192.168.3.21", "192.168.3.20"} {
		ctx := context.WithValue(context.Background(), clientIPContextKey{}, net.ParseIP(ip))
		wire, out, err := s.exchange(ctx, run, resolverWire(t, "example.com", uint16(i+1), mdns.TypeA))
		if err != nil {
			t.Fatal(err)
		}
		var msg mdns.Msg
		if err := msg.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		want := mdns.RcodeSuccess
		if i == 1 {
			want = mdns.RcodeRefused
		}
		if msg.Rcode != want || out.Cached != (i > 0) {
			t.Fatalf("client %s: response %d cached=%v", ip, msg.Rcode, out.Cached)
		}
	}
	mu.Lock()
	count := len(observations)
	mu.Unlock()
	if count != 3 || s.Status().Stats.CacheHits != 2 {
		t.Fatalf("client policy skipped cached response: calls=%d stats=%+v", count, s.Status().Stats)
	}
}

func TestDNSServiceFailedPreparationReleasesSockets(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	port := protocolTestPort(t)
	cfg := Default()
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = port
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	b := &resolverTestBackend{prepareErr: fmt.Errorf("test firewall failure")}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	defer s.Close()
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if s.Status().Running || s.Status().LastError == "" {
		t.Fatal("failed preparation was not reported")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed preparation left DNS listener active: %v", err)
	}
	ln.Close()
	if err := s.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
}
