package dnsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/tools/store"
)

func TestShadowConfigLegacyNormalizationAndBoundaries(t *testing.T) {
	legacy := Default()
	legacy.ShadowDNS = nil
	if err := legacy.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	if legacy.ShadowDNS == nil || legacy.ShadowDNS.Enabled {
		t.Fatal("legacy config enabled direct DNS")
	}
	cfg := &ShadowDNSConfig{Enabled: true, Servers: []string{"192.0.2.53", "192.0.2.53:53", "2001:db8::53"}, Domains: []ShadowDomain{{Domain: ".РФ"}, {Domain: ".ru"}, {Domain: "VK.COM."}, {Domain: "vk.com", IncludeSubdomains: true}, {Domain: "exact.example"}, {Domain: "*.avito.st"}}}
	if err := cfg.normalizeValidate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 0 || len(cfg.Domains) != 5 {
		t.Fatalf("normalization: %+v", cfg)
	}
	m := newShadowMatcher(cfg)
	for _, domain := range []string{"ru", "ozon.ru", "a.b.ozone.ru", "xn--e1afmkfd.xn--p1ai", "VK.COM.", "a.vk.com", "avito.st", "a.avito.st", "exact.example"} {
		if !m.matches(domain) {
			t.Errorf("missed %s", domain)
		}
	}
	for _, domain := range []string{"evilru", "ru.example", "fakevk.com", "vk.com.evil", "a.exact.example", "example.com"} {
		if m.matches(domain) {
			t.Errorf("wrong direct match %s", domain)
		}
	}
	cfg.Enabled = false
	if newShadowMatcher(cfg).matches("vk.com") {
		t.Fatal("disabled shadow matched")
	}
	for _, address := range []string{"127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "fe80::1", "https://1.1.1.1/dns-query", "dns.example", "192.0.2.1:0", "192.0.2.1:65536"} {
		if _, err := normalizeShadowServer(address); err == nil {
			t.Errorf("accepted invalid upstream %s", address)
		}
	}
	c := Default()
	c.ShadowDNS = cfg
	copy := cloneConfig(c)
	copy.ShadowDNS.Domains[0].Domain = "changed.example"
	if cfg.Domains[0].Domain == copy.ShadowDNS.Domains[0].Domain {
		t.Fatal("clone aliases caller config")
	}
	data, _ := json.Marshal(c)
	var decoded Config
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(c.ShadowDNS, decoded.ShadowDNS) {
		t.Fatal("shadow config not portable", err)
	}
	c.ShadowDNS.Servers = []string{"192.168.3.1:53", "not-an-ip"}
	if err := c.ShadowDNS.normalizeValidate(); err != nil || len(c.ShadowDNS.Servers) != 0 {
		t.Fatal("legacy manual upstreams were not discarded", err)
	}
}

func TestShadowWildcardLabelsAndIDNA(t *testing.T) {
	cfg := &ShadowDNSConfig{Enabled: true, Domains: []ShadowDomain{{Domain: "*.ru"}, {Domain: "*.РФ"}, {Domain: "*.VK.*"}, {Domain: "*.avito.*"}, {Domain: "foo.*.example"}}}
	if err := cfg.normalizeValidate(); err != nil {
		t.Fatal(err)
	}
	m := newShadowMatcher(cfg)
	for _, domain := range []string{"ru", "a.ru", "a.b.ru", "xn--e1afmkfd.xn--p1ai", "vk.com", "api.vk.ru", "a.b.vk.net", "avito.st", "x.avito.com", "foo.bar.example"} {
		if !m.matches(domain) {
			t.Errorf("missed %s", domain)
		}
	}
	for _, domain := range []string{"", "notvk.com", "vk.com.evil", "vk.co.uk", "avito", "evilru", "ru.example", "foo.example", "foo.bar.baz.example", "x.foo.bar.example"} {
		if m.matches(domain) {
			t.Errorf("matched %s", domain)
		}
	}
	for _, pattern := range []string{"*", "*.*", "**.example", "f*o.example", "foo..com", "https://vk.com", "a/b.ru", "foo。bar", strings.Repeat("a", 64) + ".ru"} {
		bad := &ShadowDNSConfig{Domains: []ShadowDomain{{Domain: pattern}}}
		if err := bad.normalizeValidate(); err == nil {
			t.Errorf("accepted mask %q", pattern)
		}
	}
	if allocations := testing.AllocsPerRun(100, func() { m.matches("cdn.api.vk.com") }); allocations != 0 {
		t.Fatalf("query allocates: %v", allocations)
	}
}

func TestShadowLegacyManualServersCannotOverrideAutomaticDiscovery(t *testing.T) {
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{}, servers: []string{"192.0.2.53"}, addresses: map[string]string{"udp|192.0.2.53:53": udp}}
	cfg := Default()
	cfg.ShadowDNS.Enabled = true
	cfg.ShadowDNS.Servers = []string{"198.51.100.66:53"}
	r := NewResolver(cfg, b)
	defer r.Close()
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "ozon.ru", 1, mdns.TypeA))
	if err != nil || out.Upstream != "192.0.2.53:53" || !r.ShadowStatus().Automatic {
		t.Fatalf("manual server overrode discovery: %+v %v", out, err)
	}
}

type shadowTestBackend struct {
	*resolverTestBackend
	shadowMu     sync.Mutex
	shadowCalls  []string
	servers      []string
	discoveryErr error
	addresses    map[string]string
}

func (b *shadowTestBackend) ShadowDNSServers(context.Context) ([]string, error) {
	return b.servers, b.discoveryErr
}
func (b *shadowTestBackend) DialShadowDNS(ctx context.Context, network, address string) (net.Conn, error) {
	b.shadowMu.Lock()
	b.shadowCalls = append(b.shadowCalls, network+"|"+address)
	target := b.addresses[network+"|"+address]
	b.shadowMu.Unlock()
	if target == "" {
		return nil, fmt.Errorf("test ISP DNS unavailable")
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}
func (b *shadowTestBackend) count() int {
	b.shadowMu.Lock()
	defer b.shadowMu.Unlock()
	return len(b.shadowCalls)
}

func shadowDNSFixture(t *testing.T, network string, reply func(*mdns.Msg) *mdns.Msg) string {
	t.Helper()
	s := &mdns.Server{Net: network, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) { _ = w.WriteMsg(reply(q)) })}
	var address string
	var err error
	if network == "udp" {
		s.PacketConn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err == nil {
			address = s.PacketConn.LocalAddr().String()
		}
	} else {
		s.Listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			address = s.Listener.Addr().String()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	s.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = s.Shutdown() })
	return address
}

func TestShadowResolverDirectCacheFallbackAndFiltering(t *testing.T) {
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{}, addresses: map[string]string{"udp|192.0.2.53:53": udp}, servers: []string{"192.0.2.53"}}
	cfg := Default()
	cfg.RouteMode = RouteModeVPNOnly
	cfg.ShadowDNS.Enabled = true
	r := NewResolver(cfg, b)
	defer r.Close()
	for i := 0; i < 3; i++ {
		wire, out, err := r.Resolve(context.Background(), resolverWire(t, "www.ozon.ru", uint16(100+i), mdns.TypeA))
		if err != nil || out.Route != shadowRoute || out.Cached != (i > 0) || out.Upstream != "192.0.2.53:53" {
			t.Fatalf("resolve%d: %+v %v", i, out, err)
		}
		var msg mdns.Msg
		if err := msg.Unpack(wire); err != nil || msg.Id != uint16(100+i) {
			t.Fatal("wrong cached client response", err)
		}
	}
	if b.count() != 1 || len(b.dialCalls()) != 0 {
		t.Fatal("cache hit or direct query contacted upstream again / leaked to DoH")
	}
	if s := r.ShadowStatus(); !s.Enabled || !s.Automatic || len(s.Servers) != 1 || s.Error != "" {
		t.Fatalf("status %+v", s)
	}
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 1, mdns.TypeA))
	if err == nil || out.Route == shadowRoute || b.count() != 1 {
		t.Fatal("nonmatching domain sent directly")
	}
	blocker, err := NewBlockMatcher(nil, []BlockingRule{{Domain: "ads.ozon.ru", Category: BlockCategoryAds}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.SetBlocker(blocker)
	_, out, err = r.Resolve(context.Background(), resolverWire(t, "ads.ozon.ru", 2, mdns.TypeA))
	if err != nil || !out.Blocked || b.count() != 1 {
		t.Fatalf("shadow bypassed filtering: %+v %v", out, err)
	}
	if s := r.SchedulerSnapshot("ozon.ru"); s.Reason != "shadow" || len(s.Candidates) != 0 || s.Effective {
		t.Fatalf("misleading scheduler: %+v", s)
	}
}

func TestShadowResolverTruncatedUDPUsesTCPAndServerFailover(t *testing.T) {
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { a := resolverAnswer(q, 60); a.Truncated = true; return a })
	tcp := shadowDNSFixture(t, "tcp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{}, addresses: map[string]string{"udp|192.0.2.53:53": udp, "tcp|192.0.2.53:53": tcp}}
	cfg := Default()
	cfg.ShadowDNS.Enabled = true
	b.servers = []string{"192.0.2.54:53", "192.0.2.53:53"}
	r := NewResolver(cfg, b)
	defer r.Close()
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "ozon.ru", 1, mdns.TypeA))
	if err != nil || out.Upstream != "192.0.2.53:53" || b.count() != 3 {
		t.Fatalf("fallback %+v %v calls=%d", out, err, b.count())
	}
	if b.shadowCalls[2] != "tcp|192.0.2.53:53" {
		t.Fatal("no TCP retry")
	}
}

func TestShadowResolverFailureNeverFallsBackToDoH(t *testing.T) {
	for _, mode := range []string{"unavailable", "discovery", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Default()
			cfg.ShadowDNS.Enabled = true
			b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{}, servers: []string{"192.0.2.53:53"}}
			var backend Backend = b
			if mode == "discovery" {
				b.discoveryErr = fmt.Errorf("ISP DNS missing")
			}
			if mode == "unsupported" {
				backend = b.resolverTestBackend
			}
			r := NewResolver(cfg, backend)
			defer r.Close()
			_, out, err := r.Resolve(context.Background(), resolverWire(t, "ozon.ru", 1, mdns.TypeA))
			if err == nil || !strings.Contains(err.Error(), "Shadow DNS") || out.Route != shadowRoute || len(b.dialCalls()) != 0 || r.CacheStatus().Entries != 0 {
				t.Fatalf("unexpected fallback: %+v %v", out, err)
			}
		})
	}
}

func BenchmarkShadowMatcher4096(b *testing.B) {
	cfg := &ShadowDNSConfig{Enabled: true}
	for i := 0; i < 4096; i++ {
		cfg.Domains = append(cfg.Domains, ShadowDomain{Domain: fmt.Sprintf("host%d.example", i), IncludeSubdomains: true})
	}
	m := newShadowMatcher(cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !m.matches("a.b.host2048.example") {
			b.Fatal("miss")
		}
	}
}

func TestShadowResolverCancellationClosesUDP(t *testing.T) {
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { time.Sleep(200 * time.Millisecond); return resolverAnswer(q, 60) })
	b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{}, addresses: map[string]string{"udp|192.0.2.53:53": udp}}
	cfg := Default()
	cfg.ShadowDNS.Enabled = true
	b.servers = []string{"192.0.2.53:53"}
	r := NewResolver(cfg, b)
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := r.Resolve(ctx, resolverWire(t, "ozon.ru", 1, mdns.TypeA))
	if err == nil || time.Since(start) > 150*time.Millisecond {
		t.Fatal("cancellation blocked", err)
	}
}

func TestShadowSchedulerDoesNotProbeSelectedDomainsOverDoH(t *testing.T) {
	cfg := Default()
	cfg.ShadowDNS.Enabled = true
	cfg.Rules = []Rule{{Enabled: true, Domain: "ozon.ru", Upstream: Upstream{Address: "https://special.example/dns-query"}}, {Enabled: true, Domain: "ordinary.example", Upstream: Upstream{Address: "https://ordinary.example/dns-query"}}}
	probes := schedulerProbeCandidates(cfg, schedulerTestRoutes())
	seenRoot, seenOrdinary := false, false
	for _, probe := range probes {
		if probe.domain == "ozon.ru" {
			t.Fatal("scheduler leaked Shadow domain through DoH")
		}
		seenRoot = seenRoot || probe.domain == "."
		seenOrdinary = seenOrdinary || probe.domain == "ordinary.example"
	}
	if !seenRoot || !seenOrdinary {
		t.Fatal("disabled unrelated probes")
	}
}

func TestShadowServicePreservesRoutingObservationOnCacheHits(t *testing.T) {
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	observed := 0
	b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{observe: func(ctx context.Context, domain string, wire []byte, client net.IP) ([]byte, error) {
		observed++
		return wire, nil
	}}, addresses: map[string]string{"udp|192.0.2.53:53": udp}}
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Enabled = true
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = protocolTestPort(t)
	cfg.SchedulerEnabled = false
	cfg.FastDNS = false
	cfg.ShadowDNS.Enabled = true
	b.servers = []string{"192.0.2.53:53"}
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	defer s.Close()
	s.StartEnabled()
	client := &mdns.Client{Net: "udp", Timeout: time.Second}
	for i := 0; i < 2; i++ {
		q := new(mdns.Msg)
		q.SetQuestion("ozon.ru.", mdns.TypeA)
		answer, _, err := client.Exchange(q, s.Status().Endpoints.DNS)
		if err != nil || answer.Rcode != mdns.RcodeSuccess {
			t.Fatal("service failed", err)
		}
	}
	stats := s.Status().Stats
	if observed != 2 || b.count() != 1 || stats.ShadowSuccess != 1 || stats.CacheHits != 1 || stats.AWGSuccess != 0 || stats.NFQWSSuccess != 0 {
		t.Fatalf("observation=%d calls=%d stats=%+v", observed, b.count(), stats)
	}
}

func TestShadowResolverHonorsConfiguredTimeoutBeyondLibraryDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("wait beyond library default timeout")
	}
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { time.Sleep(2100 * time.Millisecond); return resolverAnswer(q, 60) })
	b := &shadowTestBackend{resolverTestBackend: &resolverTestBackend{}, addresses: map[string]string{"udp|192.0.2.53:53": udp}}
	cfg := Default()
	cfg.TimeoutSeconds = 4
	cfg.ShadowDNS.Enabled = true
	b.servers = []string{"192.0.2.53:53"}
	r := NewResolver(cfg, b)
	defer r.Close()
	_, _, err := r.Resolve(context.Background(), resolverWire(t, "ozon.ru", 1, mdns.TypeA))
	if err != nil {
		t.Fatal("configured timeout was cut to the DNS library default:", err)
	}
}
