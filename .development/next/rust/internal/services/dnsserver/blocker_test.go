package dnsserver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func TestBlockerParsesSafeFormatsAndMatchesLabelSuffixes(t *testing.T) {
	source := BlockSource{ID: "plain", Category: BlockCategoryAds, Data: []byte(strings.Join([]string{
		"example.com",
		"0.0.0.0 hosts.example",
		"0.0.0.0 first-host.example second-host.example",
		"0.0.0.0 comment-host.example # source note",
		"127.0.0.1 localhost",
		"::1 v6hosts.example",
		"||abp.example^",
		"@@||allowed.abp.example^",
		"||unsupported.example^$third-party",
		"/regex.example/",
		"good.example##.ad",                       // cosmetic syntax must never become good.example
		"1.2.3.4 malformed.example extra.example", // non-sinkhole hosts entries are ignored
		"bücher.example",
	}, "\n"))}
	b, err := NewBlockMatcher([]BlockSource{source}, []BlockingRule{
		{Domain: "*.custom.example", Category: BlockCategoryTrackers},
		{Domain: "*-netseer-ipaddr-assoc.xy.fbcdn.net", Category: BlockCategoryTrackers},
		{Domain: "*-netseer-ipaddr-assoc.xz.fbcdn.net", Category: BlockCategoryTrackers},
		{Domain: "manual.allowed.abp.example", Category: BlockCategoryTrackers},
		{Domain: "custom.allow.example.com", Category: BlockCategoryTrackers},
	}, []string{"*.allow.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		domain   string
		blocked  bool
		category string
	}{
		{"example.com", true, BlockCategoryAds},
		{"sub.example.com", true, BlockCategoryAds},
		{"notexample.com", false, ""},
		{"allow.example.com", false, ""},
		{"deep.allow.example.com", false, ""},
		{"custom.allow.example.com", false, ""},
		{"hosts.example", true, BlockCategoryAds},
		{"localhost", false, ""},
		{"first-host.example", true, BlockCategoryAds},
		{"second-host.example", true, BlockCategoryAds},
		{"comment-host.example", true, BlockCategoryAds},
		{"v6hosts.example", true, BlockCategoryAds},
		{"abp.example", true, BlockCategoryAds},
		{"allowed.abp.example", false, ""},
		{"manual.allowed.abp.example", true, BlockCategoryTrackers},
		{"unsupported.example", false, ""},
		{"regex.example", false, ""},
		{"good.example", false, ""},
		{"malformed.example", false, ""},
		{"bücher.example", true, BlockCategoryAds},
		{"xn--bcher-kva.example.", true, BlockCategoryAds},
		{"custom.example", false, ""},
		{"x.custom.example", true, BlockCategoryTrackers},
		{"123-netseer-ipaddr-assoc.xy.fbcdn.net", true, BlockCategoryTrackers},
		{"123-netseer-ipaddr-assoc.xz.fbcdn.net", true, BlockCategoryTrackers},
		{"123-netseer-ipaddr-assoc.other.fbcdn.net", false, ""},
		{"deep.123-netseer-ipaddr-assoc.xy.fbcdn.net", false, ""},
		{"random.xy.fbcdn.net", false, ""},
	} {
		match, blocked := b.Match(tc.domain)
		if blocked != tc.blocked || blocked && match.Category != tc.category {
			t.Errorf("Match(%q) = (%+v, %v), want blocked=%v category=%s", tc.domain, match, blocked, tc.blocked, tc.category)
		}
	}
	stats := b.Stats()
	if stats.Ignored["plain"] != 5 || stats.Sources["custom"] != 5 {
		t.Fatalf("source stats = %+v", stats)
	}
}

func TestBlockerAdGuardEngineHonorsExceptionsBadfilterAndType(t *testing.T) {
	data := []byte(strings.Join([]string{
		"||ad.example^",
		"@@||good.ad.example^",
		"||disabled.example^",
		"||disabled.example^$badfilter",
		"||type.example^$dnstype=AAAA",
		"||wild*.example^",
		"||important.example^$important",
		"@@||important.example^",
		"||rewrite.example^$dnsrewrite=1.2.3.4",
	}, "\n"))
	b, err := NewBlockMatcher([]BlockSource{{ID: "adguard-dns", Category: BlockCategoryMixed, Data: data}},
		[]BlockingRule{{Domain: "manual.good.ad.example", Category: BlockCategoryTrackers}},
		[]string{"*.allow.important.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		domain  string
		qtype   uint16
		blocked bool
	}{
		{"ad.example", mdns.TypeA, true},
		{"child.ad.example", mdns.TypeA, true},
		{"good.ad.example", mdns.TypeA, false},
		{"manual.good.ad.example", mdns.TypeA, true},
		{"disabled.example", mdns.TypeA, false},
		{"type.example", mdns.TypeA, false},
		{"type.example", mdns.TypeAAAA, true},
		{"wild123.example", mdns.TypeA, true},
		{"important.example", mdns.TypeA, true},
		{"allow.important.example", mdns.TypeA, false},
		{"rewrite.example", mdns.TypeA, false},
	} {
		match, blocked := b.MatchDNS(tc.domain, tc.qtype)
		if blocked != tc.blocked {
			t.Errorf("MatchDNS(%q, %d) = (%+v, %v), want %v", tc.domain, tc.qtype, match, blocked, tc.blocked)
		}
		if blocked && tc.domain != "manual.good.ad.example" && (match.Source != "adguard-dns" || match.Rule == "") {
			t.Errorf("missing official rule metadata for %s: %+v", tc.domain, match)
		}
	}
	if match, blocked := b.Match("manual.good.ad.example"); !blocked || match.Source != "custom" || match.Category != BlockCategoryTrackers {
		t.Fatalf("explicit custom rule lost to downloaded exception: %+v, %v", match, blocked)
	}
	if !b.Stats().Approximate || b.Stats().Sources["adguard-dns"] == 0 {
		t.Fatalf("AdGuard stats = %+v", b.Stats())
	}
}

func TestBlockerReplaceAtomicAndCustomCategoryWins(t *testing.T) {
	b, err := NewBlockMatcher([]BlockSource{
		{ID: "ads", Category: BlockCategoryAds, Data: []byte("shared.example\n")},
		{ID: "tracking", Category: BlockCategoryTrackers, Data: []byte("shared.example\n")},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if match, ok := b.Match("shared.example"); !ok || match.Category != BlockCategoryMixed || b.Stats().Rules != 1 {
		t.Fatalf("overlap should count once as mixed: %+v, stats=%+v", match, b.Stats())
	}
	if err := b.Replace(nil, []BlockingRule{{Domain: "shared.example", Category: BlockCategoryTrackers}}, nil); err != nil {
		t.Fatal(err)
	}
	if match, ok := b.Match("shared.example"); !ok || match.Category != BlockCategoryTrackers || match.Source != "custom" {
		t.Fatalf("custom category did not replace downloaded category: %+v", match)
	}
	if err := b.Replace(nil, []BlockingRule{{Domain: "*.fbcdn.net", Category: "unknown"}}, nil); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if match, ok := b.Match("shared.example"); !ok || match.Source != "custom" {
		t.Fatalf("failed replacement changed published snapshot: %+v", match)
	}
}

func TestResolverBlocksBeforePositiveCacheAndAnyRoute(t *testing.T) {
	cfg := Default()
	cfg.Rules = nil
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: true}}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	query := resolverWire(t, "blocked.example", 42, mdns.TypeA)
	q, _, err := parseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	zeroID := q.Copy()
	zeroID.Id = 0
	key, err := zeroID.Pack()
	if err != nil {
		t.Fatal(err)
	}
	r.cachePut(string(key), resolverAnswer(q, 60), "nfqws", cfg.DefaultUpstream.Address, 0)
	if r.CacheStatus().Entries != 1 {
		t.Fatal("positive test answer was not cached")
	}
	b, err := NewBlockMatcher(nil, []BlockingRule{{Domain: "blocked.example", Category: BlockCategoryAds}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.SetBlocker(b)
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeHTTPS, mdns.TypeDNSKEY} {
		wire, out, err := r.Resolve(context.Background(), resolverWire(t, "blocked.example", qtype, qtype))
		if err != nil {
			t.Fatal(err)
		}
		var response mdns.Msg
		if err := response.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		if response.Rcode != mdns.RcodeNameError || response.Authoritative || response.AuthenticatedData || len(response.Answer) != 0 || len(response.Ns) != 1 || response.Ns[0].Header().Ttl != 60 {
			t.Fatalf("blocked response for type %d: %+v", qtype, response)
		}
		if !out.Blocked || out.Cached || out.Route != "blocked" || out.Upstream != "" || out.BlockCategory != BlockCategoryAds || out.BlockRule != "blocked.example" || out.BlockSource != "custom" {
			t.Fatalf("blocked outcome for type %d: %+v", qtype, out)
		}
	}
	if calls := backend.dialCalls(); len(calls) != 0 {
		t.Fatalf("blocked query reached upstream routes: %v", calls)
	}
}

func TestFilteringConfigLegacyAndClone(t *testing.T) {
	cfg := Default()
	cfg.Filtering = nil
	if err := cfg.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Filtering == nil || cfg.Filtering.Enabled || len(cfg.Filtering.Lists) == 0 {
		t.Fatalf("legacy filter default = %+v", cfg.Filtering)
	}
	clone := cloneConfig(cfg)
	clone.Filtering.Lists[0] = "hagezi-light"
	clone.Filtering.CustomRules[0].Domain = "changed.example"
	if cfg.Filtering.Lists[0] == "hagezi-light" || cfg.Filtering.CustomRules[0].Domain == "changed.example" {
		t.Fatal("filter config clone shares user-editable slices")
	}
	clone.Filtering.CustomRules = []BlockingRule{{Domain: "*foo.example", Category: BlockCategoryAds}}
	if err := clone.NormalizeValidate(); err == nil {
		t.Fatal("generic wildcard should be rejected")
	}
}

func BenchmarkBlockerLookup(b *testing.B) {
	matcher, err := NewBlockMatcher([]BlockSource{{ID: "plain", Category: BlockCategoryAds, Data: []byte("ads.example\ntracker.example\n")}}, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct{ name, domain string }{{"hit", "sub.ads.example"}, {"miss", "ordinary.example"}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				matcher.Match(tc.domain)
			}
		})
	}
}

func BenchmarkBlockerAdGuardLargeList(b *testing.B) {
	var lines strings.Builder
	lines.Grow(177000 * 24)
	for i := 0; i < 177000; i++ {
		fmt.Fprintf(&lines, "||ad%06d.example^\n", i)
	}
	matcher, err := NewBlockMatcher([]BlockSource{{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte(lines.String())}}, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	if got := matcher.Stats().Sources["adguard-dns"]; got != 177000 {
		b.Fatalf("loaded %d official rules, want 177000", got)
	}
	b.ResetTimer()
	for _, tc := range []struct{ name, domain string }{{"hit", "ad176999.example"}, {"miss", "ordinary.example"}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				matcher.MatchDNS(tc.domain, mdns.TypeA)
			}
		})
	}
}
