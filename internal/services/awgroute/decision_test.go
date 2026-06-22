package awgroute

import (
	"testing"

	"nfqws2strategy/internal/services/awg"
)

// TestRouteFor exercises the unified first-match-wins decision walker across
// the user-visible scenarios. Bug it was born from: under a catch-all "*"
// rule the legacy DNS-proxy AAAA blocker stripped AAAA for every name (RU
// included). routeFor must respect rule order AND the rule's route AND the
// tunnelV6 reachability snapshot.
func TestRouteFor(t *testing.T) {
	svc := &Service{}

	mkTable := func(zones []awg.Zone, tunnelV6 bool) *routeTable {
		cfg := &awg.ServerConfig{Routing: awg.RoutingConfig{Mode: "zones", Zones: zones}}
		return svc.buildRouteTable(cfg, tunnelV6)
	}

	cases := []struct {
		name        string
		zones       []awg.Zone
		tunnelV6    bool
		qname       string
		srcIP       string
		wantRoute   Route
		wantBlockA4 bool // BlockAAAA
		wantRuleIdx int  // 0 = unknown, else 1-based
	}{
		// (a) RU bypass + catch-all tunnel — yandex direct, google tunnel +
		// BlockAAAA (tunnelV6=false). The original bug: pre-FMW MatchAny
		// matched everything via catch-all → AAAA blocked for yandex too.
		{
			"RU bypass first → yandex direct, no AAAA block",
			[]awg.Zone{
				zone("ru", "exclude", true, "domain:yandex.ru", "domain:ya.ru"),
				zone("all", "include", true, "*"),
			},
			false, "yandex.ru", "",
			RouteDirect, false, 1,
		},
		{
			"RU bypass first → google tunnel + AAAA blocked",
			[]awg.Zone{
				zone("ru", "exclude", true, "domain:yandex.ru"),
				zone("all", "include", true, "*"),
			},
			false, "google.com", "",
			RouteTunnel, true, 2,
		},

		// (b) Catch-all first SHADOWS later carve-out (the FMW bug we fixed).
		{
			"catch-all tunnel at #0 SHADOWS later RU direct → google tunnel",
			[]awg.Zone{
				zone("all", "include", true, "*"),
				zone("ru", "exclude", true, "domain:yandex.ru"),
			},
			false, "yandex.ru", "",
			RouteTunnel, true, 1, // catch-all wins even for yandex
		},

		// (c) Catch-all direct + tg tunnel — tg goes tunnel + AAAA blocked,
		// google goes direct (catch-all default) — NO AAAA block.
		{
			"tg tunnel first → web.telegram.tg tunnel",
			[]awg.Zone{
				zone("tg", "include", true, "*.tg"),
				zone("all", "exclude", true, "*"),
			},
			false, "web.telegram.tg", "",
			RouteTunnel, true, 1,
		},
		{
			"tg first + catch-all direct → google direct, no AAAA block",
			[]awg.Zone{
				zone("tg", "include", true, "*.tg"),
				zone("all", "exclude", true, "*"),
			},
			false, "google.com", "",
			RouteDirect, false, 2,
		},

		// (d) tunnelV6=true → tunnel rules should NOT block AAAA (v6 can
		// travel the tunnel once VPS NAT66 is up).
		{
			"tunnelV6=true → tunnel rule does NOT block AAAA",
			[]awg.Zone{
				zone("all", "include", true, "*"),
			},
			true, "google.com", "",
			RouteTunnel, false, 1,
		},

		// (e) No rule matches at all → RouteUnknown, no block.
		{
			"empty zones → unknown",
			[]awg.Zone{},
			false, "anything.com", "",
			RouteUnknown, false, 0,
		},

		// (f) Source-bound zone wins over global for matching srcIP, leaves
		// global decision alone for non-matching srcIP.
		{
			"source-bound tunnel rule fires for matching src",
			[]awg.Zone{
				// Note source-bound zones come AFTER catch-all here but
				// effectiveZones preserves them; routeFor walks source-bound
				// FIRST.
				zone("ru", "exclude", true, "domain:yandex.ru"),
				zone("all", "include", true, "*"),
				srcZone("kids", "include", "192.168.31.106", "*"),
			},
			false, "yandex.ru", "192.168.31.106",
			RouteTunnel, true, 3, // source-bound wins; tunnel + !tunnelV6 → block AAAA
		},
		{
			"source-bound zone does NOT apply to other LAN clients",
			[]awg.Zone{
				zone("ru", "exclude", true, "domain:yandex.ru"),
				zone("all", "include", true, "*"),
				srcZone("kids", "include", "192.168.31.106", "*"),
			},
			false, "yandex.ru", "192.168.31.200", // different src
			RouteDirect, false, 1, // global RU rule fires
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc.route.routeTable.Store(mkTable(c.zones, c.tunnelV6))
			got := svc.routeFor(c.qname, c.srcIP)
			if got.Route != c.wantRoute {
				t.Errorf("Route=%q, want %q", got.Route, c.wantRoute)
			}
			if got.BlockAAAA != c.wantBlockA4 {
				t.Errorf("BlockAAAA=%v, want %v", got.BlockAAAA, c.wantBlockA4)
			}
			if got.RuleIdx != c.wantRuleIdx {
				t.Errorf("RuleIdx=%d, want %d", got.RuleIdx, c.wantRuleIdx)
			}
		})
	}
}

// srcZone builds a source-bound zone for testing.
func srcZone(name, mode, srcIP string, domains ...string) awg.Zone {
	return awg.Zone{
		Name:      name,
		Mode:      mode,
		Enabled:   true,
		Domains:   domains,
		SourceIPs: []string{srcIP},
	}
}

func TestSrcIPMatches(t *testing.T) {
	cases := []struct {
		ip    string
		cidrs []string
		want  bool
	}{
		{"192.168.31.106", []string{"192.168.31.106"}, true},
		{"192.168.31.106", []string{"192.168.31.0/24"}, true},
		{"192.168.31.106", []string{"10.0.0.0/8"}, false},
		{"192.168.31.106", []string{}, false},
		{"", []string{"192.168.31.0/24"}, false},
		{"192.168.31.106", []string{"192.168.31.105", "192.168.31.0/24"}, true},
		{"2a05:3580:d32f:600::dead", []string{"2a05:3580:d32f:600::/64"}, true},
		{"2a05:3580:d32f:600::dead", []string{"2a05:3580::/32"}, true},
		{"2a05:3580:d32f:600::dead", []string{"2a02::/16"}, false},
	}
	for _, c := range cases {
		if got := srcIPMatches(c.ip, c.cidrs); got != c.want {
			t.Errorf("srcIPMatches(%q, %v) = %v, want %v", c.ip, c.cidrs, got, c.want)
		}
	}
}
