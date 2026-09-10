package awgroute

import (
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func zone(name, mode string, enabled bool, domains ...string) awg.Zone {
	return awg.Zone{Name: name, Mode: mode, Enabled: enabled, Domains: domains}
}

func TestAwgEffectiveMode(t *testing.T) {
	cases := []struct {
		name string
		r    awg.RoutingConfig
		want string
	}{
		{"off", awg.RoutingConfig{Mode: "off"}, "off"},
		{"full", awg.RoutingConfig{Mode: "full"}, "full"},
		{"legacy global include, no zones → empty", awg.RoutingConfig{Mode: "include"}, ""},
		{"zones empty", awg.RoutingConfig{Mode: "zones"}, ""},
		{"zones include", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("a", "include", true, "youtube.com")}}, "include"},
		{"zones exclude only", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("a", "exclude", true, "vk.com")}}, "exclude"},
		{"zones disabled → empty", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("a", "include", false, "youtube.com")}}, ""},
		{"catch-all alone → full", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("all", "include", true, "*")}}, "full"},
		{"catch-all + other domains → full", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("all", "include", true, "youtube.com", "*")}}, "full"},
		// First-match-wins: a catch-all=tunnel at array index 0 SHADOWS the
		// *.ru direct rule at index 1 → "full". The .ru rule is dead code; it
		// never enters the chain, so the global mode is "every dst marks".
		// (Old code returned "exclude" — that was the bug the user kept hitting.)
		{"catch-all-tunnel at #0 SHADOWS later direct → full", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
			zone("all", "include", true, "*"),
			zone("ru", "exclude", true, "*.ru"),
		}}, "full"},
		// First-match-wins: a direct rule at #0 with catch-all=tunnel at #1
		// is the classic "VPN by default with carve-out" → "exclude".
		{"direct at #0 + catch-all-tunnel at #1 → exclude", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
			zone("ru", "exclude", true, "*.ru"),
			zone("all", "include", true, "*"),
		}}, "exclude"},
		// Catch-all=direct at #0 makes everything else dead code — no global mark.
		{"catch-all-direct at #0 alone → empty", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
			zone("all", "exclude", true, "*"),
		}}, ""},
		// Catch-all=direct at #1 with an earlier tunnel rule → "include":
		// the tunnel zone's IPs are realised via awg2_inc, everything else stays direct.
		{"tunnel at #0 + catch-all-direct at #1 → include", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
			zone("tg", "include", true, "*.tg"),
			zone("all", "exclude", true, "*"),
		}}, "include"},
		{"catch-all disabled → ignored", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
			zone("all", "include", false, "*"),
			zone("yt", "include", true, "youtube.com"),
		}}, "include"},
		{"mask-only include (no catch-all) → include", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("com", "include", true, "*.com")}}, "include"},
	}
	for _, c := range cases {
		if got := awgEffectiveMode(c.r); got != c.want {
			t.Errorf("%s: awgEffectiveMode = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFirstMatchWins is the load-bearing assertion: rules walk in array order
// and the FIRST matching rule's route decides. The in-test resolve() mirrors
// the runtime onMatch / onHello walk — same effectiveZones truncation, same
// per-zone MatcherSet, same first-hit short-circuit.
func TestFirstMatchWins(t *testing.T) {
	resolve := func(zones []awg.Zone, name string) string {
		r := awg.RoutingConfig{Mode: "zones", Zones: zones}
		for _, z := range effectiveZones(r) {
			if !z.Enabled || len(z.SourceIPs) > 0 {
				continue
			}
			var ms awg.MatcherSet
			if z.IsCatchAll() {
				ms, _ = awg.CompileMatcherSet([]string{"[re]^"})
			} else {
				ms, _ = awg.CompileMatcherSet(awgDropCatchAll(z.Domains))
			}
			if ms.MatchAny(name) {
				return z.RouteValue()
			}
		}
		return "nomatch"
	}

	cases := []struct {
		label string
		zones []awg.Zone
		name  string
		want  string
	}{
		// (a) catch-all=tunnel at #0 SHADOWS the later *.ru direct rule
		// completely; effectiveZones drops the .ru rule. Both google.com and
		// ya.ru fall under the catch-all → tunnel.
		{"a/google catch-all-tunnel shadows .ru", []awg.Zone{
			zone("all", "include", true, "*"),
			zone("ru", "exclude", true, "*.ru"),
		}, "google.com", "tunnel"},
		{"a/ya.ru catch-all-tunnel shadows .ru", []awg.Zone{
			zone("all", "include", true, "*"),
			zone("ru", "exclude", true, "*.ru"),
		}, "ya.ru", "tunnel"},

		// (b) *.ru direct at #0 + catch-all=tunnel at #1 — the .ru rule fires
		// first for ya.ru, the catch-all wins for non-.ru.
		{"b/google non-.ru → catch-all tunnel", []awg.Zone{
			zone("ru", "exclude", true, "*.ru"),
			zone("all", "include", true, "*"),
		}, "google.com", "tunnel"},
		{"b/ya.ru → direct rule wins before catch-all", []awg.Zone{
			zone("ru", "exclude", true, "*.ru"),
			zone("all", "include", true, "*"),
		}, "ya.ru", "direct"},

		// (c) *.tg tunnel at #0 + catch-all=direct at #1 — Telegram tunnels,
		// everything else stays direct.
		{"c/web.telegram.tg tunnel rule wins first", []awg.Zone{
			zone("tg", "include", true, "*.tg"),
			zone("all", "exclude", true, "*"),
		}, "web.telegram.tg", "tunnel"},
		{"c/google.com → catch-all direct wins", []awg.Zone{
			zone("tg", "include", true, "*.tg"),
			zone("all", "exclude", true, "*"),
		}, "google.com", "direct"},
	}
	for _, c := range cases {
		if got := resolve(c.zones, c.name); got != c.want {
			t.Errorf("%s: resolve(%q) = %q, want %q", c.label, c.name, got, c.want)
		}
	}
}

// TestEffectiveZonesTruncation confirms zones after the first catch-all are
// dropped (except source-bound ones, which stay alive).
func TestEffectiveZonesTruncation(t *testing.T) {
	src := awg.Zone{Name: "kids", Enabled: true, Route: "tunnel", Domains: []string{"*"}, SourceIPs: []string{"192.168.1.50"}}
	r := awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
		zone("ru", "exclude", true, "*.ru"),
		zone("all", "include", true, "*"),
		zone("dead", "exclude", true, "vk.com"), // shadowed by catch-all → dropped
		src, // source-bound, kept regardless
	}}
	ez := effectiveZones(r)
	if len(ez) != 3 {
		t.Fatalf("effectiveZones len=%d, want 3 (ru + catch-all + source-bound), got %v", len(ez), ez)
	}
	if ez[0].Name != "ru" || ez[1].Name != "all" || ez[2].Name != "kids" {
		t.Errorf("unexpected zone order: %v", []string{ez[0].Name, ez[1].Name, ez[2].Name})
	}
}

func TestIsMaskEntry(t *testing.T) {
	mask := []string{"*", "*.com", "ip*", "*ip*", "test##.com", "[re]^x$"}
	plain := []string{"youtube.com", "2ip.ru", "sub.example.org", ""}
	for _, m := range mask {
		if !isMaskEntry(m) {
			t.Errorf("isMaskEntry(%q) = false, want true", m)
		}
	}
	for _, p := range plain {
		if isMaskEntry(p) {
			t.Errorf("isMaskEntry(%q) = true, want false", p)
		}
	}
}

func TestAwgZonesHaveMask(t *testing.T) {
	cfg := func(zs ...awg.Zone) *awg.ServerConfig {
		return &awg.ServerConfig{Routing: awg.RoutingConfig{Zones: zs}}
	}
	cases := []struct {
		name string
		cfg  *awg.ServerConfig
		want bool
	}{
		{"real mask", cfg(zone("a", "include", true, "*.com")), true},
		{"regex mask", cfg(zone("a", "include", true, "[re]^.*\\.cdn\\.net$")), true},
		{"bare star is NOT a mask (handled by mode)", cfg(zone("a", "include", true, "*")), false},
		{"plain only", cfg(zone("a", "include", true, "youtube.com")), false},
		{"disabled mask ignored", cfg(zone("a", "include", false, "*.com")), false},
		{"mask in exclude zone", cfg(zone("a", "exclude", true, "*ip*")), true},
	}
	for _, c := range cases {
		if got := awgZonesHaveMask(c.cfg); got != c.want {
			t.Errorf("%s: awgZonesHaveMask = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAwgUsesDNSProxy(t *testing.T) {
	mk := func(src string, zs ...awg.Zone) *awg.ServerConfig {
		return &awg.ServerConfig{Routing: awg.RoutingConfig{DomainSource: src, Zones: zs}}
	}
	if !awgUsesDNSProxy(mk("dnsproxy")) {
		t.Error("domain_source=dnsproxy should use the proxy")
	}
	if awgUsesDNSProxy(mk("resolve", zone("a", "include", true, "youtube.com"))) {
		t.Error("resolve + plain domains should NOT use the proxy")
	}
	if !awgUsesDNSProxy(mk("resolve", zone("a", "include", true, "*.com"))) {
		t.Error("resolve + a real mask MUST auto-enable the proxy")
	}
	if awgUsesDNSProxy(mk("resolve", zone("a", "include", true, "*"))) {
		t.Error("resolve + bare '*' should NOT need the proxy (handled by full mode)")
	}
}

func TestAwgDropCatchAll(t *testing.T) {
	got := awgDropCatchAll([]string{"*", "a.com", " * ", "b.net", "*.com"})
	want := []string{"a.com", "b.net", "*.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("awgDropCatchAll = %v, want %v", got, want)
	}
}
