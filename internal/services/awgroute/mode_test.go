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
		// A legacy global Mode of "include"/"exclude" (or "zones") with no zones marks
		// nothing — direction is decided per-zone; only "off"/"full" short-circuit.
		{"legacy global include, no zones → empty", awg.RoutingConfig{Mode: "include"}, ""},
		{"zones empty", awg.RoutingConfig{Mode: "zones"}, ""},
		{"zones include", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("a", "include", true, "youtube.com")}}, "include"},
		{"zones exclude only", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("a", "exclude", true, "vk.com")}}, "exclude"},
		{"zones disabled → empty", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("a", "include", false, "youtube.com")}}, ""},
		// the new behaviour: a bare "*" in an include zone means "route everything"
		{"catch-all alone → full", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("all", "include", true, "*")}}, "full"},
		{"catch-all + other domains → full", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{zone("all", "include", true, "youtube.com", "*")}}, "full"},
		{"catch-all + exclude → exclude", awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{
			zone("all", "include", true, "*"),
			zone("ru", "exclude", true, "*.ru"),
		}}, "exclude"},
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
