package nfqws2

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func serviceProfileFixture() []ServiceStrategy {
	return []ServiceStrategy{{ID: "facepunch", Name: "FacePunch", Enabled: true, Groups: []ServiceStrategyGroup{
		{ID: "web", Name: "Web", Kind: "domains", Entries: []string{"facepunch.com"}, Strategy: "--filter-tcp=443 --lua-desync=multisplit:pos=1,midsld"},
	}}}
}

func TestCompileServiceStrategiesScopesEveryProfile(t *testing.T) {
	services := serviceProfileFixture()
	services[0].Groups[0].Strategy = "--filter-tcp=80,443 \\\n--out-range=<n2 --lua-desync='multisplit:pos=1,midsld' --new\n--filter-udp=27015-27050 --lua-desync=fake:blob=quic_initial"
	services[0].Groups = append(services[0].Groups, ServiceStrategyGroup{ID: "servers", Name: "Servers", Kind: "ips", Entries: []string{"192.0.2.23/24", "2001:db8::1"}, Strategy: "--filter-udp=443 --lua-desync=fake:blob=quic_initial"})
	got, err := CompileServiceStrategies(services, "/opt/etc/nfqws2/service-lists")
	if err != nil {
		t.Fatal(err)
	}
	if got.Profiles != 3 || got.EnabledGroups != 2 || got.EnabledServices != 1 {
		t.Fatalf("counts: %+v", got)
	}
	if got.TCPPorts != "80,443" || got.UDPPorts != "443,27015:27050" {
		t.Fatalf("ports TCP=%s UDP=%s", got.TCPPorts, got.UDPPorts)
	}
	wantScopes := []string{
		"--hostlist=" + filepath.ToSlash(filepath.Join("/opt/etc/nfqws2/service-lists", serviceListBasename("facepunch", "web", "domains", "facepunch.com\n"))),
		"--hostlist=" + filepath.ToSlash(filepath.Join("/opt/etc/nfqws2/service-lists", serviceListBasename("facepunch", "web", "domains", "facepunch.com\n"))),
		"--ipset=" + filepath.ToSlash(filepath.Join("/opt/etc/nfqws2/service-lists", serviceListBasename("facepunch", "servers", "ips", "192.0.2.0/24\n2001:db8::1\n"))),
	}
	profile := 0
	for i, arg := range got.Args {
		if i == 0 || got.Args[i-1] == "--new" {
			if arg != wantScopes[profile] {
				t.Fatalf("profile %d scope=%q want=%q", profile, arg, wantScopes[profile])
			}
			profile++
		}
	}
	if profile != 3 || got.Args[len(got.Args)-1] == "--new" {
		t.Fatalf("invalid profiles: %v", got.Args)
	}
	if got.Lists[serviceListBasename("facepunch", "web", "domains", "facepunch.com\n")] != "facepunch.com\n" || got.Lists[serviceListBasename("facepunch", "servers", "ips", "192.0.2.0/24\n2001:db8::1\n")] != "192.0.2.0/24\n2001:db8::1\n" {
		t.Fatalf("lists: %v", got.Lists)
	}
	if services[0].Groups[1].Entries[0] != "192.0.2.23/24" {
		t.Fatal("compiler mutated input")
	}
}

func TestNormalizeServiceTargets(t *testing.T) {
	tests := []struct{ input, want string }{
		{" FacePunch.COM. ", "facepunch.com"},
		{"*.FacePunch.COM", "facepunch.com"},
		{".FacePunch.COM", "facepunch.com"},
		{"пример.рф", "xn--e1afmkfd.xn--p1ai"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizeServiceDomain(test.input)
			if err != nil || got != test.want {
				t.Fatalf("got %q %v want %q", got, err, test.want)
			}
		})
	}
	for _, invalid := range []string{"localhost", "https://facepunch.com/path", "192.0.2.1", "bad_domain.com", "bad..example.com", "-bad.example", "bad-.example", "a.*.example", "example.com:443", "example.com\nother.example"} {
		if _, err := NormalizeServiceDomain(invalid); err == nil {
			t.Errorf("accepted invalid domain %q", invalid)
		}
	}
	for _, test := range []struct{ input, want string }{{"192.0.2.1/24", "192.0.2.0/24"}, {"192.0.2.1/32", "192.0.2.1"}, {"2001:0db8:0000::1", "2001:db8::1"}, {"2001:db8::1/32", "2001:db8::/32"}, {"::ffff:192.0.2.1", "192.0.2.1"}, {"::ffff:192.0.2.1/120", "192.0.2.0/24"}} {
		got, err := normalizeServiceIP(test.input)
		if err != nil || got != test.want {
			t.Errorf("normalize IP %s: %s %v", test.input, got, err)
		}
	}
	for _, invalid := range []string{"192.0.2.1:443", "facepunch.com", "192.0.2.1/33", "fe80::1%eth0", "2001:db8::/129"} {
		if _, err := normalizeServiceIP(invalid); err == nil {
			t.Errorf("accepted invalid IP %q", invalid)
		}
	}
	services := serviceProfileFixture()
	services[0].Groups[0].Entries = []string{"FacePunch.COM.", "# comment", "", "*.facepunch.com", "пример.рф", "xn--e1afmkfd.xn--p1ai"}
	got, err := NormalizeServiceStrategies(services)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got[0].Groups[0].Entries, []string{"facepunch.com", "xn--e1afmkfd.xn--p1ai"}) {
		t.Fatalf("entries %v", got[0].Groups[0].Entries)
	}
}

func TestCompileServiceStrategiesDisabledDraftsUseGlobal(t *testing.T) {
	services := serviceProfileFixture()
	services[0].Enabled = false
	services[0].Groups[0].Strategy = "--unfinished=\""
	services[0].Groups = append(services[0].Groups, ServiceStrategyGroup{ID: "empty", Name: "Empty", Kind: "ips", Entries: []string{}})
	got, err := CompileServiceStrategies(services, "/opt/lists")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Args) != 0 || len(got.Lists) != 0 || got.TCPPorts != "" || got.UDPPorts != "" || got.Profiles != 0 || got.EnabledServices != 0 {
		t.Fatalf("disabled draft affects runtime: %+v", got)
	}
	if got.Services[0].Groups[0].Strategy != "--unfinished=\"" {
		t.Fatal("draft lost")
	}
	services[0].Enabled = true
	if _, err := CompileServiceStrategies(services, "/opt/lists"); err == nil {
		t.Fatal("enabled incomplete draft accepted")
	}
	services = serviceProfileFixture()
	services[0].Groups = append(services[0].Groups, ServiceStrategyGroup{ID: "empty", Name: "Empty", Kind: "ips"})
	got, err = CompileServiceStrategies(services, "/opt/lists")
	if err != nil || got.Profiles != 1 {
		t.Fatalf("empty placeholder group: %+v %v", got, err)
	}
}

func TestServiceStrategiesPortFilters(t *testing.T) {
	for _, test := range []struct{ filter, want string }{{"443", "443"}, {"80-90,85-100,443", "80:100,443"}, {"*", "1:65535"}, {"~443", "1:442,444:65535"}, {"~80,443", "1:79,81:65535"}, {"~400-450", "1:399,451:65535"}, {"~*,443", "443"}, {"63-65,127-129", "63:65,127:129"}, {"65535", "65535"}} {
		t.Run(test.filter, func(t *testing.T) {
			got, err := parseServicePorts(test.filter)
			if err != nil || got.String() != test.want {
				t.Fatalf("ports=%s err=%v want=%s", got.String(), err, test.want)
			}
		})
	}
	for _, invalid := range []string{"", "443,", "443,,80", "garbage", "80:90", "90-80", "0", "65536", "-443", "+443", "~", "~*", "80-90-100", "443 80", "*garbage"} {
		if _, err := parseServicePorts(invalid); err == nil {
			t.Errorf("accepted invalid ports %q", invalid)
		}
	}
	profiles, tcp, udp, err := compileServiceGroupProfiles("--filter-tcp=80 --filter-tcp=443 --filter-udp=53 --new --filter-udp=443")
	if err != nil || len(profiles) != 2 || tcp.String() != "80,443" || udp.String() != "53,443" {
		t.Fatalf("repeated/mixed ports: %v %s %s %v", profiles, tcp.String(), udp.String(), err)
	}
}

func TestServiceStrategiesRejectUnsafeAndMalformedProfiles(t *testing.T) {
	for _, invalid := range []string{
		"--new --filter-tcp=443", "--filter-tcp=443 --new", "--filter-tcp=443 --new --new --filter-udp=443",
		"--new=other --filter-tcp=443", "--lua-desync=fake", "--filter-tcp=443 --new --lua-desync=fake",
		"--filter-tcp=443 --hostlist=/tmp/other", "--filter-tcp=443 --hostlist-exclude=/tmp/other", "--filter-tcp=443 --hostlist-domains=other.example", "--filter-tcp=443 --ipset=/tmp/other",
		"--filter-tcp=443 --import=other", "--filter-tcp=443 --template=other", "--filter-tcp=443 --skip=1", "--filter-tcp=443 --lua-init=@/tmp/evil.lua",
		"--filter-tcp=443 --qnum=123", "--filter-tcp=443 --filter-icmp=*", "--filter-tcp=443; touch /tmp/evil", "--filter-tcp=$(touch /tmp/evil)", "--filter-tcp=`touch /tmp/evil`",
		"--filter-tcp=443 && echo evil", "--filter-tcp=443 | echo evil", "--filter-tcp=443\x00", "--filter-tcp=443 --lua-desync='unfinished",
		"--filter-tcp=443 --lua-desync=\"fake:blob=@/tmp/with space.bin\"", "--filter-tcp=443 positional", "--filter-tcp 443", "--filter-tcp=443 --payload=",
	} {
		t.Run(invalid, func(t *testing.T) {
			services := serviceProfileFixture()
			services[0].Groups[0].Strategy = invalid
			if _, err := CompileServiceStrategies(services, "/opt/lists"); err == nil {
				t.Fatalf("accepted %q", invalid)
			}
		})
	}
	if _, err := CompileServiceStrategies(serviceProfileFixture(), "/opt/with space/lists"); err == nil {
		t.Fatal("accepted runtime path with space")
	}
	for _, invalidID := range []string{"../escape", "foo/bar", "a.b", "foo\\bar", "", "a\n", "a b"} {
		services := serviceProfileFixture()
		services[0].ID = invalidID
		if _, err := NormalizeServiceStrategies(services); err == nil {
			t.Errorf("accepted unsafe ID %q", invalidID)
		}
	}
}

func TestServiceStrategiesConflicts(t *testing.T) {
	for _, test := range []struct{ kind, a, b string }{{"domains", "example.com", "api.example.com"}, {"domains", "api.example.com", "example.com"}, {"domains", "пример.рф", "xn--e1afmkfd.xn--p1ai"}, {"ips", "192.0.2.0/24", "192.0.2.128/25"}, {"ips", "192.0.2.1", "192.0.2.0/24"}, {"ips", "2001:db8::/32", "2001:db8:1::/48"}} {
		t.Run(test.a+test.b, func(t *testing.T) {
			services := serviceProfileFixture()
			services[0].Groups[0].Kind = test.kind
			services[0].Groups[0].Entries = []string{test.a}
			second := services[0]
			second.ID = "second"
			second.Name = "Second"
			second.Groups = []ServiceStrategyGroup{{ID: "other", Name: "Other", Kind: test.kind, Entries: []string{test.b}, Strategy: "--filter-tcp=443"}}
			services = append(services, second)
			if _, err := CompileServiceStrategies(services, "/opt/lists"); err == nil || !strings.Contains(err.Error(), "FacePunch") || !strings.Contains(err.Error(), "Second") {
				t.Fatalf("missing actionable conflict: %v", err)
			}
			services[1].Enabled = false
			if _, err := CompileServiceStrategies(services, "/opt/lists"); err != nil {
				t.Fatalf("disabled draft conflicts: %v", err)
			}
		})
	}
	services := serviceProfileFixture()
	services[0].Groups[0].Entries = []string{"example.com", "www.example.com", "example-aaa.com", "other.example.com"}
	if _, err := CompileServiceStrategies(services, "/opt/lists"); err != nil {
		t.Fatalf("same group overlaps: %v", err)
	}
	services[0].Groups = append(services[0].Groups, ServiceStrategyGroup{ID: "other", Name: "Other", Kind: "domains", Entries: []string{"api.example.com"}, Strategy: "--filter-tcp=443"})
	if _, err := CompileServiceStrategies(services, "/opt/lists"); err == nil {
		t.Fatal("missed domain overlap with adjacent sibling")
	}
	services[0].Groups[1].Entries = []string{"notexample.com"}
	if _, err := CompileServiceStrategies(services, "/opt/lists"); err != nil {
		t.Fatalf("false suffix conflict: %v", err)
	}
}

func TestMergeServicePorts(t *testing.T) {
	for _, test := range []struct{ base, extra, want string }{{"80,443,5000:5010", "81:90,8443", "80:90,443,5000:5010,8443"}, {"", "443", "443"}, {"443", "", "443"}, {"", "", ""}, {"80-90", "91", "80:91"}} {
		got, err := MergeServicePorts(test.base, test.extra)
		if err != nil || got != test.want {
			t.Errorf("merge %q %q: %q %v want %q", test.base, test.extra, got, err, test.want)
		}
	}
	for _, invalid := range []string{"$PORTS", "80:90:100", "0", "~80", "*", "443,,80"} {
		if _, err := MergeServicePorts(invalid, "443"); err == nil {
			t.Errorf("accepted invalid base %q", invalid)
		}
	}
	var fragmented []string
	for port := 1; port <= 31; port += 2 {
		fragmented = append(fragmented, fmt.Sprint(port))
	}
	if _, err := MergeServicePorts(strings.Join(fragmented, ","), ""); err == nil {
		t.Fatal("accepted more than 15 multiport slots")
	}
	if _, err := MergeServicePorts("1:2,4:5,7:8,10:11,13:14,16:17,19:20,22:23", ""); err == nil {
		t.Fatal("ranges must consume two slots")
	}
}

func TestServiceStrategiesLimitsAndImmutableLists(t *testing.T) {
	tests := []struct {
		name string
		edit func([]ServiceStrategy) []ServiceStrategy
	}{
		{"services", func(s []ServiceStrategy) []ServiceStrategy { return make([]ServiceStrategy, MaxServiceStrategies+1) }},
		{"groups", func(s []ServiceStrategy) []ServiceStrategy {
			s[0].Groups = make([]ServiceStrategyGroup, MaxServiceGroups+1)
			return s
		}},
		{"entries", func(s []ServiceStrategy) []ServiceStrategy {
			s[0].Groups[0].Entries = make([]string, MaxServiceEntries+1)
			return s
		}},
		{"strategy", func(s []ServiceStrategy) []ServiceStrategy {
			s[0].Groups[0].Strategy = strings.Repeat(" ", MaxServiceStrategyBytes+1)
			return s
		}},
		{"name", func(s []ServiceStrategy) []ServiceStrategy { s[0].Name = strings.Repeat("x", 121); return s }},
		{"kind", func(s []ServiceStrategy) []ServiceStrategy { s[0].Groups[0].Kind = "unknown"; return s }},
		{"duplicate_service", func(s []ServiceStrategy) []ServiceStrategy {
			second := s[0]
			second.ID = "FACEPUNCH"
			return append(s, second)
		}},
		{"duplicate_group", func(s []ServiceStrategy) []ServiceStrategy {
			second := s[0].Groups[0]
			second.ID = "WEB"
			s[0].Groups = append(s[0].Groups, second)
			return s
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizeServiceStrategies(test.edit(serviceProfileFixture())); err == nil {
				t.Fatal("invalid or unbounded input accepted")
			}
		})
	}
	services := serviceProfileFixture()
	before, err := CompileServiceStrategies(services, "/opt/lists")
	if err != nil {
		t.Fatal(err)
	}
	services[0].Groups[0].Entries = []string{"other.example"}
	after, err := CompileServiceStrategies(services, "/opt/lists")
	if err != nil {
		t.Fatal(err)
	}
	if before.Args[0] == after.Args[0] {
		t.Fatal("changed content reused a running profile's list path")
	}
	for name, content := range before.Lists {
		if !strings.HasPrefix(name, "n2s_service_") || !strings.HasSuffix(name, ".list") || strings.Count(name, ".") != 1 || content != "facepunch.com\n" {
			t.Fatalf("unsafe or mutated managed list: %q %q", name, content)
		}
	}
}
