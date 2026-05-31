package awg

import "testing"

func TestDomainMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		// plain → domain + all subdomains
		{"main.com", "main.com", true},
		{"main.com", "a.main.com", true},
		{"main.com", "x.y.main.com", true},
		{"main.com", "main.com.", true}, // trailing dot ignored
		{"main.com", "MAIN.COM", true},  // case-insensitive
		{"main.com", "notmain.com", false},
		{"main.com", "mainXcom", false},
		{"main.com", "main.community", false},
		{".main.com", "a.main.com", true}, // leading dot tolerated
		// glob: * = any run, # = exactly one char
		{"*main.com", "main.com", true},
		{"*main.com", "xmain.com", true},
		{"*main.com", "a.main.com", true},
		{"*main.com", "main.community", false},
		{"server*", "server", true},
		{"server*", "server1.example.net", true},
		{"server*", "myserver", false},
		{"test##.com", "test12.com", true},
		{"test##.com", "test1.com", false},   // # = exactly one char (only 1 here)
		{"test##.com", "test123.com", false}, // 3 chars
		{"domain*.*", "domain12.com", true},
		{"domain*.*", "domain3124214.net", true},
		// regexp
		{`[re]^.*\.googlevideo\.com$`, "r1---sn.googlevideo.com", true},
		{`[re]^.*\.googlevideo\.com$`, "googlevideo.com", false},
		{`[re]^(a|b)\.x\.com$`, "a.x.com", true},
		{`[re]^(a|b)\.x\.com$`, "c.x.com", false},
	}
	for _, c := range cases {
		m, err := NewDomainMatcher(c.pattern)
		if err != nil {
			t.Fatalf("NewDomainMatcher(%q): %v", c.pattern, err)
		}
		if got := m.Match(c.name); got != c.want {
			t.Errorf("matcher %q . Match(%q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestDomainMatcherErrors(t *testing.T) {
	for _, p := range []string{"", "   ", "[re]", "[re](unclosed"} {
		if _, err := NewDomainMatcher(p); err == nil {
			t.Errorf("NewDomainMatcher(%q): expected error", p)
		}
	}
}

func TestMatchAny(t *testing.T) {
	ms, bad := CompileMatchers([]string{"main.com", "*.cdn.net", "[re]bad(", "server*"})
	if len(bad) != 1 || bad[0] != "[re]bad(" {
		t.Fatalf("CompileMatchers bad = %v, want [\"[re]bad(\"]", bad)
	}
	if !MatchAny(ms, "a.main.com") || !MatchAny(ms, "x.cdn.net") || !MatchAny(ms, "server9") {
		t.Error("MatchAny should match a.main.com / x.cdn.net / server9")
	}
	if MatchAny(ms, "example.org") {
		t.Error("MatchAny should not match example.org")
	}
}
