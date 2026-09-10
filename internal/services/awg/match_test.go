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
	set, bad := CompileMatcherSet([]string{"main.com", "*.cdn.net", "[re]bad(", "server*"})
	if len(bad) != 1 || bad[0] != "[re]bad(" {
		t.Fatalf("CompileMatcherSet bad = %v, want [\"[re]bad(\"]", bad)
	}
	if !set.MatchAny("a.main.com") || !set.MatchAny("x.cdn.net") || !set.MatchAny("server9") {
		t.Error("MatcherSet should match a.main.com / x.cdn.net / server9")
	}
	if set.MatchAny("example.org") {
		t.Error("MatcherSet should not match example.org")
	}
}

func TestSuffixTrie(t *testing.T) {
	tr := newSuffixTrie()
	tr.addBase("abr.ru")
	tr.addBase("main.com")

	yes := []string{"abr.ru", "sub.abr.ru", "x.y.abr.ru", "main.com", "a.main.com"}
	no := []string{"barbr.ru", "abr.run", "abrXru", "main.community", "notmain.com"}

	for _, q := range yes {
		if !tr.match(q) {
			t.Errorf("SuffixTrie.match(%q) = false, want true", q)
		}
	}
	for _, q := range no {
		if tr.match(q) {
			t.Errorf("SuffixTrie.match(%q) = true, want false", q)
		}
	}
}

func TestCompileMatcherSetDedup(t *testing.T) {
	// Catch-all regex must absorb every plain that ends in .ru / .xn--p1ai;
	// shorter plain must absorb longer subdomain plain.
	// CompileMatcherSet receives the post-expand bare entries (the `domain:` /
	// `geosite:` prefixes are stripped upstream in expand.go), so we feed bare
	// plain names here.
	set, bad := CompileMatcherSet([]string{
		`[re]\.ru$`,
		`[re]\.xn--p1ai$`,
		"abr.ru",         // covered by \.ru$ regex
		"vk.ru",          // covered by \.ru$ regex
		"example.com",    // kept
		"cdn.example.com", // covered by example.com
		"main.com",       // kept
		"main.com",       // exact duplicate of the above
	})
	if len(bad) != 0 {
		t.Fatalf("unexpected bad entries: %v", bad)
	}
	// Two regexes + example.com + main.com = 4 total. abr.ru/vk.ru collapsed
	// into regex, cdn.example.com folded under example.com, dup main.com gone.
	if got := set.Len(); got != 4 {
		t.Errorf("MatcherSet.Len() = %d, want 4 (regexes + example.com + main.com)", got)
	}
	if !set.MatchAny("abr.ru") || !set.MatchAny("sub.example.com") || !set.MatchAny("main.com") {
		t.Error("set should match abr.ru / sub.example.com / main.com")
	}
	if set.MatchAny("notmain.io") {
		t.Error("set should not match notmain.io")
	}
}
