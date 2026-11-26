package dnsserver

import (
	"fmt"
	"strings"
	"testing"
)

func TestBlockerReusesAdGuardEngineAcrossRuleEdits(t *testing.T) {
	adguard := BlockSource{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte(strings.Join([]string{
		"||ad.example^",
		"||other.example^",
		"@@||good.ad.example^",
		"||ad.example^",
		"example.org##.cosmetic",
	}, "\n"))}
	plain := BlockSource{ID: "plain", Category: BlockCategoryAds, Data: []byte("plain.example\n")}
	before, err := NewBlockMatcher([]BlockSource{plain, adguard}, []BlockingRule{{Domain: "old-custom.example"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := before.snapshot.Load()
	if previous.adguard == nil || previous.stats.Ignored[adguard.ID] == 0 {
		t.Fatal("fixture did not compile an AdGuard engine with ignored rules")
	}
	adguard.Category = BlockCategoryAds
	after, err := newBlockMatcher([]BlockSource{adguard, plain}, []BlockingRule{
		{Domain: "new-custom.example", Category: BlockCategoryTrackers},
		{Domain: "manual.good.ad.example", Category: BlockCategoryTrackers},
	}, []string{"ad.example"}, before)
	if err != nil {
		t.Fatal(err)
	}
	current := after.snapshot.Load()
	if current == previous || current.adguard != previous.adguard {
		t.Fatal("unchanged source did not share its engine in a new snapshot")
	}
	if current.stats.Sources[adguard.ID] != previous.stats.Sources[adguard.ID] || current.stats.Ignored[adguard.ID] != previous.stats.Ignored[adguard.ID] {
		t.Fatal("reused engine lost its source statistics")
	}
	if match, blocked := after.Match("other.example"); !blocked || match.Category != BlockCategoryAds {
		t.Fatalf("reused engine lost new source category: %+v, %v", match, blocked)
	}
	for _, tc := range []struct {
		domain string
		before bool
		after  bool
	}{
		{"ad.example", true, false},
		{"old-custom.example", true, false},
		{"new-custom.example", false, true},
		{"plain.example", true, true},
	} {
		if _, blocked := before.Match(tc.domain); blocked != tc.before {
			t.Errorf("old snapshot changed for %s: blocked=%v", tc.domain, blocked)
		}
		if _, blocked := after.Match(tc.domain); blocked != tc.after {
			t.Errorf("new snapshot ignored rule edits for %s: blocked=%v", tc.domain, blocked)
		}
	}
	// A custom rule still overrides a downloaded exception after allow removal.
	if err := after.Replace([]BlockSource{adguard, plain}, []BlockingRule{{Domain: "manual.good.ad.example", Category: BlockCategoryTrackers}}, nil); err != nil {
		t.Fatal(err)
	}
	if after.snapshot.Load().adguard != previous.adguard {
		t.Fatal("Replace recompiled unchanged AdGuard bytes")
	}
	if match, blocked := after.Match("manual.good.ad.example"); !blocked || match.Source != customBlockSource {
		t.Fatalf("custom rule lost to reused source exception: %+v, %v", match, blocked)
	}
}

func TestBlockerRecompilesChangedAdGuardBytesAndKeepsOldSnapshot(t *testing.T) {
	source := BlockSource{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte("||before.example^\n")}
	before, err := NewBlockMatcher([]BlockSource{source}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := before.snapshot.Load()
	// The fingerprint belongs to the compiled engine, not the mutable caller buffer.
	copy(source.Data, "||afterx.example^\n")
	after, err := newBlockMatcher([]BlockSource{source}, nil, nil, before)
	if err != nil {
		t.Fatal(err)
	}
	if after.snapshot.Load().adguard == previous.adguard {
		t.Fatal("changed source reused a stale engine")
	}
	if _, blocked := before.Match("before.example"); !blocked {
		t.Fatal("source buffer mutation damaged the old compiled engine")
	}
	if _, blocked := after.Match("before.example"); blocked {
		t.Fatal("changed source retained old rules")
	}
	if _, blocked := after.Match("afterx.example"); !blocked {
		t.Fatal("changed source rules were not compiled")
	}
	current := after.snapshot.Load()
	for _, invalid := range []struct {
		custom []BlockingRule
		allow  []string
	}{
		{custom: []BlockingRule{{Domain: "*invalid.example"}}},
		{allow: []string{"invalid..example"}},
	} {
		if err := after.Replace([]BlockSource{source}, invalid.custom, invalid.allow); err == nil {
			t.Fatal("invalid rule edit accepted")
		}
		if after.snapshot.Load() != current {
			t.Fatal("failed edit published a partial snapshot")
		}
	}
	if err := after.Replace(nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if after.snapshot.Load().adguard != nil {
		t.Fatal("removed source retained its engine")
	}
}

func BenchmarkBlockerAdGuardUnchangedRebuild(b *testing.B) {
	var lines strings.Builder
	lines.Grow(177000 * 24)
	for i := 0; i < 177000; i++ {
		fmt.Fprintf(&lines, "||ad%06d.example^\n", i)
	}
	sources := []BlockSource{{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte(lines.String())}}
	matcher, err := NewBlockMatcher(sources, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	engine := matcher.snapshot.Load().adguard
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher, err = newBlockMatcher(sources, []BlockingRule{{Domain: "custom.example"}}, []string{"allow.example"}, matcher)
		if err != nil {
			b.Fatal(err)
		}
		if matcher.snapshot.Load().adguard != engine {
			b.Fatal("unchanged source recompiled")
		}
	}
}
