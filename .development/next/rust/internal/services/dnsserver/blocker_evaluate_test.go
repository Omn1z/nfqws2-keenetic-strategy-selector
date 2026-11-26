package dnsserver

import (
	"testing"

	mdns "github.com/miekg/dns"
)

func TestBlockerEvaluationDistinguishesExceptionsAndPreservesPrecedence(t *testing.T) {
	blocker, err := NewBlockMatcher([]BlockSource{
		{ID: "plain", Category: BlockCategoryAds, Data: []byte("plain.example\n@@||safe.plain.example^\n")},
		{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte("||adguard.example^\n@@||safe.adguard.example^\n||typed.example^$dnstype=A\n@@||typed.example^$dnstype=AAAA\n")},
	}, []BlockingRule{
		{Domain: "manual.example", Category: BlockCategoryTrackers},
		{Domain: "custom.safe.plain.example", Category: BlockCategoryTrackers},
		{Domain: "custom.safe.adguard.example", Category: BlockCategoryTrackers},
	}, []string{"manual.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		domain  string
		qtype   uint16
		blocked bool
		allowed bool
		source  string
	}{
		{"manual.example", mdns.TypeA, false, true, ""},
		{"child.manual.example", mdns.TypeA, false, true, ""},
		{"safe.plain.example", mdns.TypeA, false, true, ""},
		{"custom.safe.plain.example", mdns.TypeA, true, false, customBlockSource},
		{"safe.adguard.example", mdns.TypeA, false, true, ""},
		{"custom.safe.adguard.example", mdns.TypeA, true, false, customBlockSource},
		{"plain.example", mdns.TypeA, true, false, "plain"},
		{"adguard.example", mdns.TypeA, true, false, "adguard-dns"},
		{"typed.example", mdns.TypeA, true, false, "adguard-dns"},
		{"typed.example", mdns.TypeAAAA, false, true, ""},
		{"typed.example", mdns.TypeHTTPS, false, false, ""},
		{"ordinary.example", mdns.TypeA, false, false, ""},
		{"invalid..example", mdns.TypeA, false, false, ""},
	} {
		match, blocked, allowed := blocker.evaluateDNS(tc.domain, tc.qtype, false)
		if blocked != tc.blocked || allowed != tc.allowed || match.Source != tc.source {
			t.Errorf("evaluateDNS(%q, %d) = (%+v, %v, %v), want blocked=%v allowed=%v source=%q", tc.domain, tc.qtype, match, blocked, allowed, tc.blocked, tc.allowed, tc.source)
		}
		if oldMatch, oldBlocked := blocker.MatchDNS(tc.domain, tc.qtype); oldMatch != match || oldBlocked != blocked {
			t.Errorf("MatchDNS wrapper changed evaluation for %q: %+v, %v", tc.domain, oldMatch, oldBlocked)
		}
	}
	for _, empty := range []*Blocker{nil, {}} {
		if match, blocked, allowed := empty.evaluateDNS("ordinary.example", mdns.TypeA, false); match != (BlockMatch{}) || blocked || allowed {
			t.Fatalf("empty matcher evaluation = (%+v, %v, %v)", match, blocked, allowed)
		}
	}
}
