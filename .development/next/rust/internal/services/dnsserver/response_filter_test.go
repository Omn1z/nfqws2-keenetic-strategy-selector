package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func responseFilterRR(t *testing.T, text string) mdns.RR {
	t.Helper()
	rr, err := mdns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestResolverFiltersReachableResponseAliases(t *testing.T) {
	for _, tc := range []struct {
		name        string
		list        string
		custom      []BlockingRule
		allow       []string
		answers     []string
		additional  []string
		qtype       uint16
		blocked     bool
		blockDomain string
		blockRule   string
		blockSource string
	}{
		{
			name:    "direct CNAME",
			custom:  []BlockingRule{{Domain: "track.example", Category: BlockCategoryAds}},
			answers: []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
			blocked: true, blockDomain: "track.example", blockRule: "track.example", blockSource: "custom",
		},
		{
			name:    "shuffled case-insensitive CNAME chain",
			list:    "||track.example^",
			answers: []string{"middle.example. 60 IN CNAME TRACK.EXAMPLE.", "track.example. 60 IN A 203.0.113.20", "ALIAS.EXAMPLE. 60 IN CNAME Middle.Example."},
			blocked: true, blockDomain: "track.example", blockRule: "||track.example^", blockSource: "adguard-dns",
		},
		{
			name: "explicit original query allowance",
			list: "||track.example^", allow: []string{"alias.example"},
			answers: []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
		},
		{
			name:    "downloaded original query allowance",
			list:    "@@||alias.example^\n||track.example^",
			answers: []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
		},
		{
			name: "explicit target allowance",
			list: "||track.example^", allow: []string{"track.example"},
			answers: []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
		},
		{
			name:    "downloaded target allowance",
			list:    "||parent.example^\n@@||safe.parent.example^",
			answers: []string{"alias.example. 60 IN CNAME safe.parent.example.", "safe.parent.example. 60 IN A 203.0.113.20"},
		},
		{
			name:    "CNAME type applies to an A response alias",
			list:    "||track.example^$dnstype=CNAME",
			answers: []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
			blocked: true, blockDomain: "track.example", blockRule: "||track.example^$dnstype=CNAME", blockSource: "adguard-dns",
		},
		{
			name:    "A type does not apply to a CNAME target",
			list:    "||track.example^$dnstype=A",
			answers: []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
		},
		{
			name:    "unrelated answer is ignored",
			list:    "||track.example^",
			answers: []string{"alias.example. 60 IN A 203.0.113.20", "unrelated.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.21"},
		},
		{
			name:    "CNAME loop terminates",
			list:    "||track.example^",
			answers: []string{"alias.example. 60 IN CNAME middle.example.", "middle.example. 60 IN CNAME alias.example."},
		},
		{
			name:    "official IPv4 rule filters reachable address",
			list:    "||194.63.143.96^",
			answers: []string{"alias.example. 60 IN A 194.63.143.96"},
			blocked: true, blockDomain: "194.63.143.96", blockRule: "||194.63.143.96^", blockSource: "adguard-dns",
		},
		{
			name:    "IPv4 after a CNAME is reachable",
			list:    "||194.63.143.96^",
			answers: []string{"middle.example. 60 IN A 194.63.143.96", "alias.example. 60 IN CNAME middle.example."},
			blocked: true, blockDomain: "194.63.143.96", blockRule: "||194.63.143.96^", blockSource: "adguard-dns",
		},
		{
			name:       "unrelated answer and additional IPs are ignored",
			list:       "||194.63.143.96^",
			answers:    []string{"alias.example. 60 IN A 203.0.113.20", "unrelated.example. 60 IN A 194.63.143.96"},
			additional: []string{"alias.example. 60 IN A 194.63.143.96"},
		},
		{
			name:    "original allowance bypasses address filtering",
			list:    "@@||alias.example^\n||194.63.143.96^",
			answers: []string{"alias.example. 60 IN A 194.63.143.96"},
		},
		{
			name: "canonical IPv6 response address",
			list: "|2001:db8::bad|", qtype: mdns.TypeAAAA,
			answers: []string{"alias.example. 60 IN AAAA 2001:0db8:0000:0000:0000:0000:0000:0bad"},
			blocked: true, blockDomain: "2001:db8::bad", blockRule: "|2001:db8::bad|", blockSource: "adguard-dns",
		},
		{
			name: "HTTPS IPv4 hint uses HTTPS RR type",
			list: "||194.63.143.96^$dnstype=HTTPS", qtype: mdns.TypeHTTPS,
			answers: []string{"alias.example. 60 IN HTTPS 1 . alpn=h2 ipv4hint=194.63.143.96"},
			blocked: true, blockDomain: "194.63.143.96", blockRule: "||194.63.143.96^$dnstype=HTTPS", blockSource: "adguard-dns",
		},
		{
			name: "A modifier does not filter HTTPS hint",
			list: "||194.63.143.96^$dnstype=A", qtype: mdns.TypeHTTPS,
			answers: []string{"alias.example. 60 IN HTTPS 1 . alpn=h2 ipv4hint=194.63.143.96"},
		},
		{
			name: "SVCB IPv4 hint uses SVCB RR type",
			list: "||194.63.143.96^$dnstype=SVCB", qtype: mdns.TypeSVCB,
			answers: []string{"alias.example. 60 IN SVCB 1 . alpn=h2 ipv4hint=194.63.143.96"},
			blocked: true, blockDomain: "194.63.143.96", blockRule: "||194.63.143.96^$dnstype=SVCB", blockSource: "adguard-dns",
		},
		{
			name: "HTTPS IPv6 hint is canonicalized",
			list: "|2001:db8::bad|", qtype: mdns.TypeHTTPS,
			answers: []string{"alias.example. 60 IN HTTPS 1 . alpn=h2 ipv6hint=2001:0db8::0bad"},
			blocked: true, blockDomain: "2001:db8::bad", blockRule: "|2001:db8::bad|", blockSource: "adguard-dns",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answers := make([]mdns.RR, len(tc.answers))
			for i, text := range tc.answers {
				answers[i] = responseFilterRR(t, text)
			}
			additional := make([]mdns.RR, len(tc.additional))
			for i, text := range tc.additional {
				additional[i] = responseFilterRR(t, text)
			}
			r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(q)
				response.RecursionAvailable = true
				response.AuthenticatedData = true
				for _, rr := range answers {
					response.Answer = append(response.Answer, mdns.Copy(rr))
				}
				for _, rr := range additional {
					response.Extra = append(response.Extra, mdns.Copy(rr))
				}
				return response
			})
			var sources []BlockSource
			if tc.list != "" {
				sources = []BlockSource{{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte(tc.list)}}
			}
			blocker, err := NewBlockMatcher(sources, tc.custom, tc.allow)
			if err != nil {
				t.Fatal(err)
			}
			r.SetBlocker(blocker)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			qtype := tc.qtype
			if qtype == 0 {
				qtype = mdns.TypeA
			}
			wire, out, err := r.Resolve(ctx, resolverWire(t, "alias.example", 42, qtype))
			if err != nil {
				t.Fatal(err)
			}
			var response mdns.Msg
			if err := response.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			if out.Blocked != tc.blocked || out.Domain != "alias.example" || response.Id != 42 {
				t.Fatalf("unexpected response outcome: %+v; response=%v", out, &response)
			}
			if !tc.blocked {
				if response.Rcode != mdns.RcodeSuccess || len(response.Answer) != len(answers) || !response.AuthenticatedData || out.BlockDomain != "" {
					t.Fatalf("allowed response was modified: %+v; response=%v", out, &response)
				}
				return
			}
			if out.BlockDomain != tc.blockDomain || out.BlockRule != tc.blockRule || out.BlockSource != tc.blockSource || out.Route != "blocked" {
				t.Fatalf("missing alias block metadata: %+v", out)
			}
			category := BlockCategoryMixed
			if tc.blockSource == "custom" {
				category = BlockCategoryAds
			}
			if out.BlockCategory != category {
				t.Fatalf("block category = %q, want %q", out.BlockCategory, category)
			}
			if response.Rcode != mdns.RcodeNameError || response.Authoritative || response.AuthenticatedData || !response.RecursionAvailable || len(response.Answer) != 0 || len(response.Ns) != 1 {
				t.Fatalf("blocked response retained upstream data: %v", &response)
			}
			soa, ok := response.Ns[0].(*mdns.SOA)
			if !ok || soa.Hdr.Name != "alias.example." || soa.Hdr.Ttl != 60 {
				t.Fatalf("blocked response missing original-owner SOA: %v", response.Ns)
			}
			if r.CacheStatus().Entries != 0 {
				t.Fatal("blocked response was stored as a positive cache entry")
			}
		})
	}
}

func TestResolverRechecksCachedAliasesAgainstCurrentFilter(t *testing.T) {
	cfg := Default()
	cfg.Rules = nil
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	wire := resolverWire(t, "alias.example", 77, mdns.TypeA)
	q, _, err := parseQuery(wire)
	if err != nil {
		t.Fatal(err)
	}
	zeroID := q.Copy()
	zeroID.Id = 0
	key, err := zeroID.Pack()
	if err != nil {
		t.Fatal(err)
	}
	answer := new(mdns.Msg)
	answer.SetReply(q)
	answer.AuthenticatedData = true
	answer.Answer = []mdns.RR{
		responseFilterRR(t, "alias.example. 60 IN CNAME track.example."),
		&mdns.A{Hdr: mdns.RR_Header{Name: "track.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.20")},
	}
	r.cachePut(string(key), answer, "nfqws", cfg.DefaultUpstream.Address, 0)
	_, before, err := r.Resolve(context.Background(), wire)
	if err != nil || !before.Cached || before.Blocked {
		t.Fatalf("could not prime a permitted cached response: %+v, %v", before, err)
	}
	blocker, err := NewBlockMatcher(nil, []BlockingRule{{Domain: "track.example", Category: BlockCategoryTrackers}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.SetBlocker(blocker)
	wire, out, err := r.Resolve(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	var response mdns.Msg
	if err := response.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if !out.Blocked || out.Domain != "alias.example" || out.BlockDomain != "track.example" || out.BlockSource != "custom" || out.BlockCategory != BlockCategoryTrackers || out.Route != "blocked" {
		t.Fatalf("cached alias escaped the current filter: %+v", out)
	}
	if response.Rcode != mdns.RcodeNameError || response.AuthenticatedData || len(response.Answer) != 0 || response.Id != 77 {
		t.Fatalf("cached alias did not produce a policy reply: %v", &response)
	}
	if calls := backend.dialCalls(); len(calls) != 0 {
		t.Fatalf("cached response filtering reached an upstream: %v", calls)
	}
}
