package dnsserver

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func cacheNegativeAnswer(q *mdns.Msg, code int, ttl, minimum uint32) *mdns.Msg {
	answer := new(mdns.Msg)
	answer.SetRcode(q, code)
	answer.RecursionAvailable = true
	answer.Ns = []mdns.RR{&mdns.SOA{Hdr: mdns.RR_Header{Name: "example.", Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: ttl}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: minimum}}
	return answer
}

func TestResolverCacheNegativeAnswersRespectSOAMinimumAndExpire(t *testing.T) {
	for _, test := range []struct {
		name                 string
		code                 int
		qtype                uint16
		ttl, minimum         uint32
		configured, lifetime int
	}{
		{"NXDOMAIN", mdns.RcodeNameError, mdns.TypeA, 40, 3, 60, 3},
		{"NODATA HTTPS", mdns.RcodeSuccess, mdns.TypeHTTPS, 3, 40, 60, 3},
		{"NODATA AAAA configured cap", mdns.RcodeSuccess, mdns.TypeAAAA, 40, 30, 2, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
				calls.Add(1)
				return cacheNegativeAnswer(q, test.code, test.ttl, test.minimum)
			})
			r.cfg.AWGFallback = "off"
			r.cfg.CacheSize = 8
			r.cfg.CacheTTLSeconds = test.configured
			var seconds atomic.Int64
			start := time.Now()
			r.now = func() time.Time { return start.Add(time.Duration(seconds.Load()) * time.Second) }
			if _, out, err := r.Resolve(context.Background(), resolverWire(t, "negative.example", 1, test.qtype)); err != nil || out.Cached {
				t.Fatal(out, err)
			}
			seconds.Store(int64(test.lifetime - 1))
			wire, out, err := r.Resolve(context.Background(), resolverWire(t, "negative.example", 2, test.qtype))
			if err != nil || !out.Cached || calls.Load() != 1 {
				t.Fatalf("negative answer repeatedly fetched: %+v err=%v calls=%d", out, err, calls.Load())
			}
			var answer mdns.Msg
			if err := answer.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			soa := answer.Ns[0].(*mdns.SOA)
			minimum := test.ttl
			if test.minimum < minimum {
				minimum = test.minimum
			}
			if answer.Rcode != test.code || answer.Id != 2 || soa.Hdr.Ttl != minimum-uint32(test.lifetime-1) {
				t.Fatalf("negative TTL not aged from SOA bound: %s", answer.String())
			}
			seconds.Store(int64(test.lifetime))
			if _, out, err := r.Resolve(context.Background(), resolverWire(t, "negative.example", 3, test.qtype)); err != nil || out.Cached || calls.Load() != 2 {
				t.Fatal("negative answer outlived upstream/cache TTL", out, err, calls.Load())
			}
		})
	}
}

func TestResolverNegativeCacheRequiresRelevantNonzeroSOA(t *testing.T) {
	for _, test := range []struct {
		name         string
		code         int
		ttl, minimum uint32
		zone         string
	}{
		{"missing SOA", mdns.RcodeNameError, 30, 30, ""},
		{"zero minimum", mdns.RcodeSuccess, 30, 0, "example."},
		{"zero SOA TTL", mdns.RcodeNameError, 0, 30, "example."},
		{"unrelated SOA", mdns.RcodeSuccess, 30, 30, "elsewhere."},
		{"SERVFAIL", mdns.RcodeServerFailure, 30, 30, "example."},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			r := NewResolver(cfg, &resolverTestBackend{})
			t.Cleanup(r.Close)
			q := new(mdns.Msg)
			q.SetQuestion("negative.example.", mdns.TypeAAAA)
			answer := cacheNegativeAnswer(q, test.code, test.ttl, test.minimum)
			if test.zone == "" {
				answer.Ns = nil
			} else {
				answer.Ns[0].Header().Name = test.zone
			}
			r.cachePut("key", answer, "nfqws", cfg.DefaultUpstream.Address, 0)
			if r.CacheStatus().Entries != 0 {
				t.Fatal("cached an unbounded or unsupported negative answer")
			}
		})
	}
}

func TestResolverNegativeCNAMECacheUsesTerminalSOAAndChainTTL(t *testing.T) {
	cfg := Default()
	r := NewResolver(cfg, &resolverTestBackend{})
	t.Cleanup(r.Close)
	start := time.Now()
	r.now = func() time.Time { return start }
	q := new(mdns.Msg)
	q.SetQuestion("alias.example.", mdns.TypeHTTPS)
	answer := cacheNegativeAnswer(q, mdns.RcodeSuccess, 50, 2)
	answer.Ns[0].Header().Name = "target.test."
	answer.Answer = []mdns.RR{&mdns.CNAME{Hdr: mdns.RR_Header{Name: "alias.example.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 20}, Target: "missing.target.test."}}
	r.cachePut("key", answer, "nfqws", cfg.DefaultUpstream.Address, 0)
	if r.CacheStatus().Entries != 1 {
		t.Fatal("valid terminal CNAME negative proof not cached")
	}
	start = start.Add(2 * time.Second)
	if r.CacheStatus().Entries != 0 {
		t.Fatal("CNAME-only answer outlived negative SOA minimum")
	}
	answer.Ns[0].(*mdns.SOA).Minttl = 60
	answer.Answer[0].Header().Ttl = 1
	r.cachePut("key", answer, "nfqws", cfg.DefaultUpstream.Address, 0)
	start = start.Add(time.Second)
	if r.CacheStatus().Entries != 0 {
		t.Fatal("negative answer outlived a CNAME record")
	}
}

func TestResolverNegativeCacheDoesNotTreatUnrelatedAnswerAsPositive(t *testing.T) {
	cfg := Default()
	r := NewResolver(cfg, &resolverTestBackend{})
	t.Cleanup(r.Close)
	now := time.Now()
	r.now = func() time.Time { return now }
	q := new(mdns.Msg)
	q.SetQuestion("missing.example.", mdns.TypeA)
	answer := cacheNegativeAnswer(q, mdns.RcodeSuccess, 60, 2)
	unrelated := resolverAnswer(q, 60).Answer[0]
	unrelated.Header().Name = "unrelated.elsewhere."
	answer.Answer = []mdns.RR{unrelated}
	r.cachePut("key", answer, "nfqws", cfg.DefaultUpstream.Address, 0)
	if r.CacheStatus().Entries != 1 {
		t.Fatal("negative proof rejected")
	}
	now = now.Add(2 * time.Second)
	if r.CacheStatus().Entries != 0 {
		t.Fatal("unrelated same-type record bypassed SOA negative lifetime")
	}
}

func TestResolverNegativeCacheIgnoresCNAMEOfDifferentClass(t *testing.T) {
	cfg := Default()
	r := NewResolver(cfg, &resolverTestBackend{})
	t.Cleanup(r.Close)
	q := new(mdns.Msg)
	q.SetQuestion("alias.example.", mdns.TypeAAAA)
	answer := cacheNegativeAnswer(q, mdns.RcodeSuccess, 60, 2)
	answer.Ns[0].Header().Name = "target.test."
	answer.Answer = []mdns.RR{&mdns.CNAME{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassCHAOS, Ttl: 60}, Target: "missing.target.test."}}
	r.cachePut("key", answer, "nfqws", cfg.DefaultUpstream.Address, 0)
	if r.CacheStatus().Entries != 0 {
		t.Fatal("foreign-class CNAME made unrelated SOA proof relevant")
	}
}

func TestResolverCacheSharesQNameCaseButEchoesCurrentQuestion(t *testing.T) {
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { calls.Add(1); return resolverAnswer(q, 60) })
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	for i, name := range []string{"MiXeD.example", "mixed.example", "MIXED.EXAMPLE"} {
		wire, out, err := r.Resolve(context.Background(), resolverWire(t, name, uint16(i+1), mdns.TypeA))
		if err != nil || out.Cached != (i > 0) {
			t.Fatalf("case %q caused cache miss: %+v %v", name, out, err)
		}
		var answer mdns.Msg
		if err := answer.Unpack(wire); err != nil || answer.Id != uint16(i+1) || answer.Question[0].Name != mdns.Fqdn(name) {
			t.Fatal("cache did not echo client ID/question exactly", answer.String(), err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("equivalent names repeated upstream", calls.Load())
	}
}

func TestResolverCacheKeepsDNSSECTypeClassAndEDNSSeparate(t *testing.T) {
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		calls.Add(1)
		response := resolverAnswer(q, 60)
		response.Answer[0].Header().Class = q.Question[0].Qclass
		if q.Question[0].Qtype == mdns.TypeAAAA {
			response.Answer = []mdns.RR{&mdns.AAAA{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeAAAA, Class: q.Question[0].Qclass, Ttl: 60}, AAAA: net.ParseIP("2001:db8::20")}}
		}
		return response
	})
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 32
	variants := []func(*mdns.Msg){func(*mdns.Msg) {}, func(q *mdns.Msg) { q.CheckingDisabled = true }, func(q *mdns.Msg) { q.SetEdns0(1232, true) }, func(q *mdns.Msg) { q.SetEdns0(1232, false) }, func(q *mdns.Msg) { q.Question[0].Qtype = mdns.TypeAAAA }, func(q *mdns.Msg) { q.Question[0].Qclass = mdns.ClassCHAOS }, func(q *mdns.Msg) {
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = []mdns.EDNS0{&mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: "0102030405060708"}}
	}}
	for i, change := range variants {
		q := new(mdns.Msg)
		q.SetQuestion("same.example.", mdns.TypeA)
		q.Id = uint16(i + 1)
		change(q)
		wire, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, out, err := r.Resolve(context.Background(), wire); err != nil || out.Cached {
			t.Fatal("semantically different query shared cache", i, out, err)
		}
		if _, out, err := r.Resolve(context.Background(), wire); err != nil || !out.Cached {
			t.Fatal("exact repeat was not cached", i, out, err)
		}
	}
	if calls.Load() != int32(len(variants)) {
		t.Fatal(fmt.Sprintf("queries mixed or repeatedly fetched: %d", calls.Load()))
	}
}
