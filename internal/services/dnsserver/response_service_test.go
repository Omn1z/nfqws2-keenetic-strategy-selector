package dnsserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

func cacheResponseServiceAnswer(t *testing.T, s *Service, domain string, qtype uint16, answers ...string) *mdns.Msg {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(domain), qtype)
	query.Id = 0
	key, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	response := new(mdns.Msg)
	response.SetReply(query)
	response.AuthenticatedData = true
	for _, answer := range answers {
		response.Answer = append(response.Answer, responseFilterRR(t, answer))
	}
	run := activeDNSRun(s)
	if run == nil {
		t.Fatal("service is not running")
	}
	run.resolver.mu.Lock()
	generation := run.resolver.cacheGeneration
	run.resolver.mu.Unlock()
	run.resolver.cachePut(string(key), response, "nfqws", run.resolver.cfg.DefaultUpstream.Address, generation)
	if run.resolver.CacheStatus().Entries == 0 {
		t.Fatal("could not prime a positive cache entry")
	}
	return query
}

func TestServiceCountsAndLogsCachedResponseBlocks(t *testing.T) {
	for _, tc := range []struct {
		name        string
		list        string
		custom      []BlockingRule
		answers     []string
		blockDomain string
		blockRule   string
		blockSource string
		category    string
	}{
		{
			name:        "CNAME ad",
			custom:      []BlockingRule{{Domain: "track.example", Category: BlockCategoryAds}},
			answers:     []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
			blockDomain: "track.example", blockRule: "track.example", blockSource: "custom", category: BlockCategoryAds,
		},
		{
			name:        "CNAME tracker",
			custom:      []BlockingRule{{Domain: "track.example", Category: BlockCategoryTrackers}},
			answers:     []string{"alias.example. 60 IN CNAME track.example.", "track.example. 60 IN A 203.0.113.20"},
			blockDomain: "track.example", blockRule: "track.example", blockSource: "custom", category: BlockCategoryTrackers,
		},
		{
			name:        "official IPv4 rule",
			list:        "||194.63.143.96^",
			answers:     []string{"alias.example. 60 IN A 194.63.143.96"},
			blockDomain: "194.63.143.96", blockRule: "||194.63.143.96^", blockSource: "adguard-dns", category: BlockCategoryMixed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, backend, client := newFilteringServiceFixture(t, tc.custom)
			if tc.list != "" {
				blocker, err := NewBlockMatcher([]BlockSource{{ID: "adguard-dns", Category: tc.category, Data: []byte(tc.list)}}, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				activeDNSRun(s).resolver.SetBlocker(blocker)
			}
			var observed atomic.Int64
			backend.mu.Lock()
			backend.observe = func(_ context.Context, _ string, wire []byte, _ net.IP) ([]byte, error) {
				observed.Add(1)
				return wire, nil
			}
			backend.mu.Unlock()
			query := cacheResponseServiceAnswer(t, s, "alias.example", mdns.TypeA, tc.answers...)
			logStart := s.Logs(0).LastID
			for i := 1; i <= 2; i++ {
				query.Id = uint16(i)
				response, _, err := client.Exchange(query, s.Status().Endpoints.DNS)
				if err != nil || response.Rcode != mdns.RcodeNameError || response.AuthenticatedData || len(response.Answer) != 0 {
					t.Fatalf("cached response was not blocked: %v, %v", response, err)
				}
				stats := s.Status().Stats
				if stats.Queries != uint64(i) || stats.BlockedTotal != uint64(i) || stats.CacheHits != 0 || stats.Failures != 0 || stats.NFQWSSuccess != 0 || stats.AWGSuccess != 0 {
					t.Fatalf("cached response counted more than once or as an upstream/cache success: %+v", stats)
				}
				ads, trackers, mixed := uint64(0), uint64(0), uint64(0)
				switch tc.category {
				case BlockCategoryAds:
					ads = uint64(i)
				case BlockCategoryTrackers:
					trackers = uint64(i)
				default:
					mixed = uint64(i)
				}
				if stats.BlockedAds != ads || stats.BlockedTrackers != trackers || stats.BlockedMixed != mixed {
					t.Fatalf("wrong category counters: %+v", stats)
				}
			}
			if observed.Load() != 0 || len(backend.dialCalls()) != 0 {
				t.Fatalf("response policy answer reached backend route observation: observed=%d, dials=%v", observed.Load(), backend.dialCalls())
			}
			logs := s.Logs(logStart).Entries
			if len(logs) != 2 {
				t.Fatalf("want exactly one blocked entry per query, got %+v", logs)
			}
			for _, entry := range logs {
				if entry.Event != "blocked" || entry.Domain != "alias.example" || entry.BlockDomain != tc.blockDomain || entry.BlockCategory != tc.category || entry.BlockRule != tc.blockRule || entry.BlockSource != tc.blockSource || entry.Route != "blocked" || entry.QType != "A" {
					t.Fatalf("cached block was logged as a cache hit or lost its metadata: %+v", entry)
				}
			}
		})
	}
}

func TestServiceResponseDiagnosticsSupportAliasAndServiceTypes(t *testing.T) {
	s, backend, _ := newFilteringServiceFixture(t, []BlockingRule{{Domain: "track.example", Category: BlockCategoryTrackers}})
	blocker, err := NewBlockMatcher([]BlockSource{{ID: "adguard-dns", Category: BlockCategoryMixed, Data: []byte("||194.63.143.96^")}}, []BlockingRule{{Domain: "track.example", Category: BlockCategoryTrackers}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	activeDNSRun(s).resolver.SetBlocker(blocker)
	var observed atomic.Int64
	backend.mu.Lock()
	backend.observe = func(_ context.Context, _ string, wire []byte, _ net.IP) ([]byte, error) {
		observed.Add(1)
		return wire, nil
	}
	backend.mu.Unlock()
	for _, tc := range []struct {
		kind        string
		qtype       uint16
		answer      string
		blockDomain string
	}{
		{kind: "CNAME", qtype: mdns.TypeCNAME, answer: "alias.example. 60 IN CNAME track.example.", blockDomain: "track.example"},
		{kind: "HTTPS", qtype: mdns.TypeHTTPS, answer: "alias.example. 60 IN HTTPS 1 . alpn=h2 ipv4hint=194.63.143.96", blockDomain: "194.63.143.96"},
		{kind: "SVCB", qtype: mdns.TypeSVCB, answer: "alias.example. 60 IN SVCB 1 . alpn=h2 ipv4hint=194.63.143.96", blockDomain: "194.63.143.96"},
	} {
		cacheResponseServiceAnswer(t, s, "alias.example", tc.qtype, tc.answer)
		result := s.Test(context.Background(), "alias.example", tc.kind)
		if !result.OK || !result.Blocked || result.Type != tc.kind || result.Domain != "alias.example" || result.BlockDomain != tc.blockDomain || result.BlockRule == "" || result.BlockSource == "" || result.Route != "blocked" || len(result.Answers) != 0 || result.Error != "" {
			t.Fatalf("diagnostic lost response block or rejected supported type %s: %+v", tc.kind, result)
		}
	}
	before := s.Status().Stats
	for _, kind := range []string{"TXT", "DNSKEY", "NOT-A-TYPE"} {
		result := s.Test(context.Background(), "alias.example", kind)
		if result.OK || result.Blocked || result.Error == "" {
			t.Fatalf("unsupported diagnostic type %q was accepted: %+v", kind, result)
		}
	}
	if stats := s.Status().Stats; stats != before || stats.Queries != 3 || stats.BlockedTotal != 3 || stats.BlockedTrackers != 1 || stats.BlockedMixed != 2 {
		t.Fatalf("diagnostics were counted incorrectly: %+v, before=%+v", stats, before)
	}
	if observed.Load() != 0 || len(backend.dialCalls()) != 0 {
		t.Fatalf("blocked/invalid diagnostics reached route observation: observed=%d dials=%v", observed.Load(), backend.dialCalls())
	}
}

func TestServiceResponseDiagnosticsReturnAllowedServiceAnswers(t *testing.T) {
	s, backend, _ := newFilteringServiceFixture(t, nil)
	var observed atomic.Int64
	backend.mu.Lock()
	backend.observe = func(_ context.Context, _ string, wire []byte, _ net.IP) ([]byte, error) {
		observed.Add(1)
		return wire, nil
	}
	backend.mu.Unlock()
	for _, tc := range []struct {
		kind   string
		qtype  uint16
		answer string
	}{
		{kind: "CNAME", qtype: mdns.TypeCNAME, answer: "alias.example. 60 IN CNAME permitted.example."},
		{kind: "HTTPS", qtype: mdns.TypeHTTPS, answer: "alias.example. 60 IN HTTPS 1 . alpn=h2 ipv4hint=203.0.113.20"},
		{kind: "SVCB", qtype: mdns.TypeSVCB, answer: "alias.example. 60 IN SVCB 1 . alpn=h2 ipv4hint=203.0.113.20"},
	} {
		cacheResponseServiceAnswer(t, s, "alias.example", tc.qtype, tc.answer)
		result := s.Test(context.Background(), "alias.example", tc.kind)
		if !result.OK || result.Blocked || result.Type != tc.kind || result.BlockDomain != "" || len(result.Answers) != 1 || result.Answers[0] != responseFilterRR(t, tc.answer).String() {
			t.Fatalf("supported diagnostic did not return %s answer: %+v", tc.kind, result)
		}
	}
	if stats := s.Status().Stats; stats.Queries != 3 || stats.CacheHits != 3 || stats.BlockedTotal != 0 || stats.Failures != 0 || observed.Load() != 3 {
		t.Fatalf("allowed diagnostics did not use normal answer observation: stats=%+v observed=%d", stats, observed.Load())
	}
}
