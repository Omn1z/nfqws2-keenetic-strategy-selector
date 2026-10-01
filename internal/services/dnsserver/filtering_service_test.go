package dnsserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

func newFilteringServiceFixture(t *testing.T, rules []BlockingRule) (*Service, *resolverTestBackend, *mdns.Client) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Enabled = false
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = protocolTestPort(t)
	cfg.Rules = nil
	cfg.FastDNS = false
	cfg.TimeoutSeconds = 1
	cfg.Filtering = &FilteringConfig{Enabled: true, Lists: []string{}, CustomRules: rules, Allowlist: []string{}}
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}}
	backend.dialHook = func(context.Context, string, string, string) (net.Conn, error) {
		return nil, errors.New("test upstream unavailable")
	}
	s := New(st, backend, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); !status.Running || !status.Filtering.Enabled {
		t.Fatalf("filtering service did not start: %+v", status)
	}
	return s, backend, &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
}

func TestFilteringServiceCountsAndLogsEachBlockedQueryWithoutNetwork(t *testing.T) {
	s, backend, client := newFilteringServiceFixture(t, []BlockingRule{
		{Domain: "ad.example", Category: BlockCategoryAds},
		{Domain: "tracker.example", Category: BlockCategoryTrackers},
		{Domain: "mixed.example", Category: BlockCategoryMixed},
	})
	observed := 0
	backend.observe = func(_ context.Context, _ string, wire []byte, _ net.IP) ([]byte, error) {
		observed++
		return wire, nil
	}
	for i, domain := range []string{"ad.example", "ad.example", "tracker.example", "mixed.example"} {
		query := new(mdns.Msg)
		query.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
		query.Id = uint16(i + 1)
		answer, _, err := client.Exchange(query, s.Status().Endpoints.DNS)
		if err != nil || answer.Rcode != mdns.RcodeNameError || len(answer.Answer) != 0 {
			t.Fatalf("blocked DNS query %q returned %+v, %v", domain, answer, err)
		}
	}
	status := s.Status()
	if status.Stats.Queries != 4 || status.Stats.BlockedTotal != 4 || status.Stats.BlockedAds != 2 || status.Stats.BlockedTrackers != 1 || status.Stats.BlockedMixed != 1 || status.Stats.CacheHits != 0 || status.Stats.Failures != 0 || status.Stats.NFQWSSuccess != 0 || status.Stats.AWGSuccess != 0 {
		t.Fatalf("blocked statistics = %+v", status.Stats)
	}
	if status.Stats.LastRoute != "blocked" || status.Stats.LastUpstream != "" {
		t.Fatalf("blocked query recorded an upstream: %+v", status.Stats)
	}
	if observed != 0 || len(backend.dialCalls()) != 0 {
		t.Fatalf("blocked queries used backend: observed=%d dials=%v", observed, backend.dialCalls())
	}
	wantCategories := []string{BlockCategoryAds, BlockCategoryAds, BlockCategoryTrackers, BlockCategoryMixed}
	var blocked []LogEntry
	for _, entry := range s.Logs(0).Entries {
		if entry.Event == "blocked" {
			blocked = append(blocked, entry)
		}
	}
	if len(blocked) != len(wantCategories) {
		t.Fatalf("blocked log entries = %+v", blocked)
	}
	for i, entry := range blocked {
		if entry.BlockCategory != wantCategories[i] || entry.BlockRule == "" || entry.BlockSource != "custom" || entry.Route != "blocked" || entry.Upstream != "" {
			t.Errorf("blocked log entry %d = %+v", i, entry)
		}
	}
	testResult := s.Test(context.Background(), "ad.example", "AAAA")
	if !testResult.OK || !testResult.Blocked || testResult.BlockCategory != BlockCategoryAds || testResult.BlockRule != "ad.example" || testResult.BlockSource != "custom" || testResult.Route != "blocked" || testResult.Upstream != "" || len(testResult.Answers) != 0 {
		t.Fatalf("DNS test result lost blocking metadata: %+v", testResult)
	}
	if s.Status().Stats.BlockedTotal != 5 || observed != 0 || len(backend.dialCalls()) != 0 {
		t.Fatalf("DNS test bypassed blocker: stats=%+v observed=%d dials=%v", s.Status().Stats, observed, backend.dialCalls())
	}
}

func TestFilteringServiceAllowlistAndDisableApplyImmediately(t *testing.T) {
	s, backend, client := newFilteringServiceFixture(t, []BlockingRule{{Domain: "ad.example", Category: BlockCategoryAds}})
	queryAd := func(id uint16) int {
		q := new(mdns.Msg)
		q.SetQuestion("ad.example.", mdns.TypeA)
		q.Id = id
		answer, _, err := client.Exchange(q, s.Status().Endpoints.DNS)
		if err != nil {
			t.Fatal(err)
		}
		return answer.Rcode
	}
	if got := queryAd(10); got != mdns.RcodeNameError {
		t.Fatalf("initial blocked response = %s", mdns.RcodeToString[got])
	}
	cfg := s.Config()
	cfg.Filtering.Allowlist = []string{"*.ad.example"}
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := queryAd(11); got != mdns.RcodeServerFailure {
		t.Fatalf("allowlisted response remained blocked: %s", mdns.RcodeToString[got])
	}
	if calls := backend.dialCalls(); len(calls) == 0 {
		t.Fatal("allowlisted query did not reach configured upstream")
	}
	cfg = s.Config()
	cfg.Filtering.Allowlist = []string{}
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := queryAd(12); got != mdns.RcodeNameError {
		t.Fatalf("removed allowlist did not restore blocking: %s", mdns.RcodeToString[got])
	}
	backend.setFailures()
	cfg = s.Config()
	cfg.Filtering.Enabled = false
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := queryAd(13); got != mdns.RcodeServerFailure {
		t.Fatalf("disabled filter still blocked: %s", mdns.RcodeToString[got])
	}
	if s.Status().Filtering.Enabled || len(backend.dialCalls()) == 0 {
		t.Fatalf("disabled filter did not restore resolver path: %+v", s.Status().Filtering)
	}
}

func TestFilteringServiceMigratesOldConfigDisabledAndReturnsClone(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Enabled = false
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = protocolTestPort(t)
	cfg.FastDNS = false
	wire, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err := json.Unmarshal(wire, &old); err != nil {
		t.Fatal(err)
	}
	delete(old, "filtering")
	if err := st.Save(configFile, old); err != nil {
		t.Fatal(err)
	}
	backend := &resolverTestBackend{}
	s := New(st, backend, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	status := s.Status()
	if status.Config.Filtering == nil || status.Config.Filtering.Enabled || status.Filtering.Enabled {
		t.Fatalf("old config unexpectedly enabled blocking: %+v", status)
	}
	returned := s.Config()
	if !reflect.DeepEqual(returned.Filtering, status.Config.Filtering) {
		t.Fatalf("Config and Status disagree: %+v vs %+v", returned.Filtering, status.Config.Filtering)
	}
	returned.Filtering.Lists[0] = "hagezi-light"
	returned.Filtering.CustomRules[0].Domain = "changed.example"
	if actual := s.Config().Filtering; actual.Lists[0] == "hagezi-light" || actual.CustomRules[0].Domain == "changed.example" {
		t.Fatalf("service returned mutable config internals: %+v", actual)
	}
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	q := new(mdns.Msg)
	q.SetQuestion("report.appmetrica.yandex.net.", mdns.TypeA) // bundled example, but disabled
	answer, _, err := (&mdns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(q, s.Status().Endpoints.DNS)
	if err != nil || answer.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("legacy DNS blocked unexpectedly: %+v, %v", answer, err)
	}
	if s.Status().Stats.BlockedTotal != 0 || strings.Contains(s.Status().Stats.LastRoute, "blocked") {
		t.Fatalf("legacy DNS generated block statistics: %+v", s.Status().Stats)
	}
}
