package dnsserver

import "testing"

func TestSchedulerGeneralViewDoesNotSelectAnExampleDomainRule(t *testing.T) {
	s, _, _ := newDNSServiceFixture(t, 8)
	cfg := s.Config()
	cfg.DefaultPool = []Upstream{{Address: "https://general.example/dns-query"}}
	cfg.Rules = []Rule{{ID: "example", Enabled: true, Domain: "example.com", IncludeSubdomains: true, Upstream: Upstream{Address: "https://special.example/dns-query"}}}
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"", " \t "} {
		view, err := s.SchedulerSnapshot(domain)
		if err != nil || view.Domain != "" || view.PoolSource != "default" || len(view.Candidates) != 6 {
			t.Fatalf("general view chose a domain pool: %+v %v", view, err)
		}
		for _, candidate := range view.Candidates {
			if candidate.Upstream == cfg.Rules[0].Upstream.Address {
				t.Fatal("domain-only provider leaked into default view")
			}
		}
	}
	domain, err := s.SchedulerSnapshot("API.EXAMPLE.COM.")
	if err != nil || domain.Domain != "api.example.com" || domain.PoolSource != "example.com" || len(domain.Candidates) != 3 {
		t.Fatalf("explicit domain did not select its rule: %+v %v", domain, err)
	}
	for _, candidate := range domain.Candidates {
		if candidate.Upstream != cfg.Rules[0].Upstream.Address {
			t.Fatal("general provider leaked into domain view")
		}
	}
	if s.scheduler.races != 0 {
		t.Fatal("viewing queues advanced the scheduler")
	}
	if _, err := s.SchedulerSnapshot("not a domain"); err == nil {
		t.Fatal("invalid nonempty domain accepted")
	}
}
