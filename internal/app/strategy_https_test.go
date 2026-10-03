package app

import (
	"context"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/strategy/core/catalog"
)

const (
	regressionHTTPArgs = "--filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=multisplit:pos=method+2,host+1"
	regressionTLSArgs  = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=tls_clienthello --lua-desync=multisplit:pos=1,midsld"
)

func TestHTTPSStrategyApplicability(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		ok   bool
	}{
		{"live HTTP winner", regressionHTTPArgs, false},
		{"TLS candidate", regressionTLSArgs, true},
		{"legacy unfiltered", "--lua-desync=multisplit:pos=1,midsld", true},
		{"legacy dpi desync", "--dpi-desync=fake,split2", true},
		{"HTTP on 443", "--filter-tcp=443 --filter-l7=http --lua-desync=fake", false},
		{"QUIC", "--filter-udp=443 --filter-l7=quic --lua-desync=fake", false},
		{"UDP with TLS label in args", "--filter-udp=443 --filter-l7=tls --lua-desync=fake", false},
		{"mixed transport", "--filter-udp=443 --filter-tcp=443 --lua-desync=fake", true},
		{"port list", "--filter-tcp=80,443 --filter-l7=http,tls --lua-desync=fake", true},
		{"port range", "--filter-tcp=400-450 --lua-desync=fake", true},
		{"port range excludes 443", "--filter-tcp=444-450 --lua-desync=fake", false},
		{"wildcard port", "--filter-tcp=* --lua-desync=fake", true},
		{"negated port excludes HTTP", "--filter-tcp=~80 --lua-desync=fake", true},
		{"negated range excludes TLS", "--filter-tcp=~400-450 --lua-desync=fake", false},
		{"filter entries are OR", "--filter-tcp=~80,443 --lua-desync=fake", true},
		{"repeated ports are OR", "--filter-tcp=80 --filter-tcp=443 --lua-desync=fake", true},
		{"repeated l7 replaces TLS", "--filter-l7=tls --filter-l7=http --lua-desync=fake", false},
		{"repeated l7 restores TLS", "--filter-l7=http --filter-l7=tls --lua-desync=fake", true},
		{"known protocols", "--filter-l7=known --payload=known --lua-desync=fake", true},
		{"all protocols", "--filter-l7=all --payload=all --lua-desync=fake", true},
		{"IPv6 only", "--filter-l3=ipv6 --lua-desync=fake", false},
		{"dual stack", "--filter-l3=ipv6,ipv4 --lua-desync=fake", true},
		{"repeated L3 is OR", "--filter-l3=ipv6 --filter-l3=ipv4 --lua-desync=fake", true},
		{"HTTP payload without port", "--payload=http_req --lua-desync=fake", false},
		{"HTTP instance payload", "--lua-desync=fake:payload=http_req", false},
		{"negated instance payload list", "--filter-tcp=443 --filter-l7=tls --lua-desync=fake:payload=~http_req,tls_client_hello", false},
		{"negated instance payload with known", "--lua-desync=fake:payload=~tls_client_hello,known", false},
		{"negated outer payload list", "--payload=~http_req,tls_client_hello --lua-desync=fake", false},
		{"TLS plus later HTTP", "--payload=tls_client_hello --lua-desync=fake --payload=http_req --lua-desync=multisplit:pos=method+2", true},
		{"HTTP plus later unused TLS selector", "--payload=http_req --lua-desync=fake --payload=tls_client_hello", false},
		{"inner selector cannot broaden outer", "--payload=http_req --lua-desync=fake:payload=tls_client_hello", false},
		{"HTTP method without filters", "--lua-desync=http_methodeol", false},
		{"no operation", "--filter-tcp=443 --filter-l7=tls", false},
		{"skip", regressionTLSArgs + " --skip", false},
		{"template", regressionTLSArgs + " --template=example", false},
		{"import", regressionTLSArgs + " --import=example", false},
		{"second profile", regressionTLSArgs + " --new " + regressionHTTPArgs, false},
		{"malformed port", "--filter-tcp=443,garbage --lua-desync=fake", false},
		{"iptables range is not nfqws syntax", "--filter-tcp=400:450 --lua-desync=fake", false},
		{"out of range", "--filter-tcp=65536 --lua-desync=fake", false},
		{"inverted range", "--filter-tcp=450-400 --lua-desync=fake", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateHTTPSStrategy(tc.args); (err == nil) != tc.ok {
				t.Fatalf("applicability = %v, want accepted=%v", err, tc.ok)
			}
		})
	}
}

func TestHTTPSRunExcludesHTTPFalseSuccess(t *testing.T) {
	candidates := catalog.AutoCandidates()
	selected := httpsRunStrategies(candidates)
	wantTLS, httpCount := 0, 0
	for _, candidate := range candidates {
		if candidate.L7 == "tls" {
			wantTLS++
		} else if candidate.L7 == "http" {
			httpCount++
		}
	}
	if wantTLS == 0 || httpCount == 0 || len(selected) != wantTLS {
		t.Fatalf("catalog/selection: TLS=%d HTTP=%d selected=%d", wantTLS, httpCount, len(selected))
	}
	for _, candidate := range selected {
		if candidate.L7 != "tls" {
			t.Fatalf("incompatible candidate selected: %+v", candidate)
		}
	}
	// Labels are informational. A mislabeled HTTP profile must never reach the
	// engine/prober, even when the worker is called without the planning filter.
	job := runJob{strat: catalog.Strategy{ID: "old-winner", L7: "tls", ArgLine: regressionHTTPArgs}}
	result := (&App{}).testStrategy(context.Background(), nil, nil, job, []string{"youtube.com"}, nil)
	if result.Success || result.Error == "" || len(result.PerTarget) != 0 {
		t.Fatalf("HTTP-only profile was evaluated as HTTPS: %+v", result)
	}
}

func TestHTTPSRunRejectsHTTPOnlySelectionBeforeStarting(t *testing.T) {
	a := &App{custom: []catalog.Strategy{{ID: "custom-http", ArgLine: regressionHTTPArgs}}}
	run, err := a.StartRun(RunRequest{Targets: []string{"youtube.com"}, StrategyIDs: []string{"custom-http"}})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") || run != nil || a.active != nil {
		t.Fatalf("HTTP-only selection started a run: run=%+v active=%+v err=%v", run, a.active, err)
	}
}
