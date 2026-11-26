package awgroute

import (
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestRenderWARPAmneziaConfImportsAsAWGWithoutSSH(t *testing.T) {
	conf := renderWARPAmneziaConf(
		"kBAoKn010lyD1EfH/HTuCwLjpcweg7v70BzZ4ynfb1s=",
		"172.16.0.2/32",
		"RB78swIIfUFo/YfDnFJk32oggQFd8c5uJXodSj86xxs=",
		"162.159.192.1:4500",
	)
	cfg, err := awg.ImportClientConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Install != "imported" || cfg.Protocol != "awg" {
		t.Fatalf("flags install=%q protocol=%q", cfg.Install, cfg.Protocol)
	}
	if cfg.Endpoint != "162.159.192.1:4500" {
		t.Fatalf("endpoint=%q", cfg.Endpoint)
	}
	if cfg.Conn.Host != "" || cfg.Conn.Port != 0 || cfg.Conn.User != "" {
		t.Fatalf("imported WARP must not keep SSH credentials: %+v", cfg.Conn)
	}
	if cfg.Obf.Jc != 4 || cfg.Obf.Jmin != 40 || cfg.Obf.Jmax != 70 || cfg.Obf.H4 != "4" || cfg.Obf.I1 == "" || cfg.Obf.I2 == "" {
		t.Fatalf("obfuscation not imported: %+v", cfg.Obf)
	}
	out, err := awg.RenderUAPISet(cfg, cfg.Peers[0], "162.159.192.1", 4500)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"jc=4", "jmin=40", "jmax=70", "h1=1", "h4=4", "i1=", "i2="} {
		if !strings.Contains(out, want) {
			t.Fatalf("UAPI missing %q:\n%s", want, out)
		}
	}
}

func TestNormalizeWARPEndpoint(t *testing.T) {
	if got := normalizeWARPEndpoint("162.159.192.1"); got != "162.159.192.1:2408" {
		t.Fatalf("default port endpoint=%q", got)
	}
	if got := normalizeWARPEndpoint("bad:port"); got != "" {
		t.Fatalf("invalid endpoint=%q", got)
	}
}

func TestWARPEndpointCandidatesIncludeKnownIngressPools(t *testing.T) {
	got := warpEndpointCandidates("188.114.97.1:8886")
	have := map[string]bool{}
	for _, ep := range got {
		have[ep] = true
	}
	for _, want := range []string{
		"188.114.97.1:8886",
		"162.159.193.1:2408",
		"162.159.192.1:2408",
		"162.159.195.1:500",
		"188.114.96.1:2408",
	} {
		if !have[want] {
			t.Fatalf("candidate %q missing from %v", want, got[:min(len(got), 12)])
		}
	}
}

func TestPrioritizeWARPEndpointsUsesThroughputSeedsBeforeRanked(t *testing.T) {
	got := prioritizeWARPEndpoints(
		warpDefaultEP,
		[]string{"188.114.97.100:2408"},
		[]string{"162.159.192.64:2408", "188.114.97.100:2408"},
	)
	if len(got) == 0 || got[0] != "188.114.97.100:2408" {
		t.Fatalf("first endpoint = %q, want throughput-proven seed; all=%v", got[:min(len(got), 4)], got)
	}
	seen := map[string]bool{}
	for _, ep := range got {
		if seen[ep] {
			t.Fatalf("duplicate endpoint %q in %v", ep, got)
		}
		seen[ep] = true
	}
}

func TestPrioritizeWARPEndpointsKeepsManualNonDefaultPortFirst(t *testing.T) {
	got := prioritizeWARPEndpoints(
		"188.114.96.250:8886",
		[]string{"188.114.97.100:2408"},
		[]string{"162.159.193.100:2408", "188.114.96.250:8886"},
	)
	if len(got) == 0 || got[0] != "188.114.96.250:8886" {
		t.Fatalf("endpoint order = %v", got[:min(len(got), 4)])
	}
}
