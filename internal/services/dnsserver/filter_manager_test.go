package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

func filterFixture(t *testing.T) (*FilterManager, *Resolver) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &FilteringConfig{Enabled: true, Lists: []string{"adguard-dns"}}
	m, err := NewFilterManager(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(Default(), &resolverTestBackend{})
	t.Cleanup(r.Close)
	return m, r
}

func filterData(prefix string, count int) []byte {
	var data strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&data, "||%s%d.example^\n", prefix, i)
	}
	return []byte(data.String())
}

func TestFilteringAtomicCacheAndRestart(t *testing.T) {
	m, r := filterFixture(t)
	data := filterData("ads", 2500)
	if err := m.install(m.revision, m.cfg, "adguard-dns", data, r); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Blocker().Match("ads0.example"); !ok {
		t.Fatal("installed rule inactive")
	}
	before := m.Blocker()
	for _, invalid := range [][]byte{[]byte("<html>error</html>"), filterData("short", 1000)} {
		if err := m.install(m.revision, m.cfg, "adguard-dns", invalid, r); err == nil {
			t.Fatal("invalid/truncated download accepted")
		}
		if m.Blocker() != before {
			t.Fatal("failed update replaced active matcher")
		}
		cached, err := m.readCache("adguard-dns")
		if err != nil || string(cached) != string(data) {
			t.Fatalf("failed update damaged cache: %v", err)
		}
	}
	restarted, err := NewFilterManager(m.store, &m.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Status().Ready || restarted.due() {
		t.Fatalf("fresh persisted cache not restored: %+v", restarted.Status())
	}
	if _, ok := restarted.Blocker().Match("ads0.example"); !ok {
		t.Fatal("restart lost cached rule")
	}
}

func TestFilteringMissingOrTruncatedCacheIsDue(t *testing.T) {
	for _, damaged := range []string{"missing", "truncated"} {
		t.Run(damaged, func(t *testing.T) {
			m, r := filterFixture(t)
			if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("ads", 2500), r); err != nil {
				t.Fatal(err)
			}
			if damaged == "missing" {
				if err := m.store.Delete("dns-blocklists/adguard-dns.txt"); err != nil {
					t.Fatal(err)
				}
			} else if err := m.store.WriteBytes("dns-blocklists/adguard-dns.txt", filterData("prefix", 1)); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewFilterManager(m.store, &m.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !restarted.due() || restarted.Status().Ready {
				t.Fatalf("damaged cache not due: %+v", restarted.Status())
			}
		})
	}
}

func TestFilteringConfigSaveFailureAndStaleInstall(t *testing.T) {
	m, r := filterFixture(t)
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("ads", 1000), r); err != nil {
		t.Fatal(err)
	}
	before, revision := m.Blocker(), m.revision
	if err := m.ConfigurePersist(&m.cfg, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if m.Blocker() != before {
		t.Fatal("unchanged settings recompiled the filter")
	}
	revision = m.revision
	cfg := copyFilteringConfig(&m.cfg)
	cfg.Allowlist = []string{"ads0.example"}
	if err := m.ConfigurePersist(&cfg, func() error { return errors.New("disk unavailable") }); err == nil {
		t.Fatal("save failure hidden")
	}
	if m.Blocker() != before || m.revision != revision {
		t.Fatal("failed save changed live configuration")
	}
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Blocker().Match("ads0.example"); ok {
		t.Fatal("allowlist ignored")
	}
	if err := m.install(revision, cfg, "adguard-dns", filterData("obsolete", 1000), r); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale result accepted: %v", err)
	}
	cache, _ := m.readCache("adguard-dns")
	if strings.Contains(string(cache), "obsolete") {
		t.Fatal("stale download overwrote cache")
	}
	cfg.Enabled = false
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if m.Blocker() != nil || m.Status().Rules != 0 || m.Status().Ready {
		t.Fatal("disabled filtering retained compiled feeds")
	}
}

func TestFilteringStoppedResolverCannotPublishAndRestartLoadsLatest(t *testing.T) {
	m, r := filterFixture(t)
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("ads", 1000), r); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("stale", 1000), r); !errors.Is(err, context.Canceled) {
		t.Fatalf("stopped resolver published: %v", err)
	}
	replacement := NewResolver(Default(), &resolverTestBackend{})
	defer replacement.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx, replacement)
	if replacement.blocker.Load() != m.Blocker() {
		t.Fatal("restarted resolver did not attach current snapshot")
	}
	if _, ok := replacement.blocker.Load().Match("ads0.example"); !ok {
		t.Fatal("restart lost list")
	}
}

func TestFilteringMetadataFailureStillPublishesValidMatcher(t *testing.T) {
	m, r := filterFixture(t)
	if err := os.MkdirAll(m.store.Path(filterMetadataFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("ads", 1000), r); err == nil {
		t.Fatal("metadata write failure hidden")
	}
	if r.blocker.Load() != m.Blocker() {
		t.Fatal("metadata failure split live resolver and manager")
	}
	if _, ok := m.Blocker().Match("ads0.example"); !ok {
		t.Fatal("valid cached list was lost")
	}
}

func TestFilteringTwoDamagedCachesCanBeRepairedIndependently(t *testing.T) {
	m, r := filterFixture(t)
	cfg := copyFilteringConfig(&m.cfg)
	cfg.Lists = []string{"adguard-dns", "hagezi-light"}
	for _, id := range cfg.Lists {
		if err := m.store.WriteBytes("dns-blocklists/"+id+".txt", make([]byte, maxFilteringSourceBytes+1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.install(m.revision, cfg, "adguard-dns", filterData("ads", 1000), r); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Blocker().Match("ads0.example"); !ok {
		t.Fatal("other corrupt cache prevented repairing AdGuard")
	}
	if err := m.install(m.revision, cfg, "hagezi-light", filterData("tracker", 1000), r); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Ready {
		t.Fatalf("not ready after both repairs: %+v", m.Status())
	}
}

func TestFilteringUpdateCancelsOnConfigurationChange(t *testing.T) {
	m, _ := filterFixture(t)
	dialing := make(chan struct{}, 16)
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "awg:test", Available: true}}}
	backend.dialHook = func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		select {
		case dialing <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := NewResolver(Default(), backend)
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !m.Trigger(ctx, r) || m.Trigger(ctx, r) {
		t.Fatal("update did not deduplicate")
	}
	select {
	case <-dialing:
	case <-time.After(time.Second):
		t.Fatal("update never started")
	}
	cfg := copyFilteringConfig(&m.cfg)
	cfg.Lists = []string{"hagezi-light"}
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if !m.Trigger(ctx, r) {
		t.Fatal("cancelled old update blocked new configuration")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if m.Status().Updating {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !m.Status().Updating {
		t.Fatal("old completion cleared new update status")
	}
	cancel()
	for m.Status().Updating && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Status().Updating {
		t.Fatal("update did not finish after lifetime cancellation")
	}
}

func TestFilteringSyntaxDamagedCacheDoesNotPreventOtherFeedRepair(t *testing.T) {
	m, r := filterFixture(t)
	cfg := copyFilteringConfig(&m.cfg)
	cfg.Lists = []string{"adguard-dns", "hagezi-light"}
	if err := m.store.WriteBytes("dns-blocklists/hagezi-light.txt", []byte(strings.Repeat("x", (1<<20)+1))); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.install(m.revision, cfg, "adguard-dns", filterData("ads", 1000), r); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Blocker().Match("ads0.example"); !ok {
		t.Fatal("syntax error in another cache blocked recovery")
	}
}
