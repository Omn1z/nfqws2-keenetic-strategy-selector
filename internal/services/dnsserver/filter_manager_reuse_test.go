package dnsserver

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestFilteringUnchangedRefreshReusesEngineAndUpdatesMetadata(t *testing.T) {
	m, r := filterFixture(t)
	data := filterData("ads", 1000)
	if err := m.install(m.revision, m.cfg, "adguard-dns", data, r); err != nil {
		t.Fatal(err)
	}
	before := m.Blocker()
	engine := before.snapshot.Load().adguard
	oldUpdated := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	m.mu.Lock()
	meta := m.metadata["adguard-dns"]
	meta.LastUpdated, meta.LastError = oldUpdated, "old refresh failure"
	m.metadata["adguard-dns"] = meta
	m.mu.Unlock()
	if err := m.install(m.revision, m.cfg, "adguard-dns", append([]byte(nil), data...), r); err != nil {
		t.Fatal(err)
	}
	if m.Blocker().snapshot.Load().adguard != engine {
		t.Fatal("unchanged refresh recompiled the downloaded engine")
	}
	if r.blocker.Load() != m.Blocker() {
		t.Fatal("unchanged refresh did not publish the current matcher")
	}
	m.mu.Lock()
	meta = m.metadata["adguard-dns"]
	m.mu.Unlock()
	if meta.LastUpdated <= oldUpdated || meta.LastError != "" || meta.Rules != 1000 {
		t.Fatalf("unchanged refresh lost successful update metadata: %+v", meta)
	}
	var persisted map[string]filterMetadata
	if err := m.store.Load(filterMetadataFile, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted["adguard-dns"] != meta {
		t.Fatalf("unchanged refresh metadata not saved: %+v", persisted)
	}
	cached, err := m.readCache("adguard-dns")
	if err != nil || !bytes.Equal(cached, data) {
		t.Fatalf("unchanged refresh damaged cached bytes: %v", err)
	}
}

func TestFilteringRuleEditsReuseEngineWithoutChangingLastGoodMatcher(t *testing.T) {
	m, r := filterFixture(t)
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("ads", 1000), r); err != nil {
		t.Fatal(err)
	}
	before := m.Blocker()
	engine := before.snapshot.Load().adguard
	cfg := copyFilteringConfig(&m.cfg)
	cfg.CustomRules = []BlockingRule{{Domain: "manual.example", Category: BlockCategoryTrackers}}
	cfg.Allowlist = []string{"ads0.example"}
	if err := m.ConfigurePersist(&cfg, func() error { return errors.New("save failed") }); err == nil {
		t.Fatal("save failure hidden")
	}
	if m.Blocker() != before {
		t.Fatal("failed persistence replaced the last good matcher")
	}
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if m.Blocker() == before || m.Blocker().snapshot.Load().adguard != engine {
		t.Fatal("manual rule edit did not rebuild local rules with the reused engine")
	}
	if _, blocked := m.Blocker().Match("ads0.example"); blocked {
		t.Fatal("allowlist edit did not apply")
	}
	if match, blocked := m.Blocker().Match("manual.example"); !blocked || match.Source != customBlockSource {
		t.Fatalf("custom rule edit did not apply: %+v, %v", match, blocked)
	}
	if _, blocked := before.Match("ads0.example"); !blocked {
		t.Fatal("manual edits changed the previously published matcher")
	}
	before = m.Blocker()
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("invalid", 1), r); err == nil {
		t.Fatal("truncated replacement accepted")
	}
	if m.Blocker() != before || m.Blocker().snapshot.Load().adguard != engine {
		t.Fatal("failed replacement changed the active engine")
	}
	if err := m.install(m.revision, m.cfg, "adguard-dns", filterData("new", 1000), r); err != nil {
		t.Fatal(err)
	}
	if m.Blocker().snapshot.Load().adguard == engine {
		t.Fatal("changed download retained the old engine")
	}
	if _, blocked := m.Blocker().Match("new0.example"); !blocked {
		t.Fatal("changed source was not published")
	}
	if _, blocked := m.Blocker().Match("ads1.example"); blocked {
		t.Fatal("changed source retained old rules")
	}
}
