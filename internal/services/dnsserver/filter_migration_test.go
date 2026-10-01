package dnsserver

import (
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/store"
)

var retiredFilteringIDs = []string{
	"hagezi-light", "hagezi-normal", "hagezi-pro", "oisd-small", "blocklist-ads", "blocklist-tracking",
}

func TestFilteringCatalogOnlyOfficialAdGuard(t *testing.T) {
	if len(filteringCatalog) != 1 || filteringCatalog[0].ID != "adguard-dns" || filteringCatalog[0].URL != "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt" {
		t.Fatalf("unexpected downloadable catalog: %+v", filteringCatalog)
	}
	for _, id := range retiredFilteringIDs {
		if _, exists := filteringList(id); exists {
			t.Fatalf("retired source %s remains downloadable", id)
		}
	}
}

func TestFilteringConfigMigratesRetiredSelectionsAndPreservesLocalRules(t *testing.T) {
	selections := append([]string{}, retiredFilteringIDs...)
	selections = append(selections, "adguard-dns")
	for _, id := range selections {
		for _, enabled := range []bool{false, true} {
			t.Run(id+"/"+map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
				cfg := &FilteringConfig{
					Enabled: enabled, Lists: []string{id},
					CustomRules: []BlockingRule{{Domain: "manual.example", Category: BlockCategoryAds}},
					Allowlist:   []string{"trusted.manual.example"},
				}
				want := copyFilteringConfig(cfg)
				want.Lists = []string{"adguard-dns"}
				if err := normalizeFilteringConfig(cfg); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(*cfg, want) {
					t.Fatalf("migration changed local settings: got %+v, want %+v", *cfg, want)
				}
			})
		}
	}
	combined := &FilteringConfig{Lists: append(selections, " adguard-dns ", " hagezi-light ")}
	if err := normalizeFilteringConfig(combined); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(combined.Lists, []string{"adguard-dns"}) {
		t.Fatalf("migrated selections were not deduplicated: %v", combined.Lists)
	}
}

func TestFilteringConfigManualOnlyAndUnknownSelections(t *testing.T) {
	cfg := &FilteringConfig{
		Enabled: true, Lists: []string{},
		CustomRules: []BlockingRule{{Domain: "manual.example", Category: BlockCategoryTrackers}},
		Allowlist:   []string{"trusted.manual.example"},
	}
	want := copyFilteringConfig(cfg)
	if err := normalizeFilteringConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*cfg, want) {
		t.Fatalf("manual-only config gained a downloaded source: %+v", cfg)
	}
	for _, selection := range [][]string{{"unknown-source"}, {"hagezi-light", "unknown-source"}, {""}} {
		cfg.Lists = selection
		if err := normalizeFilteringConfig(cfg); err == nil {
			t.Fatalf("unknown or invalid selection accepted: %v", selection)
		}
	}
}

func TestFilteringServiceRetiredSelectionDoesNotResetSavedDNSConfig(t *testing.T) {
	for _, lists := range [][]string{{"hagezi-normal", "oisd-small"}, {"adguard-dns", "blocklist-tracking"}, {"adguard-dns"}, {}} {
		t.Run("selection="+strings.Join(lists, ","), func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cfg := Default()
			cfg.Enabled = false
			cfg.ListenHost = "127.0.0.1"
			cfg.DNSPort = 5533
			cfg.RouteMode = RouteModeVPNOnly
			cfg.DefaultUpstream = Upstream{Address: "https://dns.example/dns-query", BootstrapIPs: []string{"9.9.9.9"}}
			cfg.DefaultPool = []Upstream{}
			cfg.Rules = []Rule{{ID: "preserved-route", Enabled: true, Domain: "routed.example", IncludeSubdomains: true, Upstream: cfg.DefaultUpstream, Pool: []Upstream{}}}
			cfg.TimeoutSeconds = 7
			cfg.CacheSize = 64
			cfg.CacheTTLSeconds = 123
			cfg.LoggingEnabled = false
			cfg.FastDNS = false
			cfg.Filtering = &FilteringConfig{
				Enabled: true, Lists: lists,
				CustomRules: []BlockingRule{{Domain: "manual.example", Category: BlockCategoryAds}},
				Allowlist:   []string{"trusted.manual.example"},
			}
			want := cloneConfig(cfg)
			if len(lists) > 0 {
				want.Filtering.Lists = []string{"adguard-dns"}
			}
			if err := want.NormalizeValidate(); err != nil {
				t.Fatal(err)
			}
			if err := st.Save(configFile, cfg); err != nil {
				t.Fatal(err)
			}
			if err := st.WriteBytes("dns-blocklists/adguard-dns.txt", filterData("existing", 1000)); err != nil {
				t.Fatal(err)
			}
			if err := st.WriteBytes("dns-blocklists/hagezi-normal.txt", filterData("retired", 1000)); err != nil {
				t.Fatal(err)
			}
			s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			t.Cleanup(s.Close)
			if actual := s.Config(); !reflect.DeepEqual(actual, want) {
				t.Fatalf("startup reset saved DNS config:\ngot  %+v\nwant %+v", actual, want)
			}
			if status := s.Status(); status.LastError != "" || len(status.Filtering.Lists) != 1 || status.Filtering.Lists[0].ID != "adguard-dns" {
				t.Fatalf("startup did not expose only AdGuard: %+v", status)
			}
			if _, blocked := s.filtering.Blocker().Match("existing0.example"); blocked != (len(lists) > 0) {
				t.Fatal("migration did not preserve the selected AdGuard cache or manual-only mode")
			}
			if _, blocked := s.filtering.Blocker().Match("retired0.example"); blocked {
				t.Fatal("migration loaded retired cache")
			}
			// An already open settings form may still submit the retired IDs.
			if err := s.SetConfig(cfg); err != nil {
				t.Fatal(err)
			}
			var persisted Config
			if err := st.Load(configFile, &persisted); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(persisted, want) {
				t.Fatalf("save did not retain migrated config: %+v", persisted)
			}
		})
	}
}

func TestFilteringManagerMigratesStaleSelectionAndRejectsUnknownSource(t *testing.T) {
	m, _ := filterFixture(t)
	cfg := copyFilteringConfig(&m.cfg)
	cfg.Lists = []string{"hagezi-pro", "blocklist-ads"}
	cfg.CustomRules = []BlockingRule{{Domain: "manual.example", Category: BlockCategoryAds}}
	cfg.Allowlist = []string{"trusted.manual.example"}
	if err := m.Configure(&cfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.cfg.Lists, []string{"adguard-dns"}) || !m.cfg.Enabled {
		t.Fatalf("stale selection was not migrated: %+v", m.cfg)
	}
	if _, blocked := m.Blocker().Match("manual.example"); !blocked {
		t.Fatal("migration lost manual blocking rule")
	}
	if _, blocked := m.Blocker().Match("trusted.manual.example"); blocked {
		t.Fatal("migration lost exclusion")
	}
	before, revision := m.Blocker(), m.revision
	cfg.Lists = []string{"unknown-source"}
	if err := m.Configure(&cfg); err == nil {
		t.Fatal("unknown source accepted by manager")
	}
	if m.Blocker() != before || m.revision != revision {
		t.Fatal("rejected source changed active config")
	}
}
