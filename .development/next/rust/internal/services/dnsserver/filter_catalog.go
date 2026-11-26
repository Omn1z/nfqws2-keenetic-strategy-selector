package dnsserver

// Only publisher-controlled HTTPS addresses can be fetched. DNS filter updates
// must never turn the router into a downloader for arbitrary local addresses.
type FilteringListDefinition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	URL         string `json:"url"`
	Homepage    string `json:"homepage"`
	Description string `json:"description"`
}

var filteringCatalog = []FilteringListDefinition{
	{ID: "adguard-dns", Name: "AdGuard DNS filter", Category: "mixed", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter", Description: "Реклама и трекеры, включая русскоязычные сайты. Официальный DNS-фильтр AdGuard."},
}

func filteringList(id string) (FilteringListDefinition, bool) {
	for _, item := range filteringCatalog {
		if item.ID == id {
			return item, true
		}
	}
	return FilteringListDefinition{}, false
}

// Filtering is opt-in for existing installations. The selected preset and
// editable examples make enabling it useful without blocking every CDN host.
func DefaultFilteringConfig() *FilteringConfig {
	cfg := &FilteringConfig{Lists: []string{"adguard-dns"}, CustomRules: []BlockingRule{}, Allowlist: []string{}}
	for _, domain := range []string{
		"report.appmetrica.yandex.net", "ep1.adtrafficquality.google", "ogads-pa.clients6.google.com",
		"rosenberg.appmetrica.yandex.net", "ca.iadsdk.apple.com",
	} {
		cfg.CustomRules = append(cfg.CustomRules, BlockingRule{Domain: domain, Category: "ads"})
	}
	for _, domain := range []string{
		"www.tns-counter.ru", "inapps.appsflyersdk.com", "app-analytics-services.com", "app-measurement.com",
		"r0.mradx.net", "top-fwz1.mail.ru", "sdk-api.apptracer.ru", "stats.vk-portal.net", "c.msn.com",
		"events.statsigapi.net", "gx-target-experiments-frontend-api.gx.nvidia.com", "ampltd2.medal.tv",
		"events.launchdarkly.com", "spade.twitch.tv", "*-netseer-ipaddr-assoc.xy.fbcdn.net", "*-netseer-ipaddr-assoc.xz.fbcdn.net",
	} {
		cfg.CustomRules = append(cfg.CustomRules, BlockingRule{Domain: domain, Category: "trackers"})
	}
	return cfg
}
