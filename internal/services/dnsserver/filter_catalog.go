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
	{ID: "hagezi-light", Name: "HaGeZi Light", Category: "mixed", URL: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt", Homepage: "https://github.com/hagezi/dns-blocklists", Description: "Компактный список рекламы, трекеров и телеметрии для роутеров с небольшой памятью."},
	{ID: "hagezi-normal", Name: "HaGeZi Normal", Category: "mixed", URL: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt", Homepage: "https://github.com/hagezi/dns-blocklists", Description: "Более широкий список рекламы и трекеров. Требует больше памяти, чем Light."},
	{ID: "hagezi-pro", Name: "HaGeZi Pro", Category: "mixed", URL: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt", Homepage: "https://github.com/hagezi/dns-blocklists", Description: "Расширенная блокировка телеметрии и трекеров. При проблемах с приложениями добавьте исключение."},
	{ID: "oisd-small", Name: "OISD small", Category: "mixed", URL: "https://small.oisd.nl/domainswild2", Homepage: "https://oisd.nl", Description: "Компактный список с акцентом на рекламу. Также содержит часть трекеров."},
	{ID: "blocklist-ads", Name: "Block List Project — Ads", Category: "ads", URL: "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt", Homepage: "https://github.com/blocklistproject/Lists", Description: "Отдельный большой список рекламных доменов. Используйте при достаточном объёме памяти."},
	{ID: "blocklist-tracking", Name: "Block List Project — Tracking", Category: "trackers", URL: "https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt", Homepage: "https://github.com/blocklistproject/Lists", Description: "Отдельный большой список доменов аналитики и отслеживания."},
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
