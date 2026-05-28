package app

import (
	"nfqws2strategy/internal/dns"
	"nfqws2strategy/internal/store"
)

const dnsConfigFile = "dns.json"

// initDNS loads the persisted DNS server list, seeding it with the defaults on
// first run (or if the file is missing/empty).
func (a *App) initDNS() {
	var servers []dns.Server
	if err := a.store.Load(dnsConfigFile, &servers); err != nil || len(servers) == 0 {
		servers = dns.Defaults()
		_ = a.store.Save(dnsConfigFile, servers)
	}
	a.dnsServers = servers
}

// DNSServers returns a copy of the configured DNS servers.
func (a *App) DNSServers() []dns.Server {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	return append([]dns.Server{}, a.dnsServers...)
}

// SaveDNSServer creates (empty id) or updates a DNS server.
func (a *App) SaveDNSServer(s dns.Server) (dns.Server, error) {
	s.Normalize()
	if err := s.Validate(); err != nil {
		return s, err
	}
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	if s.ID == "" {
		s.ID = "user-" + store.NewID()
		a.dnsServers = append(a.dnsServers, s)
	} else {
		found := false
		for i := range a.dnsServers {
			if a.dnsServers[i].ID == s.ID {
				a.dnsServers[i] = s
				found = true
				break
			}
		}
		if !found {
			a.dnsServers = append(a.dnsServers, s)
		}
	}
	return s, a.store.Save(dnsConfigFile, a.dnsServers)
}

// DeleteDNSServer removes a DNS server by id.
func (a *App) DeleteDNSServer(id string) error {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	out := a.dnsServers[:0]
	for _, s := range a.dnsServers {
		if s.ID != id {
			out = append(out, s)
		}
	}
	a.dnsServers = out
	return a.store.Save(dnsConfigFile, a.dnsServers)
}

// ResetDNSServers restores the default DNS server list.
func (a *App) ResetDNSServers() ([]dns.Server, error) {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	a.dnsServers = dns.Defaults()
	return append([]dns.Server{}, a.dnsServers...), a.store.Save(dnsConfigFile, a.dnsServers)
}
