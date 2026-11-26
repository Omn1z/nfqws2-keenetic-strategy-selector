package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"nfqws2strategy/internal/tools/dns"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/store"
	"os"
)

const dnsConfigFile = "dns.json"

func validateDNSList(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return fmt.Errorf("список DNS должен быть массивом; null и объект не являются настройками")
	}
	var servers []dns.Server
	if err := json.Unmarshal(data, &servers); err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, server := range servers {
		server.Normalize()
		if err := server.Validate(); err != nil {
			return err
		}
		if server.ID == "" || ids[server.ID] {
			return fmt.Errorf("список DNS содержит пустой или повторяющийся ID")
		}
		ids[server.ID] = true
	}
	return nil
}

// Empty arrays are intentional; only a genuinely new store is seeded.
func (a *App) initDNS() { a.dnsMu.Lock(); defer a.dnsMu.Unlock(); _ = a.loadDNSLocked(true) }

func (a *App) loadDNSLocked(seedMissing bool) error {
	var servers []dns.Server
	recovered, err := a.store.LoadConfig(dnsConfigFile, &servers, validateDNSList)
	if os.IsNotExist(err) && seedMissing {
		servers = dns.Defaults()
		err = a.store.Save(dnsConfigFile, servers)
	}
	if err != nil {
		a.dnsConfigErr = fmt.Errorf("сохранённый список DNS не загружен; исходные данные сохранены: %w", err)
		logbuf.Append("dns", "error", a.dnsConfigErr.Error())
		return a.dnsConfigErr
	}
	if recovered {
		logbuf.Append("dns", "warn", "Список DNS восстановлен из резервной копии")
	}
	a.dnsServers = append([]dns.Server{}, servers...)
	a.dnsConfigErr = nil
	return nil
}

func (a *App) DNSConfigError() error { a.dnsMu.Lock(); defer a.dnsMu.Unlock(); return a.dnsConfigErr }

// Fence both DNS files while application backup commits or rolls back.
func (a *App) WithDNSConfigRestore(restore func() error) error {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	wasInitialized := a.dnsServers != nil || a.dnsConfigErr != nil
	var restoreErr error
	if a.dnsServer != nil {
		restoreErr = a.dnsServer.WithConfigRestore(restore)
	} else {
		restoreErr = restore()
	}
	loadErr := a.loadDNSLocked(false)
	if !wasInitialized && errors.Is(loadErr, os.ErrNotExist) {
		// A partial App used for an AWG-only restore may never have had a DNS
		// list. Absence is not corruption, and restore must not create defaults.
		a.dnsConfigErr = nil
		loadErr = nil
	}
	return errors.Join(restoreErr, loadErr)
}

func (a *App) DNSServers() []dns.Server {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	return append([]dns.Server{}, a.dnsServers...)
}

func (a *App) SaveDNSServer(server dns.Server) (dns.Server, error) {
	server.Normalize()
	if err := server.Validate(); err != nil {
		return server, err
	}
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	if a.dnsConfigErr != nil {
		return server, a.dnsConfigErr
	}
	next := append([]dns.Server{}, a.dnsServers...)
	if server.ID == "" {
		server.ID = "user-" + store.NewID()
		next = append(next, server)
	} else {
		found := false
		for i := range next {
			if next[i].ID == server.ID {
				next[i] = server
				found = true
				break
			}
		}
		if !found {
			next = append(next, server)
		}
	}
	if err := a.store.Save(dnsConfigFile, next); err != nil {
		return server, err
	}
	a.dnsServers = next
	return server, nil
}

func (a *App) DeleteDNSServer(id string) error {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	if a.dnsConfigErr != nil {
		return a.dnsConfigErr
	}
	next := make([]dns.Server, 0, len(a.dnsServers))
	for _, server := range a.dnsServers {
		if server.ID != id {
			next = append(next, server)
		}
	}
	if err := a.store.Save(dnsConfigFile, next); err != nil {
		return err
	}
	a.dnsServers = next
	return nil
}

// Reset is explicit user intent and may replace an unavailable configuration.
func (a *App) ResetDNSServers() ([]dns.Server, error) {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	next := dns.Defaults()
	if err := a.store.RecoverConfig(dnsConfigFile, next); err != nil {
		return nil, err
	}
	a.dnsServers = next
	a.dnsConfigErr = nil
	return append([]dns.Server{}, next...), nil
}
