package dnsserver

import (
	"fmt"
	"net"
	"strconv"
)

// Summary is the dashboard snapshot. It needs no route discovery or copying
// of provider pools and domain rules on every dashboard poll.
type Summary struct {
	Enabled   bool        `json:"enabled"`
	Running   bool        `json:"running"`
	Endpoint  string      `json:"endpoint"`
	LastError string      `json:"last_error"`
	Stats     Stats       `json:"stats"`
	Cache     CacheStatus `json:"cache"`
}

func (s *Service) cacheStatusLocked() CacheStatus {
	if s.active != nil {
		return s.active.resolver.CacheStatus()
	}
	return CacheStatus{Capacity: s.cfg.CacheSize, TTLSeconds: s.cfg.CacheTTLSeconds}
}

func (s *Service) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	view := Summary{Enabled: s.cfg.Enabled, Running: s.active != nil, LastError: s.lastError, Stats: s.stats, Cache: s.cacheStatusLocked()}
	if s.host != "" {
		view.Endpoint = net.JoinHostPort(s.host, strconv.Itoa(s.cfg.DNSPort))
	}
	return view
}

// ClearCache keeps the active listeners, statistics, transport pools and
// scheduler. Configuration changes cannot replace the resolver during clear.
func (s *Service) ClearCache() int {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	run := s.active
	s.mu.RUnlock()
	removed := 0
	if run != nil {
		removed = run.resolver.ClearCache()
	}
	s.logs.Append(LogEntry{Level: "info", Event: "cache_clear", Message: fmt.Sprintf("Кэш ответов DNS очищен: удалено записей — %d", removed)})
	return removed
}
