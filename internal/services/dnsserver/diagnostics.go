package dnsserver

import "strings"

// DNS diagnostics are independent of the application's general log switch.
// The ring and scheduler remain in memory across DNS configuration changes.
func (s *Service) Logs(afterID uint64) LogSnapshot { return s.logs.Snapshot(afterID) }

func (s *Service) ClearLogs() LogSnapshot {
	s.logs.Clear()
	return s.logs.Snapshot(0)
}

func (s *Service) SetLoggingEnabled(enabled bool) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	cfg := s.Config()
	cfg.LoggingEnabled = enabled
	if err := s.store.Save(configFile, cfg); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg.LoggingEnabled = enabled
	s.mu.Unlock()
	if !enabled {
		s.logs.Append(LogEntry{Level: "info", Event: "logging", Message: "Запись журнала DNS выключена"})
	}
	s.logs.SetEnabled(enabled)
	if enabled {
		s.logs.Append(LogEntry{Level: "info", Event: "logging", Message: "Запись журнала DNS включена; предел 128 КБ"})
	}
	return nil
}

func (s *Service) SchedulerSnapshot(domain string) (SchedulerSnapshot, error) {
	// No domain means the shared default pool. Do not substitute an example
	// hostname: a user rule could legitimately assign that name another pool.
	if strings.TrimSpace(domain) == "" {
		return s.scheduler.Snapshot(s.Config(), s.backend.Routes(), ""), nil
	}
	name, err := normalizeDomain(domain)
	if err != nil {
		return SchedulerSnapshot{}, err
	}
	return s.scheduler.Snapshot(s.Config(), s.backend.Routes(), name), nil
}

func (s *Service) recordAttempt(attempt AttemptEvent) {
	// The final answer already identifies the winning provider and route.
	// Cancellations are summarized once after this query's workers finish.
	if attempt.Success || attempt.Canceled {
		return
	}
	s.logs.Append(LogEntry{Level: "warn", Event: "attempt_error", Domain: attempt.Domain, QType: attempt.Type, Upstream: attempt.Upstream, Route: attempt.Route, DurationMS: attempt.DurationMS, Message: attempt.Error})
}

func (s *Service) recordCancellations(summary CancellationSummary) {
	if summary.Count > 0 {
		s.logs.Append(LogEntry{Level: "debug", Event: "canceled", Domain: summary.Domain, QType: summary.Type, Count: summary.Count})
	}
}
