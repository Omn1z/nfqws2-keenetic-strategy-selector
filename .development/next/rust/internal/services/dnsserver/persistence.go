package dnsserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"nfqws2strategy/internal/tools/store"
)

var ErrConfigConflict = errors.New("настройки DNS изменились; загрузите актуальные настройки перед сохранением")

func storedConfigSeed() Config {
	cfg := Default()
	return Config{LoggingEnabled: true, CacheTTLSeconds: cfg.CacheTTLSeconds, FastDNS: cfg.FastDNS, SchedulerEnabled: true}
}

func validateStoredConfig(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if len(fields) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("сохранённые настройки DNS должны содержать объект конфигурации")
	}
	cfg := storedConfigSeed()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if _, hasPort := fields["dns_port"]; !hasPort {
		cfg.DNSPort = Default().DNSPort
	}
	return cfg.NormalizeValidate()
}

func (s *Service) loadStoredConfig() (Config, bool, bool, error) {
	cfg := storedConfigSeed()
	recovered, err := s.store.LoadConfig(configFile, &cfg, validateStoredConfig)
	if err != nil {
		return Config{}, false, false, err
	}
	legacy := cfg.DNSPort == 0
	if legacy {
		cfg.DNSPort = Default().DNSPort
	}
	if err := cfg.NormalizeValidate(); err != nil {
		return Config{}, false, recovered, err
	}
	return cfg, legacy, recovered, nil
}

func (s *Service) configurationErrorLocked() error {
	s.mu.RLock()
	err := s.configLoadErr
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("сохранённые настройки DNS не загружены; запись остановлена для защиты данных: %w", err)
	}
	return nil
}

func (s *Service) ConfigError() error { return s.configurationErrorLocked() }

func (s *Service) persistConfigLocked(cfg Config) error {
	if s.saveConfig != nil {
		return s.saveConfig(cfg)
	}
	return s.store.Save(configFile, cfg)
}

func (s *Service) persistenceErrorLocked(err error) error {
	var committed *store.CommitError
	if err != nil && (errors.As(err, &committed) || errors.Is(err, store.ErrConfigChanged)) {
		// Rename may already have published the new data. Reload before another
		// small switch can serialize the previous in-memory rule list over it.
		return errors.Join(err, s.reloadStoredConfigLocked())
	}
	return err
}

// ConfigEditDigest omits switches owned by independent controls. A stale form
// cannot overwrite other fields, while toggling logs need not invalidate it.
func ConfigEditDigest(cfg Config) string {
	cfg.DNSPort = 0
	cfg.LoggingEnabled = false
	cfg.DisabledMethods = nil
	return ConfigDigest(cfg)
}

// UpdateConfig compares and merges inside the same operation as persistence.
// An empty hash is reserved for narrow internal updates, not an HTTP form.
func (s *Service) UpdateConfig(expectedHash string, update func(Config) Config) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.configurationErrorLocked(); err != nil {
		return err
	}
	current := s.Config()
	if expectedHash != "" && expectedHash != ConfigEditDigest(current) {
		return ErrConfigConflict
	}
	return s.setConfigLocked(update(current))
}

// WithConfigRestore fences every DNS writer until disk restoration and a
// validated reload have finished, including when commit/rollback reports an
// error. It never writes the old in-memory configuration back to disk.
func (s *Service) WithConfigRestore(restore func() error) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	restoreErr := restore()
	return errors.Join(restoreErr, s.reloadStoredConfigLocked())
}

func (s *Service) reloadStoredConfigLocked() error {
	cfg, _, recovered, loadErr := s.loadStoredConfig()
	if loadErr == nil {
		s.mu.Lock()
		s.configLoadErr = nil
		if recovered {
			s.configWarning = "Настройки DNS восстановлены из резервной копии"
		}
		s.mu.Unlock()
		loadErr = s.applyConfigLocked(cfg, nil)
	}
	if loadErr != nil {
		s.mu.Lock()
		s.configLoadErr = loadErr
		s.lastError = "не удалось загрузить восстановленные настройки DNS: " + loadErr.Error()
		s.mu.Unlock()
	}
	return loadErr
}
