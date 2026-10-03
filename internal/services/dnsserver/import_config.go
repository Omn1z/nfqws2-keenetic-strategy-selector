package dnsserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
)

var ErrImportConfigConflict = errors.New("настройки DNS изменились после проверки; повторите предварительную проверку")

// ConfigDigest includes the complete saved settings, independent of runtime
// counters, listeners and cache contents. Cloning canonicalizes empty arrays.
func ConfigDigest(cfg Config) string {
	wire, _ := json.Marshal(cloneConfig(cfg))
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// ValidateImportedConfig does not persist settings, bind sockets or start DNS.
func (s *Service) ValidateImportedConfig(cfg Config) (Config, string, error) {
	return s.validateImportedConfig(cfg, false)
}

// PrepareImportedConfig adapts a valid, but unavailable, source-router LAN
// address to this router before previewing an import. The normal validator and
// commit remain strict: they must validate the exact listener being applied.
func (s *Service) PrepareImportedConfig(cfg Config) (Config, string, error) {
	return s.validateImportedConfig(cfg, true)
}

func (s *Service) validateImportedConfig(cfg Config, adaptListener bool) (Config, string, error) {
	cfg = cloneConfig(cfg)
	if err := cfg.NormalizeValidate(); err != nil {
		return Config{}, "", err
	}
	host, err := s.resolveHost(cfg.ListenHost)
	if err != nil && adaptListener && cfg.ListenHost != "auto" {
		// Prefer the destination's configured listener. It may also have become
		// stale after a LAN change, in which case discover a current LAN address.
		for _, candidate := range []string{s.Config().ListenHost, "auto"} {
			if candidate == cfg.ListenHost {
				continue
			}
			host, err = s.resolveHost(candidate)
			if err == nil {
				cfg.ListenHost = candidate
				break
			}
		}
	}
	if err != nil {
		return Config{}, "", err
	}
	if err := validateNoSelfUpstream(cfg, host); err != nil {
		return Config{}, "", err
	}
	return cfg, host, nil
}

// ImportConfig serializes the comparison with every config writer, not merely
// HTTP requests. A failed imported startup restores the old persisted settings.
func (s *Service) ImportConfig(cfg Config, expectedHash string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	cfg, host, err := s.ValidateImportedConfig(cfg)
	if err != nil {
		return err
	}
	if raw, err := hex.DecodeString(expectedHash); err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("укажите base_hash из предварительной проверки")
	}
	previous := s.Config()
	s.mu.RLock()
	wasRunning := s.active != nil
	previousHost := s.host
	healthy := !previous.Enabled || s.active != nil && s.controlCancel != nil && host == s.host && s.lastError == "" && s.active.resolver.lifetime.Err() == nil && s.active.listeners.ctx.Err() == nil
	s.mu.RUnlock()
	// Retrying the exact successfully committed document after a lost ACK is
	// read-only. It must neither restart DNS nor reject the original preview.
	if ConfigDigest(previous) == ConfigDigest(cfg) && healthy {
		return nil
	}
	if ConfigDigest(previous) != expectedHash {
		return ErrImportConfigConflict
	}
	// Detect known socket conflicts before stopping a healthy listener. The
	// real startup still checks again, and rollback covers a race after probing.
	if host != previousHost || cfg.DNSPort != previous.DNSPort {
		if err := probeImportedDNSListener(host, cfg.DNSPort); err != nil {
			return err
		}
	}
	if err := s.setConfigLocked(cfg); err != nil {
		return err
	}
	s.mu.RLock()
	running, startupError := s.active != nil, s.lastError
	s.mu.RUnlock()
	if !cfg.Enabled || running {
		return nil
	}
	if startupError == "" {
		startupError = "DNS не запущен"
	}
	failure := fmt.Errorf("не удалось применить импорт DNS: %s", startupError)
	if rollback := s.setConfigLocked(previous); rollback != nil {
		return fmt.Errorf("%w; восстановление предыдущих настроек: %v", failure, rollback)
	}
	s.mu.RLock()
	restored, rollbackError := s.active != nil, s.lastError
	s.mu.RUnlock()
	if wasRunning && !restored {
		return fmt.Errorf("%w; настройки восстановлены, но DNS не запустился: %s", failure, rollbackError)
	}
	return fmt.Errorf("%w; предыдущие настройки восстановлены", failure)
}

func probeImportedDNSListener(host string, port int) error {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("порт DNS %d TCP недоступен: %w", port, err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("порт DNS %d UDP недоступен: %w", port, err)
	}
	return udp.Close()
}
