package awgroute

import (
	"fmt"
	"time"
)

// RecoverySettings is router-wide local client policy. Pauses start only after
// the current handshake verification window has finished; they do not delay a
// newly detected failure and do not change the server's protocol parameters.
type RecoverySettings struct {
	FastRetrySeconds        int `json:"fast_retry_seconds"`
	RetryDelaySeconds       int `json:"retry_delay_seconds"`
	SlowRetryAfterSeconds   int `json:"slow_retry_after_seconds"`
	SlowRetryDelaySeconds   int `json:"slow_retry_delay_seconds"`
	HandshakeTimeoutSeconds int `json:"handshake_timeout_seconds"`
}

func DefaultRecoverySettings() RecoverySettings {
	return RecoverySettings{FastRetrySeconds: 60, RetryDelaySeconds: 5,
		SlowRetryAfterSeconds: 3600, SlowRetryDelaySeconds: 90, HandshakeTimeoutSeconds: 20}
}

func (s RecoverySettings) Validate() error {
	checks := []struct {
		name            string
		value, min, max int
	}{
		{"первая фаза повторов", s.FastRetrySeconds, 1, 600},
		{"обычная пауза повторов", s.RetryDelaySeconds, 1, 30},
		{"начало длительных пауз", s.SlowRetryAfterSeconds, 1800, 3600},
		{"длительная пауза повторов", s.SlowRetryDelaySeconds, 90, 900},
		{"проверка handshake", s.HandshakeTimeoutSeconds, 5, 60},
	}
	for _, check := range checks {
		if check.value < check.min || check.value > check.max {
			return fmt.Errorf("%s: допустимо от %d до %d секунд", check.name, check.min, check.max)
		}
	}
	if s.SlowRetryAfterSeconds <= s.FastRetrySeconds {
		return fmt.Errorf("длительные паузы должны начинаться после первой фазы повторов")
	}
	return nil
}

// Older configurations have no global settings. A damaged saved field falls
// back to its default; the write API validates every field instead of silently
// accepting an out-of-range value.
func normalizeRecoverySettings(saved *RecoverySettings) RecoverySettings {
	defaults := DefaultRecoverySettings()
	if saved == nil {
		return defaults
	}
	settings := *saved
	if settings.FastRetrySeconds < 1 || settings.FastRetrySeconds > 600 {
		settings.FastRetrySeconds = defaults.FastRetrySeconds
	}
	if settings.RetryDelaySeconds < 1 || settings.RetryDelaySeconds > 30 {
		settings.RetryDelaySeconds = defaults.RetryDelaySeconds
	}
	if settings.SlowRetryAfterSeconds < 1800 || settings.SlowRetryAfterSeconds > 3600 {
		settings.SlowRetryAfterSeconds = defaults.SlowRetryAfterSeconds
	}
	if settings.SlowRetryDelaySeconds < 90 || settings.SlowRetryDelaySeconds > 900 {
		settings.SlowRetryDelaySeconds = defaults.SlowRetryDelaySeconds
	}
	if settings.HandshakeTimeoutSeconds < 5 || settings.HandshakeTimeoutSeconds > 60 {
		settings.HandshakeTimeoutSeconds = defaults.HandshakeTimeoutSeconds
	}
	return settings
}

func (s RecoverySettings) handshakeTimeout() time.Duration {
	return time.Duration(s.HandshakeTimeoutSeconds) * time.Second
}

func (s RecoverySettings) retryDelay(outage time.Duration) time.Duration {
	if outage < time.Duration(s.FastRetrySeconds)*time.Second {
		return 0
	}
	if outage < time.Duration(s.SlowRetryAfterSeconds)*time.Second {
		return time.Duration(s.RetryDelaySeconds) * time.Second
	}
	return time.Duration(s.SlowRetryDelaySeconds) * time.Second
}

func (svc *Service) currentRecoverySettings() RecoverySettings {
	svc.mu.RLock()
	settings := normalizeRecoverySettings(svc.recoverySettings)
	svc.mu.RUnlock()
	return settings
}

func (svc *Service) AWG2SetRecoverySettings(in RecoverySettings) error {
	if err := in.Validate(); err != nil {
		return err
	}
	ctx, unlock := svc.lockClientOps(false)
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if svc.store == nil {
		return fmt.Errorf("хранилище настроек AWG недоступно")
	}
	// Keep failed writes invisible to status reads and future unrelated saves.
	candidate := svc.snapshotAWGState()
	candidate.RecoverySettings = &in
	if err := svc.store.SaveSecret(awgConfigFile, &candidate); err != nil {
		return err
	}
	svc.mu.Lock()
	svc.recoverySettings = &in
	svc.mu.Unlock()
	// Recalculate against the original outage and attempt timestamps. Saving
	// settings must neither forgive a long outage nor restart a healthy peer.
	svc.clients.mu.Lock()
	for am, recovery := range svc.clients.states {
		recovery.updateSettings(in)
		svc.clients.states[am] = recovery
	}
	svc.clients.mu.Unlock()
	return nil
}
