package app

import (
	"os"
	"time"

	"nfqws2strategy/internal/auth"
	"nfqws2strategy/internal/logbuf"
)

const (
	sessionTTL   = 7 * 24 * time.Hour
	settingsFile = "settings.json"
)

type settings struct {
	AuthEnabled     bool `json:"auth_enabled"`
	LoggingDisabled bool `json:"logging_disabled"`
}

// initAuth loads system settings (auth default enabled, logging default on).
// N2S_NOAUTH=1 forces auth off as a recovery escape hatch.
func (a *App) initAuth() {
	s := settings{AuthEnabled: true}
	if a.store.Exists(settingsFile) {
		_ = a.store.Load(settingsFile, &s)
	}
	if os.Getenv("N2S_NOAUTH") == "1" {
		s.AuthEnabled = false
	}
	a.authEnabled = s.AuthEnabled
	a.loggingDisabled = s.LoggingDisabled
	logbuf.SetEnabled(!s.LoggingDisabled)
}

// saveSettings persists the current toggles (call with a.mu held).
func (a *App) saveSettings() error {
	return a.store.Save(settingsFile, settings{AuthEnabled: a.authEnabled, LoggingDisabled: a.loggingDisabled})
}

func (a *App) AuthEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authEnabled
}

// AuthForcedOff reports whether N2S_NOAUTH pins auth off (so the UI can show the
// toggle as locked).
func (a *App) AuthForcedOff() bool { return os.Getenv("N2S_NOAUTH") == "1" }

// LoggingEnabled reports whether logging (ring + file) is currently on.
func (a *App) LoggingEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.loggingDisabled
}

// SetAuthEnabled persists the auth toggle (ignored if N2S_NOAUTH=1 forces off).
func (a *App) SetAuthEnabled(enabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.authEnabled = enabled
	return a.saveSettings()
}

// SetLoggingEnabled turns logging on/off and persists it.
func (a *App) SetLoggingEnabled(enabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.loggingDisabled = !enabled
	logbuf.SetEnabled(enabled)
	return a.saveSettings()
}

// Login verifies credentials and returns a new session token on success.
func (a *App) Login(user, password string) (string, bool) {
	if !auth.Verify(user, password) {
		return "", false
	}
	return a.sessions.New(), true
}

func (a *App) Logout(token string)            { a.sessions.Delete(token) }
func (a *App) ValidSession(token string) bool { return a.sessions.Valid(token) }
