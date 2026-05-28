package app

import (
	"os"
	"time"

	"nfqws2strategy/internal/auth"
)

const (
	sessionTTL   = 7 * 24 * time.Hour
	settingsFile = "settings.json"
)

type settings struct {
	AuthEnabled bool `json:"auth_enabled"`
}

// initAuth loads the auth setting (default enabled). N2S_NOAUTH=1 forces it off
// as a recovery escape hatch.
func (a *App) initAuth() {
	s := settings{AuthEnabled: true}
	if a.store.Exists(settingsFile) {
		_ = a.store.Load(settingsFile, &s)
	}
	if os.Getenv("N2S_NOAUTH") == "1" {
		s.AuthEnabled = false
	}
	a.authEnabled = s.AuthEnabled
}

func (a *App) AuthEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authEnabled
}

// SetAuthEnabled persists the auth toggle (ignored if N2S_NOAUTH=1 forces off).
func (a *App) SetAuthEnabled(enabled bool) error {
	a.mu.Lock()
	a.authEnabled = enabled
	a.mu.Unlock()
	return a.store.Save(settingsFile, settings{AuthEnabled: enabled})
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
