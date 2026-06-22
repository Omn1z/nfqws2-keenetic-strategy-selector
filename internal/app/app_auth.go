package app

import (
	"os"
	"time"

	"nfqws2strategy/internal/tools/auth"
	"nfqws2strategy/internal/tools/logbuf"
)

const (
	sessionTTL   = 7 * 24 * time.Hour
	settingsFile = "settings.json"
)

type settings struct {
	AuthEnabled      bool   `json:"auth_enabled"`
	LoggingDisabled  bool   `json:"logging_disabled"`
	HTTPLogsDisabled bool   `json:"http_logs_disabled"`
	// TraceMode is the AWG2 per-flow trace recording policy:
	//   "off"    — never record; counters still tick (dashboard RPS stays alive).
	//   "auto"   — record only while a client (TracePane) is viewing the log.
	//   "always" — record continuously.
	// "auto" is the default — costs nothing when nobody is looking and Just
	// Works when the user opens the tab.
	TraceMode string `json:"trace_mode"`
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
	if s.TraceMode == "" {
		s.TraceMode = "auto"
	}
	a.authEnabled = s.AuthEnabled
	a.loggingDisabled = s.LoggingDisabled
	a.httpLogsDisabled = s.HTTPLogsDisabled
	a.traceMode = s.TraceMode
	logbuf.SetEnabled(!s.LoggingDisabled)
}

// saveSettings persists the current toggles (call with a.mu held).
func (a *App) saveSettings() error {
	return a.store.Save(settingsFile, settings{
		AuthEnabled:      a.authEnabled,
		LoggingDisabled:  a.loggingDisabled,
		HTTPLogsDisabled: a.httpLogsDisabled,
		TraceMode:        a.traceMode,
	})
}

// TraceMode returns the persisted recording policy (off|auto|always).
func (a *App) TraceMode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.traceMode == "" {
		return "auto"
	}
	return a.traceMode
}

// SetTraceMode persists the policy and pushes it to the AWG route service.
// "always" → flip the ring on immediately; "off" → flip it off; "auto" lets
// the frontend tab control it (mount-on / unmount-off).
func (a *App) SetTraceMode(mode string) error {
	if mode != "off" && mode != "auto" && mode != "always" {
		mode = "auto"
	}
	a.mu.Lock()
	a.traceMode = mode
	err := a.saveSettings()
	a.mu.Unlock()
	switch mode {
	case "always":
		a.awgroute.TraceSetEnabled(true)
	case "off":
		a.awgroute.TraceSetEnabled(false)
	}
	return err
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

// HTTPLogsEnabled reports whether the per-request HTTP access log is on.
func (a *App) HTTPLogsEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.httpLogsDisabled
}

// SetHTTPLogsEnabled toggles the HTTP access log (the noisy "GET /api/… 14ms"
// lines) without affecting other module logs, and persists it.
func (a *App) SetHTTPLogsEnabled(enabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.httpLogsDisabled = !enabled
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
