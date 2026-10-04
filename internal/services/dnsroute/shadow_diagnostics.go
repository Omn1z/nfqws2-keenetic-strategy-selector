package dnsroute

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

const shadowDiagnosticAttempts = 6
const shadowDiagnosticEvents = 48
const shadowDiagnosticMessageBytes = 512

// ShadowDiagnostics is a bounded, passive snapshot. It contains only structured
// discovery metadata, never packet payloads, native command output or DNS names.
type ShadowDiagnostics struct {
	Version    int                       `json:"version"`
	Enabled    bool                      `json:"enabled"`
	AppVersion string                    `json:"app_version,omitempty"`
	Platform   string                    `json:"platform"`
	CapturedAt time.Time                 `json:"captured_at"`
	InProgress bool                      `json:"in_progress"`
	Attempts   []ShadowDiagnosticAttempt `json:"attempts"`
}

type ShadowDiagnosticAttempt struct {
	ID          uint64                  `json:"id"`
	StartedAt   time.Time               `json:"started_at"`
	FinishedAt  *time.Time              `json:"finished_at,omitempty"`
	DurationMS  int64                   `json:"duration_ms"`
	Error       string                  `json:"error,omitempty"`
	Servers     []string                `json:"servers"`
	NextRetryAt *time.Time              `json:"next_retry_at,omitempty"`
	Events      []ShadowDiagnosticEvent `json:"events"`
}

type ShadowDiagnosticEvent struct {
	At         time.Time `json:"at"`
	Stage      string    `json:"stage"`
	Message    string    `json:"message"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// Never take discoveryMu from this mutex: reading status must remain immediate
// while firmware commands or DHCP sockets are waiting for their deadlines.
type shadowDiagnosticState struct {
	session  atomic.Pointer[shadowDiagnosticSession]
	mu       sync.Mutex
	nextID   uint64
	attempts []ShadowDiagnosticAttempt
}

// Each enable cycle has its own cancellation scope. Disabling diagnostics must
// stop optional capture without cancelling discovery or the native DHCP client.
type shadowDiagnosticSession struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type shadowDiagnosticContextKey struct{}
type shadowDiagnosticContext struct {
	state   *shadowDiagnosticState
	session *shadowDiagnosticSession
	id      uint64
}

func shadowDiagnosticEnabled(ctx context.Context) bool {
	collector, ok := ctx.Value(shadowDiagnosticContextKey{}).(shadowDiagnosticContext)
	return ok && collector.session != nil && collector.state.session.Load() == collector.session
}

func (s *shadowDiagnosticState) setEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.session.Load()
	if enabled == (current != nil) {
		return
	}
	if enabled {
		ctx, cancel := context.WithCancel(context.Background())
		s.session.Store(&shadowDiagnosticSession{ctx: ctx, cancel: cancel})
		return
	}
	s.session.Store(nil)
	s.attempts = nil
	current.cancel()
	// Keep nextID monotonic: late completion from an old enable cycle must
	// never match an attempt created after diagnostics are enabled again.
}

func (s *shadowDiagnosticState) begin(ctx context.Context) (context.Context, func([]string, error, time.Time)) {
	session := s.session.Load()
	if session == nil {
		return ctx, shadowDiagnosticNoopFinish
	}
	now := time.Now().UTC()
	s.mu.Lock()
	if s.session.Load() != session {
		s.mu.Unlock()
		return ctx, shadowDiagnosticNoopFinish
	}
	s.nextID++
	id := s.nextID
	if len(s.attempts) == shadowDiagnosticAttempts {
		copy(s.attempts, s.attempts[1:])
		s.attempts = s.attempts[:len(s.attempts)-1]
	}
	s.attempts = append(s.attempts, ShadowDiagnosticAttempt{ID: id, StartedAt: now, Servers: []string{}, Events: []ShadowDiagnosticEvent{}})
	s.mu.Unlock()
	ctx = context.WithValue(ctx, shadowDiagnosticContextKey{}, shadowDiagnosticContext{state: s, session: session, id: id})
	return ctx, func(servers []string, err error, nextRetry time.Time) {
		if s.session.Load() == session {
			s.finish(id, servers, err, nextRetry)
		}
	}
}

func shadowDiagnosticNoopFinish([]string, error, time.Time) {}

func (s *shadowDiagnosticState) finish(id uint64, servers []string, err error, nextRetry time.Time) {
	if s.session.Load() == nil {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.attempts {
		a := &s.attempts[i]
		if a.ID != id || a.FinishedAt != nil {
			continue
		}
		a.FinishedAt = &now
		a.DurationMS = max(0, now.Sub(a.StartedAt).Milliseconds())
		if err != nil {
			a.Error = shadowDiagnosticText(err.Error(), shadowDiagnosticMessageBytes)
		}
		if len(servers) > 8 {
			servers = servers[:8]
		}
		for _, server := range servers {
			a.Servers = append(a.Servers, shadowDiagnosticText(server, 128))
		}
		if !nextRetry.IsZero() {
			nextRetry = nextRetry.UTC()
			a.NextRetryAt = &nextRetry
		}
		return
	}
}

// Callers supply fixed stage names and summaries; raw native output and packet
// bytes must never be passed here. An absent collector makes the call a no-op.
func shadowDiagnosticEvent(ctx context.Context, stage, message string, duration time.Duration) {
	collector, ok := ctx.Value(shadowDiagnosticContextKey{}).(shadowDiagnosticContext)
	if !ok || collector.session == nil || collector.state.session.Load() != collector.session {
		return
	}
	event := ShadowDiagnosticEvent{At: time.Now().UTC(), Stage: shadowDiagnosticText(stage, 64), Message: shadowDiagnosticText(message, shadowDiagnosticMessageBytes), DurationMS: max(0, duration.Milliseconds())}
	s := collector.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session.Load() != collector.session {
		return
	}
	for i := range s.attempts {
		a := &s.attempts[i]
		if a.ID != collector.id || a.FinishedAt != nil {
			continue
		}
		if len(a.Events) == shadowDiagnosticEvents {
			copy(a.Events, a.Events[1:])
			a.Events = a.Events[:len(a.Events)-1]
		}
		a.Events = append(a.Events, event)
		return
	}
}

func shadowDiagnosticText(value string, limit int) string {
	// Bound work as well as storage, and do not split UTF-8 or retain controls.
	if len(value) > limit {
		value = value[:limit]
	}
	for !utf8.ValidString(value) && len(value) > 0 {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
}

func (s *shadowDiagnosticState) snapshot() ShadowDiagnostics {
	now := time.Now().UTC()
	result := ShadowDiagnostics{Version: 1, Platform: runtime.GOOS + "/" + runtime.GOARCH, CapturedAt: now, Attempts: []ShadowDiagnosticAttempt{}}
	s.mu.Lock()
	defer s.mu.Unlock()
	result.Enabled = s.session.Load() != nil
	for _, original := range s.attempts {
		a := original
		a.Servers = append([]string{}, original.Servers...)
		a.Events = append([]ShadowDiagnosticEvent{}, original.Events...)
		if original.FinishedAt != nil {
			finished := *original.FinishedAt
			a.FinishedAt = &finished
		} else {
			result.InProgress = true
			a.DurationMS = max(0, now.Sub(a.StartedAt).Milliseconds())
		}
		if original.NextRetryAt != nil {
			next := *original.NextRetryAt
			a.NextRetryAt = &next
		}
		result.Attempts = append(result.Attempts, a)
	}
	return result
}

// ShadowDiagnostics never initiates discovery or waits for its network mutex.
func (a *Adapter) ShadowDiagnostics() ShadowDiagnostics {
	result := a.shadow.diagnostics.snapshot()
	if a.cfg != nil {
		result.AppVersion = shadowDiagnosticText(a.cfg.Version, 128)
	}
	return result
}

// SetShadowDiagnostics changes only optional diagnostic collection. It never
// starts discovery, invalidates DNS caches, or changes the native DHCP observer.
// The switch is intentionally runtime-only and defaults off after process start.
func (a *Adapter) SetShadowDiagnostics(enabled bool) {
	a.shadow.diagnostics.setEnabled(enabled)
}
