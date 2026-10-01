package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/store"
)

const filterMetadataFile = "dns-blocklists/metadata.json"

type FilteringListStatus struct {
	FilteringListDefinition
	Selected    bool   `json:"selected"`
	Rules       int    `json:"rules"`
	LastUpdated string `json:"last_updated"`
	LastError   string `json:"last_error"`
}

type FilteringStatus struct {
	IgnoredRules int                   `json:"ignored_rules"`
	Approximate  bool                  `json:"approximate"`
	Enabled      bool                  `json:"enabled"`
	Ready        bool                  `json:"ready"`
	Rules        int                   `json:"rules"`
	Updating     bool                  `json:"updating"`
	LastUpdated  string                `json:"last_updated"`
	LastError    string                `json:"last_error"`
	Lists        []FilteringListStatus `json:"lists"`
}

type filterMetadata struct {
	Rules       int    `json:"rules"`
	LastUpdated string `json:"last_updated"`
	LastError   string `json:"last_error"`
}

// The query path holds an immutable Blocker, not this manager's locks. Builds
// and disk writes happen only on configuration changes or list refreshes.
type FilterManager struct {
	opMu         sync.Mutex
	mu           sync.Mutex
	store        *store.Store
	cfg          FilteringConfig
	blocker      *Blocker
	metadata     map[string]filterMetadata
	revision     uint64
	updating     bool
	updateID     uint64
	updateCancel context.CancelFunc
	resolver     *Resolver
	lastAttempt  time.Time
	lastError    string
}

func NewFilterManager(st *store.Store, cfg *FilteringConfig) (*FilterManager, error) {
	m := &FilterManager{store: st, metadata: map[string]filterMetadata{}}
	_ = st.Load(filterMetadataFile, &m.metadata)
	if m.metadata == nil {
		m.metadata = map[string]filterMetadata{}
	}
	if err := m.Configure(cfg); err != nil {
		// A corrupt cache must not take the DNS listener down. Keep local rules
		// active and retry downloading the selected sources after startup.
		cp := copyFilteringConfig(cfg)
		blocker, buildErr := NewBlockMatcher(nil, cp.CustomRules, cp.Allowlist)
		if buildErr != nil {
			return nil, buildErr
		}
		m.cfg, m.blocker, m.lastError = cp, blocker, err.Error()
		for id, meta := range m.metadata {
			meta.LastUpdated = ""
			meta.Rules = 0
			m.metadata[id] = meta
		}
		return m, err
	}
	return m, nil
}

func copyFilteringConfig(cfg *FilteringConfig) FilteringConfig {
	if cfg == nil {
		cfg = DefaultFilteringConfig()
	}
	cp := *cfg
	cp.Lists = append([]string{}, cfg.Lists...)
	cp.CustomRules = append([]BlockingRule{}, cfg.CustomRules...)
	cp.Allowlist = append([]string{}, cfg.Allowlist...)
	return cp
}

func (m *FilterManager) sources(cfg FilteringConfig, replacement string, data []byte) ([]BlockSource, []string) {
	sources := make([]BlockSource, 0, len(cfg.Lists))
	var failures []string
	for _, id := range cfg.Lists {
		definition, ok := filteringList(id)
		if !ok {
			failures = append(failures, "неизвестный список "+id)
			continue
		}
		var content []byte
		var err error
		if id == replacement {
			content = data
		} else {
			content, err = m.readCache(id)
		}
		if err != nil {
			if !os.IsNotExist(err) {
				failures = append(failures, definition.Name+": "+err.Error())
			}
			continue
		}
		sources = append(sources, BlockSource{ID: id, Category: definition.Category, Data: content})
	}
	return sources, failures
}

func (m *FilterManager) readCache(id string) ([]byte, error) {
	f, err := os.Open(m.store.Path("dns-blocklists/" + id + ".txt"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("список превышает 8 МиБ")
	}
	return data, err
}

// A valid HTTP prefix can still be a truncated filter. Check each cached feed
// independently, so a damaged second feed cannot prevent repairing the first.
func (m *FilterManager) build(cfg FilteringConfig, replacement string, data []byte) (*Blocker, []string, error) {
	sources, failures := m.sources(cfg, replacement, data)
	blocker, err := NewBlockMatcher(sources, cfg.CustomRules, cfg.Allowlist)
	if err != nil {
		valid := make([]BlockSource, 0, len(sources))
		for _, source := range sources {
			_, sourceErr := NewBlockMatcher([]BlockSource{source}, nil, nil)
			if sourceErr != nil && source.ID != replacement {
				failures = append(failures, source.ID+": "+sourceErr.Error())
				continue
			}
			valid = append(valid, source)
		}
		if len(valid) == len(sources) {
			return nil, failures, err
		}
		sources = valid
		blocker, err = NewBlockMatcher(sources, cfg.CustomRules, cfg.Allowlist)
		if err != nil {
			return nil, failures, err
		}
	}
	stats := blocker.Stats()
	m.mu.Lock()
	counts := make(map[string]int, len(m.metadata))
	for id, meta := range m.metadata {
		counts[id] = meta.Rules
	}
	m.mu.Unlock()
	valid := make([]BlockSource, 0, len(sources))
	for _, source := range sources {
		count := stats.Sources[source.ID]
		if source.ID != replacement && (count < 1000 || counts[source.ID] > 0 && count < counts[source.ID]/2) {
			failures = append(failures, source.ID+": сохранённый список неполный; требуется обновление")
			continue
		}
		valid = append(valid, source)
	}
	if len(valid) != len(sources) {
		blocker, err = NewBlockMatcher(valid, cfg.CustomRules, cfg.Allowlist)
	}
	return blocker, failures, err
}

func (m *FilterManager) Configure(cfg *FilteringConfig) error {
	return m.ConfigurePersist(cfg, nil)
}

// ConfigurePersist builds before saving, so a rejected configuration changes
// neither the active matcher nor the saved DNS configuration.
func (m *FilterManager) ConfigurePersist(cfg *FilteringConfig, persist func() error) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	cp := copyFilteringConfig(cfg)
	var failures []string
	var blocker *Blocker
	var err error
	m.mu.Lock()
	unchanged := m.blocker != nil && cp.Enabled == m.cfg.Enabled && slices.Equal(cp.Lists, m.cfg.Lists) && slices.Equal(cp.CustomRules, m.cfg.CustomRules) && slices.Equal(cp.Allowlist, m.cfg.Allowlist)
	if unchanged {
		blocker = m.blocker
		if m.lastError != "" {
			failures = []string{m.lastError}
		}
	}
	m.mu.Unlock()
	if unchanged {
		// The immutable matcher can be reused for unrelated DNS edits.
	} else if cp.Enabled {
		blocker, failures, err = m.build(cp, "", nil)
	} else {
		blocker, err = NewBlockMatcher(nil, nil, nil)
	}
	if err != nil {
		return err
	}
	if persist != nil {
		if err := persist(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	if m.updateCancel != nil {
		m.updateCancel()
		m.updateCancel = nil
	}
	m.updateID++
	m.updating = false
	m.cfg, m.blocker = cp, blocker
	m.revision++
	m.lastAttempt = time.Time{}
	m.lastError = strings.Join(failures, "; ")
	stats := blocker.Stats()
	for _, id := range cp.Lists {
		if !cp.Enabled {
			break
		}
		count := stats.Sources[id]
		meta := m.metadata[id]
		meta.Rules = count
		if count == 0 {
			meta.LastUpdated = ""
		}
		m.metadata[id] = meta
	}
	m.mu.Unlock()
	return nil
}

func (m *FilterManager) Blocker() *Blocker {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return nil
	}
	return m.blocker
}

func (m *FilterManager) Status() FilteringStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := FilteringStatus{Enabled: m.cfg.Enabled, Updating: m.updating, LastError: m.lastError, Lists: []FilteringListStatus{}}
	if m.blocker != nil {
		stats := m.blocker.Stats()
		st.Rules, st.Approximate = stats.Rules, stats.Approximate
		for _, count := range stats.Ignored {
			st.IgnoredRules += count
		}
		st.Ready = st.Rules > 0
		for _, id := range m.cfg.Lists {
			if stats.Sources[id] == 0 {
				st.Ready = false
			}
		}
	}
	st.Ready = st.Ready && st.Enabled
	selected := make(map[string]bool, len(m.cfg.Lists))
	for _, id := range m.cfg.Lists {
		selected[id] = true
	}
	for _, definition := range filteringCatalog {
		meta := m.metadata[definition.ID]
		st.Lists = append(st.Lists, FilteringListStatus{FilteringListDefinition: definition, Selected: selected[definition.ID], Rules: meta.Rules, LastUpdated: meta.LastUpdated, LastError: meta.LastError})
		if selected[definition.ID] && meta.LastUpdated > st.LastUpdated {
			st.LastUpdated = meta.LastUpdated
		}
	}
	return st
}

func (m *FilterManager) due() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled || m.updating || time.Since(m.lastAttempt) < 2*time.Minute {
		return false
	}
	for _, id := range m.cfg.Lists {
		updated, err := time.Parse(time.RFC3339, m.metadata[id].LastUpdated)
		if err != nil || time.Since(updated) >= 24*time.Hour {
			return true
		}
	}
	return false
}

func (m *FilterManager) Start(ctx context.Context, resolver *Resolver) {
	m.opMu.Lock()
	m.mu.Lock()
	if m.resolver != resolver {
		if m.updateCancel != nil {
			m.updateCancel()
			m.updateCancel = nil
		}
		m.updateID++
		m.updating = false
		m.lastAttempt = time.Time{}
		m.resolver = resolver
	}
	m.mu.Unlock()
	resolver.SetBlocker(m.Blocker())
	m.opMu.Unlock()
	if m.due() {
		m.Trigger(ctx, resolver)
	}
	go func() {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if m.due() {
					m.Trigger(ctx, resolver)
				}
				timer.Reset(time.Minute)
			}
		}
	}()
}

// Trigger returns immediately. The last good matcher remains in use throughout
// network failures and compilation. Saving a new config cancels the old resolver.
func (m *FilterManager) Trigger(ctx context.Context, resolver *Resolver) bool {
	m.mu.Lock()
	if m.updating || !m.cfg.Enabled {
		m.mu.Unlock()
		return false
	}
	cfg, revision := copyFilteringConfig(&m.cfg), m.revision
	ctx, cancel := context.WithCancel(ctx)
	m.updateID++
	updateID := m.updateID
	m.updateCancel = cancel
	m.updating, m.lastAttempt = true, time.Now()
	m.mu.Unlock()
	go func() {
		defer cancel()
		var failures []string
		for _, id := range cfg.Lists {
			if ctx.Err() != nil {
				break
			}
			definition, _ := filteringList(id)
			attempt, cancel := context.WithTimeout(ctx, 90*time.Second)
			data, err := resolver.FetchFilteringSource(attempt, definition.URL)
			cancel()
			if err == nil {
				err = m.install(revision, cfg, id, data, resolver)
			}
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, context.Canceled) {
					break
				}
				message := definition.Name + ": " + err.Error()
				failures = append(failures, message)
				m.mu.Lock()
				if m.revision == revision {
					meta := m.metadata[id]
					meta.LastError = err.Error()
					m.metadata[id] = meta
				}
				m.mu.Unlock()
			}
		}
		m.mu.Lock()
		if m.updateID == updateID {
			m.updating = false
			m.updateCancel = nil
			if ctx.Err() != nil {
				m.lastAttempt = time.Time{}
			}
		}
		if m.revision == revision {
			m.lastError = strings.Join(failures, "; ")
		}
		m.mu.Unlock()
	}()
	return true
}

func (m *FilterManager) install(revision uint64, cfg FilteringConfig, id string, data []byte, resolver *Resolver) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	current := m.revision == revision
	m.mu.Unlock()
	if !current {
		return context.Canceled
	}
	if err := resolver.lifetime.Err(); err != nil {
		return err
	}
	blocker, _, err := m.build(cfg, id, data)
	if err != nil {
		return err
	}
	count := blocker.Stats().Sources[id]
	m.mu.Lock()
	previousCount := m.metadata[id].Rules
	m.mu.Unlock()
	if count < 1000 || previousCount > 0 && count < previousCount/2 {
		return fmt.Errorf("скачанный список подозрительно мал (%d правил); предыдущий список сохранён", count)
	}
	if err := resolver.lifetime.Err(); err != nil {
		return err
	}
	if err := m.store.WriteBytes("dns-blocklists/"+id+".txt", data); err != nil {
		return err
	}
	m.mu.Lock()
	m.blocker = blocker
	m.metadata[id] = filterMetadata{Rules: count, LastUpdated: time.Now().UTC().Format(time.RFC3339)}
	metadata := make(map[string]filterMetadata, len(m.metadata))
	for key, value := range m.metadata {
		metadata[key] = value
	}
	m.mu.Unlock()
	resolver.SetBlocker(blocker)
	if err := m.store.Save(filterMetadataFile, metadata); err != nil {
		return err
	}
	return nil
}
