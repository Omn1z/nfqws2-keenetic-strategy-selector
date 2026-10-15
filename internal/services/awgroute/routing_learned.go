package awgroute

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

const (
	routingLearnedFile        = "awg-routing-learned.json"
	routingLearnedLimit       = 4096
	routingLearnedRuleLimit   = 512
	routingLearnedIPLimit     = 64
	routingLearnedSourceLimit = 8
	routingLearnedNamesLimit  = 128
	routingLearnedFileLimit   = 32 << 20
)

// AWGRoutingLearnedEntry is observational history, rather than an editable
// routing source. Confirmed means every displayed IP was successfully learned
// in the current, ready policy epoch. History has no authoritative DNS TTL and
// never implies that an older address has been removed from the kernel.
type AWGRoutingLearnedEntry struct {
	Domain     string   `json:"domain"`
	IPs        []string `json:"ips"`
	SourceIPs  []string `json:"source_ips"`
	Source     string   `json:"source"`
	FirstSeen  int64    `json:"first_seen"`
	LastSeen   int64    `json:"last_seen"`
	Additional bool     `json:"additional"`
	Confirmed  bool     `json:"confirmed"`
}

// AWGRoutingLearnedRuleKey follows the rule's semantic scope. Renaming,
// reordering or temporarily disabling a rule preserves its history, whereas
// assigning another destination, device scope or matcher creates a new scope.
func AWGRoutingLearnedRuleKey(z awg.Zone) string {
	type identity struct {
		Route                string   `json:"route"`
		TunnelID             string   `json:"tunnel_id"`
		FallbackTunnelIDs    []string `json:"fallback_tunnel_ids"`
		Domains              []string `json:"domains"`
		IncludeSubdomains    *bool    `json:"include_subdomains"`
		IPs                  []string `json:"ips"`
		SourceIPs            []string `json:"source_ips"`
		WaitingForConnection bool     `json:"waiting_for_connection"`
	}
	value := identity{
		Route: z.RouteValue(), TunnelID: strings.TrimSpace(z.TunnelID),
		FallbackTunnelIDs:    normalizedLearnedIdentityItems(z.FallbackTunnelIDs, false),
		Domains:              normalizedLearnedDomainIdentityItems(z.Domains),
		IncludeSubdomains:    z.IncludeSubdomains,
		IPs:                  normalizedLearnedIdentityItems(z.IPs, true),
		SourceIPs:            normalizedLearnedIdentityItems(z.SourceIPs, true),
		WaitingForConnection: z.WaitingForConnection,
	}
	// Domains and destination/source IPs are sets within one rule. Fallback
	// order determines which connection wins and must remain significant.
	sort.Strings(value.Domains)
	sort.Strings(value.IPs)
	sort.Strings(value.SourceIPs)
	wire, _ := json.Marshal(value)
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func normalizedLearnedIdentityItems(items []string, lower bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if lower {
			item = strings.ToLower(item)
		}
		if item != "" && !seen[item] {
			out = append(out, item)
			seen[item] = true
		}
	}
	return out
}

func normalizedLearnedDomainIdentityItems(items []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		lower := strings.ToLower(item)
		isReference := false
		for _, prefix := range []string{"list:", "geosite:", "geoip:"} {
			if strings.HasPrefix(lower, prefix) {
				// List names can be case-sensitive filesystem paths. Preserve
				// reference payloads rather than merging distinct source lists.
				item = prefix + strings.TrimSpace(item[len(prefix):])
				isReference = true
				break
			}
		}
		if !isReference {
			item = lower
		}
		if item != "" && !seen[item] {
			out = append(out, item)
			seen[item] = true
		}
	}
	return out
}

type routingLearnedConfirmation struct{ generation, epoch uint64 }
type routingLearnedValue struct {
	lastSeen     int64
	touch        uint64
	confirmation routingLearnedConfirmation
	confirmed    bool
}
type routingLearnedRecord struct {
	ruleKey string
	entry   AWGRoutingLearnedEntry
	ips     map[string]routingLearnedValue
	sources map[string]routingLearnedValue
	touch   uint64
}

// The zero value is usable. Record performs no disk or network I/O. Lifecycle
// callers may periodically Flush; Load belongs before installing callbacks.
type routingLearnedHistory struct {
	restoreMu                 sync.RWMutex
	mu                        sync.Mutex
	flushMu                   sync.Mutex
	entries                   map[string]*routingLearnedRecord
	ruleCounts                map[string]int
	version, persisted, touch uint64
}

func learnedHistoryDomain(raw string) (string, bool) {
	if len(raw) > 512 {
		return "", false
	}
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	name = strings.ToLower(name)
	if err != nil || !routingHostname(name) {
		return "", false
	}
	return name, true
}

func learnedHistoryRuleKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func learnedHistoryIP(raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		return "", false
	}
	return addr.Unmap().String(), true
}

func (h *routingLearnedHistory) Record(ruleKey, domain, sourceIP string, ips []string, source string, additional bool, generation, epoch uint64, at time.Time) {
	// Restoring history must not hold up an already prepared DNS response.
	// Observations made during the short restore transaction are not retained.
	if !h.restoreMu.TryRLock() {
		return
	}
	defer h.restoreMu.RUnlock()
	if !learnedHistoryRuleKey(ruleKey) || (source != "dns" && source != "sni") {
		return
	}
	domain, valid := learnedHistoryDomain(domain)
	if !valid {
		return
	}
	if sourceIP != "" {
		if sourceIP, valid = learnedHistoryIP(sourceIP); !valid {
			return
		}
	}
	validIPs := make([]string, 0, min(len(ips), routingLearnedIPLimit))
	seen := map[string]bool{}
	for _, raw := range ips {
		ip, ok := learnedHistoryIP(raw)
		if ok && !seen[ip] {
			validIPs = append(validIPs, ip)
			seen[ip] = true
		}
		if len(validIPs) >= routingLearnedIPLimit {
			break
		}
	}
	if len(validIPs) == 0 {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	when := at.Unix()
	if when <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.entries == nil {
		h.entries = map[string]*routingLearnedRecord{}
		h.ruleCounts = map[string]int{}
	}
	key := ruleKey + "\x00" + domain
	record := h.entries[key]
	if record == nil {
		record = &routingLearnedRecord{ruleKey: ruleKey, entry: AWGRoutingLearnedEntry{Domain: domain, FirstSeen: when}, ips: map[string]routingLearnedValue{}, sources: map[string]routingLearnedValue{}}
		h.entries[key] = record
		h.ruleCounts[ruleKey]++
	}
	h.touch++
	record.touch = h.touch
	if when < record.entry.FirstSeen {
		record.entry.FirstSeen = when
	}
	if when >= record.entry.LastSeen {
		record.entry.LastSeen = when
		record.entry.Source = source
		record.entry.Additional = additional
	}
	for _, ip := range validIPs {
		previous := record.ips[ip]
		value := routingLearnedValue{lastSeen: max(when, previous.lastSeen), touch: h.touch, confirmation: routingLearnedConfirmation{generation, epoch}, confirmed: true}
		if previous.confirmed && (previous.confirmation.generation > generation || (previous.confirmation.generation == generation && previous.confirmation.epoch > epoch)) {
			value.confirmation = previous.confirmation
		}
		record.ips[ip] = value
	}
	trimLearnedValues(record.ips, routingLearnedIPLimit)
	if sourceIP != "" {
		previous := record.sources[sourceIP]
		record.sources[sourceIP] = routingLearnedValue{lastSeen: max(when, previous.lastSeen), touch: h.touch}
		trimLearnedValues(record.sources, routingLearnedSourceLimit)
	}
	if h.ruleCounts[ruleKey] > routingLearnedRuleLimit {
		h.evictLocked(ruleKey)
	}
	if len(h.entries) > routingLearnedLimit {
		h.evictLocked("")
	}
	h.version++
}

func trimLearnedValues(values map[string]routingLearnedValue, limit int) {
	for len(values) > limit {
		oldest := ""
		var prior routingLearnedValue
		for key, value := range values {
			if oldest == "" || value.lastSeen < prior.lastSeen || (value.lastSeen == prior.lastSeen && (value.touch < prior.touch || (value.touch == prior.touch && key < oldest))) {
				oldest, prior = key, value
			}
		}
		delete(values, oldest)
	}
}

func (h *routingLearnedHistory) evictLocked(ruleKey string) {
	oldest := ""
	var prior *routingLearnedRecord
	for key, record := range h.entries {
		if ruleKey != "" && record.ruleKey != ruleKey {
			continue
		}
		if prior == nil || record.entry.LastSeen < prior.entry.LastSeen || (record.entry.LastSeen == prior.entry.LastSeen && (record.touch < prior.touch || (record.touch == prior.touch && key < oldest))) {
			oldest, prior = key, record
		}
	}
	delete(h.entries, oldest)
	if prior != nil {
		h.ruleCounts[prior.ruleKey]--
		if h.ruleCounts[prior.ruleKey] == 0 {
			delete(h.ruleCounts, prior.ruleKey)
		}
	}
}

func (h *routingLearnedHistory) Snapshot(ruleKey string, generation, epoch uint64, ready bool) []AWGRoutingLearnedEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []AWGRoutingLearnedEntry{}
	for _, record := range h.entries {
		if record.ruleKey != ruleKey {
			continue
		}
		entry := record.entry
		entry.IPs = make([]string, 0, len(record.ips))
		entry.SourceIPs = make([]string, 0, len(record.sources))
		entry.Confirmed = ready && len(record.ips) > 0
		for ip, value := range record.ips {
			entry.IPs = append(entry.IPs, ip)
			entry.Confirmed = entry.Confirmed && value.confirmed && value.confirmation.generation == generation && value.confirmation.epoch == epoch
		}
		for ip := range record.sources {
			entry.SourceIPs = append(entry.SourceIPs, ip)
		}
		sort.Strings(entry.IPs)
		sort.Strings(entry.SourceIPs)
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

func (h *routingLearnedHistory) Names(ruleKey string) []string {
	h.mu.Lock()
	entries := []AWGRoutingLearnedEntry{}
	for _, record := range h.entries {
		if record.ruleKey == ruleKey {
			entries = append(entries, AWGRoutingLearnedEntry{Domain: record.entry.Domain, LastSeen: record.entry.LastSeen})
		}
	}
	h.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].LastSeen != entries[j].LastSeen {
			return entries[i].LastSeen > entries[j].LastSeen
		}
		return entries[i].Domain < entries[j].Domain
	})
	out := make([]string, 0, min(len(entries), routingLearnedNamesLimit))
	for _, entry := range entries {
		out = append(out, entry.Domain)
		if len(out) >= routingLearnedNamesLimit {
			break
		}
	}
	return out
}

// AllNames supplies only candidate hostnames for fresh resolution. A caller
// must revalidate them against the current ordered rule policy: their former
// rule ownership is not permission to install an address into a new scope.
func (h *routingLearnedHistory) AllNames() []string {
	h.mu.Lock()
	latest := make(map[string]int64, len(h.entries))
	for _, record := range h.entries {
		if record.entry.LastSeen > latest[record.entry.Domain] {
			latest[record.entry.Domain] = record.entry.LastSeen
		}
	}
	h.mu.Unlock()
	out := make([]string, 0, min(len(latest), routingLearnedLimit))
	for name := range latest {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		if latest[out[i]] != latest[out[j]] {
			return latest[out[i]] > latest[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > routingLearnedLimit {
		out = out[:routingLearnedLimit]
	}
	return out
}

// The persistence format deliberately has no generation, epoch or confirmation
// fields. A successful install in a previous process proves nothing about the
// current kernel policy, even when its generation counter also starts at zero.
type routingLearnedSavedEntry struct {
	RuleKey    string   `json:"rule_key"`
	Domain     string   `json:"domain"`
	IPs        []string `json:"ips"`
	SourceIPs  []string `json:"source_ips"`
	Source     string   `json:"source"`
	FirstSeen  int64    `json:"first_seen"`
	LastSeen   int64    `json:"last_seen"`
	Additional bool     `json:"additional"`
}
type routingLearnedDocument struct {
	Version int                        `json:"version"`
	Entries []routingLearnedSavedEntry `json:"entries"`
}

func (h *routingLearnedHistory) Load(st *store.Store) error {
	if st == nil {
		return nil
	}
	h.restoreMu.RLock()
	defer h.restoreMu.RUnlock()
	h.flushMu.Lock()
	defer h.flushMu.Unlock()
	return h.loadLocked(st, false)
}

// loadLocked requires the persistence lock. Restore also holds restoreMu for
// the archive write and replacement, so no older flush can cross the boundary.
func (h *routingLearnedHistory) loadLocked(st *store.Store, replaceMissing bool) error {
	file, err := os.Open(st.Path(routingLearnedFile))
	if errors.Is(err, os.ErrNotExist) {
		if replaceMissing {
			h.replaceLoaded(new(routingLearnedHistory))
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, routingLearnedFileLimit+1))
	if err != nil {
		return err
	}
	if len(wire) > routingLearnedFileLimit {
		return fmt.Errorf("AWG learned route history is too large")
	}
	var document routingLearnedDocument
	if err := json.Unmarshal(wire, &document); err != nil {
		return err
	}
	if document.Version != 1 {
		return fmt.Errorf("unsupported AWG learned route history version %d", document.Version)
	}
	sort.SliceStable(document.Entries, func(i, j int) bool {
		a, b := document.Entries[i], document.Entries[j]
		if a.LastSeen != b.LastSeen {
			return a.LastSeen < b.LastSeen
		}
		return a.RuleKey+"\x00"+a.Domain < b.RuleKey+"\x00"+b.Domain
	})
	var loaded routingLearnedHistory
	for _, entry := range document.Entries {
		at := time.Unix(entry.LastSeen, 0)
		loaded.Record(entry.RuleKey, entry.Domain, "", entry.IPs, entry.Source, entry.Additional, 0, 0, at)
		for _, sourceIP := range entry.SourceIPs {
			loaded.Record(entry.RuleKey, entry.Domain, sourceIP, entry.IPs, entry.Source, entry.Additional, 0, 0, at)
		}
		if name, valid := learnedHistoryDomain(entry.Domain); valid {
			if record := loaded.entries[entry.RuleKey+"\x00"+name]; record != nil && entry.FirstSeen > 0 && entry.FirstSeen <= entry.LastSeen {
				record.entry.FirstSeen = min(record.entry.FirstSeen, entry.FirstSeen)
			}
		}
	}
	for _, record := range loaded.entries {
		for ip, value := range record.ips {
			value.confirmed = false
			value.confirmation = routingLearnedConfirmation{}
			record.ips[ip] = value
		}
	}
	h.replaceLoaded(&loaded)
	return nil
}

func (h *routingLearnedHistory) replaceLoaded(loaded *routingLearnedHistory) {
	h.mu.Lock()
	h.entries, h.ruleCounts, h.touch = loaded.entries, loaded.ruleCounts, loaded.touch
	h.version++
	h.persisted = h.version
	h.mu.Unlock()
}

// Restore serializes archive replacement with delayed and shutdown writes.
// Failure keeps live memory intact and rolls back this history file even if
// the archive failed after truncating it. Other backup files retain Restore's
// existing behavior; no routing policy or kernel state is applied here.
func (h *routingLearnedHistory) Restore(st *store.Store, restore func() (int, error)) (int, error) {
	if st == nil {
		return restore()
	}
	h.restoreMu.Lock()
	defer h.restoreMu.Unlock()
	h.flushMu.Lock()
	defer h.flushMu.Unlock()
	path := st.Path(routingLearnedFile)
	var previous []byte
	var mode os.FileMode
	present := false
	file, err := os.Open(path)
	if err == nil {
		info, statErr := file.Stat()
		if statErr == nil && (!info.Mode().IsRegular() || info.Size() > routingLearnedFileLimit) {
			statErr = fmt.Errorf("invalid AWG learned route history file")
		}
		if statErr == nil {
			previous, statErr = io.ReadAll(io.LimitReader(file, routingLearnedFileLimit+1))
			mode = info.Mode().Perm()
			if len(previous) > routingLearnedFileLimit {
				statErr = fmt.Errorf("AWG learned route history is too large")
			}
		}
		file.Close()
		if statErr != nil {
			return 0, statErr
		}
		present = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	n, err := restore()
	if err == nil {
		err = h.loadLocked(st, true)
	}
	if err == nil {
		return n, nil
	}
	var rollbackErr error
	if present {
		rollbackErr = st.WriteBytes(routingLearnedFile, previous)
		if rollbackErr == nil {
			rollbackErr = os.Chmod(path, mode)
		}
	} else {
		rollbackErr = os.Remove(path)
		if errors.Is(rollbackErr, os.ErrNotExist) {
			rollbackErr = nil
		}
	}
	return n, errors.Join(err, rollbackErr)
}

func (h *routingLearnedHistory) Flush(st *store.Store) error {
	if st == nil {
		return nil
	}
	h.restoreMu.RLock()
	defer h.restoreMu.RUnlock()
	h.flushMu.Lock()
	defer h.flushMu.Unlock()
	h.mu.Lock()
	if h.version == h.persisted {
		h.mu.Unlock()
		return nil
	}
	version := h.version
	document := routingLearnedDocument{Version: 1, Entries: make([]routingLearnedSavedEntry, 0, len(h.entries))}
	for _, record := range h.entries {
		entry := record.entry
		item := routingLearnedSavedEntry{RuleKey: record.ruleKey, Domain: entry.Domain, IPs: []string{}, SourceIPs: []string{}, Source: entry.Source, FirstSeen: entry.FirstSeen, LastSeen: entry.LastSeen, Additional: entry.Additional}
		for ip := range record.ips {
			item.IPs = append(item.IPs, ip)
		}
		for ip := range record.sources {
			item.SourceIPs = append(item.SourceIPs, ip)
		}
		sort.Strings(item.IPs)
		sort.Strings(item.SourceIPs)
		document.Entries = append(document.Entries, item)
	}
	h.mu.Unlock()
	sort.Slice(document.Entries, func(i, j int) bool {
		return document.Entries[i].RuleKey+"\x00"+document.Entries[i].Domain < document.Entries[j].RuleKey+"\x00"+document.Entries[j].Domain
	})
	if err := st.SaveSecret(routingLearnedFile, &document); err != nil {
		return err
	}
	h.mu.Lock()
	h.persisted = version // New observations remain dirty for the next Flush.
	h.mu.Unlock()
	return nil
}
