package dnsserver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

const (
	BlockCategoryAds      = "ads"
	BlockCategoryTrackers = "trackers"
	BlockCategoryMixed    = "mixed"
	customBlockSource     = "custom"
	netseerLabelSuffix    = "-netseer-ipaddr-assoc"
)

// BlockSource is one downloaded list. The downloader supplies its catalog ID
// and category; unsupported list syntax is ignored rather than guessed.
type BlockSource struct {
	ID       string
	Category string
	Data     []byte
}

type BlockMatch struct {
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Source   string `json:"source"`
}

type BlockMatcherStats struct {
	Rules   int            `json:"rules"`
	Sources map[string]int `json:"sources"`
	// Ignored counts non-comment source lines not loaded by the DNS engine.
	// Loaded AdGuard rules include exceptions, badfilter directives and duplicates.
	Ignored     map[string]int `json:"ignored"`
	Approximate bool           `json:"approximate,omitempty"`
}

type blockEntry struct {
	BlockMatch
	custom bool
}

type blockSnapshot struct {
	domains         map[string]blockEntry
	subdomains      map[string]blockEntry // *.example.com does not include example.com
	netseer         map[string]blockEntry // bounded pattern, one label beneath xy/xz.fbcdn.net
	allow           map[string]struct{}   // explicit user allowlist always wins
	sourceAllow     map[string]struct{}   // downloaded exceptions yield to custom blocks
	adguard         *urlfilter.DNSEngine
	adguardID       string
	adguardCategory string
	adguardHash     [sha256.Size]byte
	stats           BlockMatcherStats
}

// Blocker swaps fully compiled, immutable rule sets. A DNS lookup only loads
// one pointer and reads maps that are never changed after publication.
type Blocker struct{ snapshot atomic.Pointer[blockSnapshot] }

func NewBlockMatcher(sources []BlockSource, custom []BlockingRule, allow []string) (*Blocker, error) {
	return newBlockMatcher(sources, custom, allow, nil)
}

// newBlockMatcher builds a separate snapshot while sharing an unchanged
// downloaded AdGuard engine with the last good matcher.
func newBlockMatcher(sources []BlockSource, custom []BlockingRule, allow []string, previous *Blocker) (*Blocker, error) {
	b := &Blocker{}
	var prior *blockSnapshot
	if previous != nil {
		prior = previous.snapshot.Load()
	}
	if err := b.replace(sources, custom, allow, prior); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Blocker) Replace(sources []BlockSource, custom []BlockingRule, allow []string) error {
	if b == nil {
		return fmt.Errorf("DNS blocker is nil")
	}
	return b.replace(sources, custom, allow, b.snapshot.Load())
}

func (b *Blocker) replace(sources []BlockSource, custom []BlockingRule, allow []string, previous *blockSnapshot) error {
	snap := &blockSnapshot{
		domains:     make(map[string]blockEntry),
		subdomains:  make(map[string]blockEntry),
		netseer:     make(map[string]blockEntry),
		allow:       make(map[string]struct{}),
		sourceAllow: make(map[string]struct{}),
		stats:       BlockMatcherStats{Sources: make(map[string]int), Ignored: make(map[string]int)},
	}
	if len(sources) > 3 {
		return fmt.Errorf("не более трёх списков DNS-блокировки")
	}
	seenIDs := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if len(source.Data) > 8<<20 {
			return fmt.Errorf("список DNS-блокировки %s превышает 8 МиБ", source.ID)
		}
		id := strings.TrimSpace(source.ID)
		if id == "" || len(id) > 100 {
			return fmt.Errorf("неверный ID списка DNS-блокировки")
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return fmt.Errorf("повторяется ID списка DNS-блокировки %s", id)
		}
		seenIDs[id] = struct{}{}
		category, err := blockCategory(source.Category, BlockCategoryMixed)
		if err != nil {
			return fmt.Errorf("список %s: %w", id, err)
		}
		if id == "adguard-dns" {
			snap.adguardHash = sha256.Sum256(source.Data)
			if previous != nil && previous.adguard != nil && previous.adguardID == id && previous.adguardHash == snap.adguardHash {
				snap.adguard = previous.adguard
				snap.stats.Sources[id] = previous.stats.Sources[id]
				if ignored := previous.stats.Ignored[id]; ignored > 0 {
					snap.stats.Ignored[id] = ignored
				}
			} else {
				// This engine owns only the AdGuard source, so its list ID is
				// independent of the order of other selected feeds.
				list := filterlist.NewString(&filterlist.StringConfig{RulesText: string(source.Data), ID: rules.ListID(1), IgnoreCosmetic: true})
				storage, err := filterlist.NewRuleStorage([]filterlist.Interface{list})
				if err != nil {
					return fmt.Errorf("список %s: %w", id, err)
				}
				// String storage owns no files. Engine references keep it alive
				// until every snapshot and in-flight lookup releases the engine.
				snap.adguard = urlfilter.NewDNSEngine(storage)
				count := int(snap.adguard.RulesCount())
				snap.stats.Sources[id] = count
				if candidates := countRuleLines(source.Data); candidates > count {
					snap.stats.Ignored[id] = candidates - count
				}
			}
			snap.adguardID, snap.adguardCategory = id, category
			continue
		}
		seen := make(map[string]struct{})
		addDomain := func(domain string) error {
			if _, duplicate := seen[domain]; duplicate {
				return nil
			}
			seen[domain] = struct{}{}
			snap.stats.Sources[id]++
			snap.add(domain, blockEntry{BlockMatch: BlockMatch{Category: category, Rule: domain, Source: id}})
			if len(snap.domains)+len(snap.subdomains) > 500000 {
				return fmt.Errorf("не более 500000 правил DNS-блокировки")
			}
			return nil
		}
		scanner := bufio.NewScanner(bytes.NewReader(source.Data))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
				continue
			}
			if cleaned, safe := stripBlockInlineComment(line); safe {
				line = cleaned
			} else {
				snap.stats.Ignored[id]++
				continue
			}
			fields := strings.Fields(line)
			if len(fields) > 2 {
				if ip := net.ParseIP(fields[0]); ip != nil && isSinkholeIP(ip) {
					for _, host := range fields[1:] {
						domain, err := normalizeDomain(host)
						if err != nil || !strings.Contains(domain, ".") {
							snap.stats.Ignored[id]++
							continue
						}
						if err := addDomain(domain); err != nil {
							return err
						}
					}
					continue
				}
			}
			domain, exception, ok := parseBlockLine(line)
			if !ok {
				snap.stats.Ignored[id]++
				continue
			}
			if exception {
				snap.sourceAllow[domain] = struct{}{}
				continue
			}
			if err := addDomain(domain); err != nil {
				return err
			}
		}
		if len(snap.domains)+len(snap.subdomains) > 500000 {
			return fmt.Errorf("не более 500000 правил DNS-блокировки")
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("чтение списка %s: %w", id, err)
		}
	}
	for _, rule := range custom {
		domain, kind, err := normalizeBlockingPattern(rule.Domain)
		if err != nil {
			return err
		}
		category, err := blockCategory(rule.Category, BlockCategoryTrackers)
		if err != nil {
			return fmt.Errorf("правило %s: %w", domain, err)
		}
		entry := blockEntry{BlockMatch: BlockMatch{Category: category, Rule: domain, Source: customBlockSource}, custom: true}
		key := domain
		switch kind {
		case "subdomains":
			key = strings.TrimPrefix(domain, "*.")
			if _, exists := snap.subdomains[key]; !exists {
				snap.stats.Sources[customBlockSource]++
			}
			snap.subdomains[key] = entry
		case "netseer":
			parent := strings.TrimPrefix(domain, "*"+netseerLabelSuffix+".")
			if _, exists := snap.netseer[parent]; !exists {
				snap.stats.Sources[customBlockSource]++
			}
			snap.netseer[parent] = entry
		default:
			if old, exists := snap.domains[key]; !exists || !old.custom {
				snap.stats.Sources[customBlockSource]++
			}
			snap.add(key, entry)
		}
	}
	for _, raw := range allow {
		domain, err := normalizeAllowDomain(raw)
		if err != nil {
			return fmt.Errorf("разрешённый домен %q: %w", raw, err)
		}
		snap.allow[domain] = struct{}{}
	}
	snap.stats.Rules = len(snap.domains) + len(snap.subdomains)
	snap.stats.Rules += len(snap.netseer)
	if snap.adguard != nil {
		// AdGuard's engine reports active rules, including its exceptions.
		// Cross-engine domain overlap cannot be deduplicated without changing
		// AdGuard matching semantics, so this combined total is approximate.
		snap.stats.Rules += int(snap.adguard.RulesCount())
		snap.stats.Approximate = true
	}
	if snap.stats.Rules > 500000 {
		return fmt.Errorf("не более 500000 правил DNS-блокировки")
	}
	b.snapshot.Store(snap)
	return nil
}

func (s *blockSnapshot) add(domain string, entry blockEntry) {
	old, exists := s.domains[domain]
	if !exists || entry.custom && !old.custom {
		s.domains[domain] = entry
		return
	}
	if old.custom && !entry.custom {
		return
	}
	old.Category = combineBlockCategories(old.Category, entry.Category)
	s.domains[domain] = old
}

func combineBlockCategories(a, b string) string {
	if a == b {
		return a
	}
	return BlockCategoryMixed
}

func blockCategory(raw, fallback string) (string, error) {
	category := strings.TrimSpace(raw)
	if category == "" {
		category = fallback
	}
	switch category {
	case BlockCategoryAds, BlockCategoryTrackers, BlockCategoryMixed:
		return category, nil
	default:
		return "", fmt.Errorf("категория DNS-блокировки должна быть ads, trackers или mixed")
	}
}

func normalizeBlockingPattern(raw string) (domain, kind string, err error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "*"+netseerLabelSuffix+".xy.fbcdn.net" || value == "*"+netseerLabelSuffix+".xz.fbcdn.net" {
		return value, "netseer", nil
	}
	if strings.HasPrefix(value, "*.") {
		parent, e := normalizeDomain(strings.TrimPrefix(value, "*."))
		if e != nil {
			return "", "", fmt.Errorf("неверное правило DNS-блокировки %q: %w", raw, e)
		}
		return "*." + parent, "subdomains", nil
	}
	if strings.Contains(value, "*") {
		return "", "", fmt.Errorf("неподдерживаемый шаблон DNS-блокировки %q", raw)
	}
	domain, err = normalizeDomain(value)
	if err != nil {
		return "", "", fmt.Errorf("неверное правило DNS-блокировки %q: %w", raw, err)
	}
	return domain, "domain", nil
}

func normalizeAllowDomain(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	// Allow rules already cover the apex and every subdomain. Accept the
	// familiar *.example.com spelling as the same bounded suffix rule.
	value = strings.TrimPrefix(value, "*.")
	return normalizeDomain(value)
}

func normalizeFilteringConfig(cfg *FilteringConfig) error {
	if len(cfg.CustomRules) > 2000 || len(cfg.Allowlist) > 2000 {
		return fmt.Errorf("слишком много пользовательских правил DNS-блокировки")
	}
	seenLists := make(map[string]struct{}, len(cfg.Lists))
	lists := make([]string, 0, len(cfg.Lists))
	for _, raw := range cfg.Lists {
		id := strings.TrimSpace(raw)
		if id == "" || len(id) > 100 {
			return fmt.Errorf("неверный ID списка DNS-блокировки")
		}
		// Migrate previously supported feeds so their removal does not reject
		// saved DNS settings. Unrecognized IDs still fail validation below.
		switch id {
		case "hagezi-light", "hagezi-normal", "hagezi-pro", "oisd-small", "blocklist-ads", "blocklist-tracking":
			id = "adguard-dns"
		}
		if _, ok := filteringList(id); !ok {
			return fmt.Errorf("неизвестный список DNS-блокировки %q", id)
		}
		if _, exists := seenLists[id]; !exists {
			seenLists[id] = struct{}{}
			lists = append(lists, id)
		}
	}
	cfg.Lists = lists
	for i := range cfg.CustomRules {
		value, _, err := normalizeBlockingPattern(cfg.CustomRules[i].Domain)
		if err != nil {
			return err
		}
		category, err := blockCategory(cfg.CustomRules[i].Category, BlockCategoryTrackers)
		if err != nil {
			return err
		}
		cfg.CustomRules[i] = BlockingRule{Domain: value, Category: category}
	}
	seenAllow := make(map[string]struct{}, len(cfg.Allowlist))
	allow := make([]string, 0, len(cfg.Allowlist))
	for _, raw := range cfg.Allowlist {
		domain, err := normalizeAllowDomain(raw)
		if err != nil {
			return fmt.Errorf("разрешённый домен %q: %w", raw, err)
		}
		if _, exists := seenAllow[domain]; !exists {
			seenAllow[domain] = struct{}{}
			allow = append(allow, domain)
		}
	}
	cfg.Allowlist = allow
	return nil
}

// parseBlockLine accepts only domain lists, sinkhole hosts records and the
// unmodified ABP ||domain^ form (including @@ exceptions).
func parseBlockLine(raw string) (domain string, exception, ok bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
		return "", false, false
	}
	if strings.HasPrefix(line, "@@||") || strings.HasPrefix(line, "||") {
		exception = strings.HasPrefix(line, "@@||")
		if exception {
			line = strings.TrimPrefix(line, "@@||")
		} else {
			line = strings.TrimPrefix(line, "||")
		}
		if !strings.HasSuffix(line, "^") || strings.Count(line, "^") != 1 {
			return "", false, false
		}
		line = strings.TrimSuffix(line, "^")
	} else {
		var safe bool
		line, safe = stripBlockInlineComment(line)
		if !safe {
			return "", false, false
		}
		fields := strings.Fields(line)
		if len(fields) > 1 {
			ip := net.ParseIP(fields[0])
			if ip == nil || !isSinkholeIP(ip) {
				return "", false, false
			}
			// Multiple hosts after one sinkhole address are accepted by the
			// caller only when provided on separate lines; guessing can block
			// unrelated trailing tokens in malformed input.
			if len(fields) != 2 {
				return "", false, false
			}
			line = fields[1]
		} else if len(fields) != 1 {
			return "", false, false
		}
	}
	if strings.ContainsAny(line, "*/|@$^~?=#") || net.ParseIP(line) != nil {
		return "", false, false
	}
	domain, err := normalizeDomain(line)
	return domain, exception, err == nil && strings.Contains(domain, ".")
}

func stripBlockInlineComment(line string) (string, bool) {
	i := strings.IndexByte(line, '#')
	if i < 0 {
		return line, true
	}
	if i == 0 || line[i-1] != ' ' && line[i-1] != '\t' {
		return "", false
	}
	return strings.TrimSpace(line[:i]), true
}

func countRuleLines(data []byte) int {
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") && !strings.HasPrefix(line, "[") {
			count++
		}
	}
	return count
}

func isSinkholeIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}

func (b *Blocker) Match(raw string) (BlockMatch, bool) {
	return b.MatchDNS(raw, 0)
}

// MatchDNS applies DNS-type modifiers in AdGuard rules when a real question
// type is available. Match is retained for domain-only diagnostics.
func (b *Blocker) MatchDNS(raw string, qtype uint16) (BlockMatch, bool) {
	return b.matchDNS(raw, qtype, false)
}

func (b *Blocker) matchDNS(raw string, qtype uint16, answer bool) (BlockMatch, bool) {
	match, blocked, _ := b.evaluateDNS(raw, qtype, answer)
	return match, blocked
}

// evaluateDNS distinguishes an exception from a domain with no matching rule.
// Response filtering uses the exception to permit the complete original answer.
func (b *Blocker) evaluateDNS(raw string, qtype uint16, answer bool) (BlockMatch, bool, bool) {
	if b == nil {
		return BlockMatch{}, false, false
	}
	snap := b.snapshot.Load()
	if snap == nil {
		return BlockMatch{}, false, false
	}
	domain, ok := normalizedLookupDomain(raw)
	if !ok && answer {
		if ip := net.ParseIP(raw); ip != nil {
			domain, ok = ip.String(), true
		}
	}
	if !ok {
		return BlockMatch{}, false, false
	}
	for suffix := domain; ; {
		if _, allowed := snap.allow[suffix]; allowed {
			return BlockMatch{}, false, true
		}
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			break
		}
		suffix = suffix[i+1:]
	}
	var list, custom blockEntry
	hasList, hasCustom := false, false
	for suffix, isChild := domain, false; ; {
		if entry, found := snap.domains[suffix]; found {
			if entry.custom && !hasCustom {
				custom, hasCustom = entry, true
			} else if !entry.custom && !hasList {
				list, hasList = entry, true
			}
		}
		if isChild {
			if entry, found := snap.subdomains[suffix]; found && !hasCustom {
				custom, hasCustom = entry, true
			}
		}
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			break
		}
		suffix, isChild = suffix[i+1:], true
	}
	if len(snap.netseer) > 0 {
		label, parent, hasParent := strings.Cut(domain, ".")
		if entry, found := snap.netseer[parent]; hasParent && found && strings.HasSuffix(label, netseerLabelSuffix) && len(label) > len(netseerLabelSuffix) {
			if !hasCustom || custom.Rule != domain {
				custom, hasCustom = entry, true
			}
		}
	}
	if hasCustom {
		return custom.BlockMatch, true, false
	}
	for suffix := domain; ; {
		if _, allowed := snap.sourceAllow[suffix]; allowed {
			return BlockMatch{}, false, true
		}
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			break
		}
		suffix = suffix[i+1:]
	}
	if snap.adguard != nil {
		result, _ := snap.adguard.MatchRequest(&urlfilter.DNSRequest{Hostname: domain, DNSType: qtype, Answer: answer})
		if result.NetworkRule != nil {
			if result.NetworkRule.Whitelist {
				return BlockMatch{}, false, true
			}
			match := BlockMatch{Category: snap.adguardCategory, Rule: result.NetworkRule.Text(), Source: snap.adguardID}
			if hasList {
				match.Category = combineBlockCategories(match.Category, list.Category)
			}
			return match, true, false
		}
		for _, hostRule := range result.HostRulesV4 {
			if hostRule.IP.IsUnspecified() || hostRule.IP.IsLoopback() {
				return BlockMatch{Category: snap.adguardCategory, Rule: hostRule.Text(), Source: snap.adguardID}, true, false
			}
		}
		for _, hostRule := range result.HostRulesV6 {
			if hostRule.IP.IsUnspecified() || hostRule.IP.IsLoopback() {
				return BlockMatch{Category: snap.adguardCategory, Rule: hostRule.Text(), Source: snap.adguardID}, true, false
			}
		}
	}
	if hasList {
		return list.BlockMatch, true, false
	}
	return BlockMatch{}, false, false
}

// ASCII DNS queries use a zero-allocation fast path. Unicode source rules and
// direct callers still receive the same IDNA normalization as configuration.
func normalizedLookupDomain(raw string) (string, bool) {
	domain := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if len(domain) == 0 || len(domain) > 253 {
		return "", false
	}
	labelStart, ascii := 0, true
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c >= 128 {
			ascii = false
			break
		}
		if c == '.' {
			if i == labelStart || i-labelStart > 63 || domain[labelStart] == '-' || domain[i-1] == '-' {
				return "", false
			}
			labelStart = i + 1
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false
		}
	}
	if !ascii {
		normalized, err := normalizeDomain(domain)
		return normalized, err == nil
	}
	if len(domain)-labelStart == 0 || len(domain)-labelStart > 63 || domain[labelStart] == '-' || domain[len(domain)-1] == '-' {
		return "", false
	}
	return strings.ToLower(domain), true
}

func (b *Blocker) Stats() BlockMatcherStats {
	if b == nil {
		return BlockMatcherStats{Sources: map[string]int{}, Ignored: map[string]int{}}
	}
	snap := b.snapshot.Load()
	if snap == nil {
		return BlockMatcherStats{Sources: map[string]int{}, Ignored: map[string]int{}}
	}
	stats := BlockMatcherStats{Rules: snap.stats.Rules, Sources: make(map[string]int, len(snap.stats.Sources)), Ignored: make(map[string]int, len(snap.stats.Ignored)), Approximate: snap.stats.Approximate}
	for id, count := range snap.stats.Sources {
		stats.Sources[id] = count
	}
	for id, count := range snap.stats.Ignored {
		stats.Ignored[id] = count
	}
	return stats
}
