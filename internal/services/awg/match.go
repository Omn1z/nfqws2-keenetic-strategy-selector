package awg

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DomainMatcher matches a queried DNS name against one user zone entry. The
// format is auto-detected from the entry text:
//
//   - "[re] <regexp>"      → Go regular expression over the full lowercased name
//     (e.g. "[re]^.*\\.googlevideo\\.com$").
//   - contains '*' or '#'  → glob: '*' = any run of characters (incl. none),
//     '#' = exactly one character. The pattern is anchored
//     to the whole name (e.g. "*main.com", "server*",
//     "test##.com" → test + 2 chars + ".com").
//   - plain "domain.com"   → the domain itself AND every subdomain
//     (domain.com and *.domain.com).
//
// Matching is case-insensitive and ignores a trailing dot on the queried name.
type DomainMatcher struct {
	Raw  string         // original entry, for display
	re   *regexp.Regexp // compiled (for [re] and glob)
	base string         // lowercased domain (for the plain form)
}

const reMatcherPrefix = "[re]"

// NewDomainMatcher parses one zone entry into a matcher.
func NewDomainMatcher(pattern string) (DomainMatcher, error) {
	m := DomainMatcher{Raw: pattern}
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return m, fmt.Errorf("пустой шаблон домена")
	}
	switch {
	case strings.HasPrefix(p, reMatcherPrefix):
		expr := strings.TrimSpace(strings.TrimPrefix(p, reMatcherPrefix))
		if expr == "" {
			return m, fmt.Errorf("пустое регулярное выражение")
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return m, fmt.Errorf("некорректное регулярное выражение: %w", err)
		}
		m.re = re
	case strings.ContainsAny(p, "*#"):
		m.re = globToRegexp(p)
	default:
		m.base = strings.TrimPrefix(p, ".")
	}
	return m, nil
}

// globToRegexp turns a '*'/'#' glob into an anchored, case-insensitive-safe
// regexp ('*' → ".*", '#' → ".", everything else literal).
func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '#':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	// glob is already lowercased by the caller; names are lowercased in Match.
	return regexp.MustCompile(b.String())
}

// Match reports whether the queried DNS name matches this entry. Slow path:
// normalizes (lowercase + trim) every call. The hot path callers (MatchAny,
// AnyMatch on big slices) should normalize the name ONCE and use matchLower.
func (m DomainMatcher) Match(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	return m.matchLower(n)
}

// matchLower runs the actual check against an already-normalized name. Avoids
// the per-matcher lowercase that previously turned MatchAny into O(N×len(name))
// string conversions, and avoids the `"." + m.base` concatenation that
// allocated a fresh string per plain-domain check.
func (m DomainMatcher) matchLower(n string) bool {
	if n == "" {
		return false
	}
	if m.re != nil {
		return m.re.MatchString(n)
	}
	if m.base == "" {
		return false
	}
	if n == m.base {
		return true
	}
	// Suffix check without the `"." + m.base` concat: the previous form was
	// allocating one string per matcher per query.
	bl := len(m.base)
	if len(n) <= bl {
		return false
	}
	return n[len(n)-bl-1] == '.' && n[len(n)-bl:] == m.base
}

// CompileMatchers parses a list of zone entries, skipping (and reporting) bad
// ones rather than failing the whole set.
func CompileMatchers(entries []string) (ms []DomainMatcher, bad []string) {
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		if m, err := NewDomainMatcher(e); err == nil {
			ms = append(ms, m)
		} else {
			bad = append(bad, e)
		}
	}
	return ms, bad
}

// normalizedName lowercases, trims whitespace and a trailing dot. Shared by
// the hot-path matchers that need to filter without going through
// DomainMatcher.Match's per-call normalization.
func normalizedName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(n, ".")
}

// SuffixTrie is a byte-trie keyed on REVERSED plain-domain bases. It lets us
// answer "does name match ANY of N plain patterns?" in O(len(name)) instead of
// O(N × len(name)). Plain semantics: pattern "abr.ru" matches "abr.ru" itself
// AND any subdomain (e.g. "x.abr.ru"). The boundary check guards mid-label
// false positives: "barbr.ru" must NOT match "abr.ru".
type SuffixTrie struct {
	children map[byte]*SuffixTrie
	isEnd    bool
}

func newSuffixTrie() *SuffixTrie {
	return &SuffixTrie{children: make(map[byte]*SuffixTrie)}
}

// addBase inserts a lowercased plain base into the trie. Walks the bytes
// right-to-left so a query can be matched suffix-first.
func (t *SuffixTrie) addBase(base string) {
	if base == "" {
		return
	}
	cur := t
	for i := len(base) - 1; i >= 0; i-- {
		ch := base[i]
		nxt, ok := cur.children[ch]
		if !ok {
			nxt = newSuffixTrie()
			cur.children[ch] = nxt
		}
		cur = nxt
	}
	cur.isEnd = true
}

// match reports whether name is covered by any inserted base. name must be
// already lowercased (caller normalizes once).
func (t *SuffixTrie) match(name string) bool {
	if t == nil || len(name) == 0 {
		return false
	}
	cur := t
	for i := len(name) - 1; i >= 0; i-- {
		ch := name[i]
		nxt, ok := cur.children[ch]
		if !ok {
			return false
		}
		cur = nxt
		if cur.isEnd {
			// Boundary check: the byte preceding the matched suffix must be a
			// label separator or end-of-name. Otherwise we'd accept patterns
			// like "abr.ru" matching "barbr.ru".
			if i == 0 || name[i-1] == '.' {
				return true
			}
		}
	}
	return false
}

// MatcherSet pairs a SuffixTrie (for plain patterns) with a residual slice of
// regex/glob matchers that can't easily live in a trie. CompileMatcherSet
// builds it from raw zone entries and drops patterns that are already covered
// by a broader entry — so configurations like ["regexp:\\.ru$", "domain:vk.ru"]
// collapse to just the regex.
type MatcherSet struct {
	Trie       *SuffixTrie
	Regexes    []DomainMatcher // [re]+glob entries only
	plainCount int             // number of plain entries kept post-dedup
}

// MatchAny is the hot-path matcher: one normalized lowercased pass, one
// O(len(name)) trie walk, then a fallback iteration over the (small) regex set.
func (s *MatcherSet) MatchAny(name string) bool {
	if s == nil {
		return false
	}
	n := normalizedName(name)
	if n == "" {
		return false
	}
	if s.Trie.match(n) {
		return true
	}
	for i := range s.Regexes {
		if s.Regexes[i].matchLower(n) {
			return true
		}
	}
	return false
}

// Len reports the number of unique matchers retained after dedup. Callers use
// this to decide whether a sniff/proxy needs to start at all (zero matchers ⇒
// nothing to route on).
func (s *MatcherSet) Len() int {
	if s == nil {
		return 0
	}
	return s.plainCount + len(s.Regexes)
}

// CompileMatcherSet compiles raw zone entries (the strings users type in the
// UI: "domain:foo.com", "[re]^bar$", plain "baz.org", etc.) into a MatcherSet
// while dropping redundant patterns:
//
//   - Exact duplicates of plain or regex entries collapse to one.
//   - A plain entry covered by a broader plain entry (e.g. "abr.ru" when "ru"
//     is also present) is dropped.
//   - A plain entry covered by any regex (e.g. "vk.ru" when "regexp:\\.ru$" is
//     also present) is dropped.
//
// Regex-vs-regex coverage isn't decidable in general so regexes are kept as-is.
func CompileMatcherSet(entries []string) (MatcherSet, []string) {
	ms, bad := CompileMatchers(entries)

	// Split into plain and regex pools. We carry the regex pool as-is.
	var plains []DomainMatcher
	var regexes []DomainMatcher
	seenPlain := make(map[string]struct{}, len(ms))
	seenRegex := make(map[string]struct{}, len(ms))
	for _, m := range ms {
		if m.re != nil {
			key := m.re.String()
			if _, dup := seenRegex[key]; dup {
				continue
			}
			seenRegex[key] = struct{}{}
			regexes = append(regexes, m)
			continue
		}
		if m.base == "" {
			continue
		}
		if _, dup := seenPlain[m.base]; dup {
			continue
		}
		seenPlain[m.base] = struct{}{}
		plains = append(plains, m)
	}

	// Sort plains by base length ASC so we feed the trie shorter (broader)
	// suffixes first. Once a broader suffix is in the trie, a longer plain that
	// would also match it is redundant and gets skipped.
	sort.Slice(plains, func(i, j int) bool {
		return len(plains[i].base) < len(plains[j].base)
	})

	trie := newSuffixTrie()
	kept := 0
	for _, p := range plains {
		// Already covered by a broader plain that we kept? Skip.
		if trie.match(p.base) {
			continue
		}
		// Covered by any regex? Skip. This is the "regexp:\.ru$ already there,
		// drop every domain:foo.ru" case.
		coveredByRegex := false
		for _, r := range regexes {
			if r.re.MatchString(p.base) {
				coveredByRegex = true
				break
			}
		}
		if coveredByRegex {
			continue
		}
		trie.addBase(p.base)
		kept++
	}
	return MatcherSet{Trie: trie, Regexes: regexes, plainCount: kept}, bad
}
