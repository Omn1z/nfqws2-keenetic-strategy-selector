package awg

import (
	"fmt"
	"regexp"
	"strings"
)

// DomainMatcher matches a queried DNS name against one user zone entry. The
// format is auto-detected from the entry text:
//
//   - "[re] <regexp>"      → Go regular expression over the full lowercased name
//                            (e.g. "[re]^.*\\.googlevideo\\.com$").
//   - contains '*' or '#'  → glob: '*' = any run of characters (incl. none),
//                            '#' = exactly one character. The pattern is anchored
//                            to the whole name (e.g. "*main.com", "server*",
//                            "test##.com" → test + 2 chars + ".com").
//   - plain "domain.com"   → the domain itself AND every subdomain
//                            (domain.com and *.domain.com).
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

// Match reports whether the queried DNS name matches this entry.
func (m DomainMatcher) Match(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return false
	}
	if m.re != nil {
		return m.re.MatchString(n)
	}
	if m.base == "" {
		return false
	}
	return n == m.base || strings.HasSuffix(n, "."+m.base)
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

// MatchAny reports whether the name matches any of the matchers.
func MatchAny(ms []DomainMatcher, name string) bool {
	for _, m := range ms {
		if m.Match(name) {
			return true
		}
	}
	return false
}
