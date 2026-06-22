// Package strs holds the tiny string helpers shared across services.
package strs

import "strings"

// LastLines keeps at most the final n lines of s.
func LastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// Short truncates an id to its first 6 chars (for compact log lines).
func Short(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}
