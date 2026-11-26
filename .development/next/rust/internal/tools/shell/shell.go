// Package shell holds tiny shell-related primitives that several services need.
// Kept here to prevent the same 1-liner from drifting into N copies across the
// codebase (where one of them eventually has a subtle escape bug).
package shell

import "strings"

// Quote POSIX-quotes s so it can be safely concatenated into a `sh -c "..."`
// command line. Wraps the string in single quotes and escapes any embedded
// single quote via the standard close-quote / escaped-quote / reopen-quote
// trick (`'"'"'`). Works in plain POSIX sh; do NOT use the bash-only `'\''`
// form because dash and busybox sh execute it differently.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
