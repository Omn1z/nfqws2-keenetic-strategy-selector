// Package keenetic contains helpers for invoking native KeeneticOS programs
// from Entware without inheriting incompatible Entware libraries.
package keenetic

import "strings"

// NativeEnv isolates the firmware loader for one child process. In particular,
// ndmc can fail initialization when Entware's OpenSSL shadows the firmware's
// libraries. Keep the service environment and all unrelated variables intact.
func NativeEnv(environ []string) []string {
	result := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		key, _, _ := strings.Cut(entry, "=")
		if key != "LD_LIBRARY_PATH" && key != "LD_PRELOAD" {
			result = append(result, entry)
		}
	}
	return append(result, "LD_LIBRARY_PATH=/lib:/usr/lib")
}
