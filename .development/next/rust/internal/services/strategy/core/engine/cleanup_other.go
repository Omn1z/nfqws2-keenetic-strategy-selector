//go:build !linux

package engine

// killOrphanedNfqws is a no-op off Linux (the dev box has no /proc); the real
// implementation lives in cleanup_linux.go.
func killOrphanedNfqws() {}
