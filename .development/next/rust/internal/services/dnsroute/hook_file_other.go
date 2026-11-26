//go:build !linux

package dnsroute

// The router runtime is Linux. File Sync remains portable; directory fsync is
// applied by the Linux implementation where hooks are installed in production.
func syncDNSHookDir(string) error { return nil }
