//go:build !linux

package netmon

// NDP is a no-op stub for non-Linux dev hosts.
func NDP() (map[string][]string, error) { return nil, nil }
