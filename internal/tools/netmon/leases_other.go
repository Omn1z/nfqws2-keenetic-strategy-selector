//go:build !linux

package netmon

// HostnamesByMAC returns an empty map on non-Linux dev builds so the dashboard
// still renders (it will just show MACs).
func HostnamesByMAC() map[string]string { return map[string]string{} }
