//go:build !linux

package netmon

// readSystem returns an empty snapshot on non-Linux builds.
func readSystem() SystemStats { return SystemStats{CPUPercent: -1} }
