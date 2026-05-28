//go:build linux

package probe

import "syscall"

// setReuse enables SO_REUSEADDR so a worker can rebind a source port that is
// still in TIME_WAIT from a previous probe.
func setReuse(fd uintptr) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
