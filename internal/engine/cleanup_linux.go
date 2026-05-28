//go:build linux

package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// orphanMarker is the per-sandbox writeable-dir prefix passed to every test
// nfqws2 child (--writeable=/tmp/nfqws2-strategy/wN). It is unique to this tester
// and never used by the main nfqws2 service, so matching on it cannot kill the
// live DPI-bypass process.
const orphanMarker = "/tmp/nfqws2-strategy/"

// killOrphanedNfqws SIGKILLs any leftover test nfqws2 children from a previous
// unclean exit, identified by the writeable-dir argument in their cmdline.
func killOrphanedNfqws() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline is NUL-separated; a substring match is enough.
		if strings.Contains(string(b), orphanMarker) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}
