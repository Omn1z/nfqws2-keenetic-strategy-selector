//go:build linux

package app

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// verifyNfqws2Pid confirms the pid belongs to the real nfqws2 engine and NOT our
// own nfqws2-strategy process. The upstream S51 init's is_running() uses
// `pgrep -nf /opt/usr/bin/nfqws2`, which substring-matches nfqws2-strategy — so
// we verify argv[0]'s basename is EXACTLY "nfqws2" before sending any signal.
func verifyNfqws2Pid(pid int) error {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return fmt.Errorf("nfqws2 (pid %d) не запущен", pid)
	}
	argv0 := string(b)
	if i := strings.IndexByte(argv0, 0); i >= 0 {
		argv0 = argv0[:i]
	}
	base := argv0[strings.LastIndexByte(argv0, '/')+1:]
	if base != "nfqws2" {
		return fmt.Errorf("pid %d — это %q, а не nfqws2", pid, base)
	}
	return nil
}

func sighupNfqws2(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("не удалось отправить SIGHUP процессу %d: %w", pid, err)
	}
	return nil
}
