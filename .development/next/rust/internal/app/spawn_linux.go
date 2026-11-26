//go:build linux

package app

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// detachedRestart schedules a service restart in a new session so it survives
// the current process being killed by the restart. A short delay lets the HTTP
// response flush first.
func detachedRestart(initScript string) error {
	if _, err := os.Stat(initScript); err != nil {
		return fmt.Errorf("init script not found: %s", initScript)
	}
	cmd := exec.Command("sh", "-c", "sleep 1; "+initScript+" restart")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
