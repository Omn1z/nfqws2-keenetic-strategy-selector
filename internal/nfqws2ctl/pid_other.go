//go:build !linux

package nfqws2ctl

import "fmt"

// Non-Linux stubs so the project builds/tests on the Windows dev box. SIGHUP and
// /proc are Linux-only; on the router the pid_linux.go implementations run.

func verifyPid(pid int) error {
	return fmt.Errorf("reload nfqws2 поддерживается только на Linux")
}

func sighup(pid int) error {
	return fmt.Errorf("reload nfqws2 поддерживается только на Linux")
}
