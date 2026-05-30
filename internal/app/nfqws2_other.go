//go:build !linux

package app

import "fmt"

// Non-Linux stubs so the project builds/tests on the Windows dev box. SIGHUP and
// /proc are Linux-only; on the router the nfqws2_linux.go implementations run.

func verifyNfqws2Pid(pid int) error {
	return fmt.Errorf("reload nfqws2 поддерживается только на Linux")
}

func sighupNfqws2(pid int) error {
	return fmt.Errorf("reload nfqws2 поддерживается только на Linux")
}
