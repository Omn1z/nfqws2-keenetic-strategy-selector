//go:build !linux

package openwrtdns

import "os/exec"

func configureCommand(_ *exec.Cmd) {}
