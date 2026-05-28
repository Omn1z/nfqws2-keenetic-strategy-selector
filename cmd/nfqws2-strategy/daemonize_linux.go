//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// maybeDaemonize, when called in the original process, re-execs the binary in a
// new session (setsid) detached from the terminal and returns isParent=true so
// the caller exits. In the re-exec'd child (env marker set) it writes the pid
// file and returns isParent=false so the caller proceeds to serve.
func maybeDaemonize(logPath, pidPath string) (isParent bool, err error) {
	if os.Getenv("N2S_DAEMONIZED") == "1" {
		if pidPath != "" {
			_ = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644)
		}
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return true, err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "N2S_DAEMONIZED=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	var out *os.File
	if logPath != "" {
		out, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	} else {
		out, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err != nil {
		return true, err
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return true, cmd.Start()
}
