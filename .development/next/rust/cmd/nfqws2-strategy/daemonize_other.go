//go:build !linux

package main

// maybeDaemonize is a no-op on non-Linux hosts (the dev machine); the server
// runs in the foreground there.
func maybeDaemonize(logPath, pidPath string) (bool, error) { return false, nil }
