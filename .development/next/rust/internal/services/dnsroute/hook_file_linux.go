//go:build linux

package dnsroute

import (
	"errors"
	"os"
	"syscall"
)

func syncDNSHookDir(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	// Some removable/router filesystems do not implement directory fsync.
	// File contents were synced before rename; real I/O errors remain fatal.
	if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
		syncErr = nil
	}
	return errors.Join(syncErr, closeErr)
}
