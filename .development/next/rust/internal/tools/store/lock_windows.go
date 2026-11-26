//go:build windows

package store

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"time"
)

// Windows does not support fsync on a directory handle. Router persistence is
// provided by the Linux implementation; file data is still flushed on Windows.
func syncDirectory(string) error { return nil }

func lockStoreFile(name string) (func(), error) {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlap windows.Overlapped
	deadline := time.Now().Add(15 * time.Second)
	for {
		err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlap); _ = f.Close() }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("configuration store is busy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
