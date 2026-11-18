//go:build linux

package store

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

func syncDirectory(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func lockStoreFile(name string) (func(), error) {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		f, err = os.Open(name)
	}
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
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
