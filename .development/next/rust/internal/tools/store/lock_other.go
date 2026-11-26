//go:build !linux && !windows

package store

import "os"

func syncDirectory(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func lockStoreFile(string) (func(), error) { return func() {}, nil }
