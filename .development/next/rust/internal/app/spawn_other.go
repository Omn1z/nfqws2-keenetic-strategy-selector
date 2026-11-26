//go:build !linux

package app

import "fmt"

func detachedRestart(initScript string) error {
	return fmt.Errorf("self-update restart is only supported on Linux")
}
