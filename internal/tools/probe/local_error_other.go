//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

func isLocalBindError(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL)
}
