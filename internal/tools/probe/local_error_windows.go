package probe

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func isLocalBindError(err error) bool {
	// syscall.EADDR* are synthetic compatibility codes on Windows. Real socket
	// operations return Winsock codes, including when wrapped by net/url errors.
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEADDRNOTAVAIL)
}
