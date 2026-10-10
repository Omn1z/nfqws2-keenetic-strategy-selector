package probe

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSocketAllocationErrors(t *testing.T) {
	for _, code := range []error{windows.WSAEADDRINUSE, windows.WSAEADDRNOTAVAIL} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("bind", code)}
		if !isLocalBindError(err) {
			t.Errorf("Winsock error not recognized: %v", err)
		}
	}
	if isLocalBindError(windows.WSAECONNRESET) {
		t.Fatal("remote reset classified as a local bind error")
	}
}
