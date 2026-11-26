package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProbeHTTPSRedirectUsesFreshSourcePort(t *testing.T) {
	ports := make(chan int, 2)
	payload := strings.Repeat("data", 16384)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, portText, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			t.Errorf("parse remote address: %v", err)
		}
		port, _ := strconv.Atoi(portText)
		ports <- port
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/complete", http.StatusFound)
			return
		}
		fmt.Fprint(w, payload)
	}))
	defer server.Close()

	lo, hi := reserveSourcePorts(t)
	pr := New(lo, hi)
	pr.MaxTime = 5 * time.Second
	result := pr.ProbeURL(context.Background(), "redirect.test", server.URL+"/redirect")
	if !result.OK || result.LocalError || result.Err != "" || result.Code != 200 || result.Size != int64(len(payload)) {
		t.Fatalf("redirect did not transfer complete response: %+v", result)
	}
	if len(ports) != 2 {
		t.Fatalf("requests = %d, want redirect and response", len(ports))
	}
	first, second := <-ports, <-ports
	if first == second || first < lo || first > hi || second < lo || second > hi {
		t.Fatalf("source ports %d, %d: want distinct ports within %d..%d", first, second, lo, hi)
	}
}

// Find two adjacent unused ports without assuming a fixed test port range.
// Closing listening sockets leaves no TCP connection/TIME_WAIT behind.
func reserveSourcePorts(t *testing.T) (int, int) {
	t.Helper()
	for range 100 {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lo := first.Addr().(*net.TCPAddr).Port
		if lo == 65535 {
			first.Close()
			continue
		}
		second, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(lo+1)))
		first.Close()
		if err == nil {
			second.Close()
			return lo, lo + 1
		}
	}
	t.Fatal("could not reserve adjacent loopback source ports")
	return 0, 0
}

func TestProbeMarksLocalSocketAllocationErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"address unavailable", syscall.EADDRNOTAVAIL, true},
		{"address occupied", syscall.EADDRINUSE, true},
		{"remote reset", syscall.ECONNRESET, false},
		{"remote refused", syscall.ECONNREFUSED, false},
		{"deadline", context.DeadlineExceeded, false},
		{"misleading text", errors.New("cannot assign requested address"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := &url.Error{Op: "Get", URL: "https://example.invalid", Err: &net.OpError{
				Op: "dial", Net: "tcp", Err: os.NewSyscallError("bind", tc.err),
			}}
			if got := isLocalBindError(wrapped); got != tc.want {
				t.Fatalf("wrapped local error = %v, want %v", got, tc.want)
			}
			pr := New(0, 0)
			pr.Resolve = func(context.Context, string) (string, error) { return "", wrapped }
			result := pr.Probe(context.Background(), "example.invalid")
			if result.LocalError != tc.want || result.OK || result.Err == "" {
				t.Fatalf("local error classification = %+v, want LocalError=%v", result, tc.want)
			}
		})
	}
}
