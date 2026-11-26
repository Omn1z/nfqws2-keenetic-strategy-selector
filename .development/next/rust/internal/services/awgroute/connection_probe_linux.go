//go:build linux

package awgroute

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"nfqws2strategy/internal/tools/tlsroots"
)

func probeConnectionDataOS(parent context.Context, iface string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	cleanup, err := prepareConnectionProbeOS(iface)
	if err != nil {
		return "", err
	}
	defer cleanup()
	dialer := connectionProbeDialer(iface, 8*time.Second)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}, DisableKeepAlives: true, TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{RootCAs: tlsroots.Pool(), MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	// A literal IP avoids a WAN DNS lookup; TLS verification remains enabled.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "nfqws2-strategy/connection-test")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTPS через %s: %w", iface, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTPS через %s: статус %d", iface, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(body) > 4096 {
		return "", fmt.Errorf("неполный или слишком большой ответ HTTPS-проверки")
	}
	for _, line := range strings.Split(string(body), "\n") {
		if ip, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			if address, err := netip.ParseAddr(ip); err == nil {
				return address.String(), nil
			}
		}
	}
	return "", fmt.Errorf("HTTPS-проверка не вернула внешний IP")
}

func prepareConnectionProbeOS(iface string) (func(), error) {
	// Cleanup receives its own bounded context even after request cancellation.
	return prepareConnectionProbe(iface, func(cmd string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		return string(out), err
	})
}

func connectionProbeDialer(iface string, timeout time.Duration) net.Dialer {
	return net.Dialer{Timeout: timeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			if optionErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); optionErr == nil {
				optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, connectionProbeMark)
			}
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
}

var clientHealthDestinations = [...]netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:443"),
	netip.MustParseAddrPort("8.8.8.8:443"),
}

// Unlike the manual HTTPS diagnostic, this sends no application data. Two
// independent TCP destinations must time out, and the watchdog then verifies
// that the same peer actually transmitted but received no authenticated packet.
func probeClientDataTimeout(parent context.Context, iface, allowedIPs string) bool {
	for _, target := range clientHealthDestinations {
		if !clientHealthDestinationAllowed(allowedIPs, target.Addr()) {
			return false
		}
	}
	cleanup, err := prepareConnectionProbeOS(iface)
	if err != nil {
		return false
	}
	defer cleanup()

	const timeout = 2500 * time.Millisecond
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	dialer := connectionProbeDialer(iface, timeout)
	results := make(chan bool, len(clientHealthDestinations))
	for _, target := range clientHealthDestinations {
		go func() {
			conn, err := dialer.DialContext(ctx, "tcp4", target.String())
			if err == nil {
				conn.Close()
				results <- false
				return
			}
			var netErr net.Error
			results <- errors.As(err, &netErr) && netErr.Timeout()
		}()
	}
	bothTimedOut := true
	for range clientHealthDestinations {
		if !<-results {
			bothTimedOut = false
			cancel()
		}
	}
	return bothTimedOut && parent.Err() == nil
}

func clientHealthDestinationAllowed(allowedIPs string, target netip.Addr) bool {
	// The engine supplies the two default routes for an empty AllowedIPs.
	if strings.Trim(allowedIPs, " ,\t\r\n") == "" {
		return true
	}
	for cidr := range strings.SplitSeq(allowedIPs, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err == nil && prefix.Contains(target) {
			return true
		}
	}
	return false
}
