//go:build linux

package awgroute

import (
	"context"
	"crypto/tls"
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
	// Cleanup receives its own bounded context even after HTTP cancellation.
	run := func(cmd string) (string, error) {
		cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cmdCancel()
		out, err := exec.CommandContext(cmdCtx, "sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}
	cleanup, err := prepareConnectionProbe(iface, run)
	if err != nil {
		return "", err
	}
	defer cleanup()
	dialer := net.Dialer{Timeout: 8 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
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
