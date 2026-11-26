//go:build linux

package awgroute

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"nfqws2strategy/internal/tools/tlsroots"
)

// RunSpeedTest samples the same URL through the selected tunnel and through
// WAN. The body is counted and discarded as it streams.
func (svc *Service) RunSpeedTest(ctx context.Context, opts SpeedTestOptions) SpeedTestResult {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 10 * 1024 * 1024
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	res := SpeedTestResult{Sample: opts.URL}

	tunIface, err := ValidateSpeedTestIface(opts.Iface)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if tunIface == "" {
		tunIface = awgIface // active tunnel by default
	}
	_, wanDev := awgDefaultRoute()

	emit := func(e SpeedEvent) {
		if opts.OnEvent != nil {
			opts.OnEvent(e)
		}
	}

	emit(SpeedEvent{Phase: "tunnel_start"})
	res.ViaTunnel = doStreamSample(ctx, opts.URL, tunIface, opts.Timeout, opts.MaxBytes, func(b int64, el time.Duration, rate float64) {
		emit(SpeedEvent{Phase: "tunnel_progress", Bytes: b, Elapsed: el.Milliseconds(), Rate: rate})
	})
	tunnelSample := res.ViaTunnel
	emit(SpeedEvent{Phase: "tunnel_done", Sample: &tunnelSample})

	emit(SpeedEvent{Phase: "direct_start"})
	if wanDev == "" {
		res.ViaDirect.Error = "не найден WAN-интерфейс"
	} else {
		res.ViaDirect = doStreamSample(ctx, opts.URL, wanDev, opts.Timeout, opts.MaxBytes, func(b int64, el time.Duration, rate float64) {
			emit(SpeedEvent{Phase: "direct_progress", Bytes: b, Elapsed: el.Milliseconds(), Rate: rate})
		})
	}
	directSample := res.ViaDirect
	emit(SpeedEvent{Phase: "direct_done", Sample: &directSample})

	res.Comparable = res.ViaDirect.Error == "" && res.ViaTunnel.Error == "" &&
		res.ViaDirect.RxBytes > 0 && res.ViaDirect.RxBytes == res.ViaTunnel.RxBytes
	if res.Comparable {
		gain := (res.ViaTunnel.RxBytesPerSec - res.ViaDirect.RxBytesPerSec) / res.ViaDirect.RxBytesPerSec * 100
		res.TunnelGainPC = int(gain)
	}
	return res
}

// doStreamSample downloads via the given iface and reports bytes read at
// most every 250 ms.
func doStreamSample(parent context.Context, url, iface string, timeout time.Duration, maxBytes int64, progress func(b int64, el time.Duration, rate float64)) SpeedSample {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	d := &net.Dialer{Timeout: 4 * time.Second, Control: bindToDeviceControl(iface)}
	tr := &http.Transport{
		// Force tcp4: speedtest hosts often advertise AAAA, but on this router
		// the WAN v6 transit is partial (e.g. Zomro's provider blackholes TCP6
		// to certain destinations). The tunnel side is also v4-only — VPS
		// doesn't NAT66 ULA. Either way v6 just times out and lies about the
		// "direct" path having 0 B/s. We measure throughput, not stack.
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		TLSClientConfig:       &tls.Config{RootCAs: tlsroots.Pool(), MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()
	cli := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return SpeedSample{Error: err.Error()}
	}
	req.Header.Set("User-Agent", "nfqws2-strategy/speedtest")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBytes-1))

	start := time.Now()
	resp, err := cli.Do(req)
	if err != nil {
		return SpeedSample{DurationMS: time.Since(start).Milliseconds(), Error: fmt.Sprintf("HTTP-запрос через %s: %v", iface, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return SpeedSample{HTTPStatus: resp.StatusCode, DurationMS: time.Since(start).Milliseconds(), Error: "источник вернул " + resp.Status}
	}

	pw := &countingDiscard{onTick: progress, tickEvery: 250 * time.Millisecond, started: start}
	n, err := io.Copy(pw, io.LimitReader(resp.Body, maxBytes))
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}
	bps := float64(n) / elapsed.Seconds()
	out := SpeedSample{
		RxBytes:       n,
		DurationMS:    elapsed.Milliseconds(),
		RxBytesPerSec: bps,
		HTTPStatus:    resp.StatusCode,
	}
	if err != nil {
		out.Error = fmt.Sprintf("загрузка через %s прервана: %v", iface, err)
	} else if n == 0 {
		out.Error = "источник вернул пустой ответ"
	}
	return out
}

// countingDiscard is an io.Writer that drops bytes (no buffer, no disk) and
// pings a callback every tickEvery so the UI can stream progress.
type countingDiscard struct {
	written   int64
	started   time.Time
	lastTick  time.Time
	tickEvery time.Duration
	onTick    func(b int64, el time.Duration, rate float64)
}

func (c *countingDiscard) Write(p []byte) (int, error) {
	n := len(p)
	c.written += int64(n)
	now := time.Now()
	if c.onTick != nil && now.Sub(c.lastTick) >= c.tickEvery {
		c.lastTick = now
		el := now.Sub(c.started)
		rate := 0.0
		if el > 0 {
			rate = float64(c.written) / el.Seconds()
		}
		c.onTick(c.written, el, rate)
	}
	return n, nil
}

// awgSpeedtestMark is a socket mark we set on every speedtest dial so the
// AWG2_MARK chain RETURNs early (see firewall_linux.go) and never overrides
// the dialer's SO_BINDTODEVICE choice with the AWG routing decision.
//
// Without this, the WAN-bound (eth3) speedtest socket gets marked by OUTPUT
// → fwmark 0x10000000 → table 998 → default dev awg0, which contradicts
// SO_BINDTODEVICE=eth3 → kernel can't route → i/o timeout. The tunnel-side
// dial happens to work without the mark only because the AWG mark and the
// socket's bind device agree (both awg0).
//
// Picked 0x20000000 so it does NOT overlap our routing mark (0x10000000) or
// the Keenetic-style accel marks (0x0FFFFxxx) — see awgMarkCollision.
const awgSpeedtestMark = 0x20000000

// bindToDeviceControl returns a Dialer.Control func that pins the outbound
// socket to a specific NIC via SO_BINDTODEVICE AND sets SO_MARK so the AWG
// mangle chain RETURNs early. Both ops run inside the same Control() call so
// they apply BEFORE the socket connects.
func bindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); err != nil {
				opErr = err
				return
			}
			opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, awgSpeedtestMark)
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
