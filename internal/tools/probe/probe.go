// Package probe measures whether a host is reachable through the current test
// sandbox and how fast, capturing the metrics used to rank strategies.
package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"syscall"
	"time"
)

// Result is the outcome of a single probe.
type Result struct {
	Host      string `json:"host"`
	Code      int    `json:"code"`
	RemoteIP  string `json:"remote_ip"`
	Size      int64  `json:"size"`
	TTFBms    int64  `json:"ttfb_ms"`
	TotalMs   int64  `json:"total_ms"`
	SpeedBps  int64  `json:"speed_bps"`
	OK        bool   `json:"ok"`
	Truncated bool   `json:"truncated"`
	Err       string `json:"err,omitempty"`
}

// Prober runs probes bound to a worker's source-port range.
type Prober struct {
	PortLo, PortHi int
	next           int32
	ConnectTimeout time.Duration
	MaxTime        time.Duration
	MinBytes       int64 // a success must transfer more than this (defeats the ~16KB cap)
	ReadCap        int64 // stop reading after this many bytes (enough to confirm + measure speed)

	// Resolve, when set, maps a hostname to an IP via a chosen DNS server (DoH/
	// DoT). The dial then targets that IP while the TLS SNI stays the original
	// host. nil = use the system resolver. A worker sets this per job.
	Resolve func(ctx context.Context, host string) (string, error)
}

func New(portLo, portHi int) *Prober {
	return &Prober{
		PortLo:         portLo,
		PortHi:         portHi,
		ConnectTimeout: 6 * time.Second,
		MaxTime:        20 * time.Second,
		MinBytes:       16384,
		ReadCap:        131072,
	}
}

func (p *Prober) pickPort() int {
	n := atomic.AddInt32(&p.next, 1)
	span := p.PortHi - p.PortLo + 1
	if span < 1 {
		span = 1
	}
	return p.PortLo + int(uint32(n)%uint32(span))
}

// Probe fetches https://host/ through the sandbox and reports metrics. The ctx
// lets a run cancellation abort an in-flight probe immediately (quick cancel).
func (p *Prober) Probe(ctx context.Context, host string) Result {
	return p.ProbeURL(ctx, host, "https://"+host+"/")
}

// ProbeURL fetches an explicit URL (used when a list specifies a large test
// resource) but still keys the result on host.
func (p *Prober) ProbeURL(ctx context.Context, host, url string) Result {
	r := Result{Host: host}
	ctx, cancel := context.WithTimeout(ctx, p.MaxTime)
	defer cancel()

	dialer := &net.Dialer{
		Timeout:   p.ConnectTimeout,
		LocalAddr: &net.TCPAddr{Port: p.pickPort()},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(setReuse)
		},
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Resolve the host through the chosen DNS server (if any) and dial the
			// returned IP; the SNI/Host stays the original name from the URL.
			if p.Resolve != nil {
				if host, port, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) == nil {
					ip, rerr := p.Resolve(ctx, host)
					if rerr != nil {
						return nil, rerr
					}
					addr = net.JoinHostPort(ip, port)
				}
			}
			return dialer.DialContext(ctx, "tcp4", addr) // force IPv4 to match our v4 rules
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: p.ConnectTimeout,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{Transport: tr, Timeout: p.MaxTime}

	start := time.Now()
	var ttfb time.Time
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { ttfb = time.Now() },
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				r.RemoteIP = info.Conn.RemoteAddr().String()
			}
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", url, nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (nfqws2-strategy)")

	resp, err := client.Do(req)
	if err != nil {
		r.Err = err.Error()
		r.TotalMs = time.Since(start).Milliseconds()
		return r
	}
	defer resp.Body.Close()
	r.Code = resp.StatusCode
	if !ttfb.IsZero() {
		r.TTFBms = ttfb.Sub(start).Milliseconds()
	}

	buf := make([]byte, 32*1024)
	var n int64
	var readErr error
	for n < p.ReadCap {
		m, e := resp.Body.Read(buf)
		n += int64(m)
		if e != nil {
			readErr = e
			break
		}
	}
	r.Size = n
	r.TotalMs = time.Since(start).Milliseconds()
	if r.TotalMs > 0 {
		r.SpeedBps = n * 1000 / r.TotalMs
	}
	if h, _, e := net.SplitHostPort(r.RemoteIP); e == nil {
		r.RemoteIP = h
	}

	reachedCap := n >= p.ReadCap
	if readErr != nil && readErr != io.EOF && !reachedCap {
		// Mid-stream failure. A reset around ~16KB is the classic DPI cap.
		if n > 0 && n <= 17408 {
			r.Truncated = true
		}
		if r.Err == "" {
			r.Err = readErr.Error()
		}
	}
	completed := readErr == io.EOF || reachedCap
	r.OK = r.Code >= 200 && r.Code < 400 && n > p.MinBytes && !r.Truncated && completed
	return r
}
