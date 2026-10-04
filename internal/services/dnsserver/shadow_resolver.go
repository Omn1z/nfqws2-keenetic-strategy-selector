package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

// Optional so existing backends cannot silently send selected domains over an
// ordinary dialer/VPN when they do not implement the explicit direct path.
type shadowBackend interface {
	DialShadowDNS(context.Context, string, string) (net.Conn, error)
	ShadowDNSServers(context.Context) ([]string, error)
}

type ShadowDNSStatus struct {
	Enabled     bool                        `json:"enabled"`
	Automatic   bool                        `json:"automatic"`
	Servers     []string                    `json:"servers"`
	Error       string                      `json:"error"`
	Diagnostics *dnsroute.ShadowDiagnostics `json:"diagnostics,omitempty"`
}

func initialShadowStatus(cfg *ShadowDNSConfig) ShadowDNSStatus {
	s := ShadowDNSStatus{Servers: []string{}, Automatic: true}
	if cfg != nil {
		s.Enabled = cfg.Enabled
	}
	return s
}

func (r *Resolver) ShadowStatus() ShadowDNSStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.shadowStatus
	s.Servers = append([]string{}, s.Servers...)
	return s
}

func (r *Resolver) resolveShadow(ctx context.Context, query *mdns.Msg, domain string) (response *mdns.Msg, out Outcome, err error) {
	out = Outcome{Domain: domain, Route: shadowRoute}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	stopClose := context.AfterFunc(r.lifetime, cancel)
	defer stopClose()
	var servers []string
	defer func() {
		if err != nil {
			out.Error = err.Error()
		}
		r.mu.Lock()
		r.shadowStatus.Servers = append([]string{}, servers...)
		r.shadowStatus.Error = out.Error
		r.mu.Unlock()
	}()
	backend, ok := r.backend.(shadowBackend)
	if !ok {
		return nil, out, fmt.Errorf("Shadow DNS: прямой DNS не поддерживается на этой платформе")
	}
	servers, err = backend.ShadowDNSServers(ctx)
	if err != nil {
		return nil, out, fmt.Errorf("Shadow DNS: %w", err)
	}
	if len(servers) == 0 || len(servers) > 8 {
		return nil, out, fmt.Errorf("Shadow DNS: DNS провайдера ещё не получен от WAN")
	}
	for i, address := range servers {
		servers[i], err = normalizeShadowServer(address)
		if err != nil {
			return nil, out, err
		}
	}
	// Cached discovery is serialized by the backend. A burst of callers
	// waiting for the first firmware lookup must not occupy all DoH slots.
	select {
	case r.attempts <- struct{}{}:
		defer func() { <-r.attempts }()
	case <-ctx.Done():
		return nil, out, ctx.Err()
	}
	r.mu.Lock()
	observer := r.observer
	r.mu.Unlock()
	origin := requestOriginFromContext(ctx)
	failures := make([]string, 0, len(servers))
	for i, address := range servers {
		if ctx.Err() != nil {
			return nil, out, ctx.Err()
		}
		deadline, _ := ctx.Deadline()
		attempt, stop := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(servers)-i))
		started := time.Now()
		response, err = exchangeShadowDNS(attempt, backend, address, query)
		stop()
		out.Upstream = address
		if observer != nil {
			event := AttemptEvent{Domain: domain, Type: mdns.TypeToString[query.Question[0].Qtype], Route: shadowRoute, RouteName: "Shadow DNS · провайдер", Upstream: address, DurationMS: time.Since(started).Milliseconds(), Success: err == nil, Canceled: errors.Is(err, context.Canceled), ClientIP: origin.ClientIP, Source: origin.Source, Transport: origin.Transport}
			if err != nil && !event.Canceled {
				event.Error = err.Error()
			}
			observer(event)
		}
		if err == nil {
			return response, out, nil
		}
		failures = append(failures, address+": "+err.Error())
	}
	return nil, out, fmt.Errorf("Shadow DNS недоступен: %s", strings.Join(failures, "; "))
}

func exchangeShadowDNS(ctx context.Context, backend shadowBackend, address string, query *mdns.Msg) (*mdns.Msg, error) {
	q := query.Copy()
	// Cache/singleflight wire has ID=0. Plain DNS requires an unpredictable
	// transaction ID; restore the original ID only after verifying the reply.
	q.Id = mdns.Id()
	for _, network := range []string{"udp", "tcp"} {
		conn, err := backend.DialShadowDNS(ctx, network, address)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		client := &mdns.Client{Net: network, UDPSize: 4096}
		if deadline, ok := ctx.Deadline(); ok {
			client.Timeout = time.Until(deadline)
		}
		response, _, err := client.ExchangeWithConnContext(ctx, q, &mdns.Conn{Conn: conn, UDPSize: 4096})
		stop()
		_ = conn.Close()
		if err != nil {
			return nil, err
		}
		if response.Truncated && network == "udp" {
			continue
		}
		wire, err := response.Pack()
		if err != nil {
			return nil, err
		}
		validated, err := validateResponse(wire, q)
		if err != nil {
			return nil, err
		}
		validated.Id = query.Id
		return validated, nil
	}
	return nil, fmt.Errorf("Shadow DNS: усечённый ответ TCP")
}
