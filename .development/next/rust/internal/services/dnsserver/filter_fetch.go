package dnsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
)

const maxFilteringSourceBytes = 8 << 20

// FetchFilteringSource downloads only a catalog URL through a selected DNS
// route. Both bootstrap DNS and the HTTPS socket use the same routed backend;
// no system DNS lookup or default HTTP client is involved.
func (r *Resolver) FetchFilteringSource(ctx context.Context, address string) ([]byte, error) {
	allowed := false
	for _, definition := range filteringCatalog {
		if address == definition.URL {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("источник DNS-блокировки отсутствует в каталоге")
	}
	endpoint, err := url.Parse(address)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, fmt.Errorf("неверный HTTPS-адрес списка DNS-блокировки")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.lifetime.Err(); err != nil {
		return nil, fmt.Errorf("DNS-сервер остановлен: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(r.lifetime, cancel)
	defer stopClose()

	routes := eligibleRoutes(r.policyConfig(), r.backend.Routes())
	// A healthy AWG route is preferred even in auto mode, so list updates do
	// not hit the ISP path while a VPN is available.
	sort.SliceStable(routes, func(i, j int) bool {
		return strings.HasPrefix(routes[i].ID, "awg:") && !strings.HasPrefix(routes[j].ID, "awg:")
	})
	available := make([]dnsroute.Route, 0, len(routes))
	for _, route := range routes {
		if route.Available {
			available = append(available, route)
		}
	}
	if len(available) == 0 {
		if r.cfg.RouteMode == RouteModeVPNOnly {
			return nil, fmt.Errorf("режим «только VPN»: нет доступного AWG-подключения для обновления списка")
		}
		return nil, fmt.Errorf("нет доступного маршрута для обновления списка DNS-блокировки")
	}
	var failures []string
	for _, route := range available {
		routeCtx := ctx
		var release context.CancelFunc
		if len(available) > 1 {
			routeCtx, release = context.WithTimeout(ctx, 45*time.Second)
		}
		data, err := r.fetchFilteringRoute(routeCtx, route.ID, endpoint)
		if release != nil {
			release()
		}
		if err == nil {
			return data, nil
		}
		failures = append(failures, route.ID+": "+err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("не удалось скачать список DNS-блокировки: %s", strings.Join(failures, "; "))
}

func (r *Resolver) fetchFilteringRoute(ctx context.Context, route string, endpoint *url.URL) ([]byte, error) {
	host := endpoint.Hostname()
	var ips []string
	if literal := net.ParseIP(host); literal != nil {
		ips = []string{literal.String()}
	} else {
		var err error
		ips, _, err = r.lookupEndpointIPs(ctx, route, host)
		if err != nil {
			return nil, err
		}
	}
	var failures []string
	for index, ip := range ips {
		if index == 4 {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		data, err := r.fetchFilteringIP(attempt, route, endpoint, ip, nil)
		cancel()
		if err == nil {
			return data, nil
		}
		failures = append(failures, ip+": "+err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("HTTPS: %s", strings.Join(failures, "; "))
}

func (r *Resolver) fetchFilteringIP(ctx context.Context, route string, endpoint *url.URL, ip string, roots *x509.CertPool) ([]byte, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !parsedIP.IsGlobalUnicast() || parsedIP.IsPrivate() {
		return nil, fmt.Errorf("список DNS-блокировки должен загружаться с публичного IP")
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(ip, port)
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname(), RootCAs: roots},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 1}
	transport.DialTLSContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		attempt, cancel := context.WithTimeout(dialCtx, 10*time.Second)
		defer cancel()
		stopRequest := context.AfterFunc(ctx, cancel)
		defer stopRequest()
		stopClose := context.AfterFunc(r.lifetime, cancel)
		defer stopClose()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := r.backend.DialContext(attempt, route, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, transport.TLSClientConfig.Clone())
		if err := tlsConn.HandshakeContext(attempt); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxFilteringSourceBytes {
		return nil, fmt.Errorf("список превышает 8 МиБ")
	}
	if media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err == nil && (media == "text/html" || media == "application/xhtml+xml") {
		return nil, fmt.Errorf("сервер вернул HTML вместо списка")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxFilteringSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFilteringSourceBytes {
		return nil, fmt.Errorf("список превышает 8 МиБ")
	}
	preview := strings.ToLower(strings.TrimSpace(string(data[:min(len(data), 256)])))
	if strings.HasPrefix(preview, "<!doctype html") || strings.HasPrefix(preview, "<html") || len(data) == 0 {
		return nil, fmt.Errorf("сервер вернул HTML или пустой список")
	}
	return data, nil
}
