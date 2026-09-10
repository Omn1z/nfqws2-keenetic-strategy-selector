package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

type Backend interface {
	Prepare(context.Context, dnsroute.ListenOptions) error
	Routes() []dnsroute.Route
	DialContext(context.Context, string, string, string) (net.Conn, error)
	ObserveAnswer(context.Context, string, []byte, net.IP) ([]byte, error)
	Close() error
}

type Outcome struct {
	Domain   string `json:"domain"`
	Route    string `json:"route"`
	Upstream string `json:"upstream"`
	Cached   bool   `json:"cached"`
	Error    string `json:"error,omitempty"`
}

type CacheStatus struct {
	Entries    int `json:"entries"`
	Capacity   int `json:"capacity"`
	TTLSeconds int `json:"ttl_seconds"`
}

// CancellationSummary counts only dispatched, canceled attempts belonging to
// one network query. It never combines concurrent queries for the same name.
type CancellationSummary struct {
	Domain string
	Type   string
	Count  int
}

type dnsCacheEntry struct {
	msg              *mdns.Msg
	created, expires time.Time
	route, upstream  string
}
type endpointEntry struct {
	ips     []string
	expires time.Time
}

// Route attempts share a router-wide limit. A request with fewer candidates
// starts all of them immediately; larger sets use the same bounded workers.
const maxConcurrentRouteAttempts = 32

type resolverRequestContextKey struct{}

// Every cache miss races the available routes. The upstream remains attached
// to its domain rule, regardless of which route supplies the first valid reply.
type Resolver struct {
	cfg             Config
	backend         Backend
	mu              sync.Mutex
	cache           map[string]dnsCacheEntry
	cacheGeneration uint64
	endpoints       map[string]endpointEntry
	clients         map[string]*http.Client
	ipCursor        map[string]int
	attempts        chan struct{}
	lifetime        context.Context
	cancel          context.CancelFunc
	closed          bool
	now             func() time.Time
	scheduler       *Scheduler
	observer        func(AttemptEvent)
	cancelObserver  func(CancellationSummary)
	fastDNS         *FastDNSCache
	maintenanceOnce sync.Once
	methods         *methodPolicy
}

func NewResolver(cfg Config, backend Backend) *Resolver {
	lifetime, cancel := context.WithCancel(context.Background())
	r := &Resolver{cfg: cloneConfig(cfg), backend: backend, cache: map[string]dnsCacheEntry{}, endpoints: map[string]endpointEntry{}, clients: map[string]*http.Client{}, ipCursor: map[string]int{}, attempts: make(chan struct{}, maxConcurrentRouteAttempts), lifetime: lifetime, cancel: cancel, now: time.Now, scheduler: NewScheduler()}
	r.methods = newMethodPolicy(cfg.DisabledMethods)
	if cfg.FastDNS {
		r.fastDNS = NewFastDNSCache(lifetime, func(ctx context.Context, route, host string) ([]string, error) {
			ips, _, err := r.lookupEndpointIPs(ctx, route, host)
			return ips, err
		}, func() []FastDNSTarget { return fastDNSTargets(r.policyConfig(), r.backend.Routes()) })
		r.fastDNS.allowed = func(route, host string) bool { return fastDNSConfiguredHost(r.cfg, route, host, r.methods.allowed) }
	}
	return r
}

func (r *Resolver) SetScheduler(scheduler *Scheduler) {
	if scheduler == nil {
		return
	}
	r.mu.Lock()
	r.scheduler = scheduler
	r.mu.Unlock()
}

func (r *Resolver) SetAttemptObserver(observer func(AttemptEvent)) {
	r.mu.Lock()
	r.observer = observer
	r.mu.Unlock()
}

// SetCancellationObserver observes each query after its dispatched workers
// finish. It runs independently of returning the first answer to the client.
func (r *Resolver) SetCancellationObserver(observer func(CancellationSummary)) {
	r.mu.Lock()
	r.cancelObserver = observer
	r.mu.Unlock()
}

func (r *Resolver) SchedulerSnapshot(domain string) SchedulerSnapshot {
	r.mu.Lock()
	scheduler := r.scheduler
	r.mu.Unlock()
	return scheduler.Snapshot(r.policyConfig(), r.backend.Routes(), domain)
}

func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.cancel()
	for _, c := range r.clients {
		c.CloseIdleConnections()
	}
	r.clients = map[string]*http.Client{}
}

func parseQuery(raw []byte) (*mdns.Msg, string, error) {
	if len(raw) < 12 || len(raw) > 65535 {
		return nil, "", fmt.Errorf("неверный размер DNS-запроса")
	}
	var q mdns.Msg
	if err := q.Unpack(raw); err != nil {
		return nil, "", fmt.Errorf("неверный DNS-запрос: %w", err)
	}
	if q.Response || q.Opcode != mdns.OpcodeQuery || len(q.Question) != 1 || len(q.Answer) > 0 || len(q.Ns) > 0 || q.IsTsig() != nil {
		return nil, "", fmt.Errorf("ожидается один обычный DNS-вопрос")
	}
	domain := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")
	if _, ok := mdns.IsDomainName(q.Question[0].Name); !ok {
		return nil, "", fmt.Errorf("неверное доменное имя DNS")
	}
	return &q, domain, nil
}

func (r *Resolver) Resolve(ctx context.Context, raw []byte) ([]byte, Outcome, error) {
	// Clearing answers invalidates writes from requests that already started,
	// while those requests may still finish normally for their clients.
	r.mu.Lock()
	cacheGeneration := r.cacheGeneration
	r.mu.Unlock()
	q, domain, err := parseQuery(raw)
	out := Outcome{Domain: domain}
	if err != nil {
		out.Error = err.Error()
		return nil, out, err
	}
	if r.lifetime.Err() != nil {
		err = fmt.Errorf("DNS-сервер остановлен")
		out.Error = err.Error()
		return nil, out, err
	}
	if err := ctx.Err(); err != nil {
		out.Error = err.Error()
		return nil, out, err
	}
	pool, _ := r.cfg.upstreamsFor(domain)
	out.Upstream = pool[0].Address
	query := q.Copy()
	query.Id = 0
	wire, err := query.Pack()
	if err != nil {
		return nil, out, err
	}
	key := string(wire)
	if cached, route, upstream := r.cacheGet(key, q.Id); cached != nil {
		out.Cached = true
		out.Route = route
		out.Upstream = upstream
		return cached, out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	stopClose := context.AfterFunc(r.lifetime, cancel)
	defer stopClose()
	r.mu.Lock()
	scheduler, observer, cancelObserver := r.scheduler, r.observer, r.cancelObserver
	r.mu.Unlock()
	ordered := scheduler.order(r.policyConfig(), r.backend.Routes(), domain)
	type result struct {
		index int
		msg   *mdns.Msg
		err   error
	}
	results := make(chan result, len(ordered))
	// One dispatcher acquires each slot before taking the next queue entry.
	// Priority therefore controls actual starts when the shared limit is full,
	// while ordinary pools still start all their pairs without a delay.
	go func() {
		var workers sync.WaitGroup
		var canceled atomic.Int64
		defer func() {
			workers.Wait()
			if count := int(canceled.Load()); count > 0 && cancelObserver != nil {
				cancelObserver(CancellationSummary{Domain: domain, Type: mdns.TypeToString[query.Question[0].Qtype], Count: count})
			}
		}()
		for index, candidate := range ordered {
			select {
			case r.attempts <- struct{}{}:
			case <-ctx.Done():
				return
			case <-r.lifetime.Done():
				return
			}
			if ctx.Err() != nil || r.lifetime.Err() != nil {
				<-r.attempts
				return
			}
			methodCtx, releaseMethod, methodErr := r.methods.begin(ctx, candidate.route.ID, candidate.upstream.Address)
			if methodErr != nil {
				<-r.attempts
				results <- result{index: index, err: methodErr}
				continue
			}
			scheduler.started(candidate.route.ID, candidate.upstream.Address)
			workers.Add(1)
			go func(index int, candidate attemptCandidate) {
				defer workers.Done()
				defer releaseMethod()
				started := time.Now()
				attempt, stop := context.WithTimeout(methodCtx, time.Duration(r.cfg.TimeoutSeconds)*time.Second)
				resp, err := r.exchangeEndpoint(attempt, candidate.route.ID, candidate.upstream, wire, query)
				stop()
				<-r.attempts
				event := AttemptEvent{Domain: domain, Type: mdns.TypeToString[query.Question[0].Qtype], Route: candidate.route.ID, RouteName: candidate.route.Name, Upstream: candidate.upstream.Address, DurationMS: time.Since(started).Milliseconds(), Success: err == nil, Canceled: err != nil && (ctx.Err() != nil || r.lifetime.Err() != nil || errors.Is(err, errMethodDisabled) || errors.Is(context.Cause(methodCtx), errMethodDisabled))}
				if err != nil && !event.Canceled {
					event.Error = err.Error()
				}
				if event.Canceled {
					canceled.Add(1)
				}
				scheduler.record(event)
				if observer != nil {
					observer(event)
				}
				select {
				case results <- result{index: index, msg: resp, err: err}:
				case <-ctx.Done():
				}
			}(index, candidate)
		}
	}()
	failuresByRoute := make([]string, len(ordered))
collect:
	for remaining := len(ordered); remaining > 0; remaining-- {
		select {
		case <-ctx.Done():
			break collect
		case result := <-results:
			candidate := ordered[result.index]
			route := candidate.route
			if result.err != nil {
				failuresByRoute[result.index] = route.Name + " → " + candidate.upstream.Address + ": " + result.err.Error()
				continue
			}
			cancel()
			out.Route = route.ID
			out.Upstream = candidate.upstream.Address
			r.cachePut(key, result.msg, route.ID, candidate.upstream.Address, cacheGeneration)
			result.msg.Id = q.Id
			answer, err := result.msg.Pack()
			if err != nil {
				out.Error = err.Error()
			}
			return answer, out, err
		}
	}
	var failures []string
	for _, failure := range failuresByRoute {
		if failure != "" {
			failures = append(failures, failure)
		}
	}
	if len(failures) == 0 {
		failures = append(failures, "нет доступных включённых методов в выбранном пуле DoH: проверьте выключенные методы, NFQWS и AWG-подключения")
	}
	if ctx.Err() != nil {
		failures = append(failures, ctx.Err().Error())
	}
	err = fmt.Errorf("DNS недоступен: %s", strings.Join(failures, "; "))
	out.Error = err.Error()
	return nil, out, err
}

func validateResponse(raw []byte, query *mdns.Msg) (*mdns.Msg, error) {
	if len(raw) < 12 || len(raw) > 65535 {
		return nil, fmt.Errorf("неверный размер ответа DNS")
	}
	var resp mdns.Msg
	if err := resp.Unpack(raw); err != nil {
		return nil, fmt.Errorf("неверный ответ DNS: %w", err)
	}
	if !resp.Response || resp.Opcode != query.Opcode || resp.Id != query.Id || len(resp.Question) != 1 || len(query.Question) != 1 {
		return nil, fmt.Errorf("ответ DNS не соответствует запросу")
	}
	a, b := resp.Question[0], query.Question[0]
	if !strings.EqualFold(a.Name, b.Name) || a.Qtype != b.Qtype || a.Qclass != b.Qclass {
		return nil, fmt.Errorf("DNS-сервер ответил на другой вопрос")
	}
	if resp.Truncated {
		return nil, fmt.Errorf("усечённый ответ DoH")
	}
	if resp.Rcode != mdns.RcodeSuccess && resp.Rcode != mdns.RcodeNameError {
		return nil, fmt.Errorf("ответ DNS: %s", mdns.RcodeToString[resp.Rcode])
	}
	return &resp, nil
}

func (r *Resolver) exchangeEndpoint(ctx context.Context, route string, u Upstream, wire []byte, q *mdns.Msg) (*mdns.Msg, error) {
	methodCtx, release, err := r.methods.begin(ctx, route, u.Address)
	if err != nil {
		return nil, err
	}
	defer release()
	response, err := r.exchangeEnabledEndpoint(methodCtx, route, u, wire, q)
	if errors.Is(context.Cause(methodCtx), errMethodDisabled) {
		return nil, errMethodDisabled
	}
	return response, err
}

func (r *Resolver) exchangeEnabledEndpoint(ctx context.Context, route string, u Upstream, wire []byte, q *mdns.Msg) (*mdns.Msg, error) {
	endpoint, _ := url.Parse(u.Address)
	ips, err := r.endpointIPs(ctx, route, u, endpoint.Hostname())
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("нет адресов DNS-сервера")
	}
	var last error
	key := route + "|" + u.Address
	r.mu.Lock()
	start := r.ipCursor[key] % len(ips)
	r.mu.Unlock()
	for i := range ips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		index := (start + i) % len(ips)
		ip := ips[index]
		budget := time.Duration(r.cfg.TimeoutSeconds) * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			budget = time.Until(deadline) / time.Duration(len(ips)-i)
		}
		if budget < 400*time.Millisecond {
			budget = 400 * time.Millisecond
		}
		attempt, done := context.WithTimeout(ctx, budget)
		resp, e := r.doH(attempt, route, endpoint, ip, wire)
		done()
		if e == nil {
			parsed, e := validateResponse(resp, q)
			if e == nil {
				r.mu.Lock()
				if ctx.Err() == nil && !r.closed {
					r.ipCursor[key] = index
				}
				r.mu.Unlock()
				return parsed, nil
			}
			last = e
		} else {
			last = e
		}
		// Another route winning is not evidence that this endpoint IP failed.
		if ctx.Err() == context.Canceled {
			return nil, ctx.Err()
		}
		r.mu.Lock()
		if len(r.ipCursor) >= 256 {
			for k := range r.ipCursor {
				delete(r.ipCursor, k)
				break
			}
		}
		r.ipCursor[key] = (index + 1) % len(ips)
		r.mu.Unlock()
	}
	if last == nil {
		last = fmt.Errorf("нет адресов DNS-сервера")
	}
	if r.fastDNS != nil && len(u.BootstrapIPs) == 0 && net.ParseIP(endpoint.Hostname()) == nil && ctx.Err() == nil && r.lifetime.Err() == nil {
		r.fastDNS.RefreshSoon(route, endpoint.Hostname())
	}
	return nil, last
}

func (r *Resolver) doH(ctx context.Context, route string, endpoint *url.URL, ip string, wire []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(ip, port)
	if port == fmt.Sprint(r.cfg.DNSPort) && net.ParseIP(ip).Equal(net.ParseIP(r.cfg.ListenHost)) {
		return nil, fmt.Errorf("DoH upstream указывает на этот DNS-сервер: рекурсия запрещена")
	}
	// Host and SNI stay at the provider name while only the socket is pinned.
	key := route + "|" + endpoint.Host + "|" + addr
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("DNS-сервер остановлен")
	}
	client := r.clients[key]
	if client == nil {
		tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()},
			MaxIdleConns:    2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 16, IdleConnTimeout: 45 * time.Second,
			TLSHandshakeTimeout: time.Duration(r.cfg.TimeoutSeconds) * time.Second, ResponseHeaderTimeout: time.Duration(r.cfg.TimeoutSeconds) * time.Second, MaxResponseHeaderBytes: 16384}
		tr.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Transport detaches dialing from request cancellation so it can
			// reuse late connections. Racing DNS routes must cancel losing TCP
			// dials and TLS handshakes too; request values survive that detach.
			dialCtx, cancel := context.WithTimeout(ctx, time.Duration(r.cfg.TimeoutSeconds)*time.Second)
			defer cancel()
			stopClose := context.AfterFunc(r.lifetime, cancel)
			defer stopClose()
			if requestCtx, ok := ctx.Value(resolverRequestContextKey{}).(context.Context); ok {
				stopRequest := context.AfterFunc(requestCtx, cancel)
				defer stopRequest()
				if requestCtx.Err() != nil {
					return nil, requestCtx.Err()
				}
			}
			conn, err := r.backend.DialContext(dialCtx, route, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, tr.TLSClientConfig.Clone())
			if err := tlsConn.HandshakeContext(dialCtx); err != nil {
				conn.Close()
				return nil, err
			}
			// The connection can now be shared by other HTTP/2 requests. All
			// request-bound cancellation hooks end before handing it over.
			return tlsConn, nil
		}
		client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		// Endpoint changes may create new pools; keep the router's memory bounded.
		if len(r.clients) >= 64 {
			for k, c := range r.clients {
				c.CloseIdleConnections()
				delete(r.clients, k)
				break
			}
		}
		r.clients[key] = client
	}
	r.mu.Unlock()
	requestCtx := context.WithValue(ctx, resolverRequestContextKey{}, ctx)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			client.CloseIdleConnections()
		}
		return nil, fmt.Errorf("DoH соединение: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	media, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || media != "application/dns-message" {
		return nil, fmt.Errorf("DoH вернул неверный Content-Type")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(body) > 65535 {
		return nil, fmt.Errorf("слишком большой ответ DoH")
	}
	return body, nil
}

// Bootstrap never consults /etc/resolv.conf or the system resolver. Those may
// already point back to this service. Only the provider's hostname is looked up
// through independent literal-IP DoH endpoints, over the SAME selected route.
func (r *Resolver) endpointIPs(ctx context.Context, route string, u Upstream, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	if len(u.BootstrapIPs) > 0 {
		return append([]string{}, u.BootstrapIPs...), nil
	}
	if r.fastDNS != nil {
		return r.fastDNS.Lookup(ctx, route, host)
	}
	key := route + "|" + strings.ToLower(host)
	r.mu.Lock()
	cached, ok := r.endpoints[key]
	r.mu.Unlock()
	if ok && r.now().Before(cached.expires) {
		return append([]string{}, cached.ips...), nil
	}
	ips, ttl, err := r.lookupEndpointIPs(ctx, route, host)
	if err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = 1
	}
	r.mu.Lock()
	if len(r.endpoints) >= 256 {
		for k := range r.endpoints {
			delete(r.endpoints, k)
			break
		}
	}
	r.endpoints[key] = endpointEntry{ips: append([]string{}, ips...), expires: r.now().Add(time.Duration(ttl) * time.Second)}
	r.mu.Unlock()
	return ips, nil
}

func (r *Resolver) lookupEndpointIPs(ctx context.Context, route, host string) ([]string, uint32, error) {
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
	q.Id = 0
	wire, _ := q.Pack()
	var errs []string
	for _, base := range []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"} {
		endpoint, _ := url.Parse(base)
		methodCtx, release, methodErr := r.methods.begin(ctx, route, base)
		if methodErr != nil {
			errs = append(errs, base+": "+methodErr.Error())
			continue
		}
		probe, done := context.WithTimeout(methodCtx, time.Second)
		body, err := r.doH(probe, route, endpoint, endpoint.Hostname(), wire)
		done()
		if errors.Is(context.Cause(methodCtx), errMethodDisabled) {
			err = errMethodDisabled
		}
		release()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		msg, err := validateResponse(body, q)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		ips, ttl := bootstrapAnswerIPs(msg, host)
		if len(ips) == 0 {
			errs = append(errs, "bootstrap не вернул IPv4")
			continue
		}
		if len(ips) > 16 {
			ips = ips[:16]
		}
		return ips, ttl, nil
	}
	return nil, 0, fmt.Errorf("bootstrap %s: задайте IP DNS-сервера вручную, если независимый DoH заблокирован (%s)", host, strings.Join(errs, "; "))
}

// Only addresses for the queried owner (or its CNAME chain) may become socket
// destinations. Unrelated answer records never get trusted as bootstrap IPs.
func bootstrapAnswerIPs(msg *mdns.Msg, host string) ([]string, uint32) {
	owner := strings.ToLower(mdns.Fqdn(host))
	seen := map[string]bool{}
	ttl := uint32(300)
	for depth := 0; depth < 16; depth++ {
		if seen[owner] {
			return nil, 0
		}
		seen[owner] = true
		next := ""
		for _, rr := range msg.Answer {
			if c, ok := rr.(*mdns.CNAME); ok && strings.EqualFold(c.Hdr.Name, owner) {
				next = strings.ToLower(c.Target)
				if c.Hdr.Ttl < ttl {
					ttl = c.Hdr.Ttl
				}
				break
			}
		}
		if next != "" {
			owner = next
			continue
		}
		ips := []string{}
		unique := map[string]bool{}
		for _, rr := range msg.Answer {
			a, ok := rr.(*mdns.A)
			if !ok || !strings.EqualFold(a.Hdr.Name, owner) || a.A.IsUnspecified() || a.A.IsMulticast() {
				continue
			}
			ip := a.A.String()
			if !unique[ip] {
				unique[ip] = true
				ips = append(ips, ip)
			}
			if a.Hdr.Ttl < ttl {
				ttl = a.Hdr.Ttl
			}
			if len(ips) == 16 {
				break
			}
		}
		return ips, ttl
	}
	return nil, 0
}

func (r *Resolver) cacheGet(key string, id uint16) ([]byte, string, string) {
	r.mu.Lock()
	e, ok := r.cache[key]
	if ok && !r.now().Before(e.expires) {
		delete(r.cache, key)
		ok = false
	}
	if !ok {
		r.mu.Unlock()
		return nil, "", ""
	}
	msg := e.msg.Copy()
	age := uint32(r.now().Sub(e.created) / time.Second)
	r.mu.Unlock()
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == mdns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > age {
				rr.Header().Ttl -= age
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
	msg.Id = id
	b, err := msg.Pack()
	if err != nil {
		return nil, "", ""
	}
	return b, e.route, e.upstream
}

func (r *Resolver) cachePut(key string, msg *mdns.Msg, route, upstream string, generation uint64) {
	if r.cfg.CacheSize == 0 || msg.Rcode != mdns.RcodeSuccess || len(msg.Answer) == 0 || msg.IsTsig() != nil {
		return
	}
	wire, err := msg.Pack()
	if err != nil || len(wire) > 4096 || len(key) > 4096 {
		return
	}
	ttl := uint32(r.cfg.CacheTTLSeconds)
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != mdns.TypeOPT && rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	if ttl == 0 {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.cacheGeneration || r.closed {
		return
	}
	r.pruneCacheLocked(now)
	if len(r.cache) >= r.cfg.CacheSize {
		// Replacing an existing entry must not evict an unrelated answer.
		if _, exists := r.cache[key]; !exists {
			var oldest string
			var earliest time.Time
			for k, v := range r.cache {
				if earliest.IsZero() || v.expires.Before(earliest) {
					oldest = k
					earliest = v.expires
				}
			}
			delete(r.cache, oldest)
		}
	}
	r.cache[key] = dnsCacheEntry{msg: msg.Copy(), created: now, expires: now.Add(time.Duration(ttl) * time.Second), route: route, upstream: upstream}
}

// CacheStatus counts live DNS answers only; bootstrap addresses are separate.
func (r *Resolver) CacheStatus() CacheStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneCacheLocked(r.now())
	return CacheStatus{Entries: len(r.cache), Capacity: r.cfg.CacheSize, TTLSeconds: r.cfg.CacheTTLSeconds}
}

// ClearCache preserves transports, provider bootstrap addresses and scheduler
// history. Advancing the generation also invalidates pending cache inserts.
func (r *Resolver) ClearCache() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := len(r.cache)
	clear(r.cache)
	r.cacheGeneration++
	return removed
}

func (r *Resolver) pruneCacheLocked(now time.Time) {
	for key, entry := range r.cache {
		if !now.Before(entry.expires) {
			delete(r.cache, key)
		}
	}
}

func errorReply(raw []byte, rcode int) []byte {
	var q mdns.Msg
	if q.Unpack(raw) == nil {
		m := new(mdns.Msg)
		m.SetRcode(&q, rcode)
		b, _ := m.Pack()
		return b
	}
	b := make([]byte, 12)
	if len(raw) >= 2 {
		copy(b, raw[:2])
	}
	binary.BigEndian.PutUint16(b[2:4], 0x8000|uint16(rcode))
	return b
}
