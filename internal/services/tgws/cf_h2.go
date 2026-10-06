package tgws

// The CF /api endpoint accepts complete MTProto packets on independent HTTP/2
// streams. Keep each origin on one TLS connection; response completion order
// deliberately does not follow upload order (long polls must not block media).
import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/tlsroots"
)

const (
	cfH2MaxPacket       = h2MaxPacket
	cfH2ChannelRequests = 8
	cfH2ChannelBytes    = 8 << 20
	cfH2LaneRequests    = 64
	cfH2LaneBytes       = 32 << 20
	cfH2RequestTimeout  = 65 * time.Second
	cfH2SetupTimeout    = 8 * time.Second
	cfH2Cooldown        = 30 * time.Second
)

type mtprotoTransportError struct {
	code   int32
	source string
}

func (e *mtprotoTransportError) Error() string {
	return fmt.Sprintf("MTProto transport error %d (%s)", e.code, e.source)
}

type cfH2Pool struct {
	ctx         context.Context
	cancel      context.CancelFunc
	bal         *domainBalancer
	stats       *Stats
	mu          sync.Mutex
	closeOnce   sync.Once
	openingWG   sync.WaitGroup
	closed      bool
	lanes       map[string]*cfH2Lane
	opening     map[string]chan struct{}
	failedUntil map[string]time.Time
	setupRetry  map[int]time.Time
	// Immutable after construction. Tests substitute a verified local TLS origin.
	newLane func(string) *cfH2Lane
}

func newCFH2Pool(ctx context.Context, bal *domainBalancer, stats *Stats) *cfH2Pool {
	ctx, cancel := context.WithCancel(ctx)
	p := &cfH2Pool{ctx: ctx, cancel: cancel, bal: bal, stats: stats, lanes: make(map[string]*cfH2Lane), opening: make(map[string]chan struct{}), failedUntil: make(map[string]time.Time), setupRetry: make(map[int]time.Time)}
	p.newLane = func(host string) *cfH2Lane { return newCFH2Lane(ctx, host, stats, nil) }
	return p
}

func (p *cfH2Pool) open(ctx context.Context, dc int, label string) (*cfH2Channel, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, ok := dcDefaultIPs[dc]; !ok {
		return nil, nil
	}
	p.mu.Lock()
	closed, cooling := p.closed || p.ctx.Err() != nil, time.Now().Before(p.setupRetry[dc])
	p.mu.Unlock()
	if closed {
		return nil, io.ErrClosedPipe
	}
	if cooling {
		return nil, nil
	}
	setup, cancel := context.WithTimeout(ctx, cfH2SetupTimeout)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	domains := p.bal.candidatesFor(dc)
	p.prune(domains)
	for _, base := range domains {
		host := fmt.Sprintf("kws%d.%s", dc, base)
		lane, err := p.getLane(setup, host)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if p.ctx.Err() != nil {
				return nil, io.ErrClosedPipe
			}
			if setup.Err() != nil {
				p.mu.Lock()
				p.setupRetry[dc] = time.Now().Add(cfH2Cooldown)
				p.mu.Unlock()
				return nil, nil
			}
			if isWSHandshakeQueueError(err) {
				return nil, nil
			}
			continue
		}
		if lane == nil {
			continue
		}
		ch, err := lane.open(label)
		if err != nil {
			continue
		}
		p.promoteCurrentDomain(dc, base)
		return ch, nil
	}
	return nil, nil
}

func (p *cfH2Pool) getLane(ctx context.Context, host string) (*cfH2Lane, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, io.ErrClosedPipe
		}
		if time.Now().Before(p.failedUntil[host]) {
			p.mu.Unlock()
			return nil, nil
		}
		if lane := p.lanes[host]; lane != nil {
			p.mu.Unlock()
			lane.mu.Lock()
			cooling := time.Now().Before(lane.failedUntil)
			lane.mu.Unlock()
			if cooling {
				return nil, nil
			}
			return lane, nil
		}
		if waiting := p.opening[host]; waiting != nil {
			p.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ready := make(chan struct{})
		p.opening[host] = ready
		p.openingWG.Add(1)
		p.mu.Unlock()
		lane := p.newLane(host)
		err := lane.preflight(ctx)
		p.mu.Lock()
		if err == nil && (p.closed || p.ctx.Err() != nil) {
			err = io.ErrClosedPipe
		}
		if err == nil {
			p.lanes[host] = lane
		} else if !isWSHandshakeQueueError(err) && ctx.Err() == nil {
			p.failedUntil[host] = time.Now().Add(cfH2Cooldown)
		}
		delete(p.opening, host)
		close(ready)
		p.mu.Unlock()
		if err != nil {
			lane.close()
			p.openingWG.Done()
			if !errors.Is(err, context.Canceled) && !isWSHandshakeQueueError(err) {
				p.stats.h2Errors.Add(1)
				log.Printf("tgws: H2 preflight %s: %s; trying existing routes", censorDomains(host), censorDomains(err.Error()))
			}
			return nil, err
		}
		p.openingWG.Done()
		return lane, nil
	}
}

func (p *cfH2Pool) close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		lanes := make([]*cfH2Lane, 0, len(p.lanes))
		for _, l := range p.lanes {
			lanes = append(lanes, l)
		}
		p.lanes = make(map[string]*cfH2Lane)
		p.mu.Unlock()
		for _, l := range lanes {
			l.close()
		}
		p.openingWG.Wait()
	})
}

// A preflight may overlap the hourly domain refresh. Its established channel
// remains usable, but completion must not restore a removed domain as preferred.
func (p *cfH2Pool) promoteCurrentDomain(dc int, domain string) {
	p.bal.mu.Lock()
	defer p.bal.mu.Unlock()
	for _, current := range p.bal.domains {
		if current == domain {
			p.bal.active[dc] = domain
			return
		}
	}
}

// Refreshes rotate the domain list hourly. Retire only idle obsolete origins;
// established Telegram streams keep their connection until their normal close.
func (p *cfH2Pool) prune(domains []string) {
	keep := make(map[string]bool, len(domains))
	for _, domain := range domains {
		keep[domain] = true
	}
	var retired []*cfH2Lane
	p.mu.Lock()
	for host, until := range p.failedUntil {
		if !time.Now().Before(until) {
			delete(p.failedUntil, host)
		}
	}
	for host, lane := range p.lanes {
		_, base, _ := strings.Cut(host, ".")
		if keep[base] {
			continue
		}
		lane.mu.Lock()
		if len(lane.channels) == 0 {
			lane.closed = true
			delete(p.lanes, host)
			retired = append(retired, lane)
		}
		lane.mu.Unlock()
	}
	p.mu.Unlock()
	for _, lane := range retired {
		lane.close()
	}
}

type cfH2Lane struct {
	ctx                               context.Context
	cancel                            context.CancelFunc
	host                              string
	endpoint                          string
	stats                             *Stats
	transport                         *http.Transport
	mu                                sync.Mutex // Also guards all mutable channel/request/replay state.
	closeOnce                         sync.Once
	changed                           chan struct{}
	closed                            bool
	failedUntil                       time.Time
	channels                          map[*cfH2Channel]struct{}
	inflight, queuedBytes, replyBytes int
}

func newCFH2Lane(parent context.Context, host string, stats *Stats, tlsTemplate *tls.Config) *cfH2Lane {
	ctx, cancel := context.WithCancel(parent)
	l := &cfH2Lane{ctx: ctx, cancel: cancel, host: host, endpoint: "https://" + host + "/api", stats: stats, changed: make(chan struct{}), channels: make(map[*cfH2Channel]struct{})}
	if tlsTemplate == nil {
		tlsTemplate = &tls.Config{RootCAs: tlsroots.Pool(), ClientSessionCache: wsTLSSessions}
	}
	tlsConfig := tlsTemplate.Clone()
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		name = host
	}
	tlsConfig.ServerName = name
	tlsConfig.InsecureSkipVerify = false
	tlsConfig.NextProtos = []string{"h2"}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	l.transport = &http.Transport{
		Protocols: protocols, TLSClientConfig: tlsConfig,
		DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
		IdleConnTimeout: 90 * time.Second, MaxResponseHeaderBytes: 64 << 10,
		HTTP2: &http.HTTP2Config{StrictMaxConcurrentRequests: true, MaxReceiveBufferPerConnection: (4 << 20) - 1, MaxReceiveBufferPerStream: 256 << 10, MaxReadFrameSize: 16 << 10, WriteByteTimeout: cfH2RequestTimeout},
	}
	l.transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		queue, cancelQueue := context.WithTimeout(ctx, time.Second)
		stopQueue := context.AfterFunc(l.ctx, cancelQueue)
		release, err := wsHandshakes.acquire(queue)
		stopQueue()
		cancelQueue()
		if err != nil {
			return nil, err
		}
		defer release()
		dialCtx, cancelDial := context.WithTimeout(ctx, cfH2SetupTimeout)
		defer cancelDial()
		stop := context.AfterFunc(l.ctx, cancelDial)
		defer stop()
		raw, err := (&net.Dialer{}).DialContext(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		applyConnOptions(raw, 0)
		conn := tls.Client(raw, tlsConfig.Clone())
		if err = conn.HandshakeContext(dialCtx); err != nil {
			raw.Close()
			return nil, err
		}
		if conn.ConnectionState().NegotiatedProtocol != "h2" {
			conn.Close()
			return nil, errors.New("CF endpoint did not negotiate HTTP/2")
		}
		l.stats.h2TCPConnections.Add(1)
		return conn, nil
	}
	return l
}

func (l *cfH2Lane) preflight(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, l.endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := l.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		return errors.New("CF preflight requires HTTP/2")
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != 405 && resp.StatusCode != 501 {
		return fmt.Errorf("CF preflight HTTP %d", resp.StatusCode)
	}
	return nil
}

func (l *cfH2Lane) signalLocked() { close(l.changed); l.changed = make(chan struct{}) }
func (l *cfH2Lane) hasCapacityLocked(size int) bool {
	return l.inflight < cfH2LaneRequests && l.queuedBytes+size <= cfH2LaneBytes
}

func (l *cfH2Lane) open(label string) (*cfH2Channel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	ctx, cancel := context.WithCancel(l.ctx)
	c := &cfH2Channel{lane: l, ctx: ctx, cancel: cancel, label: label, pending: make(map[*cfH2Request]struct{}), sendGate: make(chan struct{}, 1), lastProgress: time.Now()}
	l.channels[c] = struct{}{}
	c.wg.Add(1)
	go c.recover()
	return c, nil
}

func (l *cfH2Lane) close() {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.cancel()
		l.signalLocked()
		channels := make([]*cfH2Channel, 0, len(l.channels))
		for c := range l.channels {
			channels = append(channels, c)
		}
		l.mu.Unlock()
		for _, c := range channels {
			c.close()
		}
		l.transport.CloseIdleConnections()
	})
}
