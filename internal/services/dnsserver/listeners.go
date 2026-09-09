package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	maxDNSMessage = 65535
	dnsHeaderSize = 12
	maxUDPPayload = 1232
)

type ExchangeFunc func(context.Context, []byte) ([]byte, error)

// DNS uses the same port over UDP and TCP. BindHost must be a literal LAN or
// loopback address, never a wildcard or a public interface.
type ListenerOptions struct {
	BindHost       string
	DNSPort        int
	Exchange       ExchangeFunc
	AllowClient    func(net.IP) bool
	OnError        func(error)
	RequestTimeout time.Duration
}

type ListenerAddresses struct {
	DNS string `json:"dns"`
}

type clientIPContextKey struct{}

func ContextClientIP(ctx context.Context) net.IP {
	ip, _ := ctx.Value(clientIPContextKey{}).(net.IP)
	return append(net.IP(nil), ip...)
}

type Listeners struct {
	ctx             context.Context
	cancel          context.CancelFunc
	opts            ListenerOptions
	addresses       ListenerAddresses
	tcp             net.Listener
	udp             net.PacketConn
	closeOnce       sync.Once
	wg              sync.WaitGroup
	mu              sync.Mutex
	connections     map[net.Conn]struct{}
	connectionSlots chan struct{}
	requestSlots    chan struct{}
	querySlots      chan struct{}
}

// StartListeners binds both sockets before serving. A conflict rolls back all
// binds, so a failed configuration never leaves a partial service.
func StartListeners(ctx context.Context, opts ListenerOptions) (*Listeners, error) {
	bindIP := net.ParseIP(opts.BindHost)
	if bindIP == nil || (!bindIP.IsPrivate() && !bindIP.IsLoopback()) || bindIP.IsUnspecified() {
		return nil, errors.New("DNS listener must bind a literal private LAN or loopback IP")
	}
	if opts.Exchange == nil {
		return nil, errors.New("DNS listener requires a resolver")
	}
	if opts.DNSPort < 1 || opts.DNSPort > 65535 {
		return nil, errors.New("DNS listener port is outside 1..65535")
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 30 * time.Second
	}
	child, cancel := context.WithCancel(ctx)
	s := &Listeners{ctx: child, cancel: cancel, opts: opts, connections: map[net.Conn]struct{}{}, connectionSlots: make(chan struct{}, 128), requestSlots: make(chan struct{}, 64), querySlots: make(chan struct{}, 64)}
	address := net.JoinHostPort(bindIP.String(), strconv.Itoa(opts.DNSPort))
	var err error
	s.tcp, err = net.Listen("tcp", address)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("DNS TCP listen: %w", err)
	}
	s.udp, err = net.ListenPacket("udp", address)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("DNS UDP listen: %w", err)
	}
	s.addresses.DNS = address
	s.wg.Add(2)
	go s.acceptTCP()
	go s.serveUDP()
	go func() { <-child.Done(); s.Close() }()
	return s, nil
}

func (s *Listeners) Addresses() ListenerAddresses { return s.addresses }

func (s *Listeners) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.cancel()
		if s.tcp != nil {
			_ = s.tcp.Close()
		}
		if s.udp != nil {
			_ = s.udp.Close()
		}
		s.mu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
}

func (s *Listeners) failed(err error) {
	s.cancel()
	if s.opts.OnError != nil {
		go s.opts.OnError(err)
	}
}

func (s *Listeners) allowAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if s.opts.AllowClient != nil {
		return s.opts.AllowClient(ip)
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func validDNSQuery(query []byte) bool {
	if len(query) < dnsHeaderSize || len(query) > maxDNSMessage || query[2]&0x80 != 0 {
		return false
	}
	var msg mdns.Msg
	return msg.Unpack(query) == nil && len(msg.Question) == 1 && msg.Opcode == mdns.OpcodeQuery
}

func (s *Listeners) exchange(ctx context.Context, query []byte, remote string) ([]byte, error) {
	select {
	case s.querySlots <- struct{}{}:
		defer func() { <-s.querySlots }()
	default:
		return nil, errors.New("DNS server is busy")
	}
	host, _, _ := net.SplitHostPort(remote)
	ctx = context.WithValue(ctx, clientIPContextKey{}, net.ParseIP(host))
	ctx, cancel := context.WithTimeout(ctx, s.opts.RequestTimeout)
	defer cancel()
	response, err := s.opts.Exchange(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(response) < dnsHeaderSize || len(response) > maxDNSMessage || response[2]&0x80 == 0 || response[0] != query[0] || response[1] != query[1] {
		return nil, errors.New("resolver returned an invalid DNS response")
	}
	return response, nil
}

func (s *Listeners) serveUDP() {
	defer s.wg.Done()
	buffer := make([]byte, maxDNSMessage)
	for {
		n, remote, err := s.udp.ReadFrom(buffer)
		if err != nil {
			if s.ctx.Err() == nil {
				s.failed(fmt.Errorf("DNS UDP listener: %w", err))
			}
			return
		}
		if !s.allowAddr(remote.String()) || !validDNSQuery(buffer[:n]) {
			continue
		}
		// Bound allocation and work before copying a datagram into a goroutine.
		select {
		case s.requestSlots <- struct{}{}:
		default:
			continue
		}
		query := append([]byte(nil), buffer[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.requestSlots }()
			response, err := s.exchange(s.ctx, query, remote.String())
			if err != nil {
				response = dnsServFail(query)
			}
			response = truncateUDP(query, response)
			if s.ctx.Err() == nil {
				_, _ = s.udp.WriteTo(response, remote)
			}
		}()
	}
}

// Respect classic DNS's 512-byte limit and the client's EDNS receive size,
// capped to 1232 bytes to avoid IP fragmentation. TC asks the client to retry
// over TCP, where the complete response remains available.
func truncateUDP(query, response []byte) []byte {
	limit := 512
	var q mdns.Msg
	if q.Unpack(query) == nil {
		if opt := q.IsEdns0(); opt != nil && opt.UDPSize() > 512 {
			limit = int(opt.UDPSize())
			if limit > maxUDPPayload {
				limit = maxUDPPayload
			}
		}
	}
	if len(response) <= limit {
		return response
	}
	var msg mdns.Msg
	if msg.Unpack(response) == nil {
		msg.Truncate(limit)
		if wire, err := msg.Pack(); err == nil && len(wire) <= limit {
			return wire
		}
	}
	// Even unusual signed or malformed upstream records cannot bypass the cap.
	fallback := new(mdns.Msg)
	fallback.SetReply(&q)
	fallback.Truncated = true
	fallback.RecursionAvailable = true
	wire, err := fallback.Pack()
	if err == nil && len(wire) <= limit {
		return wire
	}
	return []byte{query[0], query[1], 0x82 | (query[2] & 0x79), 0x80, 0, 0, 0, 0, 0, 0, 0, 0}
}

func (s *Listeners) acceptTCP() {
	defer s.wg.Done()
	ln := &dnsLimitedListener{Listener: s.tcp, owner: s}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() == nil {
				s.failed(fmt.Errorf("DNS TCP listener: %w", err))
			}
			return
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); defer conn.Close(); s.serveTCP(conn) }()
	}
}

func (s *Listeners) serveTCP(conn net.Conn) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		query, err := readDNSFrame(conn)
		if err != nil || !validDNSQuery(query) {
			return
		}
		response, err := s.exchange(s.ctx, query, conn.RemoteAddr().String())
		if err != nil {
			response = dnsServFail(query)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeDNSFrame(conn, response); err != nil {
			return
		}
	}
}

func readDNSFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length < dnsHeaderSize {
		return nil, errors.New("short DNS message")
	}
	message := make([]byte, length)
	_, err := io.ReadFull(r, message)
	return message, err
}

func writeDNSFrame(w io.Writer, message []byte) error {
	if len(message) < dnsHeaderSize || len(message) > maxDNSMessage {
		return errors.New("invalid DNS response length")
	}
	frame := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func dnsServFail(query []byte) []byte {
	return errorReply(query, mdns.RcodeServerFailure)
}

type dnsLimitedListener struct {
	net.Listener
	owner *Listeners
}

func (l *dnsLimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.owner.allowAddr(conn.RemoteAddr().String()) {
			_ = conn.Close()
			continue
		}
		select {
		case l.owner.connectionSlots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		l.owner.mu.Lock()
		if l.owner.ctx.Err() != nil {
			l.owner.mu.Unlock()
			<-l.owner.connectionSlots
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		l.owner.connections[conn] = struct{}{}
		l.owner.mu.Unlock()
		return &dnsTrackedConn{Conn: conn, owner: l.owner}, nil
	}
}

type dnsTrackedConn struct {
	net.Conn
	owner *Listeners
	once  sync.Once
}

func (c *dnsTrackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.connections, c.Conn)
		c.owner.mu.Unlock()
		<-c.owner.connectionSlots
	})
	return err
}
