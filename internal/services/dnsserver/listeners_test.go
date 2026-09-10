package dnsserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func protocolTestQuery() []byte {
	return []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
}

func protocolTestPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		tcp.Close()
		if err == nil {
			udp.Close()
			return port
		}
	}
	t.Fatal("cannot reserve a free DNS port")
	return 0
}

func protocolTestExchange(_ context.Context, q []byte) ([]byte, error) {
	r := append([]byte{}, q...)
	r[2] |= 0x80
	return r, nil
}

func TestPlainDNSProtocolsAndClientIdentity(t *testing.T) {
	listener, err := StartListeners(context.Background(), ListenerOptions{
		BindHost: "127.0.0.1", DNSPort: protocolTestPort(t),
		Exchange: func(ctx context.Context, q []byte) ([]byte, error) {
			if !ContextClientIP(ctx).Equal(net.ParseIP("127.0.0.1")) {
				t.Errorf("client IP = %v", ContextClientIP(ctx))
			}
			return protocolTestExchange(ctx, q)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addresses().DNS
	query := protocolTestQuery()
	udp, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := udp.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	if err != nil || n != len(query) || buf[2]&0x80 == 0 {
		t.Fatalf("UDP response: %x %v", buf[:n], err)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Pipeline two differently identified queries over one ordinary TCP stream.
	for i := 0; i < 2; i++ {
		query[1] = byte(i)
		if err := writeDNSFrame(conn, query); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		response, err := readDNSFrame(conn)
		if err != nil || len(response) != len(query) || response[2]&0x80 == 0 || response[1] != byte(i) {
			t.Fatalf("TCP response: %x %v", response, err)
		}
	}
}

func TestUDPTruncatesAtClientLimitAndTCPReturnsFullAnswer(t *testing.T) {
	s, err := StartListeners(context.Background(), ListenerOptions{BindHost: "127.0.0.1", DNSPort: protocolTestPort(t), Exchange: func(_ context.Context, wire []byte) ([]byte, error) {
		var q mdns.Msg
		if err := q.Unpack(wire); err != nil {
			return nil, err
		}
		r := new(mdns.Msg)
		r.SetReply(&q)
		for i := 0; i < 16; i++ {
			r.Answer = append(r.Answer, &mdns.TXT{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 200)}})
		}
		return r.Pack()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct {
		edns  uint16
		limit int
	}{{0, 512}, {128, 512}, {800, 800}, {4096, maxUDPPayload}} {
		q := new(mdns.Msg)
		q.SetQuestion("example.com.", mdns.TypeTXT)
		if tc.edns != 0 {
			q.SetEdns0(tc.edns, false)
		}
		client := &mdns.Client{Net: "udp", UDPSize: 4096, Timeout: 3 * time.Second}
		r, _, err := client.Exchange(q, s.Addresses().DNS)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := r.Pack()
		if err != nil || !r.Truncated || len(wire) > tc.limit {
			t.Fatalf("EDNS %d: truncated=%v size=%d limit=%d err=%v", tc.edns, r.Truncated, len(wire), tc.limit, err)
		}
		client.Net = "tcp"
		r, _, err = client.Exchange(q, s.Addresses().DNS)
		if err != nil || r.Truncated || len(r.Answer) != 16 {
			t.Fatalf("TCP answer after truncation: %v %v", r, err)
		}
	}
}

func TestDNSRejectsMalformedQueriesAndDisallowedClients(t *testing.T) {
	for _, denied := range []bool{false, true} {
		s, err := StartListeners(context.Background(), ListenerOptions{BindHost: "127.0.0.1", DNSPort: protocolTestPort(t), AllowClient: func(net.IP) bool { return !denied }, Exchange: func(context.Context, []byte) ([]byte, error) {
			t.Error("invalid or disallowed request reached resolver")
			return nil, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		query := protocolTestQuery()
		if !denied {
			query[2] |= 0x80 // responses must never be recursively resolved
		}
		for _, network := range []string{"udp", "tcp"} {
			conn, err := net.Dial(network, s.Addresses().DNS)
			if err != nil {
				s.Close()
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
			if network == "tcp" {
				_ = writeDNSFrame(conn, query)
			} else {
				_, _ = conn.Write(query)
			}
			var b [512]byte
			if n, err := conn.Read(b[:]); err == nil || n != 0 {
				t.Errorf("%s invalid query produced response %x: %v", network, b[:n], err)
			}
			conn.Close()
		}
		s.Close()
	}
}

func TestListenerBindingRollbackAndShutdown(t *testing.T) {
	port := protocolTestPort(t)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	occupied, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	opts := ListenerOptions{BindHost: "127.0.0.1", DNSPort: port, Exchange: protocolTestExchange}
	if s, err := StartListeners(context.Background(), opts); err == nil {
		s.Close()
		t.Fatal("accepted occupied UDP port")
	}
	reused, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("failed startup leaked TCP socket: %v", err)
	}
	reused.Close()
	occupied.Close()
	for _, bind := range []string{"0.0.0.0", "::", "8.8.8.8", "localhost"} {
		opts.BindHost = bind
		if s, err := StartListeners(context.Background(), opts); err == nil {
			s.Close()
			t.Errorf("accepted non-LAN bind %q", bind)
		}
	}
	for _, network := range []string{"udp", "tcp"} {
		opts.BindHost = "127.0.0.1"
		entered := make(chan struct{})
		opts.Exchange = func(ctx context.Context, _ []byte) ([]byte, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		s, err := StartListeners(ctx, opts)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		client := &mdns.Client{Net: network, Timeout: time.Second}
		done := make(chan struct{})
		go func() {
			defer close(done)
			q := new(mdns.Msg)
			q.SetQuestion("example.com.", mdns.TypeA)
			_, _, _ = client.Exchange(q, s.Addresses().DNS)
		}()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("query never started")
		}
		cancel()
		s.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown did not cancel active request")
		}
	}
}

func TestTCPResolverFailureReturnsSERVFAILAndKeepsConnection(t *testing.T) {
	attempts := 0
	s, err := StartListeners(context.Background(), ListenerOptions{BindHost: "127.0.0.1", DNSPort: protocolTestPort(t), Exchange: func(ctx context.Context, q []byte) ([]byte, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("test network failure")
		}
		return protocolTestExchange(ctx, q)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	conn, err := net.Dial("tcp", s.Addresses().DNS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 2; i++ {
		if err := writeDNSFrame(conn, protocolTestQuery()); err != nil {
			t.Fatal(err)
		}
		wire, err := readDNSFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		var msg mdns.Msg
		if err := msg.Unpack(wire); err != nil || msg.Rcode == mdns.RcodeServerFailure != (i == 0) {
			t.Fatalf("attempt %d response %v err %v", i, msg, err)
		}
	}
}
