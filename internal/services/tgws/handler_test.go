package tgws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTestDCRoutingUsesSeparateEnvironment(t *testing.T) {
	for _, tc := range []struct {
		raw   int
		force bool
		dc    int
		test  bool
		ip    string
	}{
		{2, false, 2, false, "149.154.167.51"},
		{10002, false, 2, true, "149.154.167.40"},
		{3, true, 3, true, "149.154.175.117"},
		{10001, true, 1, true, "149.154.175.10"},
		{4, true, 4, true, ""},
	} {
		dc, isTest := normalizeClientDC(tc.raw, tc.force)
		if dc != tc.dc || isTest != tc.test || fallbackIP(dc, isTest) != tc.ip {
			t.Fatalf("raw=%d force=%t -> DC%d test=%t IP=%s", tc.raw, tc.force, dc, isTest, fallbackIP(dc, isTest))
		}
	}
	if connectionDCKey(2, true, true) != "2tm" || connectionDCKey(2, false, true) != "2m" {
		t.Fatal("production/test/media connection keys must be distinct")
	}
}

func TestAuthenticatedTestDCUsesTestWebSocketPathAndNormalizedRelay(t *testing.T) {
	client, local := net.Pipe()
	remote, telegram := net.Pipe()
	defer client.Close()
	defer local.Close()
	defer remote.Close()
	defer telegram.Close()
	_ = telegram.SetDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stats := &Stats{}
	pool := newWSPool(ctx, 1, 4096, stats)
	var gotPath, gotDomain string
	pool.dial = func(_ context.Context, _, domain string, _ time.Duration, path string, _ int, sni string) (*rawWebSocket, error) {
		gotPath, gotDomain = path, domain
		return &rawWebSocket{conn: remote, r: bufio.NewReader(remote), domain: domain, sni: sni}, nil
	}
	key := poolKey{dc: 2, media: true, test: true, targetIP: "192.0.2.1"}
	pool.scheduleRefill(key, key.targetIP, wsDomainsFor(2, true))
	waitForPool(t, pool)
	// Keep the fixture's single upstream socket dedicated to this client.
	pool.mu.Lock()
	pool.refillAfter[key] = time.Now().Add(time.Hour)
	pool.mu.Unlock()
	h := newClientHandler(ctx, handlerSettings{
		secret: bytes.Repeat([]byte{1}, 16), dcRedirects: map[int]string{2: "192.0.2.1"},
	}, pool, stats, newDomainBalancer())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.serveAuthenticated(&clientHandshake{dcID: 10002, isMedia: true,
			protoTag: protoTagAbridged, prekeyIV: bytes.Repeat([]byte{2}, 48)}, local, local, "test")
	}()
	serverWS := &rawWebSocket{conn: telegram, r: bufio.NewReader(telegram)}
	_, init, _, err := serverWS.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if len(init) != handshakeLen {
		t.Fatalf("relay init length=%d", len(init))
	}
	plain := make([]byte, len(init))
	newCTR(init[8:40], init[40:56]).XORKeyStream(plain, init)
	if dc := int16(binary.LittleEndian.Uint16(plain[60:62])); dc != -2 {
		t.Fatalf("relay encoded DC%d; want media DC-2 in the test environment", dc)
	}
	_ = telegram.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("test DC bridge did not close with upstream")
	}
	if gotPath != wsTestPath || gotDomain != "kws2-1.web.telegram.org" {
		t.Fatalf("test media target=%s%s", gotDomain, gotPath)
	}
	if stats.poolHits.Load() != 1 || stats.connectionsWS.Load() != 1 || stats.poolMisses.Load() != 0 {
		t.Fatalf("test client did not use its warmed test/media bucket: %s", stats.summary())
	}
}

func TestAuthenticatedPoolMissDoesNotWaitForForegroundDial(t *testing.T) {
	for _, size := range []int{0, 1} {
		t.Run(itoa(size), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stats := &Stats{}
			pool := newWSPool(ctx, size, 4096, stats)
			started := make(chan struct{}, 1)
			var dials atomic.Int32
			pool.dial = func(ctx context.Context, _, _ string, _ time.Duration, _ string, _ int, _ string) (*rawWebSocket, error) {
				dials.Add(1)
				started <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			// DC99 has no fallback endpoint, keeping this full handler test
			// independent of real Telegram/public network availability.
			secret := bytes.Repeat([]byte{1}, 16)
			h := newClientHandler(ctx, handlerSettings{secret: secret, dcRedirects: map[int]string{99: "192.0.2.1"}}, pool, stats, newDomainBalancer())
			client, local := net.Pipe()
			defer client.Close()
			defer local.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan struct{})
			go func() { defer close(done); h.handle(local) }()
			if _, err := client.Write(makeClientInit(secret, protoTagIntermediate, 99)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(300 * time.Millisecond):
				t.Fatal("handler waited for a foreground direct WS dial on pool miss")
			}
			if size > 0 {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("pool miss did not schedule a background refill")
				}
			}
			cancel()
			waitForPool(t, pool)
			if dials.Load() != int32(size) || stats.connectionsWS.Load() != 0 || stats.connectionsActive.Load() != 0 {
				t.Fatalf("size=%d dials=%d stats=%s", size, dials.Load(), stats.summary())
			}
		})
	}
}

func TestMissingTestDCFailsWithoutProductionCFFallback(t *testing.T) {
	// There is no test DC4. Passing a nil balancer also verifies that the
	// enabled production CF fallback is never consulted for test accounts.
	if attemptFallback(context.Background(), nil, nil, func() {}, nil, 4, true, false,
		nil, &Stats{}, fallbackConfig{cfproxyEnabled: true}, nil, nil) {
		t.Fatal("unknown test DC unexpectedly used production fallback")
	}
}

func TestProxyHeaderPreservesFollowingHandshakeAndRejectsOversize(t *testing.T) {
	handshake := bytes.Repeat([]byte{0xa5}, handshakeLen)
	for _, header := range []string{"PROXY TCP4 192.0.2.1 192.0.2.2 50000 443\r\n", "PROXY UNKNOWN\r\n"} {
		br := bufio.NewReader(bytes.NewReader(append([]byte(header), handshake...)))
		if err := consumeProxyProtocol(br); err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(br)
		if !bytes.Equal(got, handshake) {
			t.Fatal("PROXY header parser consumed the MTProto handshake")
		}
	}
	for _, header := range []string{"GET / HTTP/1.0\r\n", "PROXY " + strings.Repeat("x", 108), "PROXY UNKNOWN\n"} {
		if err := consumeProxyProtocol(bufio.NewReader(strings.NewReader(header))); err == nil {
			t.Fatalf("accepted malformed PROXY header %q", header)
		}
	}
}

type deadlineCheckedConn struct {
	net.Conn
	r                  io.Reader
	deadline           time.Time
	readBeforeDeadline bool
}

func (c *deadlineCheckedConn) Read(p []byte) (int, error) {
	if c.deadline.IsZero() {
		c.readBeforeDeadline = true
	}
	return c.r.Read(p)
}

func (c *deadlineCheckedConn) SetReadDeadline(t time.Time) error { c.deadline = t; return nil }

func TestProxyHeaderReadHasHandshakeDeadline(t *testing.T) {
	h := newClientHandler(context.Background(), handlerSettings{proxyProtocol: true}, nil, &Stats{}, nil)
	c := &deadlineCheckedConn{r: strings.NewReader("PROXY ")}
	_, _, ok := h.readInit(bufio.NewReader(c), c, "test")
	if ok || c.readBeforeDeadline || c.deadline.IsZero() {
		t.Fatal("PROXY header must have a read deadline even if it never reaches a newline")
	}
}
