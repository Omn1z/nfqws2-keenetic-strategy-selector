package tgws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDirectTimeoutSkipsOtherSNIAndCoolsSharedIP(t *testing.T) {
	h := newClientHandler(context.Background(), handlerSettings{}, nil, &Stats{}, nil)
	calls := 0
	h.connect = func(_ context.Context, host, domain string, timeout time.Duration, path string, buffer int) (*rawWebSocket, error) {
		calls++
		return nil, fmt.Errorf("TLS handshake: %w", context.DeadlineExceeded)
	}
	if ws := h.connectDirect("2", "192.0.2.1", wsDomainsFor(2, false), wsPath, wsDefaultTimeout, "test"); ws != nil {
		t.Fatal("timeout returned a connection")
	}
	if calls != 1 {
		t.Fatalf("same timed-out IP dialed %d times; want one", calls)
	}
	if !h.cooldown.ipCoolingDown("192.0.2.1") || h.cooldown.ipCoolingDown("192.0.2.2") {
		t.Fatal("IP cooldown must affect exactly the failed destination")
	}
	if h.cooldown.isBlacklisted("2") || h.cooldown.remainingCooldown("2") <= 0 {
		t.Fatal("a timeout needs a temporary DC cooldown, not a redirect blacklist")
	}
}

func TestDirectRedirectBlacklistRequiresEveryAlternativeToRedirect(t *testing.T) {
	for _, tc := range []struct {
		name        string
		last        error
		blacklisted bool
	}{
		{"all redirects", &wsHandshakeError{statusCode: 302}, true},
		{"one network failure", errors.New("connection reset"), false},
		{"redirect then timeout", context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newClientHandler(context.Background(), handlerSettings{}, nil, &Stats{}, nil)
			calls := 0
			h.connect = func(context.Context, string, string, time.Duration, string, int) (*rawWebSocket, error) {
				calls++
				if calls == 1 {
					return nil, &wsHandshakeError{statusCode: 302}
				}
				return nil, tc.last
			}
			h.connectDirect("2tm", "192.0.2.1", wsDomainsFor(2, true), wsTestPath, wsDefaultTimeout, "test")
			if calls != 2 || h.cooldown.isBlacklisted("2tm") != tc.blacklisted {
				t.Fatalf("calls=%d blacklist=%t; want calls=2 blacklist=%t", calls, h.cooldown.isBlacklisted("2tm"), tc.blacklisted)
			}
			if h.cooldown.isBlacklisted("2") || h.cooldown.isBlacklisted("2m") {
				t.Fatal("test/media DC state leaked into other DC variants")
			}
		})
	}
}

func TestCanceledDialDoesNotPoisonCooldown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := newClientHandler(ctx, handlerSettings{}, nil, &Stats{}, nil)
	h.connect = func(context.Context, string, string, time.Duration, string, int) (*rawWebSocket, error) {
		cancel()
		return nil, context.Canceled
	}
	h.connectDirect("2", "192.0.2.1", wsDomainsFor(2, false), wsPath, wsDefaultTimeout, "test")
	if h.cooldown.isBlacklisted("2") || h.cooldown.ipCoolingDown("192.0.2.1") || h.cooldown.remainingCooldown("2") > 0 {
		t.Fatal("shutdown cancellation must not be remembered as upstream failure")
	}
}

func TestSuccessfulPoolDestinationCanClearIPCooldown(t *testing.T) {
	c := newCooldownTracker()
	c.cooldownIP("192.0.2.1")
	c.clearIP("192.0.2.1")
	if c.ipCoolingDown("192.0.2.1") {
		t.Fatal("a successful WS connection must clear the shared IP cooldown")
	}
	c.ipFailUntil["192.0.2.1"] = time.Now().Add(-time.Second)
	if c.ipCoolingDown("192.0.2.1") {
		t.Fatal("expired IP cooldown must allow retries")
	}
}

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
		t.Fatal("production/test/media cooldown keys must be distinct")
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
	h := newClientHandler(context.Background(), handlerSettings{
		secret: bytes.Repeat([]byte{1}, 16), dcRedirects: map[int]string{2: "192.0.2.1"},
	}, nil, &Stats{}, newDomainBalancer())
	var gotPath, gotDomain string
	h.connect = func(_ context.Context, _, domain string, _ time.Duration, path string, _ int) (*rawWebSocket, error) {
		gotPath, gotDomain = path, domain
		return &rawWebSocket{conn: remote, r: bufio.NewReader(remote)}, nil
	}
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
