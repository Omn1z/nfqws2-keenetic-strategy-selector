package tgws

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func cfH2Fixture(t *testing.T, handler http.HandlerFunc) (*cfH2Lane, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	lane := newCFH2Lane(context.Background(), strings.TrimPrefix(server.URL, "https://"), &Stats{}, &tls.Config{RootCAs: roots})
	t.Cleanup(lane.close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := lane.preflight(ctx); err != nil {
		t.Fatal(err)
	}
	return lane, server
}

func cfH2Packet(id byte) []byte          { body := make([]byte, 24); body[16] = id; return body }
func cfH2EncryptedPacket(id byte) []byte { body := cfH2Packet(id); body[0] = 1; return body }
func cfH2TestChannel(t *testing.T, lane *cfH2Lane) *cfH2Channel {
	t.Helper()
	c, err := lane.open("test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c
}
func cfH2TestReceive(t *testing.T, c *cfH2Channel) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.receive(ctx)
}

func TestCFH2MultiplexesWithoutResponseHeadOfLineBlocking(t *testing.T) {
	started := make(chan struct{})
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("not HTTP/2")
		}
		if r.URL.Path != "/api" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("unexpected packet headers")
		}
		body, _ := io.ReadAll(r.Body)
		if body[16] == 1 {
			close(started)
			<-r.Context().Done()
			return
		}
		w.Write([]byte{body[16], 0, 0, 0})
	})
	c := cfH2TestChannel(t, lane)
	if err := c.send(context.Background(), cfH2Packet(1), false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first request not started")
	}
	if err := c.send(context.Background(), cfH2Packet(2), true); err != nil {
		t.Fatal(err)
	}
	body, err := cfH2TestReceive(t, c)
	if err != nil || !bytes.Equal(body, []byte{2, 0, 0, 0}) {
		t.Fatalf("reply=%v err=%v", body, err)
	}
	c.delivered()
	if lane.stats.h2TCPConnections.Load() != 1 {
		t.Fatal("multiplexing opened extra TCP connections")
	}
	if lane.stats.h2Requests.Load() != 2 || lane.stats.bytesUp.Load() != 48 {
		t.Fatal("request accounting")
	}
	done := make(chan struct{})
	go func() { c.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("channel close did not cancel pending HTTP stream")
	}
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if lane.inflight != 0 || lane.queuedBytes != 0 || lane.replyBytes != 0 {
		t.Fatalf("leaked capacity: %d %d %d", lane.inflight, lane.queuedBytes, lane.replyBytes)
	}
}

func TestCFH2TransportErrorClosesOnlyAffectedChannel(t *testing.T) {
	for _, mode := range []string{"status403", "status404", "status429", "status444", "payload404"} {
		t.Run(mode, func(t *testing.T) {
			var heads atomic.Int64
			lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					heads.Add(1)
					w.WriteHeader(501)
					return
				}
				body, _ := io.ReadAll(r.Body)
				if body[16] == 2 {
					w.Write([]byte{2, 0, 0, 0})
					return
				}
				if mode == "payload404" {
					var b [4]byte
					code := int32(-404)
					binary.LittleEndian.PutUint32(b[:], uint32(code))
					w.Write(b[:])
					return
				}
				var code int
				fmt.Sscanf(mode, "status%d", &code)
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(code)
				w.Write([]byte("not a binary MTProto response"))
			})
			bad := cfH2TestChannel(t, lane)
			if err := bad.send(context.Background(), cfH2Packet(1), false); err != nil {
				t.Fatal(err)
			}
			_, err := cfH2TestReceive(t, bad)
			var transport *mtprotoTransportError
			if !errors.As(err, &transport) || transport.code >= 0 {
				t.Fatalf("expected native error, got %v", err)
			}
			if bad.transportError() == nil {
				t.Fatal("terminal error accessor lost error")
			}
			if err = bad.send(context.Background(), cfH2Packet(2), false); !errors.As(err, &transport) {
				t.Fatalf("send lost typed terminal error: %v", err)
			}
			lane.mu.Lock()
			poisoned := !lane.failedUntil.IsZero()
			lane.mu.Unlock()
			if poisoned {
				t.Fatal("MTProto auth/rate error poisoned whole lane")
			}
			good := cfH2TestChannel(t, lane)
			if err := good.send(context.Background(), cfH2Packet(2), false); err != nil {
				t.Fatal(err)
			}
			body, err := cfH2TestReceive(t, good)
			if err != nil || len(body) != 4 || body[0] != 2 {
				t.Fatalf("unrelated channel failed %v %v", body, err)
			}
			good.delivered()
			if heads.Load() != 1 || lane.stats.h2TCPConnections.Load() != 1 {
				t.Fatal("channel error caused lane reconnect")
			}
		})
	}
}

func TestCFH2RejectsBadResponsesAndCoolsLane(t *testing.T) {
	for _, mode := range []string{"html", "unaligned", "huge", "encoding", "status500", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					return
				}
				switch mode {
				case "html":
					w.Header().Set("Content-Type", "text/html")
					w.Write([]byte("html"))
				case "unaligned":
					w.Write([]byte{1, 2, 3})
				case "huge":
					w.Header().Set("Content-Length", fmt.Sprint(cfH2MaxPacket+4))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write([]byte{1, 2, 3, 4})
				case "status500":
					w.WriteHeader(500)
				case "truncated":
					w.Header().Set("Content-Length", "8")
					w.Write([]byte{1, 2, 3, 4})
				}
			})
			c := cfH2TestChannel(t, lane)
			if err := c.send(context.Background(), cfH2Packet(1), false); err != nil {
				t.Fatal(err)
			}
			_, err := cfH2TestReceive(t, c)
			if err == nil {
				t.Fatal("accepted corrupt response")
			}
			var native *mtprotoTransportError
			if errors.As(err, &native) {
				t.Fatal("mapped HTTP failure to MTProto auth error")
			}
			c.close()
			lane.mu.Lock()
			defer lane.mu.Unlock()
			if !time.Now().Before(lane.failedUntil) {
				t.Fatal("bad endpoint did not enter cooldown")
			}
			if lane.replyBytes != 0 || c.replyBytes != 0 {
				t.Fatal("failed response leaked buffer credits")
			}
		})
	}
}

func TestCFH2ChannelCapacityWaitHonorsCancellation(t *testing.T) {
	var arrived atomic.Int64
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		arrived.Add(1)
		<-r.Context().Done()
	})
	c := cfH2TestChannel(t, lane)
	for range cfH2ChannelRequests {
		if err := c.send(context.Background(), cfH2Packet(1), false); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := c.send(ctx, cfH2Packet(1), false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("overfull channel send=%v", err)
	}
	c.close()
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if lane.inflight != 0 || lane.queuedBytes != 0 {
		t.Fatal("capacity not returned after cancellation")
	}
}

func TestCFH2ReplyBackpressureIsBounded(t *testing.T) {
	response := make([]byte, cfH2MaxPacket)
	response[0] = 1
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		w.Write(response)
	})
	c := cfH2TestChannel(t, lane)
	for range 3 {
		if err := c.send(context.Background(), cfH2Packet(1), false); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		lane.mu.Lock()
		err := c.err
		bytes := lane.replyBytes
		lane.mu.Unlock()
		if bytes > cfH2ChannelBytes {
			t.Fatalf("exceeded channel response bound %d", bytes)
		}
		if err != nil {
			if !errors.Is(err, errCFH2ReplyBuffer) {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("response memory limit was not enforced")
		}
		time.Sleep(time.Millisecond)
	}
	c.close()
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if lane.replyBytes != 0 || c.replyBytes != 0 {
		t.Fatalf("buffer credit leaked after close: %d %d", lane.replyBytes, c.replyBytes)
	}
	if !lane.failedUntil.IsZero() {
		t.Fatal("local backpressure poisoned endpoint")
	}
}

func TestCFH2ConcurrentChannelsShareOneTCPConnection(t *testing.T) {
	const requests = 16
	ready := make(chan struct{})
	var arrived atomic.Int64
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		if arrived.Add(1) == requests {
			close(ready)
		}
		select {
		case <-ready:
		case <-r.Context().Done():
			return
		}
		w.Write([]byte{1, 0, 0, 0})
	})
	channels := []*cfH2Channel{cfH2TestChannel(t, lane), cfH2TestChannel(t, lane)}
	for _, c := range channels {
		for range requests / 2 {
			if err := c.send(context.Background(), cfH2Packet(1), false); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range channels {
		for range requests / 2 {
			if _, err := cfH2TestReceive(t, c); err != nil {
				t.Fatal(err)
			}
			c.delivered()
		}
	}
	if lane.stats.h2TCPConnections.Load() != 1 {
		t.Fatalf("opened %d TCP connections", lane.stats.h2TCPConnections.Load())
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); lane.close() }()
	}
	wg.Wait()
}

func TestCFH2RequiresVerifiedTLSAndHTTP2(t *testing.T) {
	for _, mode := range []string{"untrusted", "http1"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			s.EnableHTTP2 = mode != "http1"
			s.StartTLS()
			defer s.Close()
			roots := x509.NewCertPool()
			if mode != "untrusted" {
				roots.AddCert(s.Certificate())
			}
			lane := newCFH2Lane(context.Background(), strings.TrimPrefix(s.URL, "https://"), &Stats{}, &tls.Config{RootCAs: roots, InsecureSkipVerify: true})
			defer lane.close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := lane.preflight(ctx); err == nil {
				t.Fatal("accepted unverified TLS or HTTP/1 downgrade")
			}
		})
	}
}
