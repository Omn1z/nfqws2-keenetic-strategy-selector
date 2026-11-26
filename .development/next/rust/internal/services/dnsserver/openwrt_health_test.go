package dnsserver

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/openwrtdns"
)

type openWrtHealthDNSFixture struct {
	endpoint openwrtdns.Endpoint
	udp, tcp atomic.Int32
}

// Both test servers are loopback-only. No public DNS or system resolver is
// involved, even though the health question contains a public-looking name.
func startOpenWrtHealthDNS(t *testing.T, serveUDP, serveTCP bool, reply func(string, *mdns.Msg) *mdns.Msg) *openWrtHealthDNSFixture {
	t.Helper()
	var udp net.PacketConn
	var tcp net.Listener
	for attempt := 0; attempt < 20; attempt++ {
		var err error
		// Some Windows UDP ports are excluded despite being available for TCP.
		udp, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err = net.Listen("tcp4", udp.LocalAddr().String())
		if err == nil {
			break
		}
		_ = udp.Close()
	}
	if tcp == nil {
		t.Fatal("could not reserve TCP and UDP on one loopback port")
	}
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	f := &openWrtHealthDNSFixture{endpoint: openwrtdns.Endpoint{Host: "127.0.0.1", Port: udp.LocalAddr().(*net.UDPAddr).Port}}
	for _, transport := range []string{"udp", "tcp"} {
		if transport == "udp" && !serveUDP {
			_ = udp.Close()
			continue
		}
		if transport == "tcp" && !serveTCP {
			_ = tcp.Close()
			continue
		}
		ready, done := make(chan struct{}), make(chan error, 1)
		server := &mdns.Server{NotifyStartedFunc: func() { close(ready) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, question *mdns.Msg) {
			if transport == "udp" {
				f.udp.Add(1)
			} else {
				f.tcp.Add(1)
			}
			if len(question.Question) != 1 || question.Question[0].Name != "example.com." || question.Question[0].Qtype != mdns.TypeA {
				t.Error("unexpected health question", question.Question)
			}
			if answer := reply(transport, question); answer != nil {
				_ = w.WriteMsg(answer)
			}
		})}
		if transport == "udp" {
			server.PacketConn = udp
		} else {
			server.Listener = tcp
		}
		go func() { done <- server.ActivateAndServe() }()
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Error("stop health fixture", err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Error("health fixture stopped with error", err)
				}
			case <-ctx.Done():
				t.Error("health fixture did not stop")
			}
		})
		select {
		case <-ready:
		case err := <-done:
			t.Fatal("start health fixture", err)
		case <-time.After(2 * time.Second):
			t.Fatal("health fixture did not start")
		}
	}
	return f
}

func openWrtHealthReply(question *mdns.Msg, rcode int) *mdns.Msg {
	answer := new(mdns.Msg)
	answer.SetRcode(question, rcode)
	if rcode == mdns.RcodeSuccess {
		answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 10)}}
	}
	return answer
}

func TestOpenWrtDNSHealthRequiresSuccessfulUDPAndTCPAnswers(t *testing.T) {
	for _, rcode := range []int{mdns.RcodeSuccess, mdns.RcodeNameError} {
		t.Run(mdns.RcodeToString[rcode], func(t *testing.T) {
			fixture := startOpenWrtHealthDNS(t, true, true, func(_ string, question *mdns.Msg) *mdns.Msg { return openWrtHealthReply(question, rcode) })
			if err := checkOpenWrtDNSListener(context.Background(), fixture.endpoint); err != nil {
				t.Fatal(err)
			}
			if fixture.udp.Load() != 1 || fixture.tcp.Load() != 1 {
				t.Fatalf("health did not check both transports: udp=%d tcp=%d", fixture.udp.Load(), fixture.tcp.Load())
			}
		})
	}
}

func TestOpenWrtDNSHealthRejectsSERVFAILAndRefusedResponses(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, rcode := range []int{mdns.RcodeServerFailure, mdns.RcodeRefused} {
			t.Run(transport+"/"+mdns.RcodeToString[rcode], func(t *testing.T) {
				fixture := startOpenWrtHealthDNS(t, true, true, func(network string, question *mdns.Msg) *mdns.Msg {
					if network == transport {
						return openWrtHealthReply(question, rcode)
					}
					return openWrtHealthReply(question, mdns.RcodeSuccess)
				})
				if err := checkOpenWrtDNSListener(context.Background(), fixture.endpoint); err == nil || !strings.Contains(err.Error(), transport) {
					t.Fatalf("unhealthy DNS accepted: %v", err)
				}
				if fixture.udp.Load() != 1 || fixture.tcp.Load() != map[string]int32{"udp": 0, "tcp": 1}[transport] {
					t.Fatal("probe continued after failed transport")
				}
			})
		}
	}
}

func TestOpenWrtDNSHealthRejectsMissingTransport(t *testing.T) {
	for _, missing := range []string{"udp", "tcp"} {
		t.Run(missing, func(t *testing.T) {
			fixture := startOpenWrtHealthDNS(t, missing != "udp", missing != "tcp", func(_ string, question *mdns.Msg) *mdns.Msg { return openWrtHealthReply(question, mdns.RcodeSuccess) })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := checkOpenWrtDNSListener(ctx, fixture.endpoint); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing transport accepted: %v", err)
			}
		})
	}
}

func TestOpenWrtDNSHealthCancellationBeforeAnyQuestion(t *testing.T) {
	fixture := startOpenWrtHealthDNS(t, true, true, func(_ string, question *mdns.Msg) *mdns.Msg { return openWrtHealthReply(question, mdns.RcodeSuccess) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkOpenWrtDNSListener(ctx, fixture.endpoint); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost preflight cancellation: %v", err)
	}
	if fixture.udp.Load() != 0 || fixture.tcp.Load() != 0 {
		t.Fatal("canceled health check sent a DNS question")
	}
}

func TestOpenWrtDNSHealthCancellationInterruptsUDPRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture := startOpenWrtHealthDNS(t, true, true, func(_ string, _ *mdns.Msg) *mdns.Msg {
		cancel()   // socket is connected and the UDP request reached this fixture
		return nil // no response: cancellation must close the outstanding read
	})
	started := time.Now()
	if err := checkOpenWrtDNSListener(ctx, fixture.endpoint); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost mid-read cancellation: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled health check waited for its socket timeout: %s", elapsed)
	}
	if fixture.udp.Load() != 1 || fixture.tcp.Load() != 0 {
		t.Fatal("canceled UDP check proceeded to TCP")
	}
}
