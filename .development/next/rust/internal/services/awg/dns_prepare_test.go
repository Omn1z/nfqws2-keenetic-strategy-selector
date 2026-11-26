package awg

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestDNSBeforeReplyFailureDoesNotDeliverAddressesOrTraceSuccess(t *testing.T) {
	failure := errors.New("routing set could not be installed")
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", func(string, []string) {
		t.Fatal("live reply unexpectedly used the asynchronous replay callback")
	})
	p.SetBeforeReply(func(context.Context, string, string, []string) error { return failure })
	p.SetOnQuery(func(string, string, string, []string, bool) {
		t.Fatal("failed routing was traced as a successful answer")
	})
	response := tResponse("vpn.example", []string{"203.0.113.19"})
	before := append([]byte(nil), response...)
	got, err := p.ObserveAnswerContext(context.Background(), "192.168.3.19", "vpn.example", response)
	if got != nil || !errors.Is(err, failure) {
		t.Fatalf("got %x, %v; want no address and the installation failure", got, err)
	}
	if !bytes.Equal(before, response) {
		t.Fatal("routing failure modified the shared DNS cache entry")
	}
	failed := dnsFailureResponse(response)
	var parsed mdns.Msg
	if err := parsed.Unpack(failed); err != nil || parsed.Rcode != mdns.RcodeServerFailure || len(parsed.Answer) != 0 || len(parsed.Extra) != 0 {
		t.Fatalf("invalid failure reply: %v, %+v", err, parsed)
	}
}

func TestDNSBeforeReplyWaitsForInstalledRoute(t *testing.T) {
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", nil)
	entered, installed := make(chan struct{}), make(chan struct{})
	p.SetBeforeReply(func(ctx context.Context, src, name string, ips []string) error {
		if src != "192.168.3.19" || name != "vpn.example" || !reflect.DeepEqual(ips, []string{"203.0.113.19"}) {
			t.Errorf("unexpected learner input: %s %s %v", src, name, ips)
		}
		close(entered)
		select {
		case <-installed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := p.ObserveAnswerContext(context.Background(), "192.168.3.19", "vpn.example", tResponse("vpn.example", []string{"203.0.113.19"}))
		done <- err
	}()
	<-entered
	select {
	case err := <-done:
		t.Fatalf("answer returned before route installation: %v", err)
	default:
	}
	close(installed)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("installed route did not release DNS answer")
	}
}

func TestRetiredDNSProxyRejectsOldPolicySnapshot(t *testing.T) {
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", nil)
	p.SetBeforeReply(func(context.Context, string, string, []string) error {
		t.Fatal("retired policy was called")
		return nil
	})
	p.Stop()
	if response, err := p.ObserveAnswer("192.168.3.19", "vpn.example", tResponse("vpn.example", []string{"203.0.113.19"})); response != nil || err == nil {
		t.Fatalf("retired snapshot delivered an answer: %x %v", response, err)
	}
}

func TestDNSLargeUnrelatedAnswerIsNotRejectedByRoutingProxy(t *testing.T) {
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", nil)
	p.SetBeforeReply(func(_ context.Context, _, name string, ips []string) error {
		if name != "unrelated.example" || len(ips) != 65 {
			t.Fatalf("unexpected large answer: %s %d", name, len(ips))
		}
		return nil // An unrelated name requires no kernel destinations.
	})
	ips := make([]string, 65)
	for i := range ips {
		ips[i] = "203.0.113." + strconv.Itoa(i+1)
	}
	response := tResponse("unrelated.example", ips)
	got, err := p.ObserveAnswer("192.168.3.19", "unrelated.example", response)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("unrelated bulk response was replaced: %v", err)
	}
}

func serviceHintResponse(t *testing.T, ipv6 bool) []byte {
	t.Helper()
	q := new(mdns.Msg)
	q.SetQuestion("vpn.example.", mdns.TypeHTTPS)
	response := new(mdns.Msg)
	response.SetReply(q)
	values := []mdns.SVCBKeyValue{&mdns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("203.0.113.19")}}}
	if ipv6 {
		values = append(values, &mdns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::19")}})
	}
	response.Answer = []mdns.RR{&mdns.HTTPS{SVCB: mdns.SVCB{Hdr: mdns.RR_Header{Name: "vpn.example.", Rrtype: mdns.TypeHTTPS, Class: mdns.ClassINET, Ttl: 60}, Priority: 1, Target: ".", Value: values}}}
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestDNSHTTPSHintsLearnBeforeAnswerAndIPv6FallbackIsPerClient(t *testing.T) {
	response := serviceHintResponse(t, true)
	before := append([]byte(nil), response...)
	if got := answerIPs(response); !reflect.DeepEqual(got, []string{"203.0.113.19", "2001:db8::19"}) {
		t.Fatalf("HTTPS destinations were not parsed: %v", got)
	}
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", nil)
	p.SetAAAABlocker(func(src, _ string) bool { return src == "192.168.3.19" })
	var learned []string
	p.SetBeforeReply(func(_ context.Context, _, _ string, ips []string) error {
		learned = append([]string(nil), ips...)
		return nil
	})
	blocked, err := p.ObserveAnswer("192.168.3.19", "vpn.example", response)
	if err != nil {
		t.Fatal(err)
	}
	var nodata mdns.Msg
	if err := nodata.Unpack(blocked); err != nil || nodata.Rcode != mdns.RcodeSuccess || len(nodata.Answer) != 0 {
		t.Fatalf("IPv4-only client did not receive a valid HTTPS NODATA fallback: %v %+v", err, nodata)
	}
	if len(learned) != 0 {
		t.Fatalf("discarded IPv6 hints were learned: %v", learned)
	}
	allowed, err := p.ObserveAnswer("192.168.3.20", "vpn.example", response)
	if err != nil || !bytes.Equal(allowed, before) || !bytes.Equal(response, before) {
		t.Fatalf("another client's cached HTTPS answer changed: %v", err)
	}
	if !reflect.DeepEqual(learned, []string{"203.0.113.19", "2001:db8::19"}) {
		t.Fatalf("hints not installed before reply: %v", learned)
	}
}

func TestDNSServiceBindingMalformedHintDoesNotEscapeBounds(t *testing.T) {
	for _, body := range [][]byte{
		nil,
		{0, 1, 0, 0, 6, 0, 15},
		{0, 1, 0, 0, 4, 0, 3, 1, 2, 3},
		{0, 1, 0, 0, 4, 0xff, 0xff},
		{0, 1, 0xc0, 0xff},
	} {
		if got := serviceBindingHints(body, 0, len(body)); len(got) != 0 {
			t.Fatalf("invalid hint accepted: %x -> %v", body, got)
		}
	}
}
