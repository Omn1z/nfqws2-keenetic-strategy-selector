package awg

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestEncryptedDNSObserveLearnsBeforeReturning(t *testing.T) {
	var calls []string
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", func(name string, ips []string) { calls = append(calls, "match:"+name+":"+ips[0]) })
	ms, _ := CompileMatcherSet([]string{"claude.ai"})
	p.SetMatchers(&ms)
	p.SetOnQuery(func(src, name, qtype string, ips []string, sinkhole bool) {
		calls = append(calls, "query:"+src+":"+name+":"+qtype)
	})
	response := tResponse("claude.ai", []string{"203.0.113.19"})
	before := append([]byte(nil), response...)
	got, err := p.ObserveAnswer("192.168.3.19", "CLAUDE.AI.", response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, before) || !bytes.Equal(response, before) {
		t.Fatal("observer modified cached upstream response")
	}
	want := []string{"match:claude.ai:203.0.113.19", "query:192.168.3.19:claude.ai:A"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("callbacks must finish before delivery: got%v", calls)
	}
	if recent := p.SnapshotRecent()["claude.ai"]; len(recent) != 1 || recent[0] != "203.0.113.19" {
		t.Fatalf("missing replay cache: %v", recent)
	}
}

func TestEncryptedDNSAAAAFilterIsPerClientAndDoesNotPoisonCache(t *testing.T) {
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", nil)
	p.SetAAAABlocker(func(src, name string) bool { return src == "192.168.3.10" && name == "claude.ai" })
	response := tQueryType("claude.ai", 28)
	response[2] |= 0x80
	response[6], response[7] = 0, 1
	response = append(response, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	response = append(response, net.ParseIP("2001:db8::19").To16()...)
	before := append([]byte(nil), response...)
	blocked, err := p.ObserveAnswer("192.168.3.10", "claude.ai", response)
	if err != nil {
		t.Fatal(err)
	}
	if blocked[6] != 0 || blocked[7] != 0 || len(blocked) != len(tQueryType("claude.ai", 28)) {
		t.Fatal("IPv4-only client received answer bytes or invalid trailing records")
	}
	if !bytes.Equal(response, before) {
		t.Fatal("per-client filter mutated shared cache")
	}
	allowed, err := p.ObserveAnswer("192.168.3.20", "claude.ai", response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(allowed, before) {
		t.Fatal("another client's IPv6 answer was filtered")
	}
}

func TestEncryptedDNSObserveRejectsWrongQuestion(t *testing.T) {
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", func(string, []string) { t.Fatal("unrelated answer entered routing policy") })
	for _, response := range [][]byte{nil, {0, 1}, tQuery("claude.ai"), tResponse("other.example", []string{"203.0.113.1"})} {
		if _, err := p.ObserveAnswer("192.168.3.10", "claude.ai", response); err == nil {
			t.Fatal("invalid or unrelated response accepted")
		}
	}
}

func TestEncryptedDNSRootQuestionWithEDNSKeepsValidCountsAndClass(t *testing.T) {
	p := NewDNSProxy("127.0.0.1:0", "127.0.0.1:53", nil)
	p.SetAAAABlocker(func(string, string) bool { return true })
	// A root AAAA question in CHAOS class plus OPT; only the question survives.
	response := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 28, 0, 3, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0}
	got, err := p.ObserveAnswer("192.168.3.10", ".", response)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 17 || got[12] != 0 || got[15] != 0 || got[16] != 3 {
		t.Fatalf("invalid root question or lost QCLASS: %x", got)
	}
	for i := 6; i < 12; i++ {
		if got[i] != 0 {
			t.Fatalf("stale answer/additional counts: %x", got[:12])
		}
	}
}
