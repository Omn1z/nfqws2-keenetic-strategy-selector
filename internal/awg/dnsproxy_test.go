package awg

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func encName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func tQuery(name string) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	b = append(b, encName(name)...)
	return append(b, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN
}

func tResponse(name string, ips []string) []byte {
	b := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, byte(len(ips) >> 8), byte(len(ips)), 0, 0, 0, 0}
	b = append(b, encName(name)...)
	b = append(b, 0, 1, 0, 1)
	for _, ip := range ips {
		b = append(b, 0xc0, 0x0c)  // name = pointer to offset 12 (question)
		b = append(b, 0, 1, 0, 1)  // TYPE=A CLASS=IN
		b = append(b, 0, 0, 0, 60) // TTL
		b = append(b, 0, 4)        // RDLENGTH
		b = append(b, net.ParseIP(ip).To4()...)
	}
	return b
}

func TestDNSWireParse(t *testing.T) {
	if n, ok := questionName(tQuery("A.Main.com")); !ok || n != "a.main.com" {
		t.Errorf("questionName = %q,%v want a.main.com,true", n, ok)
	}
	ips := answerIPs(tResponse("a.main.com", []string{"1.2.3.4", "5.6.7.8"}))
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Errorf("answerIPs = %v", ips)
	}
	if got := answerIPs([]byte{0, 1, 2}); got != nil {
		t.Errorf("answerIPs(short) = %v, want nil", got)
	}
}

func TestDNSProxyE2E(t *testing.T) {
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			name, _ := questionName(buf[:n])
			_, _ = up.WriteTo(tResponse(name, []string{"1.2.3.4"}), addr)
		}
	}()

	var mu sync.Mutex
	var got []string
	p := NewDNSProxy("127.0.0.1:0", up.LocalAddr().String(), func(ip string) {
		mu.Lock()
		got = append(got, ip)
		mu.Unlock()
	})
	ms, _ := CompileMatchers([]string{"main.com"})
	p.SetMatchers(ms)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	c, err := net.Dial("udp", p.udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// matching name → onMatch should fire with the answer IP, client gets the response
	_, _ = c.Write(tQuery("a.main.com"))
	resp := make([]byte, 1500)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if ips := answerIPs(resp[:n]); len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("client got ips %v, want [1.2.3.4]", ips)
	}
	// non-matching name → onMatch must NOT fire
	_, _ = c.Write(tQuery("nope.example.org"))
	_, _ = c.Read(resp)
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("onMatch got %v, want [1.2.3.4]", got)
	}
}
