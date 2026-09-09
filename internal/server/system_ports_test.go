package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateSystemPorts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports systemPorts
		valid bool
	}{
		{"defaults", systemPorts{PanelPort: 8090, DNSPort: 5355}, true},
		{"range limits", systemPorts{PanelPort: 1, DNSPort: 65535}, true},
		{"equal ports", systemPorts{PanelPort: 5355, DNSPort: 5355}, false},
		{"panel disabled", systemPorts{PanelPort: 0, DNSPort: 5355}, false},
		{"dns disabled", systemPorts{PanelPort: 8090, DNSPort: 0}, false},
		{"negative panel", systemPorts{PanelPort: -1, DNSPort: 5355}, false},
		{"negative dns", systemPorts{PanelPort: 8090, DNSPort: -1}, false},
		{"large panel", systemPorts{PanelPort: 65536, DNSPort: 5355}, false},
		{"large dns", systemPorts{PanelPort: 8090, DNSPort: 65536}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSystemPorts(tc.ports); (err == nil) != tc.valid {
				t.Fatalf("validateSystemPorts(%+v) = %v; valid=%v", tc.ports, err, tc.valid)
			}
		})
	}
}

// Reserve the same ephemeral loopback port in both transports. This keeps the
// occupied-UDP test from accidentally failing on an unrelated TCP listener.
func reserveDNSProbePort(t *testing.T) (*net.TCPListener, net.PacketConn, int) {
	t.Helper()
	for i := 0; i < 10; i++ {
		tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			return tcp, udp, port
		}
		tcp.Close()
	}
	t.Fatal("could not reserve a loopback TCP/UDP port")
	return nil, nil, 0
}

func TestProbeDNSPortLeavesOccupiedTCPUsable(t *testing.T) {
	tcp, udp, port := reserveDNSProbePort(t)
	defer tcp.Close()
	udp.Close()
	if err := probeDNSPort("127.0.0.1", port); err == nil || !strings.Contains(err.Error(), "TCP") {
		t.Fatalf("occupied TCP port accepted or wrong failure: %v", err)
	}
	if err := tcp.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", tcp.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("original TCP listener stopped accepting: %v", err)
	}
	defer client.Close()
	accepted, err := tcp.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	accepted.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("still alive"))
	if _, err := io.ReadFull(accepted, b); err != nil || string(b) != "still alive" {
		t.Fatalf("original TCP connection unusable after probe: %q, %v", b, err)
	}
}

func TestProbeDNSPortLeavesOccupiedUDPUsableAndReleasesTCP(t *testing.T) {
	tcp, udp, port := reserveDNSProbePort(t)
	defer udp.Close()
	tcp.Close()
	if err := probeDNSPort("127.0.0.1", port); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("occupied UDP port accepted or wrong failure: %v", err)
	}
	// TCP was opened before the failed UDP bind and must have been released.
	tcpAgain, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed UDP probe leaked its TCP listener: %v", err)
	}
	defer tcpAgain.Close()
	client, err := net.DialTimeout("udp4", udp.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, _, err := udp.ReadFrom(b)
	if err != nil || string(b[:n]) != "still alive" {
		t.Fatalf("original UDP listener unusable after probe: %q, %v", b[:n], err)
	}
}

func TestProbeDNSPortReleasesAvailablePort(t *testing.T) {
	tcp, udp, port := reserveDNSProbePort(t)
	tcp.Close()
	udp.Close()
	if err := probeDNSPort("127.0.0.1", port); err != nil {
		t.Fatalf("available port rejected: %v", err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	tcpAgain, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("successful probe leaked TCP listener: %v", err)
	}
	defer tcpAgain.Close()
	udpAgain, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("successful probe leaked UDP listener: %v", err)
	}
	defer udpAgain.Close()
}

func TestPanelPortURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		tls  bool
		want string
	}{
		{"IPv4", "192.168.3.1:8090", false, "http://192.168.3.1:8095"},
		{"IPv4 default port", "192.168.3.1", false, "http://192.168.3.1:8095"},
		{"IPv6", "[fd00::1]:8090", false, "http://[fd00::1]:8095"},
		{"IPv6 default port", "[fd00::1]", false, "http://[fd00::1]:8095"},
		{"hostname", "router.home.arpa:8090", false, "http://router.home.arpa:8095"},
		{"TLS", "router.home.arpa:8090", true, "https://router.home.arpa:8095"},
		{"empty host", "", false, ""},
		{"userinfo", "user@router.home.arpa:8090", false, ""},
		{"path in host", "router.home.arpa/path", false, ""},
		{"invalid IPv6", "[fd00::1", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Host: tc.host}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := panelPortURL(r, 8095); got != tc.want {
				t.Fatalf("panelPortURL = %q; want %q", got, tc.want)
			}
		})
	}
}
