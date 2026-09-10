package tlsblob

import "testing"

func TestSNIFromEthernet(t *testing.T) {
	ch, err := GenerateClientHello("cdn.example.net", []string{"h2"}, 0x0303)
	if err != nil {
		t.Fatalf("GenerateClientHello: %v", err)
	}
	frame := ethIPv4TCP("192.168.3.97", "104.26.8.59", 51000, 443, 1, ch)
	dst, port, sni, ok := SNIFromEthernet(frame)
	if !ok {
		t.Fatal("expected ok for a valid ClientHello frame")
	}
	if dst != "104.26.8.59" || port != 443 || sni != "cdn.example.net" {
		t.Fatalf("got dst=%q port=%d sni=%q", dst, port, sni)
	}
}

func TestSNIFromEthernetRejectsNonClientHello(t *testing.T) {
	// a plain (non-TLS) TCP payload to :443 must not match
	frame := ethIPv4TCP("192.168.3.97", "1.2.3.4", 51000, 443, 1, []byte("GET / HTTP/1.1\r\n"))
	if _, _, _, ok := SNIFromEthernet(frame); ok {
		t.Fatal("non-TLS payload should not produce an SNI")
	}
	// a UDP-ish / too-short frame
	if _, _, _, ok := SNIFromEthernet([]byte{0x00, 0x01, 0x02}); ok {
		t.Fatal("short frame should not match")
	}
}
