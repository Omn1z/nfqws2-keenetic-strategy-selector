package awg

import (
	"strings"
	"testing"
)

func TestGenKeypairRoundTrip(t *testing.T) {
	priv, pub, err := GenKeypair()
	if err != nil {
		t.Fatal(err)
	}
	got, err := PubFromPriv(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != pub {
		t.Fatalf("pub mismatch: %s != %s", got, pub)
	}
}

func TestConfObfIdentical(t *testing.T) {
	c := Default()
	c.PrivateKey, c.PublicKey = "SERVERPRIV", "SERVERPUB"
	c.Conn.Host = "vpn.example.com"
	c.Normalize()
	if err := RandomizeObf(&c.Obf); err != nil {
		t.Fatal(err)
	}
	c.Obf.I1 = "<b 0xdeadbeef><r 12><t>"
	p := Peer{Name: "router", PublicKey: "PEERPUB", PrivateKey: "PEERPRIV", PSK: "PEERPSK", Address: "10.13.13.2/32", AllowedIPs: "0.0.0.0/0, ::/0", Keepalive: 25}
	c.Peers = []Peer{p}
	srv := ServerConf(c)
	cli := ClientConf(c, p)
	so, co := extractObf(srv), extractObf(cli)
	if so == "" || so != co {
		t.Fatalf("obf blocks differ:\n--server--\n%s\n--client--\n%s", so, co)
	}
	if !strings.Contains(srv, "PostUp =") || !strings.Contains(srv, "%i") {
		t.Fatal("server conf missing NAT PostUp / %i")
	}
	if !strings.Contains(cli, "Endpoint = vpn.example.com:51820") {
		t.Fatalf("client conf missing endpoint:\n%s", cli)
	}
}

func extractObf(conf string) string {
	var out []string
	for _, ln := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(ln)
		for _, k := range []string{"Jc ", "Jmin ", "Jmax ", "S1 ", "S2 ", "S3 ", "S4 ", "H1 ", "H2 ", "H3 ", "H4 ", "I1 ", "I2 ", "I3 ", "I4 ", "I5 "} {
			if strings.HasPrefix(t, k) {
				out = append(out, t)
			}
		}
	}
	return strings.Join(out, "\n")
}

func TestValidate(t *testing.T) {
	c := Default()
	if errs := c.Validate(); len(errs) == 0 {
		t.Fatal("expected error for empty host")
	}
	c.Conn.Host = "1.2.3.4"
	c.PrivateKey, c.PublicKey, _ = GenKeypair()
	c.Normalize()
	if errs := c.Validate(); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	c.Peers = []Peer{{Name: "a", Address: "bogus"}}
	if errs := c.Validate(); len(errs) == 0 {
		t.Fatal("expected error for bad peer address")
	}
}

func TestValidHeaderAndCPS(t *testing.T) {
	for _, g := range []string{"1", "12345", "0x1f", "100-200", "0x10-0x20"} {
		if !validHeader(g) {
			t.Errorf("expected valid header: %q", g)
		}
	}
	for _, b := range []string{"", "abc", "200-100", "1-2-3"} {
		if validHeader(b) {
			t.Errorf("expected invalid header: %q", b)
		}
	}
	if err := validateCPS("<b 0xdead><r 10><rc 5><rd 3><t>"); err != nil {
		t.Errorf("expected valid CPS: %v", err)
	}
	if err := validateCPS("<b 0xabc>"); err == nil {
		t.Error("expected odd-hex CPS error")
	}
	if err := validateCPS("<x 5>"); err == nil {
		t.Error("expected invalid-tag CPS error")
	}
}

func TestRenderUAPISet(t *testing.T) {
	c := Default()
	c.PublicKey = "RB78swIIfUFo/YfDnFJk32oggQFd8c5uJXodSj86xxs="
	c.Conn.Host = "vpn.example.com"
	c.Normalize()
	if err := RandomizeObf(&c.Obf); err != nil {
		t.Fatal(err)
	}
	p := Peer{Name: "router", PrivateKey: "kBAoKn010lyD1EfH/HTuCwLjpcweg7v70BzZ4ynfb1s=", PSK: "mJpNnaSR9h4gCHB7e4v4DNdGBZrV07pSgMzMU5VNCvI=", Address: "10.13.13.2/32", AllowedIPs: "0.0.0.0/0, ::/0", Keepalive: 25}
	out, err := RenderUAPISet(c, p, "1.2.3.4", 51820)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set=1", "private_key=", "public_key=", "endpoint=1.2.3.4:51820", "jc=", "h1=", "replace_peers=true", "allowed_ip=0.0.0.0/0", "persistent_keepalive_interval=25"} {
		if !strings.Contains(out, want) {
			t.Errorf("UAPI set missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "kBAoKn010") {
		t.Error("private key must be hex-encoded in UAPI, not base64")
	}
	st := ParseUAPIGet("public_key=abcd\nendpoint=1.2.3.4:51820\nlast_handshake_time_sec=1700000000\nrx_bytes=123\ntx_bytes=456\nerrno=0\n")
	if st.LastHandshake != 1700000000 || st.RxBytes != 123 || st.TxBytes != 456 || st.Endpoint != "1.2.3.4:51820" {
		t.Errorf("ParseUAPIGet wrong: %+v", st)
	}
}
