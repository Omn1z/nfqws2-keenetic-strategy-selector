package awg

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRenderUAPISetWithTransportMark(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := &ServerConfig{PublicKey: key, Protocol: "wireguard"}
	peer := Peer{PrivateKey: key}
	const mark = 0xa0000007
	payload, err := RenderUAPISetWithMark(cfg, peer, "192.0.2.1", 51820, mark)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "\nfwmark=2684354567\nreplace_peers=true\n") {
		t.Fatal("missing device fwmark before peer settings")
	}
	if st := ParseUAPIGet("fwmark=2684354567\n"); st.FWMark != mark {
		t.Fatalf("parsed fwmark = %#x", st.FWMark)
	}
	payload, err = RenderUAPISet(cfg, peer, "192.0.2.1", 51820)
	if err != nil || strings.Contains(payload, "fwmark=") {
		t.Fatalf("unexpected fwmark in direct transport (render error %v)", err)
	}
}
