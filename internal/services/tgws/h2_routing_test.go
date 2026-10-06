package tgws

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestH2FallbackRoutesMediaAndForwardsHTTP404ToTelegram(t *testing.T) {
	body := cfH2Packet(7)
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(405)
			return
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("HTTP packet changed: %x", got)
		}
		w.WriteHeader(404)
	})
	bal := newDomainBalancer()
	bal.updatePool([]string{"relay.example"})
	pool := newCFH2Pool(context.Background(), bal, lane.stats)
	pool.lanes["kws2.relay.example"] = lane
	defer pool.close()
	client, local := net.Pipe()
	defer client.Close()
	defer local.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	relay := generateRelayHandshake(protoTagIntermediate, -2)
	prekey, secret := bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 16)
	crypto := buildContext(prekey, secret, relay)
	peer := buildContext(prekey, secret, relay)
	done := make(chan bool, 1)
	go func() {
		done <- attemptFallback(context.Background(), local, local, func() { _ = local.Close() }, relay, 2, false, true, crypto, lane.stats, fallbackConfig{cfproxyEnabled: true, h2Pool: pool}, bal, nil, protoIntIntermediate)
	}()
	packet := make([]byte, len(body)+4)
	binary.LittleEndian.PutUint32(packet, uint32(len(body)))
	copy(packet[4:], body)
	peer.clientDecrypt.XORKeyStream(packet, packet)
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 8)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	peer.clientEncrypt.XORKeyStream(response, response)
	if binary.LittleEndian.Uint32(response) != 4 || int32(binary.LittleEndian.Uint32(response[4:])) != -404 {
		t.Fatalf("Telegram did not receive native -404: %x", response)
	}
	select {
	case ok := <-done:
		if !ok || lane.stats.connectionsH2.Load() != 1 || lane.stats.connectionsCFProxy.Load() != 1 || lane.stats.connectionsTCPFallback.Load() != 0 {
			t.Fatal("H2 takeover lost route accounting or fell through after consuming client data")
		}
	case <-time.After(time.Second):
		t.Fatal("completed H2 bridge did not stop")
	}
}

func TestH2FallbackEligibilityDoesNotContactProductionMediaPool(t *testing.T) {
	for _, test := range []struct {
		name                   string
		media, test, cf, plain bool
	}{
		{"ordinary connection", false, false, true, false},
		{"test environment", true, true, true, false},
		{"CF disabled", true, false, false, false},
		{"TLS disabled", true, false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			backoff := newTCPFallbackBackoff()
			calls := 0
			backoff.dial = func(context.Context, string, string) (net.Conn, error) {
				calls++
				return nil, errors.New("test fallback unavailable")
			}
			// An uninitialized H2 pool makes any accidental access fail immediately.
			// The ordinary CF balancer is empty, so this test never uses the network.
			cfg := fallbackConfig{cfproxyEnabled: test.cf, disableSecure: test.plain, h2Pool: &cfH2Pool{}, tcpBackoff: backoff}
			if attemptFallback(context.Background(), nil, nil, func() {}, nil, 2, test.test, test.media, nil, &Stats{}, cfg, newDomainBalancer(), nil, protoIntIntermediate) || calls != 1 {
				t.Fatal("invalid H2 route selection")
			}
		})
	}
}
