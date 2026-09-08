package tgws

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestWorkerForwardsPartialTransportPacketWithoutSplitting(t *testing.T) {
	client, local := net.Pipe()
	remote, telegram := net.Pipe()
	defer client.Close()
	defer local.Close()
	defer remote.Close()
	defer telegram.Close()
	_ = telegram.SetDeadline(time.Now().Add(2 * time.Second))
	stats := &Stats{}
	pool := newCFWorkerPool(context.Background(), 0, 0, stats)
	pool.idle[cfPoolKey{2, dcDefaultIPs[2]}] = []pooledWorkerWS{{
		pooledWS: pooledWS{ws: &rawWebSocket{conn: remote, r: bufio.NewReader(remote)}, created: time.Now()},
		domain:   "worker.example.com",
	}}
	relay := generateRelayHandshake(protoTagAbridged, 2)
	prekey := bytes.Repeat([]byte{1}, 48)
	secret := bytes.Repeat([]byte{2}, 16)
	reenc := buildContext(prekey, secret, relay)
	clientCrypto := buildContext(prekey, secret, relay)
	done := make(chan bool, 1)
	go func() {
		done <- cfWorker(context.Background(), local, local, func() { _ = local.Close() },
			relay, 2, false, dcDefaultIPs[2], reenc, stats,
			fallbackConfig{cfproxyWorkerDomains: []string{"worker.example.com"}, workerPool: pool})
	}()
	serverWS := &rawWebSocket{conn: telegram, r: bufio.NewReader(telegram)}
	_, gotInit, _, err := serverWS.readFrame()
	if err != nil || !bytes.Equal(gotInit, relay) {
		t.Fatalf("worker relay init: %v", err)
	}
	// The first byte declares a 16-byte abridged packet, but the connection
	// remains open with only its header sent. A Worker must relay it now.
	ciphertext := make([]byte, 1)
	clientCrypto.clientDecrypt.XORKeyStream(ciphertext, []byte{4})
	if _, err := client.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	_, got, _, err := serverWS.readFrame()
	if err != nil || len(got) != 1 {
		t.Fatalf("worker waited for a complete MTProto packet: len=%d err=%v", len(got), err)
	}
	want := make([]byte, 1)
	clientCrypto.upstreamEncrypt.XORKeyStream(want, []byte{4})
	if !bytes.Equal(got, want) {
		t.Fatal("worker partial payload was not re-encrypted correctly")
	}
	_ = telegram.Close()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("worker did not take over connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker bridge did not close")
	}
	if stats.cfPoolHits.Load() != 1 {
		t.Fatal("worker fallback did not consume the warmed pool connection")
	}
}
