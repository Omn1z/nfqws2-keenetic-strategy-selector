//go:build linux

package dnsroute

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

type shadowInformFakeSocket struct {
	sends, reads int
	onSend       func([]byte, time.Duration) error
	onReceive    func([]byte, time.Duration) (int, error)
}

func (s *shadowInformFakeSocket) send(packet []byte, wait time.Duration) error {
	s.sends++
	if s.onSend != nil {
		return s.onSend(packet, wait)
	}
	return nil
}

func (s *shadowInformFakeSocket) receive(packet []byte, wait time.Duration) (int, error) {
	s.reads++
	return s.onReceive(packet, wait)
}

func TestShadowInformCanceledBeforeSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	socket := &shadowInformFakeSocket{}
	if _, err := exchangeShadowInform(ctx, socket, shadowInformTestIdentity()); !errors.Is(err, context.Canceled) || socket.sends != 0 || socket.reads != 0 {
		t.Fatalf("canceled call touched socket: %v %+v", err, socket)
	}
	// This must return before any real interface lookup or socket creation.
	if _, err := shadowDHCPInform(ctx, "eth3", net.ParseIP("192.168.0.10"), net.ParseIP("192.168.0.1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("API ignored canceled context: %v", err)
	}
}

func TestShadowInformOneSendIgnoresUnrelatedPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	socket := &shadowInformFakeSocket{}
	socket.onReceive = func(packet []byte, wait time.Duration) (int, error) {
		if wait <= 0 || wait > shadowInformReadSlice {
			t.Fatalf("unbounded read slice %s", wait)
		}
		if socket.reads == 1 {
			return 0, syscall.EINTR
		}
		ack := shadowInformACKFixture()
		if socket.reads == 2 {
			ack[32] ^= 1
		}
		return copy(packet, ack), nil
	}
	servers, err := exchangeShadowInform(ctx, socket, shadowInformTestIdentity())
	if err != nil || len(servers) != 2 || socket.sends != 1 || socket.reads != 3 {
		t.Fatalf("servers=%v err=%v sends=%d reads=%d", servers, err, socket.sends, socket.reads)
	}
}

func TestShadowInformCancellationAfterReceiveRejectsACK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	socket := &shadowInformFakeSocket{onReceive: func(packet []byte, _ time.Duration) (int, error) {
		cancel()
		return copy(packet, shadowInformACKFixture()), nil
	}}
	if _, err := exchangeShadowInform(ctx, socket, shadowInformTestIdentity()); !errors.Is(err, context.Canceled) || socket.sends != 1 || socket.reads != 1 {
		t.Fatalf("late ACK accepted after cancellation: %v", err)
	}
}

func TestShadowInformDeadlineAndFloodAreBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	socket := &shadowInformFakeSocket{onReceive: func(_ []byte, wait time.Duration) (int, error) {
		if wait > 25*time.Millisecond {
			t.Fatalf("read exceeded remaining deadline: %s", wait)
		}
		time.Sleep(wait + time.Millisecond)
		return 0, syscall.EAGAIN
	}}
	started := time.Now()
	if _, err := exchangeShadowInform(ctx, socket, shadowInformTestIdentity()); !errors.Is(err, context.DeadlineExceeded) || socket.sends != 1 {
		t.Fatalf("timeout lost: %v", err)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("short deadline was not respected")
	}
	ctx, cancelFlood := context.WithTimeout(context.Background(), time.Second)
	defer cancelFlood()
	flood := &shadowInformFakeSocket{onReceive: func([]byte, time.Duration) (int, error) { return 0, nil }}
	if _, err := exchangeShadowInform(ctx, flood, shadowInformTestIdentity()); err == nil || flood.sends != 1 || flood.reads != shadowInformMaxReads {
		t.Fatalf("flood not bounded: %v sends=%d reads=%d", err, flood.sends, flood.reads)
	}
}

func TestShadowInformDiscoveryCanceledBeforeSocketAndSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	socket := &shadowInformFakeSocket{}
	if peer, servers, err := exchangeShadowInformFrom(ctx, socket, shadowInformTestIdentity(), true); !errors.Is(err, context.Canceled) || peer != nil || len(servers) != 0 || socket.sends != 0 || socket.reads != 0 {
		t.Fatalf("canceled discovery touched socket: %v %v %v %+v", peer, servers, err, socket)
	}
	// Canceled entry points must return before real interface/socket calls.
	if peer, servers, err := shadowDHCPInformDiscover(ctx, "eth3", net.ParseIP("192.168.0.10")); !errors.Is(err, context.Canceled) || peer != nil || len(servers) != 0 {
		t.Fatalf("discovery API ignored cancellation: %v %v %v", peer, servers, err)
	}
	if _, _, err := exchangeShadowInformFrom(context.Background(), socket, shadowInformTestIdentity(), true); err == nil || socket.sends != 0 {
		t.Fatal("discovery sent without a bounded deadline", err)
	}
}

func TestShadowInformDiscoveryOneSendLearnsMatchingServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	id := shadowInformTestIdentity()
	id.server = [4]byte{} // no DNS server, gateway, or DHCP peer is presumed
	socket := &shadowInformFakeSocket{}
	socket.onSend = func(packet []byte, wait time.Duration) error {
		if !bytes.Equal(packet, makeShadowInformPacket(id)) || wait <= 0 || wait > shadowInformReadSlice {
			t.Fatal("invalid INFORM or unbounded send timeout")
		}
		return nil
	}
	socket.onReceive = func(packet []byte, wait time.Duration) (int, error) {
		if wait <= 0 || wait > shadowInformReadSlice {
			t.Fatalf("unbounded discovery receive %s", wait)
		}
		if socket.reads == 1 {
			return 0, syscall.EINTR
		}
		ack := shadowInformACKFixture()
		switch socket.reads {
		case 2:
			ack[32] ^= 1 // another DHCP transaction on the unconnected socket
		case 3:
			ack[273] = 224 // multicast server identifier cannot identify a peer
		}
		return copy(packet, ack), nil
	}
	peer, servers, err := exchangeShadowInformFrom(ctx, socket, id, true)
	if err != nil || !peer.Equal(net.ParseIP("192.168.0.1")) || len(servers) != 2 || socket.sends != 1 || socket.reads != 4 {
		t.Fatalf("peer=%v servers=%v err=%v sends=%d reads=%d", peer, servers, err, socket.sends, socket.reads)
	}
}

func TestShadowInformTimeoutDistinguishesRejectedRepliesFromNoReply(t *testing.T) {
	for _, tc := range []struct {
		name     string
		packet   func() []byte
		rejected bool
	}{
		{name: "no reply"},
		{name: "unrelated transaction", packet: func() []byte {
			p := shadowInformACKFixture()
			p[32] ^= 1
			return p
		}},
		{name: "matching ACK without DNS", rejected: true, packet: func() []byte {
			p := shadowInformACKFixture()
			p[277] = 255
			return p
		}},
		{name: "matching wrong known server", rejected: true, packet: func() []byte {
			p := shadowInformACKFixture()
			p[273] ^= 1
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			socket := &shadowInformFakeSocket{}
			socket.onReceive = func(buf []byte, wait time.Duration) (int, error) {
				if socket.reads == 1 && tc.packet != nil {
					return copy(buf, tc.packet()), nil
				}
				time.Sleep(wait + time.Millisecond)
				return 0, syscall.EAGAIN
			}
			_, err := exchangeShadowInform(ctx, socket, shadowInformTestIdentity())
			if !errors.Is(err, context.DeadlineExceeded) || socket.sends != 1 {
				t.Fatalf("timeout identity lost: %v sends=%d", err, socket.sends)
			}
			if strings.Contains(err.Error(), "получен, но отклонён") != tc.rejected {
				t.Fatalf("incorrect reply diagnosis: %v", err)
			}
			if !tc.rejected && !strings.Contains(err.Error(), "не получен") {
				t.Fatalf("missing no-reply diagnosis: %v", err)
			}
		})
	}
}

func TestShadowInformDiscoveryCancellationRejectsLatePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	socket := &shadowInformFakeSocket{onReceive: func(packet []byte, _ time.Duration) (int, error) {
		cancel()
		return copy(packet, shadowInformACKFixture()), nil
	}}
	peer, servers, err := exchangeShadowInformFrom(ctx, socket, shadowInformTestIdentity(), true)
	if !errors.Is(err, context.Canceled) || peer != nil || servers != nil || socket.sends != 1 || socket.reads != 1 {
		t.Fatalf("late peer accepted after cancellation: %v %v %v", peer, servers, err)
	}
}

func TestShadowInformDiscoveryDeadlineAndPacketFloodAreBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	socket := &shadowInformFakeSocket{onReceive: func(_ []byte, wait time.Duration) (int, error) {
		if wait > 25*time.Millisecond {
			t.Fatalf("receive exceeded remaining deadline: %s", wait)
		}
		time.Sleep(wait + time.Millisecond)
		return 0, syscall.EAGAIN
	}}
	started := time.Now()
	peer, servers, err := exchangeShadowInformFrom(ctx, socket, shadowInformTestIdentity(), true)
	if !errors.Is(err, context.DeadlineExceeded) || peer != nil || servers != nil || socket.sends != 1 || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("discovery timeout lost: %v %v %v", peer, servers, err)
	}
	ctx, cancelFlood := context.WithTimeout(context.Background(), time.Second)
	defer cancelFlood()
	flood := &shadowInformFakeSocket{onReceive: func(packet []byte, _ time.Duration) (int, error) {
		ack := shadowInformACKFixture()
		ack[277] = 255 // matching ACK with no DNS is not usable peer evidence
		return copy(packet, ack), nil
	}}
	peer, servers, err = exchangeShadowInformFrom(ctx, flood, shadowInformTestIdentity(), true)
	if err == nil || peer != nil || servers != nil || flood.sends != 1 || flood.reads != shadowInformMaxReads {
		t.Fatalf("packet flood not bounded: %v %v %v sends=%d reads=%d", peer, servers, err, flood.sends, flood.reads)
	}
}
