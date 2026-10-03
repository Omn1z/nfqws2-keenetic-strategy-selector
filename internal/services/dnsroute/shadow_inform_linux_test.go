//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"net"
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
