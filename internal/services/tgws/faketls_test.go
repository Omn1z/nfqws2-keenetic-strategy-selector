package tgws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestFakeTLSRejectsUnauthenticatedHellos(t *testing.T) {
	secret := []byte("0123456789abcdef")
	now := uint32(time.Now().Unix())
	for _, tc := range []struct {
		name   string
		modify func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:42] }},
		{"not TLS handshake", func(b []byte) []byte { b[0] = tlsRecordAppData; return b }},
		{"not ClientHello", func(b []byte) []byte { b[5] = 0x02; return b }},
		{"tampered body", func(b []byte) []byte { b[len(b)-1] ^= 0xff; return b }},
		{"tampered random", func(b []byte) []byte { b[clientRandomOffset] ^= 0xff; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := verifyClientHello(tc.modify(makeClientHello(secret, now)), secret); ok {
				t.Fatal("unauthenticated ClientHello was accepted")
			}
		})
	}
	if _, _, ok := verifyClientHello(makeClientHello(secret, now), []byte("fedcba9876543210")); ok {
		t.Fatal("ClientHello with the wrong secret was accepted")
	}
	for _, timestamp := range []uint32{now - 3600, now + 3600} {
		if _, _, ok := verifyClientHello(makeClientHello(secret, timestamp), secret); ok {
			t.Fatalf("ClientHello with timestamp %d was accepted", timestamp)
		}
	}
}

func TestFakeTLSRecordsKeepPayloadAndSizeLimit(t *testing.T) {
	for _, size := range []int{0, 1, tlsAppDataMax, tlsAppDataMax + 1, 3*tlsAppDataMax + 100} {
		t.Run(fmt.Sprintf("size%d", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x63}, size)
			wrapped := wrapTLSRecords(payload)
			var restored []byte
			for len(wrapped) > 0 {
				if len(wrapped) < 5 || !bytes.Equal(wrapped[:3], []byte{0x17, 0x03, 0x03}) {
					t.Fatalf("invalid TLS application record: %x", wrapped)
				}
				n := int(binary.BigEndian.Uint16(wrapped[3:5]))
				if n == 0 || n > tlsAppDataMax || len(wrapped) < 5+n {
					t.Fatalf("invalid TLS application payload size: %d", n)
				}
				restored = append(restored, wrapped[5:5+n]...)
				wrapped = wrapped[5+n:]
			}
			if !bytes.Equal(restored, payload) {
				t.Fatal("TLS framing changed the payload")
			}
		})
	}
}

func TestFakeTLSStreamFragmentedRecordsAndEmptyReads(t *testing.T) {
	payload := bytes.Repeat([]byte("encrypted MTProto"), 2000)
	records := append([]byte(nil), ccsFrame...)
	records = append(records, 0x17, 0x03, 0x03, 0, 0) // Empty TLS record is not EOF.
	records = append(records, wrapTLSRecords(payload)...)
	reader := bytes.NewReader(records)
	stream := newFakeTLSStream(bufio.NewReader(iotest.OneByteReader(reader)), nil)
	if n, err := stream.Read(nil); n != 0 || err != nil || reader.Len() != len(records) {
		t.Fatalf("zero length read consumed input: n=%d err=%v remaining=%d", n, err, reader.Len())
	}
	// io.ReadFull must work across application record boundaries.
	prefix := make([]byte, tlsAppDataMax+3)
	if _, err := io.ReadFull(stream, prefix); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(prefix, tail...), payload) {
		t.Fatal("fragmented TLS stream lost bytes")
	}
}

func TestFakeTLSStreamWrite(t *testing.T) {
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	_ = writer.SetDeadline(time.Now().Add(2 * time.Second))
	_ = reader.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte("x"), tlsAppDataMax+1)
	expected := wrapTLSRecords(payload)
	readDone := make(chan error, 1)
	go func() {
		got := make([]byte, len(expected))
		_, err := io.ReadFull(reader, got)
		if err == nil && !bytes.Equal(got, expected) {
			err = fmt.Errorf("written TLS records do not match the payload")
		}
		readDone <- err
	}()
	stream := newFakeTLSStream(nil, writer)
	if n, err := stream.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("Write returned %d, %v", n, err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

type maskingSignalConn struct {
	net.Conn
	started      chan struct{}
	signalWrites bool
	once         sync.Once
}

func (c *maskingSignalConn) Read(p []byte) (int, error) {
	if !c.signalWrites {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Read(p)
}

func (c *maskingSignalConn) Write(p []byte) (int, error) {
	if c.signalWrites {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Write(p)
}

func TestMaskingRelayCancellationClosesBlockedWritesAndReads(t *testing.T) {
	for _, phase := range []string{"initial write", "relay reads"} {
		t.Run(phase, func(t *testing.T) {
			client, local := net.Pipe()
			upstream, maskingSite := net.Pipe()
			defer client.Close()
			defer local.Close()
			defer upstream.Close()
			defer maskingSite.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			initial := []byte(nil)
			if phase == "initial write" {
				initial = []byte("unread TLS ClientHello")
			}
			observed := &maskingSignalConn{Conn: upstream, started: make(chan struct{}), signalWrites: len(initial) > 0}
			done := make(chan struct{})
			go func() {
				defer close(done)
				relayMaskingStreams(ctx, local, observed, initial)
			}()
			select {
			case <-observed.started:
			case <-time.After(2 * time.Second):
				t.Fatal("masking relay did not reach the operation being cancelled")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("masking relay ignored cancellation")
			}
			for _, peer := range []net.Conn{client, maskingSite} {
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("masking peer stayed open: %v", err)
				}
			}
		})
	}
}
