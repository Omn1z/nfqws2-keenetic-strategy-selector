//go:build linux

package dnsroute

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// A Unix datagram socketpair exercises the actual kernel cBPF interpreter on
// fixture bytes, without a network interface, CAP_NET_RAW, or external traffic.
func shadowInformFilteredSocketPair(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	if err := attachShadowInformFilter(fds[1]); err != nil {
		t.Fatalf("attach kernel DHCP filter: %v", err)
	}
	return fds[0], fds[1]
}

func TestShadowInformKernelFilterKeepsOnlyDHCPReplyPorts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		alter  func([]byte) []byte
		accept bool
	}{
		{name: "DHCP ACK", accept: true},
		{name: "multihomed DHCP ACK", accept: true, alter: func(p []byte) []byte {
			copy(p[12:16], []byte{192, 168, 0, 2})
			return p
		}},
		{name: "relayed DHCP ACK", accept: true, alter: func(p []byte) []byte {
			copy(p[52:56], []byte{192, 168, 0, 3})
			return p
		}},
		{name: "IPv4 options", accept: true, alter: func(p []byte) []byte {
			p = append(append(append([]byte(nil), p[:20]...), 1, 1, 1, 1), p[20:]...)
			p[0] = 0x46
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			return p
		}},
		{name: "DF permitted", accept: true, alter: func(p []byte) []byte { p[6] = 0x40; return p }},
		{name: "wrong source port", alter: func(p []byte) []byte { binary.BigEndian.PutUint16(p[20:22], 443); return p }},
		{name: "wrong destination port", alter: func(p []byte) []byte { binary.BigEndian.PutUint16(p[22:24], 51820); return p }},
		{name: "TCP", alter: func(p []byte) []byte { p[9] = 6; return p }},
		{name: "IPv6", alter: func(p []byte) []byte { p[0] = 0x65; return p }},
		{name: "more fragments", alter: func(p []byte) []byte { p[6] = 0x20; return p }},
		{name: "fragment offset", alter: func(p []byte) []byte { p[7] = 1; return p }},
		{name: "short IHL", alter: func(p []byte) []byte { p[0] = 0x44; return p }},
		{name: "truncated IP", alter: func(p []byte) []byte { return p[:10] }},
		{name: "truncated UDP ports", alter: func(p []byte) []byte { return p[:23] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			send, receive := shadowInformFilteredSocketPair(t)
			packet := shadowInformACKFixture()
			if tc.alter != nil {
				packet = tc.alter(packet)
			}
			if err := unix.Send(send, packet, 0); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4096)
			n, _, err := unix.Recvfrom(receive, buf, unix.MSG_DONTWAIT)
			if tc.accept {
				if err != nil || !bytes.Equal(buf[:n], packet) {
					t.Fatalf("valid DHCP reply filtered/truncated: bytes=%d err=%v", n, err)
				}
			} else if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
				t.Fatalf("unrelated packet entered receive queue: bytes=%d err=%v", n, err)
			}
		})
	}
}

func TestShadowInformKernelFilterWANLoadDoesNotConsumeReadBudget(t *testing.T) {
	send, receive := shadowInformFilteredSocketPair(t)
	unrelated := shadowInformACKFixture()
	binary.BigEndian.PutUint16(unrelated[20:22], 443)
	binary.BigEndian.PutUint16(unrelated[22:24], 51820)
	// More unrelated traffic than the entire userspace read budget must not
	// fill this socket's queue or force the ACK behind hundreds of UDP packets.
	for i := 0; i < 4*shadowInformMaxReads; i++ {
		if err := unix.Send(send, unrelated, 0); err != nil {
			t.Fatalf("WAN noise filled receive queue after %d packets: %v", i, err)
		}
	}
	ack := shadowInformACKFixture()
	if err := unix.Send(send, ack, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(receive, buf, unix.MSG_DONTWAIT)
	if err != nil || !bytes.Equal(buf[:n], ack) {
		t.Fatalf("first userspace read was not ACK: bytes=%d err=%v", n, err)
	}
	if _, _, err := unix.Recvfrom(receive, buf, unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("WAN noise remained in receive queue: %v", err)
	}
}

func TestShadowInformKernelFilterAttachFailureIsReturned(t *testing.T) {
	if err := attachShadowInformFilter(-1); err == nil {
		t.Fatal("invalid socket silently proceeded without filtering")
	}
}
