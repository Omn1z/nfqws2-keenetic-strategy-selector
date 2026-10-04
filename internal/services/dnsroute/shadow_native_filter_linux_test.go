//go:build linux

package dnsroute

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func shadowNativeFilteredSocketPair(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	if err := attachShadowNativeFilter(fds[1], shadowNativeTestMAC); err != nil {
		t.Fatal(err)
	}
	return fds[0], fds[1]
}

func TestShadowNativeKernelFilterKeepsOwnDHCPBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
	}{
		{"renewal", shadowNativeTestPacket(3, 1)},
		{"selecting", shadowNativeTestSelectingRequest(1, true)},
		{"reply", shadowNativeTestPacket(5, 1)},
		{"NAK", shadowNativeTestPacket(6, 1)},
	} {
		for _, withOptions := range []bool{false, true} {
			name := tc.name
			if withOptions {
				name += "/IPv4 options"
			}
			t.Run(name, func(t *testing.T) {
				send, receive := shadowNativeFilteredSocketPair(t)
				packet := append([]byte(nil), tc.packet...)
				if withOptions {
					packet = append(append(append([]byte(nil), packet[:20]...), 1, 1, 1, 1), packet[20:]...)
					packet[0] = 0x46
					binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
					shadowNativeTestIPChecksum(packet)
				}
				if err := unix.Send(send, packet, 0); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1536)
				n, _, err := unix.Recvfrom(receive, buffer, unix.MSG_DONTWAIT)
				if err != nil || !bytes.Equal(buffer[:n], packet) {
					t.Fatalf("own DHCP filtered/truncated: bytes=%d err=%v", n, err)
				}
			})
		}
	}
}

func TestShadowNativeKernelFilterRejectsEveryOtherMACOctet(t *testing.T) {
	for message := byte(3); message <= 5; message += 2 {
		for offset := 0; offset < 6; offset++ {
			send, receive := shadowNativeFilteredSocketPair(t)
			packet := shadowNativeTestPacket(message, 1)
			packet[56+offset] ^= 2
			if err := unix.Send(send, packet, 0); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1536)
			if n, _, err := unix.Recvfrom(receive, buffer, unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
				t.Fatalf("foreign DHCP entered queue: message=%d changed MAC byte=%d bytes=%d err=%v", message, offset, n, err)
			}
		}
	}
}

func TestShadowNativeKernelFilterPreservesProtocolGuards(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"IPv6":              func(p []byte) []byte { p[0] = 0x65; return p },
		"TCP":               func(p []byte) []byte { p[9] = 6; return p },
		"short IHL":         func(p []byte) []byte { p[0] = 0x44; return p },
		"fragment":          func(p []byte) []byte { p[6] = 0x20; return p },
		"fragment offset":   func(p []byte) []byte { p[7] = 1; return p },
		"wrong source":      func(p []byte) []byte { binary.BigEndian.PutUint16(p[20:22], 443); return p },
		"wrong destination": func(p []byte) []byte { binary.BigEndian.PutUint16(p[22:24], 443); return p },
		"short IPv4":        func(p []byte) []byte { return p[:10] },
		"short UDP":         func(p []byte) []byte { return p[:23] },
		"short chaddr":      func(p []byte) []byte { return p[:61] },
	} {
		t.Run(name, func(t *testing.T) {
			send, receive := shadowNativeFilteredSocketPair(t)
			packet := mutate(shadowNativeTestPacket(5, 1))
			if err := unix.Send(send, packet, 0); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1536)
			if n, _, err := unix.Recvfrom(receive, buffer, unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
				t.Fatalf("non-DHCP/truncated packet entered queue: bytes=%d err=%v", n, err)
			}
		})
	}
}

func TestShadowNativeKernelFilterForeignDHCPFloodDoesNotConsumeQueue(t *testing.T) {
	send, receive := shadowNativeFilteredSocketPair(t)
	noise := shadowNativeTestPacket(5, 1)
	noise[61] ^= 2
	for range 2048 {
		if err := unix.Send(send, noise, 0); err != nil {
			t.Fatalf("foreign DHCP filled queue: %v", err)
		}
	}
	ack := shadowNativeTestPacket(5, 1)
	if err := unix.Send(send, ack, 0); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1536)
	n, _, err := unix.Recvfrom(receive, buffer, unix.MSG_DONTWAIT)
	if err != nil || !bytes.Equal(buffer[:n], ack) {
		t.Fatal("first userspace read was not own ACK", n, err)
	}
	if n, _, err := unix.Recvfrom(receive, buffer, unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
		t.Fatal("foreign DHCP remained in queue", n, err)
	}
}

func TestShadowNativeKernelFilterValidatesIdentityAndAttachment(t *testing.T) {
	for _, mac := range []net.HardwareAddr{nil, {0, 0, 0, 0, 0, 0}, {1, 2, 3, 4, 5, 6}, {2, 3, 4, 5, 6}} {
		if err := attachShadowNativeFilter(-1, mac); err == nil {
			t.Fatal("accepted invalid filter MAC", mac)
		}
	}
	if err := attachShadowNativeFilter(-1, shadowNativeTestMAC); err == nil {
		t.Fatal("filter attachment error ignored")
	}
	// Constructing the native program must not mutate the diagnostic filter:
	// its short window deliberately observes all transaction peers on this WAN.
	before := shadowWireFilterProgram()
	_, receive := shadowNativeFilteredSocketPair(t)
	if err := attachShadowNativeFilter(receive, shadowNativeTestMAC); err != nil {
		t.Fatal(err)
	}
	after := shadowWireFilterProgram()
	if len(after) != len(before) || after[19].Code != unix.BPF_RET|unix.BPF_K || after[19].K != 1536 {
		t.Fatal("native filter changed the all-DHCP diagnostic program")
	}
}
