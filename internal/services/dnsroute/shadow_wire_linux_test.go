//go:build linux

package dnsroute

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestShadowWireDisabledAndOldContextDoNotOpenCapture(t *testing.T) {
	var state shadowDiagnosticState
	ctx, _ := state.begin(context.Background())
	// nil NIC deliberately proves the disabled path returns before socket setup.
	startShadowWireCapture(ctx, nil, shadowInformTestIdentity(), false)()
	state.setEnabled(true)
	old, _ := state.begin(context.Background())
	state.setEnabled(false)
	state.setEnabled(true)
	startShadowWireCapture(old, nil, shadowInformTestIdentity(), false)()
	state.setEnabled(false)
}

func shadowWireTestSocketFDs(t *testing.T) map[int]bool {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("descriptor inspection unavailable", err)
	}
	result := map[int]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:") {
			fd, err := strconv.Atoi(entry.Name())
			if err == nil {
				result[fd] = true
			}
		}
	}
	return result
}

func TestShadowWireKernelSwitchOffClosesCaptureBeforeAttemptFinishes(t *testing.T) {
	nic, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("loopback unavailable", err)
	}
	var state shadowDiagnosticState
	state.setEnabled(true)
	defer state.setEnabled(false)
	ctx, _ := state.begin(context.Background())
	before := shadowWireTestSocketFDs(t)
	stop := startShadowWireCapture(ctx, nic, shadowInformTestIdentity(), false)
	defer stop()
	fd := -1
	for candidate := range shadowWireTestSocketFDs(t) {
		if !before[candidate] {
			if fd != -1 {
				t.Fatal("unexpected extra diagnostic sockets")
			}
			fd = candidate
		}
	}
	if fd == -1 {
		t.Skip("optional AF_PACKET capture unavailable (requires CAP_NET_RAW)")
	}
	state.setEnabled(false)
	deadline := time.Now().Add(time.Second)
	for {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("switch-off left optional capture open until INFORM completion")
		}
		time.Sleep(time.Millisecond)
	}
	// A late finalizer must not close a descriptor that reused the capture fd.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	stop()
	stop()
	if err := unix.Send(fds[0], []byte{1}, 0); err != nil {
		t.Fatal("late capture finalizer closed reused fd", err)
	}
	if got := state.snapshot(); got.Enabled || len(got.Attempts) != 0 {
		t.Fatal("late capture finalizer restored cleared history", got)
	}
}

func shadowWireInformFixture() []byte {
	id := shadowInformTestIdentity()
	packet := shadowInformACKFixture()
	copy(packet[12:16], id.client[:])
	copy(packet[16:20], []byte{255, 255, 255, 255})
	copy(packet[20:], makeShadowInformPacket(id))
	return packet
}

func TestShadowWireKernelFilterKeepsOnlyDHCPBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
		accept bool
	}{
		{"reply", shadowInformACKFixture(), true},
		{"outgoing broadcast", shadowWireInformFixture(), true},
		{"truncated", []byte{0x45, 0, 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			if err := attachShadowWireFilter(fds[1]); err != nil {
				t.Fatal(err)
			}
			// Ordinary WAN UDP must be discarded by the kernel, before the
			// limited capture queue/userspace parser sees it.
			noise := shadowInformACKFixture()
			binary.BigEndian.PutUint16(noise[20:22], 443)
			for range 512 {
				if err := unix.Send(fds[0], noise, 0); err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Send(fds[0], tc.packet, 0); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1536)
			n, _, err := unix.Recvfrom(fds[1], buffer, unix.MSG_DONTWAIT)
			if tc.accept {
				if err != nil || !bytes.Equal(buffer[:n], tc.packet) {
					t.Fatal("DHCP capture filtered valid packet", n, err)
				}
			} else if !errors.Is(err, unix.EAGAIN) {
				t.Fatal("unrelated packet entered capture", n, err)
			}
		})
	}
}

func TestShadowWireKernelFilterRejectsNonDHCPVariants(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0x65 },
		func(p []byte) { p[0] = 0x44 },
		func(p []byte) { p[9] = 6 },
		func(p []byte) { p[6] = 0x20 },
		func(p []byte) { p[7] = 1 },
		func(p []byte) { binary.BigEndian.PutUint16(p[22:24], 443) },
		func(p []byte) { binary.BigEndian.PutUint16(p[20:22], 68); binary.BigEndian.PutUint16(p[22:24], 68) },
	} {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			if err := attachShadowWireFilter(fds[1]); err != nil {
				t.Fatal(err)
			}
			packet := shadowInformACKFixture()
			mutate(packet)
			if err := unix.Send(fds[0], packet, 0); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1536)
			if n, _, err := unix.Recvfrom(fds[1], buffer, unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
				t.Fatal("non-DHCP captured", n, err)
			}
		}()
	}
	if err := attachShadowWireFilter(-1); err == nil {
		t.Fatal("failed filter attachment ignored")
	}
}

func TestShadowWireSummaryDistinguishesWANFromRawSocket(t *testing.T) {
	id := shadowInformTestIdentity()
	message, matches := shadowWirePacketSummary(shadowWireInformFixture(), id, true, true)
	if !matches || !strings.Contains(message, "255.255.255.255:67") || !strings.Contains(message, "DHCP=INFORM") || !strings.Contains(message, "исходящий") {
		t.Fatal("missing broadcast send evidence", message, matches)
	}
	packet := shadowInformACKFixture()
	message, matches = shadowWirePacketSummary(packet, id, false, false)
	if !matches || !strings.Contains(message, "DHCP=ACK") || !strings.Contains(message, "проверка ответа: OK") {
		t.Fatal(message, matches)
	}
	// An ACK for this transaction addressed to broadcast is visible on WAN
	// even though the unicast-bound raw socket cannot accept its destination.
	copy(packet[16:20], []byte{255, 255, 255, 255})
	message, matches = shadowWirePacketSummary(packet, id, false, false)
	if !matches || !strings.Contains(message, "wrong IPv4 destination") {
		t.Fatal("lost pre-IP evidence", message, matches)
	}
	packet[270] = 6
	message, matches = shadowWirePacketSummary(packet, id, false, false)
	if !matches || !strings.Contains(message, "DHCP=NAK") {
		t.Fatal("NAK hidden", message, matches)
	}
}

func TestShadowWireSummaryOmitsUnrelatedAndMalformedPayloads(t *testing.T) {
	id := shadowInformTestIdentity()
	packet := shadowInformACKFixture()
	for n := 0; n < len(packet); n++ {
		if message, matches := shadowWirePacketSummary(packet[:n], id, false, false); matches || message != "" {
			t.Fatal("truncated capture emitted metadata", n, message)
		}
	}
	for _, offset := range []int{32, 56, 29, 30} {
		other := append([]byte{}, packet...)
		other[offset] ^= 1
		if message, matches := shadowWirePacketSummary(other, id, false, false); matches || message != "" {
			t.Fatal("another transaction leaked metadata", offset, message)
		}
	}
	// Unrequested hostname/vendor option content must never enter the report.
	copy(packet[268:], []byte{53, 1, 5, 12, 6, 's', 'e', 'c', 'r', 'e', 't', 255})
	message, matches := shadowWirePacketSummary(packet, id, false, false)
	if !matches || strings.Contains(message, "secret") {
		t.Fatal("arbitrary DHCP options leaked", message, matches)
	}
}
