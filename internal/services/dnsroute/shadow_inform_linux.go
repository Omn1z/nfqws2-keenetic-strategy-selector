//go:build linux

package dnsroute

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const shadowInformTimeout = 1200 * time.Millisecond
const shadowInformReadSlice = 100 * time.Millisecond
const shadowInformMaxReads = 512

// shadowDHCPInform asks an already known WAN DHCP server for option6. It sends
// exactly one INFORM, never modifies a lease/address, and never occupies UDP68.
// The caller establishes WAN/server provenance and filters returned DNS loops.
func shadowDHCPInform(ctx context.Context, iface string, clientIP, serverIP net.IP) ([]string, error) {
	_, servers, err := shadowDHCPInformOnWAN(ctx, iface, clientIP, serverIP, false)
	return servers, err
}

// RFC2131 section 4.4.3 permits a broadcast INFORM when the client already has
// an address but does not know the DHCP server. It requests only DNS parameters
// and learns a peer identifier from the matching unicast ACK, never from the
// WAN gateway or merely the packet's IP source.
func shadowDHCPInformDiscover(ctx context.Context, iface string, clientIP net.IP) (net.IP, []string, error) {
	return shadowDHCPInformOnWAN(ctx, iface, clientIP, nil, true)
}

func shadowDHCPInformOnWAN(ctx context.Context, iface string, clientIP, serverIP net.IP, discover bool) (net.IP, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, shadowInformTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !validShadowWAN(iface) || clientIP.To4() == nil || !clientIP.IsGlobalUnicast() || clientIP.IsLoopback() {
		return nil, nil, fmt.Errorf("DHCPINFORM requires a WAN interface and unicast IPv4 client")
	}
	if !discover && (serverIP.To4() == nil || !serverIP.IsGlobalUnicast() || serverIP.IsLoopback() || clientIP.Equal(serverIP)) {
		return nil, nil, fmt.Errorf("DHCPINFORM requires a distinct unicast IPv4 server")
	}
	nic, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM interface: %w", err)
	}
	if nic.Flags&net.FlagUp == 0 || len(nic.HardwareAddr) != 6 || nic.HardwareAddr[0]&1 != 0 {
		return nil, nil, fmt.Errorf("DHCPINFORM requires an active Ethernet WAN")
	}
	addresses, err := nic.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM interface addresses: %w", err)
	}
	found := false
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.Equal(clientIP) {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("DHCPINFORM WAN no longer owns the expected IPv4 address")
	}
	var id shadowInformIdentity
	copy(id.client[:], clientIP.To4())
	copy(id.server[:], serverIP.To4())
	copy(id.mac[:], nic.HardwareAddr)
	if id.mac == [6]byte{} {
		return nil, nil, fmt.Errorf("DHCPINFORM requires a nonzero Ethernet MAC")
	}
	if _, err := rand.Read(id.xid[:]); err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM transaction ID: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM raw socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := attachShadowInformFilter(fd); err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM attach reply filter: %w", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM bind WAN: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: id.client}); err != nil {
		return nil, nil, fmt.Errorf("DHCPINFORM bind source: %w", err)
	}
	destination := id.server
	if discover {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
			return nil, nil, fmt.Errorf("DHCPINFORM enable broadcast: %w", err)
		}
		destination = [4]byte{255, 255, 255, 255}
	}
	// Leave both modes unconnected: RFC2131 permits a multihomed server to
	// use an IP source different from option54, even for a unicast INFORM.
	// Device/source binding and BPF limit received copies; the parser checks
	// transaction, hardware address, destination and the server identifier.
	return exchangeShadowInformFrom(ctx, shadowInformRawSocket{fd: fd, server: destination}, id, discover)
}

// A per-call interface keeps cancellation/deadline tests independent of real
// sockets or privileges. No global factory/hook is used by the transport.
type shadowInformSocket interface {
	send(packet []byte, wait time.Duration) error
	receive(packet []byte, wait time.Duration) (int, error)
}

type shadowInformRawSocket struct {
	fd     int
	server [4]byte
}

func (s shadowInformRawSocket) send(packet []byte, wait time.Duration) error {
	tv := syscall.NsecToTimeval(wait.Nanoseconds())
	if err := syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv); err != nil {
		return err
	}
	return syscall.Sendto(s.fd, packet, 0, &syscall.SockaddrInet4{Addr: s.server})
}

func (s shadowInformRawSocket) receive(packet []byte, wait time.Duration) (int, error) {
	tv := syscall.NsecToTimeval(wait.Nanoseconds())
	if err := syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return 0, err
	}
	n, _, err := syscall.Recvfrom(s.fd, packet, 0)
	return n, err
}

func exchangeShadowInform(ctx context.Context, socket shadowInformSocket, id shadowInformIdentity) ([]string, error) {
	_, servers, err := exchangeShadowInformFrom(ctx, socket, id, false)
	return servers, err
}

func shadowInformReceiveError(err, rejected error) error {
	if !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if rejected != nil {
		return fmt.Errorf("ответ DHCPINFORM получен, но отклонён (%v): %w", rejected, err)
	}
	return fmt.Errorf("ответ DHCPINFORM на текущий запрос не получен: %w", err)
}

func exchangeShadowInformFrom(ctx context.Context, socket shadowInformSocket, id shadowInformIdentity, discover bool) (net.IP, []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, fmt.Errorf("DHCPINFORM requires a deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, nil, context.DeadlineExceeded
	}
	// One attempt only; a short send timeout also bounds cancellation latency.
	if err := socket.send(makeShadowInformPacket(id), min(remaining, shadowInformReadSlice)); err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("send DHCPINFORM: %w", err)
	}
	buffer := make([]byte, 4096)
	var rejected error
	for attempt := 0; attempt < shadowInformMaxReads; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, shadowInformReceiveError(err, rejected)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil, shadowInformReceiveError(context.DeadlineExceeded, rejected)
		}
		n, err := socket.receive(buffer, min(remaining, shadowInformReadSlice))
		if ctx.Err() != nil {
			return nil, nil, shadowInformReceiveError(ctx.Err(), rejected)
		}
		if !time.Now().Before(deadline) {
			return nil, nil, shadowInformReceiveError(context.DeadlineExceeded, rejected)
		}
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return nil, nil, fmt.Errorf("receive DHCPINFORM: %w", err)
		}
		if n < 0 || n > len(buffer) {
			return nil, nil, fmt.Errorf("invalid DHCPINFORM socket length")
		}
		var parseErr error
		if discover {
			if peer, servers, err := parseShadowInformDiscoverReply(buffer[:n], id); err == nil {
				return peer, servers, nil
			} else {
				parseErr = err
			}
		} else if servers, err := parseShadowInformReply(buffer[:n], id); err == nil {
			return append(net.IP(nil), id.server[:]...), servers, nil
		} else {
			parseErr = err
		}
		// Unrelated DHCP traffic must not change this request's diagnosis.
		// Parser errors are fixed descriptions, never packet contents.
		if shadowInformReplyMatches(buffer[:n], id) {
			rejected = parseErr
		}
	}
	// A packet flood must not spin for an unbounded number of parse attempts.
	return nil, nil, fmt.Errorf("DHCPINFORM receive limit reached without a matching ACK")
}
