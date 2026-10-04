//go:build linux

package dnsroute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type shadowNativeSocket struct {
	mu    sync.Mutex
	state shadowNativeSnapshot
	wake  int
	done  chan struct{}
	once  sync.Once
}

func (s *shadowNativeSocket) snapshot() shadowNativeSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.state
	result.observation.ServerIP = append(net.IP(nil), result.observation.ServerIP...)
	result.observation.Servers = append([]string(nil), result.observation.Servers...)
	return result
}

func (s *shadowNativeSocket) close() {
	s.once.Do(func() {
		for {
			if _, err := unix.Write(s.wake, []byte{1}); !errors.Is(err, unix.EINTR) {
				break
			}
		}
		<-s.done
		_ = unix.Close(s.wake)
	})
}

// One passive reader sleeps in poll until DHCP or shutdown. It never sends
// packets, occupies UDP 68, polls ndmc, or reads ordinary client traffic.
func startShadowNativeReader(nic *net.Interface, client net.IP) (shadowNativeReader, error) {
	tracker, err := newShadowNativeDHCPTracker(client, nic.HardwareAddr)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	pipes := []int{-1, -1}
	cleanup := func() {
		_ = unix.Close(fd)
		for _, p := range pipes {
			if p >= 0 {
				_ = unix.Close(p)
			}
		}
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 16*1024); err == nil {
		err = attachShadowNativeFilter(fd, nic.HardwareAddr)
	}
	if err == nil {
		protocol := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
		err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: nic.Index})
	}
	if err == nil {
		err = unix.Pipe2(pipes, unix.O_CLOEXEC|unix.O_NONBLOCK)
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	s := &shadowNativeSocket{wake: pipes[1], done: make(chan struct{}), state: shadowNativeSnapshot{started: time.Now()}}
	go s.read(fd, pipes[0], nic.Index, tracker)
	return s, nil
}

func (s *shadowNativeSocket) read(fd, wake, ifindex int, tracker *shadowNativeDHCPTracker) {
	defer func() {
		_ = unix.Close(fd)
		_ = unix.Close(wake)
		s.mu.Lock()
		s.state.closed = true
		s.mu.Unlock()
		close(s.done)
	}()
	fail := func(err error) { s.mu.Lock(); s.state.err = err; s.mu.Unlock() }
	polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(wake), Events: unix.POLLIN}}
	buffer := make([]byte, 1536)
	for {
		_, err := unix.Poll(polls, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			fail(err)
			return
		}
		if polls[1].Revents != 0 {
			return
		}
		if polls[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			fail(fmt.Errorf("DHCP capture socket closed"))
			return
		}
		// Bound each batch so cancellation is checked even on a busy WAN.
		for i := 0; i < 32; i++ {
			n, addr, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				fail(err)
				return
			}
			link, ok := addr.(*unix.SockaddrLinklayer)
			if !ok || link.Ifindex != ifindex || n < 0 || n > len(buffer) {
				continue
			}
			now := time.Now()
			observation := tracker.Observe(buffer[:n], link.Pkttype == unix.PACKET_OUTGOING, now)
			if observation.Kind == "" {
				continue
			}
			s.mu.Lock()
			switch observation.Kind {
			case "request":
				s.state.requests++
			case "ack", "ack_no_dns", "nak":
				s.state.replies++
				s.state.sequence++
				s.state.observation, s.state.observedAt = observation, now
			case "rejected":
				s.state.err = observation.Err
			}
			s.mu.Unlock()
		}
	}
}

// Called under discoveryMu only with physical WANs verified by native state,
// configured kernel addresses and the current main default route.
func (a *Adapter) observeShadowNative(ctx context.Context, key string, eligible []shadowBroadcastWAN, local []net.IP, routerNow time.Time) bool {
	s := &a.shadow.native
	if ctx.Err() != nil {
		return false
	}
	a.mu.Lock()
	running := a.started
	a.mu.Unlock()
	if !running || key == "" || len(eligible) == 0 {
		s.stop()
		return false
	}
	wan := eligible[0] // Observe one verified default WAN with bounded resources.
	for _, candidate := range eligible {
		if s.reader != nil && candidate.device == s.device && candidate.client.Equal(s.client) {
			wan = candidate
			break
		}
	}
	nic, err := net.InterfaceByName(wan.device)
	if err != nil || nic.Flags&net.FlagUp == 0 {
		s.stop()
		shadowDiagnosticEvent(ctx, "native.capture", "WAN недоступен для наблюдения штатного DHCP", 0)
		return false
	}
	owned := false
	if addresses, err := nic.Addrs(); err == nil {
		for _, addr := range addresses {
			ip, _, _ := net.ParseCIDR(addr.String())
			owned = owned || ip.Equal(wan.client)
		}
	}
	if !owned {
		s.stop()
		return false
	}
	identity := fmt.Sprintf("%d/%s", nic.Index, nic.HardwareAddr)
	if s.reader != nil && (s.key != key || s.device != wan.device || !s.client.Equal(wan.client) || s.identity != identity || s.reader.snapshot().closed) {
		s.stop()
	}
	if s.reader == nil {
		reader, err := startShadowNativeReader(nic, wan.client)
		if err != nil {
			shadowDiagnosticEvent(ctx, "native.capture", "Наблюдение штатного DHCP недоступно: "+err.Error(), 0)
			return false
		}
		*s = shadowNativeState{reader: reader, key: key, iface: wan.native, device: wan.device, client: append(net.IP(nil), wan.client...), identity: identity}
	}
	snapshot := s.reader.snapshot()
	message := fmt.Sprintf("%s: наблюдение с %s; штатных REQUEST=%d, связанных ответов=%d", s.device, snapshot.started.UTC().Format(time.RFC3339), snapshot.requests, snapshot.replies)
	if snapshot.sequence == 0 {
		message += "; ожидается штатное обновление DHCP-аренды Keenetic (может занять несколько часов)"
	}
	if snapshot.err != nil {
		message += "; последняя ошибка: " + snapshot.err.Error()
	}
	shadowDiagnosticEvent(ctx, "native.capture", message, 0)
	if snapshot.sequence == 0 {
		return false
	}
	s.inspected = snapshot.sequence
	observation := snapshot.observation
	shadowDiagnosticEvent(ctx, "native.capture.result", fmt.Sprintf("%s: %s в %s; DNS=%d; срок аренды=%d с", s.device, observation.Kind, snapshot.observedAt.UTC().Format(time.RFC3339), len(observation.Servers), observation.LeaseSeconds), 0)
	// This observed reply supersedes ring-log evidence, including a correlated
	// NAK or ACK without option 6. Remove aliases of the same WAN/IP as well.
	for _, lease := range a.shadow.leases {
		observed := lease.observedAt
		if observed.IsZero() {
			observed = shadowLeaseObservedAt(lease.stamp, routerNow)
		}
		if lease.wanKey == key && lease.clientIP.Equal(wan.client) && observed.After(snapshot.observedAt) {
			return false // newer complete native log evidence supersedes capture
		}
	}
	if s.withdrawn != snapshot.sequence {
		for iface, target := range a.shadow.inform.targets {
			if target.valid(key, []net.IP{wan.client}) {
				delete(a.shadow.inform.answers, iface)
			}
		}
		s.withdrawn = snapshot.sequence
	}
	for iface, lease := range a.shadow.leases {
		if lease.wanKey == key && lease.clientIP.Equal(wan.client) {
			delete(a.shadow.leases, iface)
		}
	}
	servers := filterShadowServers(observation.Servers, local)
	if observation.Kind == "ack" && time.Now().Before(observation.LeaseExpires) && len(servers) > 0 {
		a.shadow.leases[s.iface] = shadowRememberedLease{wanKey: key, clientIP: append(net.IP(nil), wan.client...), servers: servers, expires: observation.LeaseExpires, observedAt: snapshot.observedAt, leaseSeconds: observation.LeaseSeconds}
	}
	return true
}
