//go:build linux

package awgroute

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/tlsblob"
)

// SNI-routing sniffer (Linux). It opens an AF_PACKET socket on each LAN bridge,
// filters in-kernel to client→server TCP :443 packets (a cBPF program — best-effort;
// userspace re-checks so a failed attach only costs extra wakeups), parses the TLS
// ClientHello SNI, and on a domain match adds that connection's destination IP to a
// short-lived ipset (awg2_sni) that the firewall hook marks into the tunnel.
//
// It is READ-ONLY: it never modifies or drops a packet, so it can never break a
// connection. The trade-off is that the very first connection to a freshly-seen IP
// still goes direct (that handshake is what teaches the IP); subsequent ones tunnel.

const (
	awgSetSNI = "awg2_sni"     // hash:ip with a TTL — SNI-learned server IPs
	awgSNITTL = 3600           // seconds a learned IP stays routed (refreshed on re-sight)
	ethPAll   = uint16(0x0003) // ETH_P_ALL
	soAttachF = 26             // SO_ATTACH_FILTER
)

func htons16(v uint16) uint16 { return v<<8 | v>>8 }

type bpfInsn struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// bpfProg mirrors C `struct sock_fprog`. The pointer field is laid out by the Go
// compiler at its natural alignment (offset 4 on 32-bit, 8 on 64-bit), matching the
// kernel ABI on every target arch without manual padding.
type bpfProg struct {
	length uint16
	filter *bpfInsn
}

// sniBPF: IPv4 && TCP && not-fragmented && TCP dst port 443. Ethernet-framed offsets.
// Skips to the final `ret #0` (drop) on any mismatch. Only client→server :443 packets
// (where the ClientHello lives) reach userspace — the bulk download traffic (dst port
// = ephemeral) is dropped in-kernel.
var sniBPF = []bpfInsn{
	{0x28, 0, 0, 0x0000000c}, // 0: ldh  [12]            ethertype
	{0x15, 0, 8, 0x00000800}, // 1: jeq  #0x0800 ? : →10
	{0x30, 0, 0, 0x00000017}, // 2: ldb  [23]            ip protocol
	{0x15, 0, 6, 0x00000006}, // 3: jeq  #6 (TCP) ? : →10
	{0x28, 0, 0, 0x00000014}, // 4: ldh  [20]            flags+frag offset
	{0x45, 4, 0, 0x00001fff}, // 5: jset #0x1fff →10 (fragmented)
	{0xb1, 0, 0, 0x0000000e}, // 6: ldxb 4*([14]&0xf)    X = IP header length
	{0x48, 0, 0, 0x00000010}, // 7: ldh  [x+16]          TCP dst port
	{0x15, 0, 1, 0x000001bb}, // 8: jeq  #443 ? accept : →10
	{0x06, 0, 0, 0x00040000}, // 9: ret  #262144
	{0x06, 0, 0, 0x00000000}, // 10: ret #0
}

// awgEnsureSNISniff starts/refreshes the SNI sniffer when SNI-routing is enabled
// and there is at least one global zone (include OR exclude) with domain matchers.
//
// Why exclude direction matters: with mode=exclude (whitelist-VPN, carve-out RU)
// many RU sites are Cloudflare-fronted (gismeteo, gosuslugi-backed CDNs, comss,
// etc.). The shared-CDN guard in DNS-proxy refuses to add their Cloudflare IPs
// to awg2_exc (otherwise we'd route every unrelated *.com on the same IP direct
// too). Same with browser DoH/DoT — the proxy never sees the query at all.
// In both cases the only place we can recover the destination is the TLS
// ClientHello on the actual connection: read its SNI and, if it matches the
// exclude zone, drop the destination IP into awg2_exc on the fly.
//
// For include direction we still feed awg2_sni (separate set, hash:ip w/ TTL).
func (svc *Service) awgEnsureSNISniff(cfg *awg.ServerConfig) bool {
	inc := svc.awgZoneMatchersByMode(cfg, "include")
	exc := svc.awgZoneMatchersByMode(cfg, "exclude")
	eff := awgEffectiveMode(cfg.Routing)
	want := cfg.Routing.SNIRouting &&
		((eff == "include" && len(inc) > 0) || (eff == "exclude" && len(exc) > 0) || (eff == "full" && len(exc) > 0))
	svc.route.mu.Lock()
	s := svc.route.sni
	svc.route.mu.Unlock()
	if !want {
		if s != nil {
			svc.awgStopSNISniff()
		}
		return false
	}
	svc.route.sniMatchers.Store(&inc) // lock-free read in the hot path (include direction)
	svc.route.excMatchers.Store(&exc) // exclude matchers are already used by the DNS proxy too
	// Zone edits / new matchers may flip earlier decisions, so the short-circuit
	// cache has to be re-learned from scratch. Cheap (single Range + Delete).
	svc.route.sniSeen.Range(func(k, _ any) bool {
		svc.route.sniSeen.Delete(k)
		return true
	})
	if s != nil {
		return true // already running; matchers refreshed above
	}
	ns := newSNISniffer(func(dstIP, sni string) {
		// Short-circuit: this IP has already been routed by an earlier ClientHello
		// in this TTL window. Skip the matcher loop and the ipset call.
		now := time.Now().Unix()
		if v, ok := svc.route.sniSeen.Load(dstIP); ok {
			if ts, _ := v.(int64); now-ts < int64(awgSNITTL) {
				return
			}
			svc.route.sniSeen.Delete(dstIP)
		}
		// Exclude wins on overlap (matches the DNS proxy + iptables semantics).
		if e := svc.route.excMatchers.Load(); e != nil && awg.MatchAny(*e, sni) {
			// We deliberately do NOT consult sharedCDNProvider here — the whole
			// point of SNI is to carve out the SHARED CDN IP for this specific
			// hostname, knowing the same IP also serves unrelated names. That's
			// safe because awg2_exc only causes a RETURN (no marking); other
			// sites on the same CDN IP that don't match an exclude rule never
			// get into awg2_exc here.
			suffix := ""
			if isIPv6(dstIP) {
				suffix = "_6"
			}
			_, _ = awgRun("ipset add " + awgSetExc + suffix + " " + dstIP + " -exist")
			svc.route.sniSeen.Store(dstIP, now)
			return
		}
		m := svc.route.sniMatchers.Load()
		if m == nil || !awg.MatchAny(*m, sni) {
			return
		}
		if provider, ok := sharedCDNProvider(dstIP); ok {
			svc.awgNoteSharedCDNSkip("sni", sni, dstIP, provider)
			return
		}
		suffix := ""
		if isIPv6(dstIP) {
			suffix = "_6"
		}
		_, _ = awgRun("ipset add " + awgSetSNI + suffix + " " + dstIP + " timeout " + strconv.Itoa(awgSNITTL) + " -exist")
		svc.route.sniSeen.Store(dstIP, now)
	})
	if err := ns.start(); err != nil {
		logbuf.Append("awg2", "warn", "SNI-маршрутизация: сниффер не запустился: "+err.Error())
		return false
	}
	svc.route.mu.Lock()
	svc.route.sni = ns
	svc.route.mu.Unlock()
	logbuf.Append("awg2", "info", fmt.Sprintf("SNI-маршрутизация включена: совпавшие по имени домены → туннель (память ≈%d мин)", awgSNITTL/60))
	return true
}

func (svc *Service) awgStopSNISniff() {
	svc.route.mu.Lock()
	s := svc.route.sni
	svc.route.sni = nil
	svc.route.mu.Unlock()
	if s != nil {
		s.stop()
	}
}

func (s *sniSniffer) start() error {
	brs := lanBridges()
	if len(brs) == 0 {
		return fmt.Errorf("не найдено LAN-мостов (br*) для прослушивания")
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.stopCh = make(chan struct{})
	s.running = true
	stopCh := s.stopCh
	s.mu.Unlock()

	var fds []int
	for _, br := range brs {
		fd, err := openSNISocket(br.Index)
		if err != nil {
			logbuf.Append("awg2", "warn", "SNI: сокет на "+br.Name+" не открыт: "+err.Error())
			continue
		}
		fds = append(fds, fd)
		go s.readLoop(fd, stopCh)
	}
	if len(fds) == 0 {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return fmt.Errorf("не удалось открыть ни одного AF_PACKET-сокета")
	}
	s.mu.Lock()
	s.fds = fds
	s.mu.Unlock()
	return nil
}

func (s *sniSniffer) stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	if s.stopCh != nil {
		close(s.stopCh)
	}
	fds := s.fds
	s.fds = nil
	s.mu.Unlock()
	for _, fd := range fds {
		_ = syscall.Close(fd) // unblocks the blocked Recvfrom in readLoop
	}
}

func (s *sniSniffer) readLoop(fd int, stopCh chan struct{}) {
	buf := make([]byte, 2048) // a ClientHello fits one frame; bigger ones are simply missed
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return // socket closed (stop) or fatal
		}
		select {
		case <-stopCh:
			return
		default:
		}
		if n <= 0 {
			continue
		}
		if dst, port, sni, ok := tlsblob.SNIFromEthernet(buf[:n]); ok && port == 443 {
			if s.onHello != nil {
				s.onHello(dst, sni)
			}
		}
	}
}

// openSNISocket opens an AF_PACKET raw socket on the given interface index, attaches
// the :443 cBPF filter (best-effort), and binds it.
func openSNISocket(ifindex int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons16(ethPAll)))
	if err != nil {
		return -1, err
	}
	prog := bpfProg{length: uint16(len(sniBPF)), filter: &sniBPF[0]}
	// Best-effort: a failed attach (unusual) just means userspace sees more packets;
	// SNIFromEthernet still rejects non-ClientHellos, so results stay correct.
	_, _, _ = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.SOL_SOCKET), uintptr(soAttachF),
		uintptr(unsafe.Pointer(&prog)), unsafe.Sizeof(prog), 0)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons16(ethPAll),
		Ifindex:  ifindex,
	}); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// lanBridges lists the up LAN bridge interfaces (br*) — devices' traffic ingresses
// here, so a sniffer bound to each sees their ClientHellos pre-NAT (real dst IP).
func lanBridges() []net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, i := range ifs {
		if strings.HasPrefix(i.Name, "br") && i.Flags&net.FlagUp != 0 {
			out = append(out, i)
		}
	}
	return out
}
