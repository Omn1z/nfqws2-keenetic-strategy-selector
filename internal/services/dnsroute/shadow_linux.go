//go:build linux

package dnsroute

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func (a *Adapter) shadowServersOS(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.shadow.discoveryMu.Lock()
	defer a.shadow.discoveryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if time.Now().Before(a.shadow.discoveryUntil) {
		return append([]string(nil), a.shadow.servers...), a.shadow.discoveryErr
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	a.loadShadowLeases()
	servers, err := discoverShadowServersWithLeases(ctx, a.cfg.WANIfaces, a.shadow.leases)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	} // a canceled caller must not poison discovery
	a.saveShadowLeases()
	a.shadow.servers, a.shadow.discoveryErr = servers, err
	a.shadow.discoveryUntil = time.Now().Add(time.Minute)
	for _, lease := range a.shadow.leases {
		if lease.expires.Before(a.shadow.discoveryUntil) {
			a.shadow.discoveryUntil = lease.expires
		}
	}
	if err != nil {
		a.shadow.discoveryUntil = time.Now().Add(15 * time.Second)
	}
	return append([]string(nil), servers...), err
}

func discoverShadowServers(ctx context.Context, wan []string) ([]string, error) {
	return discoverShadowServersWithLeases(ctx, wan, nil)
}

func discoverShadowServersWithLeases(ctx context.Context, wan []string, remembered map[string]shadowRememberedLease) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var local, wanIPs []net.IP
	for _, iface := range ifs {
		isWAN := false
		for _, name := range wan {
			if name == iface.Name {
				isWAN = true
				break
			}
		}
		addrs, e := iface.Addrs()
		if e != nil {
			return nil, e
		}
		for _, addr := range addrs {
			ip, _, e := net.ParseCIDR(addr.String())
			if e == nil {
				local = append(local, ip)
				if isWAN {
					wanIPs = append(wanIPs, ip)
				}
			}
		}
	}
	var candidates []string
	if ndmc, err := exec.LookPath("ndmc"); err == nil {
		verified := map[string]bool{}
		checked := map[string]bool{}
		statuses := map[string]string{}
		verify := func(iface string) bool {
			if !checked[iface] {
				checked[iface] = true
				status, err := command(ctx, ndmc, "-c", "show interface "+iface)
				statuses[iface] = status
				verified[iface] = err == nil && keeneticInterfaceOwnsWAN(status, wanIPs)
			}
			return verified[iface]
		}
		out, e := command(ctx, ndmc, "-c", "show ip name-server")
		if e == nil {
			entries := parseKeeneticShadowServers(out)
			if len(entries) > 32 {
				entries = entries[:32]
			}
			for _, entry := range entries {
				if !verify(entry.iface) {
					continue
				}
				port := entry.port
				if port == "" || port == "0" {
					port = "53"
				}
				candidates = append(candidates, net.JoinHostPort(entry.address, port))
			}
		}
		if len(filterShadowServers(candidates, local)) > 0 {
			// Current authoritative DNS supersedes any older ignored lease.
			clear(remembered)
		} else {
			key := ""
			if routes, err := command(ctx, "ip", "-4", "route", "show", "table", "main", "default"); err == nil {
				key = shadowWANKey(routes, wan, wanIPs)
			}
			now := time.Now()
			for iface, lease := range remembered {
				if !now.Before(lease.expires) || key != "" && !lease.valid(key, wanIPs, now) {
					delete(remembered, iface)
				}
			}
			if log, err := command(ctx, ndmc, "-c", "show log"); err == nil {
				routerNow := time.Time{}
				if clock, err := command(ctx, "date", "+%Y-%m-%dT%H:%M:%S%z"); err == nil {
					routerNow, _ = time.Parse("2006-01-02T15:04:05-0700", strings.TrimSpace(clock))
				}
				for _, lease := range parseKeeneticShadowLeases(log) {
					// A newer observed ACK always supersedes the cached lease,
					// including a renewal without DNS or with a different address.
					if previous, ok := remembered[lease.iface]; ok && (previous.stamp != lease.stamp || previous.leaseSeconds != lease.leaseSeconds || !previous.clientIP.Equal(lease.clientIP)) {
						delete(remembered, lease.iface)
					}
					ownsIP := false
					for _, ip := range wanIPs {
						ownsIP = ownsIP || ip.Equal(lease.clientIP)
					}
					remaining := time.Duration(0)
					if !routerNow.IsZero() {
						remaining = shadowLeaseRemaining(lease, routerNow)
					}
					leaseServers := filterShadowServers(lease.servers, local)
					if ownsIP && remaining > 0 && len(leaseServers) > 0 && verify(lease.iface) && keeneticInterfaceOwnsWAN(statuses[lease.iface], []net.IP{lease.clientIP}) {
						candidates = append(candidates, leaseServers...)
						if remembered != nil && key != "" {
							next := shadowRememberedLease{wanKey: key, clientIP: append(net.IP(nil), lease.clientIP...), servers: leaseServers, expires: now.Add(remaining), stamp: lease.stamp, leaseSeconds: lease.leaseSeconds}
							if previous, ok := remembered[lease.iface]; ok && sameShadowLease(previous, next) {
								next.expires = previous.expires
							}
							remembered[lease.iface] = next
						}
					}
				}
			}
			if len(filterShadowServers(candidates, local)) == 0 {
				for iface, lease := range remembered {
					if lease.valid(key, wanIPs, time.Now()) && verify(iface) && keeneticInterfaceOwnsWAN(statuses[iface], []net.IP{lease.clientIP}) {
						candidates = append(candidates, lease.servers...)
					}
				}
			}
		}
	} else if ubus, err := exec.LookPath("ubus"); err == nil {
		out, e := command(ctx, ubus, "call", "network.interface", "dump")
		if e == nil {
			_, candidates = parseOpenWrtShadowWAN(out, wan, shadowDefaultDevices(ctx))
		}
	}
	servers := filterShadowServers(candidates, local)
	if len(servers) == 0 {
		return nil, fmt.Errorf("DNS провайдера ещё не получен от активного WAN; ожидается информация DHCP/PPP")
	}
	return servers, nil
}

func keeneticInterfaceOwnsWAN(output string, wanIPs []net.IP) bool {
	connected, hasAddress := false, false
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if key == "connected" && value == "yes" {
			connected = true
		}
		if key == "address" {
			ip := net.ParseIP(value)
			for _, wanIP := range wanIPs {
				if ip != nil && ip.Equal(wanIP) {
					hasAddress = true
					break
				}
			}
		}
	}
	return connected && hasAddress
}

func (a *Adapter) dialShadowOS(ctx context.Context, network, address string) (net.Conn, error) {
	ip, err := shadowEndpoint(address)
	if err != nil {
		return nil, err
	}
	family, index := "-4", 0
	if ip.To4() == nil {
		family, index = "-6", 1
	}
	a.opMu.Lock()
	if err := ctx.Err(); err != nil {
		a.opMu.Unlock()
		return nil, err
	}
	a.mu.Lock()
	if !a.started || a.runCtx == nil {
		a.mu.Unlock()
		a.opMu.Unlock()
		return nil, fmt.Errorf("DNS routing is disabled")
	}
	runCtx := a.runCtx
	a.mu.Unlock()
	if a.shadow.route == nil {
		a.shadow.route = &routeState{Route: Route{ID: "shadow"}, slot: shadowRouteSlot}
	}
	r := a.shadow.route
	signature := r.v4
	if index == 1 {
		signature = r.v6
	}
	iface := strings.Split(signature, "|")[0]
	if time.Since(a.shadow.checked[index]) >= 15*time.Second || !validInterface(iface) {
		wan := a.shadowWANDevices(ctx)
		iface, err = a.ensureRouteForWANLocked(ctx, r, family, wan)
		if err == nil {
			a.shadow.checked[index] = time.Now()
		}
	}
	a.opMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("Shadow DNS WAN route: %w", err)
	}
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(runCtx, cancel)
	defer stop()
	defer cancel()
	mark := routeMarkBase + uint32(shadowRouteSlot)
	d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		err := raw.Control(func(fd uintptr) {
			controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			if controlErr == nil {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(int32(mark)))
			}
		})
		if err != nil {
			return err
		}
		return controlErr
	}}
	c, err := d.DialContext(dialCtx, network, address)
	if err != nil {
		if ctx.Err() == nil {
			a.opMu.Lock()
			if a.runCtx == runCtx {
				a.shadow.checked[index] = time.Time{}
			}
			a.opMu.Unlock()
		}
		return nil, err
	}
	a.mu.Lock()
	if !a.started || a.runCtx != runCtx {
		a.mu.Unlock()
		c.Close()
		return nil, fmt.Errorf("DNS routing stopped during connection")
	}
	wrapped := &routedConn{Conn: c}
	wrapped.closed = func() { a.mu.Lock(); delete(a.conns, wrapped); a.mu.Unlock() }
	a.conns[wrapped] = struct{}{}
	a.mu.Unlock()
	if packet, ok := c.(net.PacketConn); ok {
		return &shadowPacketConn{routedConn: wrapped, packet: packet}, nil
	}
	return wrapped, nil
}

func shadowDefaultDevices(ctx context.Context) []string {
	var result []string
	for _, family := range []string{"-4", "-6"} {
		out, err := command(ctx, "ip", family, "route", "show", "table", "main", "default")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != "default" {
				continue
			}
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "dev" && validShadowWAN(fields[i+1]) {
					result = append(result, fields[i+1])
				}
			}
		}
	}
	return result
}

func (a *Adapter) shadowWANDevices(ctx context.Context) []string {
	// ubus is absent on Keenetic. On OpenWrt it provides authoritative logical
	// to physical/L3 mapping without editing any network or fw4 configuration.
	if ubus, err := exec.LookPath("ubus"); err == nil {
		if out, err := command(ctx, ubus, "call", "network.interface", "dump"); err == nil {
			devices, _ := parseOpenWrtShadowWAN(out, a.cfg.WANIfaces, shadowDefaultDevices(ctx))
			return devices
		}
		return nil // fail closed when authoritative mapping cannot be obtained
	}
	return a.cfg.WANIfaces
}

type shadowPacketConn struct {
	*routedConn
	packet net.PacketConn
}

func (c *shadowPacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return c.packet.ReadFrom(p) }
func (c *shadowPacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	return c.packet.WriteTo(p, address)
}
