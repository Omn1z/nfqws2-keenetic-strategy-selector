//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

func (a *Adapter) shadowServersOS(ctx context.Context) (result []string, resultErr error) {
	callerCtx := ctx
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.shadow.discoveryMu.Lock()
	defer a.shadow.discoveryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if time.Now().Before(a.shadow.discoveryUntil) && !a.shadow.native.changed() {
		return append([]string(nil), a.shadow.servers...), a.shadow.discoveryErr
	}
	nativeReader := a.shadow.native.reader
	if nativeReader != nil {
		revision := nativeReader.snapshot().sequence
		defer func() {
			if callerCtx.Err() == nil && a.shadow.native.reader == nativeReader && revision > a.shadow.native.applied {
				a.shadow.native.applied = revision
			}
		}()
	}
	ctx, finish := a.shadow.diagnostics.begin(ctx)
	var nextRetry time.Time
	defer func() { finish(result, resultErr, nextRetry) }()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	a.loadShadowLeases()
	shadowDiagnosticEvent(ctx, "state.loaded", fmt.Sprintf("Сохранённые аренды: %d; известные DHCP-серверы: %d", len(a.shadow.leases), len(a.shadow.inform.targets)), 0)
	discoveryStarted := time.Now()
	servers, err := discoverShadowServersWithObserver(ctx, a.cfg.WANIfaces, a.shadow.leases, &a.shadow.inform, a.observeShadowNative)
	if err := shadowDiscoveryContextErr(callerCtx); err != nil {
		return nil, err
	} // a canceled caller must not poison discovery
	a.shadow.native.applied = max(a.shadow.native.applied, a.shadow.native.inspected)
	if contextErr := shadowDiscoveryContextErr(ctx); contextErr != nil && len(servers) == 0 {
		// The caller is still alive, so this was our discovery budget rather
		// than caller cancellation. Cache it below like other discovery errors;
		// otherwise a slow native CLI would repeat for every DNS question.
		err = contextErr
	}
	a.saveShadowLeases()
	a.shadow.servers, a.shadow.discoveryErr = servers, err
	a.shadow.discoveryUntil = time.Now().Add(time.Minute)
	for _, lease := range a.shadow.leases {
		if lease.expires.Before(a.shadow.discoveryUntil) {
			a.shadow.discoveryUntil = lease.expires
		}
	}
	for _, answer := range a.shadow.inform.answers {
		if discoveryStarted.Before(answer.expires) && answer.expires.Before(a.shadow.discoveryUntil) {
			a.shadow.discoveryUntil = answer.expires
		}
	}
	if err != nil {
		a.shadow.discoveryUntil = time.Now().Add(30 * time.Second)
	}
	nextRetry = a.shadow.discoveryUntil
	shadowDiagnosticEvent(ctx, "discovery.result", fmt.Sprintf("Допустимых DNS-серверов: %d; ошибка: %t", len(servers), err != nil), time.Since(discoveryStarted))
	return append([]string(nil), servers...), err
}

func discoverShadowServers(ctx context.Context, wan []string) ([]string, error) {
	return discoverShadowServersWithLeases(ctx, wan, nil)
}

func discoverShadowServersWithLeases(ctx context.Context, wan []string, remembered map[string]shadowRememberedLease) ([]string, error) {
	return discoverShadowServersWithState(ctx, wan, remembered, nil)
}

func discoverShadowServersWithState(ctx context.Context, wan []string, remembered map[string]shadowRememberedLease, inform *shadowInformState) ([]string, error) {
	return discoverShadowServersWithObserver(ctx, wan, remembered, inform, nil)
}

func discoverShadowServersWithObserver(ctx context.Context, wan []string, remembered map[string]shadowRememberedLease, inform *shadowInformState, observe func(context.Context, string, []shadowBroadcastWAN, []net.IP, time.Time) bool) ([]string, error) {
	if err := shadowDiscoveryContextErr(ctx); err != nil {
		return nil, err
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var local, wanIPs []net.IP
	wanDevices := map[string]string{}
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
					wanDevices[ip.String()] = iface.Name
				}
			}
		}
	}
	var wanSummary []string
	for ip, device := range wanDevices {
		wanSummary = append(wanSummary, device+"="+ip)
	}
	sort.Strings(wanSummary)
	shadowDiagnosticEvent(ctx, "wan.addresses", "Адреса настроенных WAN: "+strings.Join(wanSummary, ", "), 0)
	var candidates []string
	var informErr, nativeErr error
	if ndmc, err := exec.LookPath("ndmc"); err == nil {
		interfaceOutput, interfacesRead := "", false
		readNative := func(operation string) (string, error) {
			if operation == "show interface" && interfacesRead {
				return interfaceOutput, nil
			}
			started := time.Now()
			out, err := command(ctx, ndmc, "-c", operation)
			if err := shadowNativeCommandError(ctx, operation, out, err); err != nil {
				shadowDiagnosticEvent(ctx, "native.command", operation+": ошибка чтения", time.Since(started))
				if nativeErr == nil {
					nativeErr = err
				}
				return "", err
			}
			shadowDiagnosticEvent(ctx, "native.command", operation+": прочитано", time.Since(started))
			if operation == "show interface" {
				interfaceOutput, interfacesRead = out, true
			}
			return out, nil
		}
		verified := map[string]bool{}
		checked := map[string]bool{}
		statuses := map[string]string{}
		verify := func(iface string) bool {
			if !checked[iface] {
				checked[iface] = true
				status, err := readNative("show interface " + iface)
				statuses[iface] = status
				verified[iface] = err == nil && keeneticInterfaceOwnsWAN(status, wanIPs)
				shadowDiagnosticEvent(ctx, "wan.verify", fmt.Sprintf("%s: принадлежность адресу активного WAN подтверждена=%t", iface, verified[iface]), 0)
			}
			return verified[iface]
		}
		out, e := readNative("show ip name-server")
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
			shadowDiagnosticEvent(ctx, "native.dns", fmt.Sprintf("DHCP/PPP DNS-записей: %d; принято после проверки WAN и адресов: %d", len(entries), len(filterShadowServers(candidates, local))), 0)
		}
		if len(filterShadowServers(candidates, local)) > 0 {
			// Current authoritative DNS supersedes any older ignored lease.
			clear(remembered)
			if observe != nil {
				observe(ctx, "", nil, local, time.Time{})
			}
		} else {
			key, defaultRoutes := "", ""
			routeStarted := time.Now()
			routes, routeErr := command(ctx, "ip", "-4", "route", "show", "table", "main", "default")
			if routeErr == nil {
				defaultRoutes = routes
				key = shadowWANKey(routes, wan, wanIPs)
			}
			shadowDiagnosticEvent(ctx, "wan.default", fmt.Sprintf("Таблица main: прочитана=%t; принадлежность WAN подтверждена=%t", routeErr == nil, key != ""), time.Since(routeStarted))
			now := time.Now()
			for iface, lease := range remembered {
				if !now.Before(lease.expires) || key != "" && !lease.valid(key, wanIPs, now) {
					delete(remembered, iface)
				}
			}
			if inform != nil && key != "" {
				for iface, target := range inform.targets {
					if !target.valid(key, wanIPs) {
						delete(inform.targets, iface)
						delete(inform.answers, iface)
						delete(inform.retryAfter, iface)
					}
				}
			}
			routerNow := time.Time{}
			if log, err := readNative("show log"); err == nil {
				if clock, err := command(ctx, "date", "+%Y-%m-%dT%H:%M:%S%z"); err == nil {
					routerNow, _ = time.Parse("2006-01-02T15:04:05-0700", strings.TrimSpace(clock))
				}
				logLeases := parseKeeneticShadowLeases(log)
				shadowDiagnosticEvent(ctx, "native.leases", fmt.Sprintf("Связанных DHCP ACK в журнале: %d", len(logLeases)), 0)
				logShadowNativeLeases(ctx, log, logLeases, routerNow)
				for _, lease := range logLeases {
					// Native IDs and aliases (ISP/GigabitEthernet1) may differ in
					// ring logs. Compare fresh packet evidence across the WAN/IP.
					stale := false
					observed := shadowLeaseObservedAt(lease.stamp, routerNow)
					for _, previous := range remembered {
						if previous.wanKey == key && previous.clientIP.Equal(lease.clientIP) && !previous.observedAt.IsZero() && (observed.IsZero() || observed.Before(previous.observedAt)) {
							stale = true
							break
						}
					}
					if stale {
						continue
					}
					if previous, ok := remembered[lease.iface]; ok {
						observed := shadowLeaseObservedAt(lease.stamp, routerNow)
						retained := shadowLeaseObservedAt(previous.stamp, routerNow)
						if !previous.observedAt.IsZero() {
							retained = previous.observedAt
						}
						if !observed.IsZero() && !retained.IsZero() && observed.Before(retained) {
							continue // an older ring-log ACK cannot replace newer evidence
						}
						if !previous.clientIP.Equal(lease.clientIP) {
							delete(remembered, lease.iface)
						}
					}
					// Keenetic renewals can log only an ACK, without repeating the
					// obtained-address/ignored-DNS lines. Missing log detail is not
					// a DNS withdrawal. Keep verified same-WAN evidence until its
					// original expiry; only a complete new DNS observation renews it.
					ownsIP := false
					for _, ip := range wanIPs {
						ownsIP = ownsIP || ip.Equal(lease.clientIP)
					}
					if inform != nil && key != "" && ownsIP && lease.serverIP != nil && len(filterShadowServers([]string{lease.serverIP.String()}, local)) == 1 && verify(lease.iface) && keeneticInterfaceOwnsWAN(statuses[lease.iface], []net.IP{lease.clientIP}) {
						inform.remember(lease.iface, shadowDHCPTarget{wanKey: key, clientIP: append(net.IP(nil), lease.clientIP...), serverIP: append(net.IP(nil), lease.serverIP...), stamp: lease.stamp}, routerNow)
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
			// Passive capture observes the native client's ordinary renewal even
			// when the provider ignores INFORM. It is configured only for the
			// verified physical active WAN, never for OpenWrt or VPN interfaces.
			nativeObserved := false
			if observe != nil && key != "" && nativeErr == nil {
				if interfaces, err := readNative("show interface"); err == nil {
					eligible := parseShadowBroadcastWANs(interfaces, defaultRoutes, wan, wanDevices)
					nativeObserved = observe(ctx, key, eligible, local, routerNow)
					if nativeObserved {
						candidates = nil
					}
				} else {
					observe(ctx, "", nil, local, routerNow)
				}
			} else if observe != nil {
				observe(ctx, "", nil, local, routerNow)
			}
			hasNativeLease := false
			if len(filterShadowServers(candidates, local)) == 0 {
				for iface, lease := range remembered {
					if verify(iface) && keeneticInterfaceOwnsWAN(statuses[iface], []net.IP{lease.clientIP}) && lease.valid(key, wanIPs, time.Now()) {
						candidates = append(candidates, lease.servers...)
						hasNativeLease = hasNativeLease || !lease.observedAt.IsZero()
					}
				}
			}
			if hasNativeLease && inform != nil {
				candidates = shadowUnexpiredCandidates(candidates, inform, remembered, key, wanIPs, func(iface string, ip net.IP) bool {
					return verified[iface] && keeneticInterfaceOwnsWAN(statuses[iface], []net.IP{ip})
				})
				hasNativeLease = len(filterShadowServers(candidates, local)) > 0
			}
			if inform != nil && !hasNativeLease {
				verifyTarget := func(iface string, clientIP net.IP) bool {
					return verify(iface) && keeneticInterfaceOwnsWAN(statuses[iface], []net.IP{clientIP})
				}
				unicastAttempts := inform.unicastAttempts
				fresh, err := discoverShadowInform(ctx, inform, key, wanIPs, local, wanDevices, verifyTarget)
				informErr = err
				if len(fresh) > 0 {
					candidates = fresh // current option 6 supersedes older leased DNS
				}
				fallbackTargets := dueShadowInformBroadcastTargets(inform, key, wanIPs, wanDevices, verifyTarget)
				if inform.unicastAttempts == unicastAttempts && nativeErr == nil && key != "" && (len(fallbackTargets) > 0 || len(filterShadowServers(candidates, local)) == 0 && !hasShadowInformTarget(inform, key, wanIPs, wanDevices, verifyTarget)) {
					broadcastFresh := false
					if interfaces, err := readNative("show interface"); err == nil {
						eligible := parseShadowBroadcastWANs(interfaces, defaultRoutes, wan, wanDevices)
						if len(fallbackTargets) > 0 {
							eligible = shadowBroadcastFallbackWANs(inform, key, eligible, fallbackTargets)
						}
						shadowDiagnosticEvent(ctx, "discovery.broadcast", fmt.Sprintf("Подходящих WAN для broadcast: %d; переходов с unicast: %d", len(eligible), len(fallbackTargets)), 0)
						if len(eligible) > 0 {
							fresh, err := discoverShadowBroadcast(ctx, inform, key, eligible, local)
							informErr = err
							if len(fresh) > 0 {
								candidates = fresh
								broadcastFresh = true
							}
						}
					}
					if contextErr := shadowDiscoveryContextErr(ctx); contextErr != nil {
						return nil, contextErr
					}
					// Even the native interface read may outlive a cache TTL,
					// whether discovery subsequently sends a packet or not.
					if !broadcastFresh {
						candidates = shadowUnexpiredCandidates(candidates, inform, remembered, key, wanIPs, func(iface string, ip net.IP) bool {
							return verified[iface] && keeneticInterfaceOwnsWAN(statuses[iface], []net.IP{ip})
						})
					}
				}
			}
		}
	} else if ubus, err := exec.LookPath("ubus"); err == nil {
		if observe != nil {
			observe(ctx, "", nil, local, time.Time{})
		}
		started := time.Now()
		out, e := command(ctx, ubus, "call", "network.interface", "dump")
		if e == nil {
			_, candidates = parseOpenWrtShadowWAN(out, wan, shadowDefaultDevices(ctx))
		}
		shadowDiagnosticEvent(ctx, "openwrt.dns", fmt.Sprintf("ubus: прочитан=%t; принято DNS-серверов: %d", e == nil, len(filterShadowServers(candidates, local))), time.Since(started))
	} else {
		if observe != nil {
			observe(ctx, "", nil, local, time.Time{})
		}
		shadowDiagnosticEvent(ctx, "discovery.source", "Не найдены ndmc и ubus", 0)
	}
	servers := filterShadowServers(candidates, local)
	if len(servers) == 0 {
		if err := shadowDiscoveryContextErr(ctx); err != nil {
			return nil, err
		}
		if nativeErr != nil {
			return nil, nativeErr
		}
		if informErr != nil {
			return nil, fmt.Errorf("DHCPINFORM: %w", informErr)
		}
		return nil, fmt.Errorf("DNS провайдера ещё не получен от активного WAN; ожидается информация DHCP/PPP")
	}
	return servers, nil
}

func shadowUnexpiredCandidates(candidates []string, state *shadowInformState, leases map[string]shadowRememberedLease, key string, wanIPs []net.IP, verified func(string, net.IP) bool) []string {
	now := time.Now()
	valid := map[string]bool{}
	for iface, answer := range state.answers {
		target := state.targets[iface]
		if now.Before(answer.expires) && target.valid(key, wanIPs) && verified(iface, target.clientIP) {
			for _, server := range filterShadowServers(answer.servers, nil) {
				valid[server] = true
			}
		}
	}
	for iface, lease := range leases {
		if lease.valid(key, wanIPs, now) && verified(iface, lease.clientIP) {
			for _, server := range filterShadowServers(lease.servers, nil) {
				valid[server] = true
			}
		}
	}
	var result []string
	for _, server := range candidates {
		if valid[server] {
			result = append(result, server)
		}
	}
	return result
}

// Inform responses have no lease grant. Cache the verified options for five
// minutes independently of the original DHCP lease, with a bounded retry rate.
// Called only while discoveryMu is held; no per-query worker or periodic fork.
func discoverShadowInform(ctx context.Context, state *shadowInformState, key string, wanIPs, local []net.IP, devices map[string]string, verify func(string, net.IP) bool) ([]string, error) {
	const ttl, retry = 5 * time.Minute, 30 * time.Second
	now := time.Now()
	keys := make([]string, 0, len(state.targets))
	for iface := range state.targets {
		keys = append(keys, iface)
	}
	sort.Strings(keys)
	var lastErr error
	probed := false
	for _, iface := range keys {
		target := state.targets[iface]
		device := devices[target.clientIP.String()]
		if !target.valid(key, wanIPs) || !validShadowWAN(device) || !verify(iface, target.clientIP) {
			shadowDiagnosticEvent(ctx, "discovery.target", iface+": сохранённый DHCP-сервер не прошёл проверку текущего WAN", 0)
			continue
		}
		shadowDiagnosticEvent(ctx, "discovery.target", fmt.Sprintf("%s / %s; клиент %s; DHCP-сервер %s; broadcast=%t", iface, device, target.clientIP, target.serverIP, target.preferBroadcast), 0)
		answer := state.answers[iface]
		// Refresh one discovery interval before expiry so a transient failure
		// can continue using still-valid information while the retry is cooled.
		if !answer.refresh && now.Before(answer.expires.Add(-time.Minute)) {
			shadowDiagnosticEvent(ctx, "discovery.cached", iface+": действующий ответ DHCPINFORM сохранён в кеше", 0)
			return filterShadowServers(answer.servers, local), nil
		}
		if now.Before(state.retryAfter[iface]) {
			shadowDiagnosticEvent(ctx, "discovery.cooldown", iface+": повторная попытка после "+state.retryAfter[iface].UTC().Format(time.RFC3339), 0)
			if now.Before(answer.expires) {
				return filterShadowServers(answer.servers, local), nil
			}
			lastErr = fmt.Errorf("ожидается повторное получение DNS от DHCP-сервера")
			continue
		}
		if target.preferBroadcast {
			shadowDiagnosticEvent(ctx, "discovery.mode", iface+": следующий DHCPINFORM через broadcast", 0)
			if now.Before(answer.expires) {
				return filterShadowServers(answer.servers, local), nil
			}
			lastErr = fmt.Errorf("DHCP-сервер не ответил напрямую; ожидается обнаружение через broadcast активного WAN")
			continue
		}
		if probed {
			continue
		}
		probe := state.probe
		if probe == nil {
			probe = shadowDHCPInform
		}
		probed = true
		state.unicastAttempts++
		servers, err := probe(ctx, device, target.clientIP, target.serverIP)
		now = time.Now()
		if err := shadowDiscoveryContextErr(ctx); err != nil {
			if now.Before(answer.expires) {
				return filterShadowServers(answer.servers, local), nil
			}
			return nil, err // cancellation never installs a negative cache
		}
		servers = filterShadowServers(servers, local)
		if err == nil && len(servers) == 0 {
			err = fmt.Errorf("DHCP-сервер не сообщил допустимые DNS")
		}
		if state.retryAfter == nil {
			state.retryAfter = map[string]time.Time{}
		}
		state.retryAfter[iface] = time.Now().Add(retry)
		if errors.Is(err, context.DeadlineExceeded) {
			// The parent discovery context was checked above. Only a local
			// probe timeout switches transport; cancellation never does.
			target.preferBroadcast = true
			state.targets[iface] = target
			shadowDiagnosticEvent(ctx, "discovery.mode", iface+": таймаут unicast; следующая попытка через broadcast", 0)
		}
		if err == nil {
			if state.answers == nil {
				state.answers = map[string]shadowInformAnswer{}
			}
			state.answers[iface] = shadowInformAnswer{servers: append([]string(nil), servers...), expires: time.Now().Add(ttl)}
			return servers, nil
		}
		lastErr = err
		if now.Before(answer.expires) {
			return filterShadowServers(answer.servers, local), nil
		}
	}
	return nil, lastErr
}

func shadowDiscoveryContextErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
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
