//go:build linux

package dnsroute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Kept injectable for Linux tests; no test needs privileges or router mutations.
var command = executeCommand

func executeCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (a *Adapter) prepareOS(ctx context.Context, l ListenOptions) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return fmt.Errorf("DNS routing is already prepared")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.cfg.MainQueue < 0 || a.cfg.MainQueue > 65535 {
		return fmt.Errorf("invalid main NFQUEUE number")
	}
	if l.DNSPort < 1 || l.DNSPort > 65535 {
		return fmt.Errorf("invalid DNS listening port")
	}
	host, err := ResolveLANHost(l.Host, a.cfg.WANIfaces)
	if err != nil {
		return err
	}
	l.Host = host
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	iface, subnet, err := localLAN(net.ParseIP(host), ifs, a.cfg.WANIfaces)
	if err != nil {
		return err
	}
	if !validInterface(iface) {
		return fmt.Errorf("invalid LAN interface")
	}
	if data, e := os.ReadFile(hookPath); e == nil && !strings.Contains(string(data), hookSignature) {
		return fmt.Errorf("refusing to replace foreign netfilter hook %s", hookPath)
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	// Own remnants may survive an unclean restart; only our exact mark/table
	// pairs and named chains are cleaned. Never flush the user's routing tables.
	if err = a.cleanupLocked(ctx); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
		return err
	}
	script := firewallScript(a.cfg.MainQueue, l, iface, subnet)
	tmp, err := os.CreateTemp(filepath.Dir(hookPath), ".nfqws-dns-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.WriteString(script); err == nil {
		err = tmp.Chmod(0755)
	}
	if e := tmp.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmpName, hookPath); err != nil {
		return err
	}
	if _, err = command(ctx, "sh", hookPath); err != nil {
		_ = os.Remove(hookPath)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cleanupErr := a.cleanupLocked(cleanupCtx)
		a.hookReady = cleanupErr != nil // a later Close must retry incomplete cleanup
		return errors.Join(err, cleanupErr)
	}
	a.listen = l
	a.lanIface = iface
	a.lanSubnet = subnet
	a.started = true
	a.hookReady = true
	a.routes = map[string]*routeState{}
	a.nextSlot = 1
	a.updated = time.Time{}
	a.refreshLocked()
	runCtx, cancel := context.WithCancel(context.Background())
	a.runCtx = runCtx
	a.conns = make(map[*routedConn]struct{})
	a.cancel = cancel
	a.done = make(chan struct{})
	go a.maintain(runCtx, a.done)
	return nil
}

func (a *Adapter) maintain(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			if a.started {
				// ndm calls the hook after firewall reload. This check also repairs
				// manual flushes, while each new dial verifies its own queue path.
				if !a.firewallReady(ctx, "iptables") {
					_, err := command(ctx, "sh", hookPath)
					a.hookReady = err == nil
				}
				a.updated = time.Time{}
				a.refreshLocked()
			}
			a.mu.Unlock()
		}
	}
}

func (a *Adapter) refreshLocked() {
	if !a.updated.IsZero() && time.Since(a.updated) < 3*time.Second {
		return
	}
	a.updated = time.Now()
	nfq := a.routes["nfqws"]
	if nfq == nil {
		nfq = &routeState{Route: Route{ID: "nfqws", Name: "NFQWS"}}
		a.routes["nfqws"] = nfq
	}
	nfq.Available = false
	nfq.Error = ""
	if !a.started {
		nfq.Error = "сервис выключен"
	} else if !a.hookReady {
		nfq.Error = "правила NFQWS DNS недоступны"
	} else if !queueBound(a.cfg.MainQueue) {
		nfq.Error = "основная очередь NFQWS не запущена"
	} else {
		nfq.Available = true
	}
	seen := map[string]bool{"nfqws": true}
	if a.awg != nil {
		for _, t := range a.awg.DNSRouteCandidates() {
			if !validInterface(t.Interface) {
				continue
			}
			id := "awg:" + t.ID
			seen[id] = true
			r := a.routes[id]
			if r == nil {
				if a.nextSlot >= maxRouteSlots {
					continue
				}
				r = &routeState{slot: a.nextSlot}
				a.nextSlot++
				a.routes[id] = r
			}
			if r.Interface != t.Interface {
				r.v4 = ""
				r.v6 = ""
			}
			r.Route = Route{ID: id, Name: t.Name, Interface: t.Interface, Available: t.Available}
			if !r.Available {
				r.Error = "туннель выключен или восстанавливается"
			}
		}
	}
	for id, r := range a.routes {
		if !seen[id] {
			r.Available = false
			r.Error = "подключение выключено"
		}
	}
}

func (a *Adapter) routesOS() []Route {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
	out := []Route{}
	if r := a.routes["nfqws"]; r != nil {
		out = append(out, r.Route)
	}
	for slot := 1; slot < a.nextSlot; slot++ {
		for _, r := range a.routes {
			if r.slot == slot {
				out = append(out, r.Route)
			}
		}
	}
	return out
}

func queueBound(number int) bool {
	b, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == strconv.Itoa(number) {
			return true
		}
	}
	return false
}

func (a *Adapter) firewallReady(ctx context.Context, family string) bool {
	for _, x := range []struct{ parent, chain, match, direction string }{{"POSTROUTING", postChain, "mark", "original"}, {"PREROUTING", preChain, "connmark", "reply"}} {
		if _, err := command(ctx, family, "-w", "-t", "mangle", "-C", x.parent, "-m", x.match, "--mark", routeSelector(0), "-j", x.chain); err != nil {
			return false
		}
		if _, err := command(ctx, family, "-w", "-t", "mangle", "-C", x.chain, "-p", "tcp", "-m", "connbytes", "--connbytes", "1:32", "--connbytes-mode", "packets", "--connbytes-dir", x.direction, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(a.cfg.MainQueue), "--queue-bypass"); err != nil {
			return false
		}
	}
	return true
}

func (a *Adapter) dialOS(ctx context.Context, id, network, address string) (net.Conn, error) {
	ipText, port, _ := net.SplitHostPort(address)
	ip := net.ParseIP(ipText)
	if ip == nil {
		return nil, fmt.Errorf("literal upstream IP required")
	}
	family := "-4"
	ipt := "iptables"
	if ip.To4() == nil {
		family = "-6"
		ipt = "ip6tables"
	}
	a.mu.Lock()
	if !a.started {
		a.mu.Unlock()
		return nil, fmt.Errorf("DNS routing is disabled")
	}
	a.refreshLocked()
	r := a.routes[id]
	if r == nil || !r.Available {
		a.mu.Unlock()
		return nil, fmt.Errorf("DNS route %s is unavailable", id)
	}
	if id == "nfqws" {
		if port != "443" {
			a.mu.Unlock()
			return nil, fmt.Errorf("current NFQWS DNS route supports HTTPS port 443; trying AWG for %s", port)
		}
		if !queueBound(a.cfg.MainQueue) {
			a.mu.Unlock()
			return nil, fmt.Errorf("NFQWS queue is not bound")
		}
		if !a.firewallReady(ctx, ipt) {
			if _, err := command(ctx, "sh", hookPath); err != nil || !a.firewallReady(ctx, ipt) {
				a.mu.Unlock()
				return nil, fmt.Errorf("NFQWS DNS queue rules are unavailable for %s", family)
			}
		}
		if !conntrackAccounting() {
			a.mu.Unlock()
			return nil, fmt.Errorf("NFQWS requires conntrack accounting; trying AWG")
		}
	}
	iface, err := a.ensureRouteLocked(ctx, r, family)
	mark := routeMarkBase + uint32(r.slot)
	runCtx := a.runCtx
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	dialCtx, cancelDial := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(runCtx, cancelDial)
	defer stopCancel()
	defer cancelDial()
	d := net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			if controlErr == nil {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(int32(mark)))
			}
		}); err != nil {
			return err
		}
		return controlErr
	}}
	c, err := d.DialContext(dialCtx, network, address)
	if err != nil {
		// Losing a parallel DNS race is normal; it must not invalidate a
		// healthy route and force policy-table repairs on the next query.
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		// A daemon restart removes its default route from our table. The next
		// request reconstructs it; no failed path is ever disabled permanently.
		a.mu.Lock()
		if cur := a.routes[id]; cur != nil {
			cur.v4 = ""
			cur.v6 = ""
		}
		a.mu.Unlock()
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
	return wrapped, nil
}

func conntrackAccounting() bool {
	if b, e := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct"); e == nil {
		return strings.TrimSpace(string(b)) == "1"
	} else if !os.IsNotExist(e) {
		return false
	}
	// Older Keenetic kernels always account tracked packets and expose no
	// toggle. Verify their actual connection records instead of rejecting them.
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	return bytes.Contains(b, []byte(" packets="))
}

func (a *Adapter) ensureRouteLocked(ctx context.Context, r *routeState, family string) (string, error) {
	iface, gw := r.Interface, ""
	if r.ID == "nfqws" {
		out, err := command(ctx, "ip", family, "route", "show", "table", "main", "default")
		if err != nil {
			return "", err
		}
		iface, gw = pickWANDefault(out, a.cfg.WANIfaces)
		if iface == "" {
			return "", fmt.Errorf("no %s WAN default route for NFQWS", family)
		}
	}
	if !validInterface(iface) {
		return "", fmt.Errorf("invalid DNS route interface")
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil || dev.Flags&net.FlagUp == 0 {
		return "", fmt.Errorf("DNS route interface %s is down", iface)
	}
	if family == "-6" {
		addresses, _ := dev.Addrs()
		v6 := false
		for _, addr := range addresses {
			ip, _, e := net.ParseCIDR(addr.String())
			if e == nil && ip.To4() == nil && ip.IsGlobalUnicast() {
				v6 = true
			}
		}
		if !v6 {
			return "", fmt.Errorf("interface %s has no routed IPv6 address", iface)
		}
	}
	table := strconv.Itoa(routeTableBase + r.slot)
	mark := routeSelector(r.slot)
	signature := iface + "|" + gw + "|" + strconv.Itoa(dev.Index)
	cache := &r.v4
	if family == "-6" {
		cache = &r.v6
	}
	// Check the desired route even after a successful previous dial: ip link del
	// removes table routes, and a new awgN may keep the same name.
	current, err := command(ctx, "ip", family, "route", "show", "table", table)
	if err != nil && !strings.Contains(current, "does not exist") {
		return "", err
	}
	if *cache == signature && strings.Contains(current, "default") && strings.Contains(current, "dev "+iface) {
		return iface, nil
	}
	rules, err := command(ctx, "ip", family, "rule", "show")
	if err != nil {
		return "", err
	}
	owned := ownedRule(rules, r.slot)
	if !owned && strings.TrimSpace(current) != "" {
		return "", fmt.Errorf("refusing to overwrite occupied DNS route table %s", table)
	}
	if !owned {
		// Claim the empty table before adding routes, so a failure can always
		// be recovered or cleaned via our exact rule. No socket is opened until
		// all commands below succeed.
		if _, err = command(ctx, "ip", family, "rule", "add", "pref", strconv.Itoa(routePriority), "fwmark", mark, "table", table); err != nil {
			return "", err
		}
	}
	// Keep a terminal route when ip link del removes the device's default.
	// Existing sockets must fail rather than fall through to another policy.
	if _, err = command(ctx, "ip", family, "route", "replace", "blackhole", "default", "table", table, "metric", "32760"); err != nil {
		return "", err
	}
	if gw != "" {
		prefix := "/32"
		if family == "-6" {
			prefix = "/128"
		}
		if _, err = command(ctx, "ip", family, "route", "replace", gw+prefix, "dev", iface, "scope", "link", "table", table); err != nil {
			return "", err
		}
	}
	args := []string{family, "route", "replace", "default"}
	if gw != "" {
		args = append(args, "via", gw)
	}
	args = append(args, "dev", iface, "table", table)
	if _, err = command(ctx, "ip", args...); err != nil {
		return "", err
	}
	*cache = signature
	r.Interface = iface
	return iface, nil
}

func pickWANDefault(output string, wan []string) (string, string) {
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		dev, gw := "", ""
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "dev" {
				dev = f[i+1]
			}
			if f[i] == "via" {
				gw = f[i+1]
			}
		}
		valid := false
		for _, w := range wan {
			if w == dev {
				valid = true
			}
		}
		if valid && validInterface(dev) && (gw == "" || net.ParseIP(gw) != nil) {
			return dev, gw
		}
	}
	return "", ""
}

func ownedRule(rules string, slot int) bool {
	for _, line := range strings.Split(rules, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != strconv.Itoa(routePriority)+":" {
			continue
		}
		mark, table := "", ""
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "fwmark" {
				mark = f[i+1]
			}
			if f[i] == "lookup" || f[i] == "table" {
				table = f[i+1]
			}
		}
		if mark == routeSelector(slot) && table == strconv.Itoa(routeTableBase+slot) {
			return true
		}
	}
	return false
}

func (a *Adapter) cleanupLocked(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var errs []error
	cmd := exec.CommandContext(ctx, "sh")
	cmd.Stdin = strings.NewReader(cleanupFirewallScript())
	if out, err := cmd.CombinedOutput(); err != nil {
		errs = append(errs, fmt.Errorf("DNS firewall cleanup: %w: %s", err, strings.TrimSpace(string(out))))
	}
	for _, family := range []string{"-4", "-6"} {
		rules, err := command(ctx, "ip", family, "rule", "show")
		if err != nil {
			if family == "-4" {
				errs = append(errs, err)
			}
			continue
		}
		for slot := 0; slot < maxRouteSlots; slot++ {
			if ownedRule(rules, slot) {
				if _, e := command(ctx, "ip", family, "rule", "del", "pref", strconv.Itoa(routePriority), "fwmark", routeSelector(slot), "table", strconv.Itoa(routeTableBase+slot)); e != nil {
					errs = append(errs, e)
					continue
				}
				if _, e := command(ctx, "ip", family, "route", "flush", "table", strconv.Itoa(routeTableBase+slot)); e != nil {
					errs = append(errs, e)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (a *Adapter) closeOS() error {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	done := a.done
	a.done = nil
	a.cancel = nil
	a.started = false
	conns := make([]*routedConn, 0, len(a.conns))
	for c := range a.conns {
		conns = append(conns, c)
	}
	a.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	if done != nil {
		<-done
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Disabling a previously prepared adapter is safe to repeat. With no hook
	// and no preparation, leave the host entirely untouched (default is off).
	data, err := os.ReadFile(hookPath)
	if err != nil && os.IsNotExist(err) && !a.hookReady {
		return nil
	}
	if err == nil && !strings.Contains(string(data), hookSignature) {
		return fmt.Errorf("refusing to remove foreign netfilter hook %s", hookPath)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err = os.Remove(hookPath); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = a.cleanupLocked(ctx)
	a.hookReady = err != nil // retain a pending cleanup across repeated Close calls
	a.updated = time.Time{}
	return err
}
