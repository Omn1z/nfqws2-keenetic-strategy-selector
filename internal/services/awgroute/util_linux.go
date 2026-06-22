//go:build linux

package awgroute

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Low-level helpers for the AWG2 split-routing OS layer: shell exec (with a
// timeout so no single command can hang the caller), default-route + fwmark
// inspection, and hostname → IPv4 resolution.

// awgIpBatch runs every line in script through a single `ip -force -batch -`
// invocation. One fork instead of N for the consecutive ip route / ip rule
// commands every apply / refresh / watchdog full-re-assert emits. `-force`
// makes the batch continue past idempotent "rule already exists" errors so
// the script doesn't abort mid-stream on a re-assert.
//
// Lines must NOT contain a leading "ip " — the binary is already named on the
// command line. Empty / blank lines are dropped.
func awgIpBatch(lines []string) error {
	var b strings.Builder
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return nil
	}
	_, err := awgRunStdin("ip -force -batch -", b.String())
	return err
}

func awgRun(cmd string) (string, error) {
	ctx, cancel := contextTimeout(15 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// parallelResolve runs resolveDomainAll concurrently across a small worker pool
// and returns the per-domain IP lists in the SAME order as the input slice.
// Resolving 1000+ category-ru hostnames serially takes ~2 minutes; with 32
// workers it finishes in seconds (the router's resolver handles parallel queries
// fine — nslookup is just fork+exec + a UDP round trip).
func parallelResolve(domains []string, workers int) [][]string {
	if len(domains) == 0 {
		return nil
	}
	if workers < 1 {
		workers = 1
	}
	out := make([][]string, len(domains))
	jobs := make(chan int, len(domains))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = resolveDomainAll(domains[i])
			}
		}()
	}
	for i := range domains {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

// awgRunStdin runs `cmd` and pipes `stdin` into it. Used for bulk-feeding ipset
// rule streams via `ipset restore` so an apply that adds 20k entries to a zone
// finishes in a single fork+exec instead of N of them (each ~10–30 ms on the
// router, which is the real reason a full geoip:ru expansion took ~2 minutes).
func awgRunStdin(cmd, stdin string) (string, error) {
	// ipset restore for a full geoip:ru can be ~25k lines; allow a generous timeout.
	ctx, cancel := contextTimeout(90 * time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Stdin = strings.NewReader(stdin)
	out, err := c.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// awgIfaceHasGlobalV6 reports whether the tunnel interface has any global-scope
// IPv6 address assigned. Necessary precondition for v6-in-tunnel but not
// sufficient — see awgTunnelV6Reaches.
func awgIfaceHasGlobalV6() bool {
	out, _ := awgRun("ip -6 addr show dev " + awgIface + " scope global")
	return strings.Contains(out, "inet6 ")
}

var (
	awgV6ReachMu     sync.Mutex
	awgV6ReachVal    bool
	awgV6ReachExpiry time.Time
)

// awgTunnelV6Reaches reports whether v6 traffic that rides the tunnel actually
// reaches a public destination — i.e. the VPS can SNAT it to its public v6 AND
// the upstream provider routes return traffic back. Some providers hand out a
// /64 and ICMP6 works, but TCP6 silently blackholes (asymmetric ECMP, partial
// BGP, fail2ban-equivalent). In that case, leak-prevent REJECT is still
// required so Happy Eyeballs falls back to v4 fast instead of stalling.
//
// The probe pins its socket to awg0 via SO_BINDTODEVICE so it ACTUALLY rides
// the tunnel. Without this pin, the kernel routes the dial through the native
// v6 default (eth3 WAN) and the probe lies "true" whenever native v6 is up —
// which is exactly when the user's tunnelled clients silently blackhole.
//
// Cached for 90 seconds — long enough to avoid hammering the probe each
// watchdog tick (which runs ~every minute), short enough that a transient
// outage at the VPS-side v6 SNAT layer propagates into a re-render of the
// leak-prevent rules within ~2 ticks.
func awgTunnelV6Reaches() bool {
	if !awgIfaceHasGlobalV6() {
		return false
	}
	awgV6ReachMu.Lock()
	defer awgV6ReachMu.Unlock()
	if time.Now().Before(awgV6ReachExpiry) {
		return awgV6ReachVal
	}
	d := net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// SO_BINDTODEVICE: pin the outbound socket to awg0 so the dial
				// actually rides the tunnel instead of leaking through native v6.
				opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, awgIface)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp6", "[2606:4700:4700::1111]:53") // Cloudflare DNS-over-TCP
	ok := err == nil
	if c != nil {
		_ = c.Close()
	}
	awgV6ReachVal = ok
	awgV6ReachExpiry = time.Now().Add(90 * time.Second)
	return ok
}

func awgDefaultRoute() (gw, dev string) {
	out, _ := awgRun("ip route show default")
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	return
}

// awgMarkCollision returns a non-empty fwmark string if some EXISTING ip rule
// uses a fwmark whose bits overlap ours (0x10000000) — which would let our
// higher-priority rule hijack that traffic, or the router's policy routing grab
// ours. The router's own marks (e.g. Keenetic's 0x0FFFFxxx) must not overlap.
func awgMarkCollision() string {
	out, _ := awgRun("ip rule")
	const ourBit = 0x10000000
	for _, ln := range strings.Split(out, "\n") {
		i := strings.Index(ln, "fwmark ")
		if i < 0 {
			continue
		}
		fields := strings.Fields(ln[i+len("fwmark "):])
		if len(fields) == 0 {
			continue
		}
		mark := fields[0]
		if j := strings.IndexByte(mark, '/'); j >= 0 {
			mark = mark[:j]
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(mark, "0x"), "0X"), 16, 64)
		if err != nil {
			continue
		}
		if v == ourBit {
			continue // our own rule from a prior run
		}
		if v&ourBit != 0 {
			return mark
		}
	}
	return ""
}

func hostOf(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return endpoint
}

func resolveHostIP(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	for _, ip := range resolveDomain(host) {
		return ip
	}
	return ""
}

// resolveDomain returns the IPv4 addresses for a domain (system resolver).
func resolveDomain(d string) []string {
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	ips, err := net.LookupIP(d)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

// isValidHostname rejects anything that isn't a plain DNS hostname: only
// letters/digits/dot/hyphen, max 253 chars, no leading/trailing separators.
// Required because resolveDomainAll forks `nslookup` with the user-supplied
// string and a stray ';' / '|' / '$' would otherwise smuggle a command into
// the shell. ponytail: regex over arg-vec because we already fork sh in the
// rest of the file; arg-vec would mean rewriting awgRun.
func isValidHostname(d string) bool {
	if d == "" || len(d) > 253 || d[0] == '.' || d[0] == '-' || d[len(d)-1] == '.' || d[len(d)-1] == '-' {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// resolveDomainAll returns both IPv4 and IPv6 addresses (raw String form), so the
// per-zone ipset builder can populate hash:net inet AND inet6 sets in one pass.
//
// Uses the system resolver via the busybox `nslookup` command (invoked directly
// via exec.Command — not through `sh -c` — to keep zone domain entries out of
// any shell-parse path) plus net.LookupIP as a second source. CGO_ENABLED=0
// binaries fall back to a pure-Go resolver that doesn't talk reliably to the
// router's ndnproxy on 127.0.0.1:53 (it returned empty for plain `.ru`
// hostnames in practice), so nslookup is what carries the truth.
func resolveDomainAll(d string) []string {
	d = strings.TrimSpace(d)
	if !isValidHostname(d) {
		return nil
	}
	var ips []string
	seen := map[string]struct{}{}
	ctx, cancel := contextTimeout(15 * time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "nslookup", d).CombinedOutput(); err == nil && len(out) > 0 {
		ips = appendNslookupIPs(ips, seen, string(out))
	}
	if goIPs, err := net.LookupIP(d); err == nil {
		for _, ip := range goIPs {
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			ips = append(ips, s)
		}
	}
	return ips
}

func appendNslookupIPs(ips []string, seen map[string]struct{}, out string) []string {
	for _, ln := range strings.Split(out, "\n") {
		// busybox nslookup format:
		//   Name:      2ip.ru
		//   Address 1: 188.40.167.82
		//   Address 2: 2a06:98c1:3120::5fe5:dffd
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "Address") {
			continue
		}
		colon := strings.IndexByte(ln, ':')
		if colon < 0 {
			continue
		}
		val := strings.TrimSpace(ln[colon+1:])
		// "Address 1: 127.0.0.1" — drop the server-line which always echoes the
		// resolver itself before the actual answer rows.
		if val == "127.0.0.1" || val == "::1" {
			continue
		}
		if ip := net.ParseIP(val); ip != nil {
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			ips = append(ips, s)
		}
	}
	return ips
}
