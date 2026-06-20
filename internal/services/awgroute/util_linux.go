//go:build linux

package awgroute

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Low-level helpers for the AWG2 split-routing OS layer: shell exec (with a
// timeout so no single command can hang the caller), default-route + fwmark
// inspection, and hostname → IPv4 resolution.

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
	if i := strings.LastIndex(endpoint, ":"); i > 0 {
		return endpoint[:i]
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

// resolveDomainAll returns both IPv4 and IPv6 addresses (raw String form), so the
// per-zone ipset builder can populate hash:net inet AND inet6 sets in one pass.
//
// Uses the system resolver via the busybox `nslookup` command instead of Go's
// net.LookupIP — CGO_ENABLED=0 binaries fall back to a pure-Go resolver that
// doesn't talk reliably to the router's ndnproxy on 127.0.0.1:53 (it returned
// empty for plain `.ru` hostnames in practice). nslookup goes through the libc
// resolver and matches what every other tool on the router uses.
func resolveDomainAll(d string) []string {
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	// nslookup is authoritative here because Go's pure resolver may return only
	// one family (IPv6-only on this router, despite the libc resolver giving
	// both), which leaves the IPv4 ipset empty and breaks bypass. nslookup goes
	// through the libc resolver via the router's ndnproxy and reliably returns
	// every A and AAAA answer.
	var ips []string
	seen := map[string]struct{}{}
	if out, _ := awgRun("nslookup " + d + " 2>/dev/null"); out != "" {
		ips = appendNslookupIPs(ips, seen, out)
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
