//go:build linux

package app

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
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
