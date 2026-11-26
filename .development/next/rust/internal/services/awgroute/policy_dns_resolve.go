package awgroute

import (
	"context"
	"net"
	"time"
)

const policyDNSLookupTimeout = 15 * time.Second

type policyDNSNativeReader func(context.Context, string) []string
type policyDNSGoReader func(context.Context, string, string) ([]net.IP, error)

// Both resolver implementations share one deadline. Query the Go fallback
// only for a family that the native reader did not return, so a complete
// nslookup reply does not produce a second A/AAAA lookup for the same name.
func policyResolveDomainAll(ctx context.Context, name string, native policyDNSNativeReader, lookup policyDNSGoReader) []string {
	if ctx.Err() != nil {
		return nil
	}
	var ips []string
	seen := make(map[string]bool)
	has4, has6 := false, false
	add := func(raw string) {
		ip := net.ParseIP(raw)
		if ip == nil {
			return
		}
		key := ip.String()
		if !seen[key] {
			ips = append(ips, key)
			seen[key] = true
		}
		if ip.To4() != nil {
			has4 = true
		} else {
			has6 = true
		}
	}
	if native != nil {
		for _, raw := range native(ctx, name) {
			add(raw)
		}
	}
	if ctx.Err() != nil || lookup == nil || has4 && has6 {
		return ips
	}
	network := "ip"
	if has4 {
		network = "ip6"
	} else if has6 {
		network = "ip4"
	}
	if result, err := lookup(ctx, network, name); err == nil {
		for _, ip := range result {
			add(ip.String())
		}
	}
	return ips
}
