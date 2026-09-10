package awgroute

import (
	"net"
	"strings"
	"time"
)

const policyDNSCacheLimit = 4096

type policyDNSAnswer struct {
	ips     []string
	expires time.Time
}

func (svc *Service) rememberPolicyDNS(name string, ips []string) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return
	}
	valid := make([]string, 0, len(ips))
	for _, raw := range ips {
		if ip := net.ParseIP(raw); ip != nil {
			valid = append(valid, ip.String())
		}
	}
	if len(valid) > 0 {
		svc.policyDNSMu.Lock()
		defer svc.policyDNSMu.Unlock()
		if svc.policyDNS == nil {
			svc.policyDNS = make(map[string]policyDNSAnswer)
		}
		if _, exists := svc.policyDNS[name]; !exists && len(svc.policyDNS) >= policyDNSCacheLimit {
			// Bounded router memory; dropping one cached hint never removes the
			// live ipset entry, and the DNS learner can refill it on demand.
			for key := range svc.policyDNS {
				delete(svc.policyDNS, key)
				break
			}
		}
		svc.policyDNS[name] = policyDNSAnswer{ips: valid, expires: time.Now().Add(20 * time.Minute)}
	}
}

// Live resolution is reserved for explicit apply. Recovery and periodic route
// refresh must only use cached replies: waiting on one DNS request per domain
// while owning the lifecycle mutex blocks startup, down, and engine repair.
func (svc *Service) policyDNSLookup(resolve bool, live func(string) []string) func(string) []string {
	return func(name string) []string {
		key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if resolve {
			ips := live(name)
			svc.rememberPolicyDNS(key, ips)
			return ips
		}
		svc.policyDNSMu.Lock()
		defer svc.policyDNSMu.Unlock()
		if cached, ok := svc.policyDNS[key]; ok {
			if time.Now().Before(cached.expires) {
				return append([]string(nil), cached.ips...)
			}
			delete(svc.policyDNS, key)
		}
		return nil
	}
}

func (svc *Service) cachedPolicyHostIP(host string) string {
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil && ip.To4() != nil {
		return ip.To4().String()
	}
	for _, raw := range svc.policyDNSLookup(false, nil)(host) {
		if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return ""
}
