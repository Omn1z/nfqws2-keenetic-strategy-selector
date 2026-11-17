package awgroute

import (
	"context"
	"net"
	"sync"

	"nfqws2strategy/internal/services/awg"
)

// The pool is already bounded in configuration. Keep the worker count bounded
// here too, and use a cache-only resolver: an ICMP hint never delays recovery
// behind a new hostname lookup or discards a candidate with no reply.
func parallelEndpointHints(ctx context.Context, pool []string, cachedIP func(string) string, probe func(context.Context, string) bool) map[string]bool {
	result := map[string]bool{}
	var mu sync.Mutex
	var workers sync.WaitGroup
	if len(pool) > awg.MaxEndpointBackups+1 {
		pool = pool[:awg.MaxEndpointBackups+1]
	}
	for _, endpoint := range pool {
		host, _ := endpointParts(endpoint)
		ip := net.ParseIP(host)
		if ip == nil {
			ip = net.ParseIP(cachedIP(host))
		}
		if ip == nil {
			continue
		}
		workers.Add(1)
		go func(endpoint, ip string) {
			defer workers.Done()
			if ctx.Err() == nil && probe(ctx, ip) {
				mu.Lock()
				result[endpoint] = true
				mu.Unlock()
			}
		}(endpoint, ip.String())
	}
	workers.Wait()
	return result
}
