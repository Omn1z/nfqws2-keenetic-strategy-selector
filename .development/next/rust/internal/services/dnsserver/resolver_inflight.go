package dnsserver

import (
	"context"
	"fmt"
	"time"

	mdns "github.com/miekg/dns"
)

const maxResolverFlights = 128
const maxResolverFlightWaiters = 512

type resolverFlightKey struct {
	query      string
	generation uint64
}

type resolverFlight struct {
	done        chan struct{}
	cancel      context.CancelFunc
	waiters     int
	finished    bool
	response    *mdns.Msg
	out         Outcome
	err         error
	completedAt time.Time
}

// One shared operation belongs to its active callers, not to the first caller's
// context. It ends when the last waiter leaves or the resolver closes. Bounds
// never reject ordinary traffic: excess unique requests use the existing race.
func (r *Resolver) resolveShared(ctx context.Context, key string, generation uint64, query *mdns.Msg, wire []byte, domain string) (*mdns.Msg, Outcome, error) {
	pool, _ := r.cfg.upstreamsFor(domain)
	out := Outcome{Domain: domain, Upstream: pool[0].Address}
	if r.shadow.matches(domain) {
		out.Route, out.Upstream = shadowRoute, ""
	}
	r.mu.Lock()
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		out.Error = err.Error()
		return nil, out, err
	}
	if r.closed {
		r.mu.Unlock()
		err := fmt.Errorf("DNS-сервер остановлен: %w", r.lifetime.Err())
		out.Error = err.Error()
		return nil, out, err
	}
	// A preceding miss may have completed while this caller packed its key.
	// Recheck under the same mutex used to create the shared operation.
	if entry, ok := r.cache[key]; ok && generation == r.cacheGeneration && r.now().Before(entry.expires) {
		now := r.now()
		r.mu.Unlock()
		out.Cached, out.Route, out.Upstream = true, entry.route, entry.upstream
		response := entry.msg.Copy()
		dnsAgeMessage(response, now.Sub(entry.created))
		return response, out, nil
	}
	flightKey := resolverFlightKey{key, generation}
	flight := r.inflight[flightKey]
	shared := flight != nil
	if len(key) > 4096 || flight == nil && len(r.inflight) >= maxResolverFlights || flight != nil && flight.waiters >= maxResolverFlightWaiters {
		r.mu.Unlock()
		response, out, err := r.resolveUncached(ctx, query, wire, domain)
		if err == nil {
			dnsClipNegativeSOA(response)
			filterOutcome := out
			if !r.filterResponse(query, response, &filterOutcome) {
				r.cachePut(key, response, out.Route, out.Upstream, generation)
			}
		}
		return response, out, err
	}
	if flight == nil {
		if r.inflight == nil {
			r.inflight = map[resolverFlightKey]*resolverFlight{}
		}
		// Keep diagnostic attribution of the initiating caller, but never its
		// cancellation/deadline: the shared operation belongs to all waiters.
		operation, cancel := context.WithCancel(withRequestOrigin(r.lifetime, requestOriginFromContext(ctx)))
		flight = &resolverFlight{done: make(chan struct{}), cancel: cancel}
		r.inflight[flightKey] = flight
		go r.runResolverFlight(operation, flightKey, flight, query, wire, domain)
	}
	flight.waiters++
	r.mu.Unlock()
	defer r.releaseResolverFlight(flightKey, flight)
	out.Shared = shared
	select {
	case <-ctx.Done():
		out.Error = ctx.Err().Error()
		return nil, out, ctx.Err()
	case <-r.lifetime.Done():
		err := fmt.Errorf("DNS-сервер остановлен: %w", r.lifetime.Err())
		out.Error = err.Error()
		return nil, out, err
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			out.Error = err.Error()
			return nil, out, err
		}
		out = flight.out
		out.Shared = shared
		if flight.err != nil {
			return nil, out, flight.err
		}
		response := flight.response.Copy()
		dnsAgeMessage(response, r.now().Sub(flight.completedAt))
		return response, out, nil
	}
}

func (r *Resolver) runResolverFlight(ctx context.Context, key resolverFlightKey, flight *resolverFlight, query *mdns.Msg, wire []byte, domain string) {
	defer flight.cancel()
	response, out, err := r.resolveUncached(ctx, query, wire, domain)
	completedAt := r.now()
	if err == nil {
		dnsClipNegativeSOA(response)
		filterOutcome := out
		if ctx.Err() == nil && !r.filterResponse(query, response, &filterOutcome) {
			r.cachePutAt(key.query, response, out.Route, out.Upstream, key.generation, completedAt)
		}
	}
	r.mu.Lock()
	flight.response, flight.out, flight.err, flight.completedAt = response, out, err, completedAt
	flight.finished = true
	if r.inflight[key] == flight {
		delete(r.inflight, key)
	}
	close(flight.done)
	r.mu.Unlock()
}

func (r *Resolver) releaseResolverFlight(key resolverFlightKey, flight *resolverFlight) {
	r.mu.Lock()
	defer r.mu.Unlock()
	flight.waiters--
	if flight.waiters == 0 && !flight.finished {
		if r.inflight[key] == flight {
			delete(r.inflight, key)
		}
		flight.cancel()
	}
}
