package awgroute

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// routingDNSGate gives each immutable learner snapshot a policy generation.
// An apply waits for in-flight learning before replacing sets and firewall
// state. New answers wait for the completed apply, and an obsolete snapshot
// returns a retryable DNS error instead of writing into a reused set name.
type routingDNSGate struct {
	mu         sync.Mutex
	changed    chan struct{}
	generation uint64
	applying   bool
	readers    int
	err        error
	writeEpoch uint64
	learnToken chan struct{}
	learned    map[string]time.Time
}

// RoutingDNSReadiness contains lifecycle state and installation diagnostics,
// never private keys or proxy credentials. Revision changes on policy edits,
// not on routine firewall re-assertions.
type RoutingDNSReadiness struct {
	Revision uint64 `json:"revision"`
	Applying bool   `json:"applying"`
	Ready    bool   `json:"ready"`
	Error    string `json:"error,omitempty"`
}

func (svc *Service) RoutingDNSReadiness() RoutingDNSReadiness {
	g := &svc.routingDNSGate
	g.mu.Lock()
	defer g.mu.Unlock()
	state := RoutingDNSReadiness{Revision: g.generation, Applying: g.applying, Ready: !g.applying && g.err == nil}
	if g.err != nil {
		state.Error = g.err.Error()
	}
	return state
}

func (g *routingDNSGate) signalLocked() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

// begin is called by serialized routing lifecycle operations. revise=false
// protects a periodic re-assertion without invalidating an unchanged learner.
func (g *routingDNSGate) begin(revise bool) func(error) {
	g.mu.Lock()
	for g.applying {
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		<-changed
		g.mu.Lock()
	}
	g.applying = true
	g.writeEpoch++ // Even a same-version restore can recreate/flush kernel sets.
	g.learned = nil
	if revise {
		g.generation++
	}
	g.signalLocked()
	for g.readers > 0 {
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		<-changed
		g.mu.Lock()
	}
	g.mu.Unlock()
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			g.mu.Lock()
			g.err, g.applying = err, false
			g.signalLocked()
			g.mu.Unlock()
		})
	}
}

func (g *routingDNSGate) version() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generation
}

func (g *routingDNSGate) failed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err != nil
}

func (g *routingDNSGate) verify(expected uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.applying || expected != g.generation {
		return fmt.Errorf("DNS routing policy changed; retry the query")
	}
	if g.err != nil {
		return fmt.Errorf("DNS routing policy is not ready: %w", g.err)
	}
	return nil
}

func (g *routingDNSGate) acquire(ctx context.Context, expected uint64, checkVersion bool) (func(), error) {
	g.mu.Lock()
	for {
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			return nil, err
		}
		if checkVersion && expected != g.generation {
			g.mu.Unlock()
			return nil, fmt.Errorf("DNS routing policy changed; retry the query")
		}
		if !g.applying {
			break
		}
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		g.mu.Lock()
	}
	if g.err != nil {
		err := fmt.Errorf("DNS routing policy is not ready: %w", g.err)
		g.mu.Unlock()
		return nil, err
	}
	g.readers++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.readers--
			g.signalLocked()
			g.mu.Unlock()
		})
	}, nil
}
