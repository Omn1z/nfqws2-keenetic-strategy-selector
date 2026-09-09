package dnsserver

import (
	"context"
	"time"

	mdns "github.com/miekg/dns"
)

// StartMaintenance is called only after routes and listeners are ready. It
// never waits on warm-up or probes before accepting a client DNS request.
func (r *Resolver) StartMaintenance() {
	r.maintenanceOnce.Do(func() {
		if r.fastDNS != nil {
			r.fastDNS.Start()
		}
		go func() {
			ticker := time.NewTicker(schedulerProbeInterval)
			defer ticker.Stop()
			for {
				select {
				case <-r.lifetime.Done():
					return
				case <-ticker.C:
					r.runSchedulerProbe()
				}
			}
		}()
	})
}

func (r *Resolver) runSchedulerProbe() {
	if r.lifetime.Err() != nil {
		return
	}
	// A background measurement occupies one ordinary attempt slot and never
	// queues ahead of user traffic when all slots are already occupied.
	select {
	case r.attempts <- struct{}{}:
	default:
		return
	}
	defer func() { <-r.attempts }()
	if r.lifetime.Err() != nil {
		return
	}
	r.mu.Lock()
	scheduler, observer := r.scheduler, r.observer
	r.mu.Unlock()
	probe, ok := scheduler.nextProbe(r.cfg, r.backend.Routes())
	if !ok {
		return
	}
	started := time.Now()
	event := AttemptEvent{Domain: probe.domain, Type: mdns.TypeToString[probe.qtype], Route: probe.route.ID, RouteName: probe.route.Name, Upstream: probe.upstream.Address, Canceled: true}
	defer func() {
		scheduler.finishProbe(probe, event)
		if observer != nil && !event.Success && !event.Canceled {
			event.Error = "Фоновая проверка: " + event.Error
			observer(event)
		}
	}()
	ctx, cancel := context.WithTimeout(r.lifetime, time.Duration(r.cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(probe.domain), probe.qtype)
	query.Id = 0
	wire, err := query.Pack()
	if err == nil {
		_, err = r.exchangeEndpoint(ctx, probe.route.ID, probe.upstream, wire, query)
	}
	event.DurationMS = time.Since(started).Milliseconds()
	event.Success = err == nil
	event.Canceled = err != nil && r.lifetime.Err() != nil
	if err != nil && !event.Canceled {
		event.Error = err.Error()
	}
	// Probe replies never become client answers or train domain/IP routing.
}
