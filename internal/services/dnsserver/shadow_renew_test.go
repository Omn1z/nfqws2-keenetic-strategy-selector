package dnsserver

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

type shadowRenewTestBackend struct {
	resolverTestBackend
	available bool
	calls     atomic.Int32
	renew     func(context.Context) (dnsroute.ShadowRenewalResult, error)
}

func (b *shadowRenewTestBackend) ShadowRenewalAvailable() bool { return b.available }
func (b *shadowRenewTestBackend) RenewShadowDNS(ctx context.Context) (dnsroute.ShadowRenewalResult, error) {
	b.calls.Add(1)
	return b.renew(ctx)
}

func shadowRenewServiceFixture(t *testing.T) (*Service, *shadowRenewTestBackend) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &shadowRenewTestBackend{available: true}
	b.renew = func(context.Context) (dnsroute.ShadowRenewalResult, error) {
		return dnsroute.ShadowRenewalResult{Status: "resolved", Servers: []string{"192.0.2.53:53"}, Message: "DNS получены"}, nil
	}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	s.cfg.Enabled = true
	s.cfg.FastDNS = false
	s.cfg.ShadowDNS = &ShadowDNSConfig{Enabled: true, Domains: []ShadowDomain{{Domain: "ru", IncludeSubdomains: true}}}
	r := NewResolver(s.cfg, b)
	r.shadowStatus.Error = "previous timeout"
	s.active = &serviceRun{resolver: r}
	t.Cleanup(r.Close)
	return s, b
}

func TestShadowRenewServiceRequiresConfirmationAndActiveFeature(t *testing.T) {
	for _, reason := range []string{"unconfirmed", "disabled", "shadow off", "no run", "unsupported", "cancelled", "closed resolver"} {
		t.Run(reason, func(t *testing.T) {
			s, b := shadowRenewServiceFixture(t)
			confirmed := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch reason {
			case "unconfirmed":
				confirmed = false
			case "disabled":
				s.cfg.Enabled = false
			case "shadow off":
				s.cfg.ShadowDNS.Enabled = false
			case "no run":
				s.active = nil
			case "unsupported":
				b.available = false
			case "cancelled":
				cancel()
			case "closed resolver":
				s.active.resolver.Close()
			}
			if _, err := s.RenewShadowDNS(ctx, confirmed); err == nil {
				t.Fatal("action accepted", reason)
			}
			if b.calls.Load() != 0 {
				t.Fatal("rejected request reached mutation")
			}
		})
	}
}

func TestShadowRenewServiceUpdatesStatusWithoutChangingConfig(t *testing.T) {
	for _, status := range []string{"resolved", "waiting", "no_dns", "nak"} {
		t.Run(status, func(t *testing.T) {
			s, b := shadowRenewServiceFixture(t)
			before := s.Config()
			result := dnsroute.ShadowRenewalResult{Status: status, Message: "explicit result"}
			if status == "resolved" {
				result.Servers = []string{"192.0.2.53:53"}
			}
			b.renew = func(ctx context.Context) (dnsroute.ShadowRenewalResult, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 18*time.Second {
					t.Fatal("unbounded action")
				}
				return result, nil
			}
			if _, err := s.RenewShadowDNS(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			state := s.Status().ShadowDNS
			if !state.RenewalAvailable || len(state.Servers) != len(result.Servers) {
				t.Fatal(state)
			}
			if status == "resolved" && state.Error != "" || status != "resolved" && state.Error != result.Message {
				t.Fatal("old status not replaced", state)
			}
			if !reflect.DeepEqual(before, s.Config()) {
				t.Fatal("renew altered user config")
			}
			if b.calls.Load() != 1 {
				t.Fatal("status triggered renewal")
			}
			if len(result.Servers) > 0 {
				result.Servers[0] = "changed"
				if s.Status().ShadowDNS.Servers[0] == "changed" {
					t.Fatal("status aliases backend result")
				}
			}
		})
	}
}

func TestShadowRenewServiceErrorPreservesPriorStateAndCancelsOnStop(t *testing.T) {
	s, b := shadowRenewServiceFixture(t)
	prior := s.active.resolver.ShadowStatus()
	b.renew = func(context.Context) (dnsroute.ShadowRenewalResult, error) {
		return dnsroute.ShadowRenewalResult{}, errors.New("cooldown")
	}
	if _, err := s.RenewShadowDNS(context.Background(), true); err == nil {
		t.Fatal("lost error")
	}
	if !reflect.DeepEqual(prior, s.active.resolver.ShadowStatus()) {
		t.Fatal("preflight failure overwrote DNS state")
	}
	entered := make(chan struct{})
	b.renew = func(ctx context.Context) (dnsroute.ShadowRenewalResult, error) {
		close(entered)
		<-ctx.Done()
		return dnsroute.ShadowRenewalResult{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { _, err := s.RenewShadowDNS(context.Background(), true); done <- err }()
	<-entered
	s.active.resolver.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stopped resolver left renewal waiting")
	}
}

func TestShadowRenewServiceDoesNotUpdateReplacementResolver(t *testing.T) {
	s, b := shadowRenewServiceFixture(t)
	old := s.active.resolver
	b.renew = func(context.Context) (dnsroute.ShadowRenewalResult, error) {
		s.mu.Lock()
		r := NewResolver(s.cfg, b)
		t.Cleanup(r.Close)
		s.active = &serviceRun{resolver: r}
		s.mu.Unlock()
		return dnsroute.ShadowRenewalResult{Status: "resolved", Servers: []string{"192.0.2.53:53"}}, nil
	}
	if _, err := s.RenewShadowDNS(context.Background(), true); err == nil {
		t.Fatal("replacement not detected")
	}
	if len(s.active.resolver.ShadowStatus().Servers) != 0 || old.ShadowStatus().Error != "previous timeout" {
		t.Fatal("result applied to replaced resolver")
	}
}
