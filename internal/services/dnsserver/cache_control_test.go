package dnsserver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestCacheLifetimeValidation(t *testing.T) {
	if got := Default().CacheTTLSeconds; got != 3600 {
		t.Fatalf("default cache lifetime = %d, want 3600", got)
	}
	for _, seconds := range []int{-1, 0, 1, 3600, 86400, 86401} {
		cfg := Default()
		cfg.CacheTTLSeconds = seconds
		err := cfg.NormalizeValidate()
		valid := seconds >= 1 && seconds <= 86400
		if (err == nil) != valid {
			t.Errorf("lifetime %d: validation error %v, valid = %v", seconds, err, valid)
		}
	}
}

func TestCacheLifetimeUsesEarlierConfiguredOrUpstreamExpiry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		upstream   uint32
		lifetime   int
	}{
		{name: "configured limit", configured: 2, upstream: 60, lifetime: 2},
		{name: "earlier upstream TTL", configured: 60, upstream: 2, lifetime: 2},
		{name: "one day limit", configured: 86400, upstream: 100000, lifetime: 86400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
				calls.Add(1)
				return resolverAnswer(q, tc.upstream)
			})
			r.cfg.AWGFallback = "off"
			r.cfg.CacheSize = 8
			r.cfg.CacheTTLSeconds = tc.configured
			var seconds atomic.Int64
			base := time.Now()
			r.now = func() time.Time { return base.Add(time.Duration(seconds.Load()) * time.Second) }
			query := resolverWire(t, "cache-lifetime.example", 1, mdns.TypeA)
			if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Cached {
				t.Fatalf("initial query: %+v, %v", out, err)
			}
			seconds.Store(int64(tc.lifetime - 1))
			query = resolverWire(t, "cache-lifetime.example", 9, mdns.TypeA)
			answer, out, err := r.Resolve(context.Background(), query)
			if err != nil || !out.Cached || calls.Load() != 1 {
				t.Fatalf("query before expiry: %+v, %v, upstream calls %d", out, err, calls.Load())
			}
			var msg mdns.Msg
			if err := msg.Unpack(answer); err != nil || msg.Id != 9 || msg.Answer[0].Header().Ttl != tc.upstream-uint32(tc.lifetime-1) {
				t.Fatalf("cached answer changed upstream TTL or client ID: %v, %v", &msg, err)
			}
			seconds.Store(int64(tc.lifetime))
			if status := r.CacheStatus(); status.Entries != 0 || status.Capacity != 8 || status.TTLSeconds != tc.configured {
				t.Fatalf("expired cache status: %+v", status)
			}
			if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Cached || calls.Load() != 2 {
				t.Fatalf("query after expiry: %+v, %v, upstream calls %d", out, err, calls.Load())
			}
		})
	}
}

func TestCacheClearDoesNotRepopulateFromInflightQuery(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-time.After(2 * time.Second):
				t.Error("test did not release the inflight response")
			}
		}
		return resolverAnswer(q, 60)
	})
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	query := resolverWire(t, "clear-inflight.example", 42, mdns.TypeA)
	var oldQuestion mdns.Msg
	if err := oldQuestion.Unpack(resolverWire(t, "old.example", 0, mdns.TypeA)); err != nil {
		t.Fatal(err)
	}
	r.cachePut("old", resolverAnswer(&oldQuestion, 60), "nfqws", r.cfg.DefaultUpstream.Address, 0)
	r.endpoints["nfqws|dns.home.arpa"] = endpointEntry{ips: []string{"127.0.0.1"}, expires: time.Now().Add(time.Hour)}
	scheduler := r.scheduler
	type result struct {
		answer []byte
		out    Outcome
		err    error
	}
	done := make(chan result, 1)
	go func() {
		answer, out, err := r.Resolve(context.Background(), query)
		done <- result{answer: answer, out: out, err: err}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream query did not start")
	}
	if removed := r.ClearCache(); removed != 1 {
		t.Fatalf("clear removed %d answers, want 1", removed)
	}
	unblock()
	select {
	case result := <-done:
		var answer mdns.Msg
		if result.err != nil || result.out.Cached || answer.Unpack(result.answer) != nil || answer.Id != 42 {
			t.Fatalf("clearing disrupted inflight client reply: %+v, %v", result.out, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inflight request did not finish")
	}
	if status := r.CacheStatus(); status.Entries != 0 {
		t.Fatalf("pre-clear request repopulated cache: %+v", status)
	}
	if r.scheduler != scheduler || len(r.endpoints) != 1 || r.lifetime.Err() != nil {
		t.Fatal("clearing reset scheduler, bootstrap cache or resolver lifetime")
	}
	if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Cached || calls.Load() != 2 {
		t.Fatalf("first query after clear did not fetch a fresh response: %+v, %v, calls %d", out, err, calls.Load())
	}
	if _, out, err := r.Resolve(context.Background(), query); err != nil || !out.Cached || calls.Load() != 2 {
		t.Fatalf("new cache generation could not cache: %+v, %v, calls %d", out, err, calls.Load())
	}
	if got := r.SchedulerSnapshot("clear-inflight.example").Candidates[0]; got.Successes != 2 {
		t.Fatalf("clear lost scheduler observations: %+v", got)
	}
}

func TestCacheStatusExpiresAnswersAndRetainsCapacity(t *testing.T) {
	cfg := Default()
	cfg.CacheSize = 2
	r := NewResolver(cfg, &resolverTestBackend{})
	t.Cleanup(r.Close)
	now := time.Now()
	r.now = func() time.Time { return now }
	put := func(key string, ttl uint32) {
		q := new(mdns.Msg)
		q.SetQuestion(key+".example.", mdns.TypeA)
		r.cachePut(key, resolverAnswer(q, ttl), "nfqws", cfg.DefaultUpstream.Address, r.cacheGeneration)
	}
	put("short", 1)
	put("long", 60)
	now = now.Add(time.Second)
	if got := r.CacheStatus(); got != (CacheStatus{Entries: 1, Capacity: 2, TTLSeconds: 3600}) {
		t.Fatalf("expired entry counted in status: %+v", got)
	}
	put("new", 50)
	put("long", 60)
	if got := r.CacheStatus(); got.Entries != 2 {
		t.Fatalf("replacing a cached answer evicted another entry: %+v", got)
	}
	if _, ok := r.cache["new"]; !ok {
		t.Fatal("replacing an existing answer evicted unrelated new answer")
	}
	put("third", 80)
	if got := r.CacheStatus(); got.Entries != 2 {
		t.Fatalf("cache capacity exceeded: %+v", got)
	}
	if _, ok := r.cache["new"]; ok {
		t.Fatal("capacity eviction did not choose earliest expiry")
	}
	now = now.Add(80 * time.Second)
	if got := r.CacheStatus(); got.Entries != 0 {
		t.Fatalf("cache status retained expired answers: %+v", got)
	}
	if removed := r.ClearCache(); removed != 0 {
		t.Fatalf("empty cache clear removed %d entries", removed)
	}
}

func TestCacheLifetimeDoesNotCacheZeroTTLOrNegativeAnswers(t *testing.T) {
	for _, kind := range []string{"zero answer TTL", "zero additional TTL", "NXDOMAIN", "NODATA"} {
		t.Run(kind, func(t *testing.T) {
			cfg := Default()
			r := NewResolver(cfg, &resolverTestBackend{})
			t.Cleanup(r.Close)
			q := new(mdns.Msg)
			q.SetQuestion("uncached.example.", mdns.TypeA)
			msg := resolverAnswer(q, 60)
			switch kind {
			case "zero answer TTL":
				msg.Answer[0].Header().Ttl = 0
			case "zero additional TTL":
				msg.Extra = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: "uncached.example.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 0}, Txt: []string{"metadata"}}}
			case "NXDOMAIN":
				msg.Rcode = mdns.RcodeNameError
				msg.Answer = nil
			case "NODATA":
				msg.Answer = nil
			}
			r.cachePut("uncached", msg, "nfqws", cfg.DefaultUpstream.Address, 0)
			if got := r.CacheStatus(); got.Entries != 0 {
				t.Fatalf("stored an answer that must remain uncached: %+v", got)
			}
		})
	}
}

func TestCacheLifetimeUsesShortestRecordTTLIgnoringOPT(t *testing.T) {
	cfg := Default()
	cfg.CacheTTLSeconds = 60
	r := NewResolver(cfg, &resolverTestBackend{})
	t.Cleanup(r.Close)
	now := time.Now()
	r.now = func() time.Time { return now }
	q := new(mdns.Msg)
	q.SetQuestion("shortest.example.", mdns.TypeA)
	msg := resolverAnswer(q, 60)
	msg.Ns = []mdns.RR{&mdns.NS{Hdr: mdns.RR_Header{Name: "example.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 2}, Ns: "ns.example."}}
	msg.SetEdns0(1232, false)
	r.cachePut("shortest", msg, "nfqws", cfg.DefaultUpstream.Address, 0)
	if got := r.CacheStatus(); got.Entries != 1 {
		t.Fatalf("OPT pseudo-TTL prevented caching: %+v", got)
	}
	now = now.Add(2 * time.Second)
	if got := r.CacheStatus(); got.Entries != 0 {
		t.Fatalf("cache outlived an authority record TTL: %+v", got)
	}
}

func TestCacheConcurrentClearAndResolve(t *testing.T) {
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 2
	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			query := resolverWire(t, fmt.Sprintf("worker-%d.example", worker), uint16(worker+1), mdns.TypeA)
			for i := 0; i < 6; i++ {
				if i%2 == 0 {
					r.ClearCache()
				}
				if _, _, err := r.Resolve(context.Background(), query); err != nil {
					t.Errorf("concurrent cache query failed: %v", err)
					return
				}
				if status := r.CacheStatus(); status.Entries > status.Capacity {
					t.Errorf("concurrent inserts exceeded cache capacity: %+v", status)
				}
			}
		}(worker)
	}
	wg.Wait()
	r.ClearCache()
	if got := r.CacheStatus(); got.Entries != 0 {
		t.Fatalf("completed requests left entries after clear: %+v", got)
	}
}
