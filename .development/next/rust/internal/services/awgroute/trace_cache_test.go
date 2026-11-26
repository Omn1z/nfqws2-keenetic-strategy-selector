package awgroute

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTraceCacheBoundsDistinctDestinationsAndKeepsRefreshedHost(t *testing.T) {
	var cache traceTTLCache
	now := time.Unix(1_700_000_000, 0)
	for i := range traceCacheCapacity {
		cache.store(fmt.Sprint(i), "old.example", now, traceHostTTL)
	}
	cache.store("0", "new.example", now.Add(time.Second), traceHostTTL)
	cache.store("overflow", "overflow.example", now.Add(2*time.Second), traceHostTTL)
	if len(cache.entries) != traceCacheCapacity || cache.order.Len() != traceCacheCapacity {
		t.Fatalf("cache exceeded its bound: entries=%d order=%d", len(cache.entries), cache.order.Len())
	}
	if _, ok := cache.load("1", now.Add(2*time.Second)); ok {
		t.Fatal("oldest unrefreshed destination survived overflow")
	}
	if host, ok := cache.load("0", now.Add(2*time.Second)); !ok || host != "new.example" {
		t.Fatal("refreshing an observed host did not preserve its latest name")
	}
}

func TestTraceCacheSweepsExpiredDestinationsWithoutRevisitingThem(t *testing.T) {
	var cache traceTTLCache
	now := time.Unix(1_700_000_000, 0)
	for i := range 100 {
		cache.store(fmt.Sprint(i), "expired.example", now, traceHostTTL)
	}
	later := now.Add(traceHostTTL)
	cache.store("new", "current.example", later, traceHostTTL)
	if len(cache.entries) != 1 || cache.order.Len() != 1 {
		t.Fatalf("expired destinations remain retained: entries=%d order=%d", len(cache.entries), cache.order.Len())
	}
	if host, ok := cache.load("new", later); !ok || host != "current.example" {
		t.Fatal("sweep discarded the new observation")
	}
}

func TestTraceCacheEnforcesMixedPTRTimeoutsBetweenSweeps(t *testing.T) {
	var cache traceTTLCache
	now := time.Unix(1_700_000_000, 0)
	cache.store("failed-ptr", "", now, 10*time.Minute)
	cache.store("busy-ptr", "", now, time.Second)
	if _, ok := cache.load("busy-ptr", now.Add(time.Second)); ok {
		t.Fatal("expired busy-PTR backoff survived until the next sweep")
	}
	if _, ok := cache.load("failed-ptr", now.Add(time.Second)); !ok {
		t.Fatal("short backoff expiry discarded an unrelated longer backoff")
	}
	if len(cache.entries) != 1 || cache.order.Len() != 1 {
		t.Fatal("expired backoff retained its map or order entry")
	}
}

func TestTraceCacheConcurrentObservationAndLookup(t *testing.T) {
	var cache traceTTLCache
	now := time.Unix(1_700_000_000, 0)
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range 1500 {
				key := fmt.Sprintf("%d/%d", worker, i)
				cache.store(key, "host.example", now, traceHostTTL)
				cache.load(key, now)
			}
		}()
	}
	workers.Wait()
	if len(cache.entries) > traceCacheCapacity || len(cache.entries) != cache.order.Len() {
		t.Fatalf("concurrent access broke bounds: entries=%d order=%d", len(cache.entries), cache.order.Len())
	}
	cache.load("never-seen", now.Add(traceHostTTL))
	if len(cache.entries) != 0 || cache.order.Len() != 0 {
		t.Fatal("lookup did not reclaim expired observations of other destinations")
	}
}

func TestTraceAppendObservesHostWhileRecordingIsDisabled(t *testing.T) {
	previous := traceEnabled()
	traceSetEnabled(false)
	defer traceSetEnabled(previous)
	const ip = "192.0.2.211"
	defer func() {
		traceHostCache.mu.Lock()
		traceHostCache.removeLocked(ip)
		traceHostCache.mu.Unlock()
	}()
	traceAppend(TraceEntry{Kind: "dns", Dst: ip, Name: "Observed.Example."})
	if host := traceHostForIP(ip); host != "observed.example" {
		t.Fatalf("host observation requires trace recording: %q", host)
	}
}
