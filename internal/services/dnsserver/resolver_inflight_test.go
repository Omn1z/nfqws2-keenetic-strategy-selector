package dnsserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func awaitResolverFlightWaiters(t *testing.T, r *Resolver, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		waiters := 0
		for _, flight := range r.inflight {
			waiters += flight.waiters
		}
		r.mu.Unlock()
		if waiters == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("inflight waiter count did not reach %d", want)
}

type resolverFlightTestResult struct {
	wire []byte
	out  Outcome
	err  error
}

func startResolverFlightTest(r *Resolver, ctx context.Context, wire []byte) <-chan resolverFlightTestResult {
	done := make(chan resolverFlightTestResult, 1)
	go func() { wire, out, err := r.Resolve(ctx, wire); done <- resolverFlightTestResult{wire, out, err} }()
	return done
}

func resolverFlightTestReceive(t *testing.T, done <-chan resolverFlightTestResult) resolverFlightTestResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("DNS caller did not finish")
		return resolverFlightTestResult{}
	}
}

func TestResolverInflightBurstSharesOneNetworkAnswerAndClientQuestions(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		return resolverAnswer(q, 60)
	})
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	results := []<-chan resolverFlightTestResult{startResolverFlightTest(r, context.Background(), resolverWire(t, "BurSt.example", 1, mdns.TypeA))}
	awaitResolverSignal(t, started, "first upstream query")
	for i := 1; i < 8; i++ {
		name := "burst.example"
		if i%2 == 0 {
			name = "BURST.EXAMPLE"
		}
		results = append(results, startResolverFlightTest(r, context.Background(), resolverWire(t, name, uint16(i+1), mdns.TypeA)))
	}
	awaitResolverFlightWaiters(t, r, 8)
	unblock()
	shared := 0
	for i, done := range results {
		result := resolverFlightTestReceive(t, done)
		var msg mdns.Msg
		if result.err != nil || result.out.Cached || msg.Unpack(result.wire) != nil || msg.Id != uint16(i+1) {
			t.Fatal("shared answer failed", i, result.out, result.err)
		}
		name := "burst.example"
		if i == 0 {
			name = "BurSt.example"
		} else if i%2 == 0 {
			name = "BURST.EXAMPLE"
		}
		if msg.Question[0].Name != mdns.Fqdn(name) {
			t.Fatal("shared result overwrote current question", i, msg.Question)
		}
		if result.out.Shared {
			shared++
		}
	}
	if shared != 7 || calls.Load() != 1 {
		t.Fatalf("burst not coalesced: shared=%d network=%d", shared, calls.Load())
	}
	if _, out, err := r.Resolve(context.Background(), resolverWire(t, "burst.example", 99, mdns.TypeA)); err != nil || !out.Cached || out.Shared || calls.Load() != 1 {
		t.Fatal("later TTL cache hit incorrectly labeled shared", out, err)
	}
}

func TestResolverInflightLeaderCancellationKeepsFollowerAlive(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { calls.Add(1); close(started); <-release; return resolverAnswer(q, 60) })
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	attempts := make(chan AttemptEvent, 1)
	r.SetAttemptObserver(func(event AttemptEvent) { attempts <- event })
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	leaderCtx, cancel := context.WithCancel(withListenerOrigin(context.Background(), "192.168.3.40:52345", "192.168.3.1", "udp"))
	defer cancel()
	leader := startResolverFlightTest(r, leaderCtx, resolverWire(t, "cancel-leader.example", 1, mdns.TypeA))
	awaitResolverSignal(t, started, "network leader")
	follower := startResolverFlightTest(r, context.Background(), resolverWire(t, "cancel-leader.example", 2, mdns.TypeA))
	awaitResolverFlightWaiters(t, r, 2)
	cancel()
	if result := resolverFlightTestReceive(t, leader); !errors.Is(result.err, context.Canceled) {
		t.Fatal("canceled leader remained waiting", result.err)
	}
	awaitResolverFlightWaiters(t, r, 1)
	unblock()
	result := resolverFlightTestReceive(t, follower)
	if result.err != nil || !result.out.Shared || calls.Load() != 1 {
		t.Fatal("leader canceled another client's operation", result.out, result.err, calls.Load())
	}
	select {
	case attempt := <-attempts:
		if attempt.ClientIP != "192.168.3.40" || attempt.Source != "client" || attempt.Transport != "udp" || !attempt.Success || attempt.Canceled {
			t.Fatalf("shared operation lost initiating origin or inherited its cancellation: %+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("shared operation never published its network attempt")
	}
}

func TestResolverInflightFollowerCancellationAndAllWaitersCancel(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "follower only", true: "all callers"}[all], func(t *testing.T) {
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
			r.cfg.AWGFallback = "off"
			r.cfg.CacheSize = 8
			closeResolverFixtureIdle(r)
			b.mu.Lock()
			target := b.address
			b.dialHook = func(ctx context.Context, _, network, _ string) (net.Conn, error) {
				once.Do(func() { close(started) })
				select {
				case <-release:
					return (&net.Dialer{}).DialContext(ctx, network, target)
				case <-ctx.Done():
					close(canceled)
					return nil, ctx.Err()
				}
			}
			b.mu.Unlock()
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			leaderCtx, stopLeader := context.WithCancel(context.Background())
			defer stopLeader()
			followerCtx, stopFollower := context.WithCancel(context.Background())
			defer stopFollower()
			leader := startResolverFlightTest(r, leaderCtx, resolverWire(t, "cancel-followers.example", 1, mdns.TypeA))
			awaitResolverSignal(t, started, "blocked dial")
			follower := startResolverFlightTest(r, followerCtx, resolverWire(t, "cancel-followers.example", 2, mdns.TypeA))
			awaitResolverFlightWaiters(t, r, 2)
			stopFollower()
			if result := resolverFlightTestReceive(t, follower); !errors.Is(result.err, context.Canceled) {
				t.Fatal(result.err)
			}
			awaitResolverFlightWaiters(t, r, 1)
			if all {
				stopLeader()
				if result := resolverFlightTestReceive(t, leader); !errors.Is(result.err, context.Canceled) {
					t.Fatal(result.err)
				}
				awaitResolverSignal(t, canceled, "last waiter canceling network")
				awaitResolverFlightWaiters(t, r, 0)
				if r.CacheStatus().Entries != 0 {
					t.Fatal("canceled operation populated cache")
				}
			} else {
				select {
				case <-canceled:
					t.Fatal("one follower canceled the leader dial")
				default:
				}
				unblock()
				if result := resolverFlightTestReceive(t, leader); result.err != nil || result.out.Shared {
					t.Fatal(result.out, result.err)
				}
			}
		})
	}
}

func TestResolverInflightCloseCancelsSharedOperation(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.AWGFallback = "off"
	closeResolverFixtureIdle(r)
	b.mu.Lock()
	b.dialHook = func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	b.mu.Unlock()
	first := startResolverFlightTest(r, context.Background(), resolverWire(t, "close.example", 1, mdns.TypeA))
	awaitResolverSignal(t, started, "blocked shared operation")
	second := startResolverFlightTest(r, context.Background(), resolverWire(t, "close.example", 2, mdns.TypeA))
	awaitResolverFlightWaiters(t, r, 2)
	r.Close()
	if resolverFlightTestReceive(t, first).err == nil || resolverFlightTestReceive(t, second).err == nil {
		t.Fatal("closed resolver returned success")
	}
	awaitResolverSignal(t, canceled, "close canceling dial")
}

func TestResolverInflightClearSeparatesGenerationsAndPreventsRepopulation(t *testing.T) {
	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		number := calls.Add(1)
		if number == 1 {
			close(firstStarted)
			<-firstRelease
		} else {
			close(secondStarted)
			<-secondRelease
		}
		return resolverAnswer(q, 60)
	})
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	var firstOnce, secondOnce sync.Once
	unblockFirst := func() { firstOnce.Do(func() { close(firstRelease) }) }
	unblockSecond := func() { secondOnce.Do(func() { close(secondRelease) }) }
	defer unblockFirst()
	defer unblockSecond()
	first := startResolverFlightTest(r, context.Background(), resolverWire(t, "clear-shared.example", 1, mdns.TypeA))
	awaitResolverSignal(t, firstStarted, "old generation query")
	r.ClearCache()
	second := startResolverFlightTest(r, context.Background(), resolverWire(t, "clear-shared.example", 2, mdns.TypeA))
	awaitResolverSignal(t, secondStarted, "new generation query")
	unblockFirst()
	if result := resolverFlightTestReceive(t, first); result.err != nil || result.out.Shared {
		t.Fatal(result.out, result.err)
	}
	if r.CacheStatus().Entries != 0 {
		t.Fatal("old generation repopulated cleared cache")
	}
	unblockSecond()
	if result := resolverFlightTestReceive(t, second); result.err != nil || result.out.Shared {
		t.Fatal(result.out, result.err)
	}
	if r.CacheStatus().Entries != 1 || calls.Load() != 2 {
		t.Fatal("new generation did not fetch/cache separately", calls.Load())
	}
}

func TestResolverInflightZeroTTLAndErrorsSharedButNeverCached(t *testing.T) {
	for _, code := range []int{mdns.RcodeSuccess, mdns.RcodeServerFailure} {
		t.Run(mdns.RcodeToString[code], func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			var once sync.Once
			r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
				calls.Add(1)
				once.Do(func() { close(started) })
				<-release
				msg := resolverAnswer(q, 0)
				msg.Rcode = code
				return msg
			})
			r.cfg.AWGFallback = "off"
			r.cfg.CacheSize = 8
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			first := startResolverFlightTest(r, context.Background(), resolverWire(t, "not-cached.example", 1, mdns.TypeA))
			awaitResolverSignal(t, started, "uncacheable query")
			second := startResolverFlightTest(r, context.Background(), resolverWire(t, "not-cached.example", 2, mdns.TypeA))
			awaitResolverFlightWaiters(t, r, 2)
			unblock()
			a, b := resolverFlightTestReceive(t, first), resolverFlightTestReceive(t, second)
			if !b.out.Shared || a.out.Cached || b.out.Cached || calls.Load() != 1 || (a.err == nil) != (code == mdns.RcodeSuccess) || (b.err == nil) != (code == mdns.RcodeSuccess) {
				t.Fatal("uncacheable outcome not shared accurately", a.out, b.out, a.err, b.err, calls.Load())
			}
			if r.CacheStatus().Entries != 0 {
				t.Fatal("uncacheable result stored")
			}
			if _, out, _ := r.Resolve(context.Background(), resolverWire(t, "not-cached.example", 3, mdns.TypeA)); out.Cached || out.Shared || calls.Load() != 2 {
				t.Fatal("completed uncacheable flight retained or cached", out, calls.Load())
			}
		})
	}
}

func TestResolverInflightCapacityUsesExistingIndependentRace(t *testing.T) {
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.AWGFallback = "off"
	r.mu.Lock()
	r.inflight = map[resolverFlightKey]*resolverFlight{}
	for i := 0; i < maxResolverFlights; i++ {
		r.inflight[resolverFlightKey{query: string(rune(i + 1))}] = &resolverFlight{}
	}
	r.mu.Unlock()
	if _, out, err := r.Resolve(context.Background(), resolverWire(t, "over-capacity.example", 1, mdns.TypeA)); err != nil || out.Shared {
		t.Fatal("capacity rejected ordinary request", out, err)
	}
	r.mu.Lock()
	count := len(r.inflight)
	clear(r.inflight)
	r.mu.Unlock()
	if count != maxResolverFlights {
		t.Fatal("inflight capacity exceeded", count)
	}
}

func TestResolverInflightNeverJoinsDifferentDNSFlagsOrClientSubnets(t *testing.T) {
	started, release := make(chan struct{}, 8), make(chan struct{})
	var calls atomic.Int32
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return resolverAnswer(q, 60)
	})
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	variants := []func(*mdns.Msg){func(*mdns.Msg) {}, func(q *mdns.Msg) { q.CheckingDisabled = true }, func(q *mdns.Msg) { q.SetEdns0(1232, true) }, func(q *mdns.Msg) { q.SetEdns0(1232, false) }, func(q *mdns.Msg) { q.SetEdns0(4096, false) }, func(q *mdns.Msg) {
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = []mdns.EDNS0{&mdns.EDNS0_SUBNET{Code: mdns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.0")}}
	}, func(q *mdns.Msg) {
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = []mdns.EDNS0{&mdns.EDNS0_SUBNET{Code: mdns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.0")}}
	}, func(q *mdns.Msg) {
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = []mdns.EDNS0{&mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: "0102030405060708"}}
	}}
	done := []<-chan resolverFlightTestResult{}
	for i, change := range variants {
		q := new(mdns.Msg)
		q.SetQuestion("same.example.", mdns.TypeA)
		q.Id = uint16(i + 1)
		change(q)
		wire, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		done = append(done, startResolverFlightTest(r, context.Background(), wire))
	}
	for range variants {
		awaitResolverSignal(t, started, "distinct semantic query")
	}
	awaitResolverFlightWaiters(t, r, len(variants))
	unblock()
	for _, result := range done {
		if reply := resolverFlightTestReceive(t, result); reply.err != nil || reply.out.Shared || reply.out.Cached {
			t.Fatal("different semantic query was merged", reply.out, reply.err)
		}
	}
	if calls.Load() != int32(len(variants)) {
		t.Fatal("semantic variants did not use separate upstream requests", calls.Load())
	}
}

func TestResolverInflightCacheLifetimeStartsAtSharedAnswerCompletion(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		once.Do(func() { close(started) })
		<-release
		return resolverAnswer(q, 60)
	})
	r.cfg.AWGFallback = "off"
	r.cfg.CacheSize = 8
	start := time.Now()
	var ticks atomic.Int64
	r.now = func() time.Time { return start.Add(time.Duration(ticks.Add(1)) * time.Second) }
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	leader := startResolverFlightTest(r, context.Background(), resolverWire(t, "timestamp.example", 1, mdns.TypeA))
	awaitResolverSignal(t, started, "shared timestamp query")
	follower := startResolverFlightTest(r, context.Background(), resolverWire(t, "timestamp.example", 2, mdns.TypeA))
	awaitResolverFlightWaiters(t, r, 2)
	r.mu.Lock()
	var flight *resolverFlight
	for _, active := range r.inflight {
		flight = active
	}
	r.mu.Unlock()
	unblock()
	if result := resolverFlightTestReceive(t, leader); result.err != nil {
		t.Fatal(result.err)
	}
	if result := resolverFlightTestReceive(t, follower); result.err != nil {
		t.Fatal(result.err)
	}
	r.mu.Lock()
	var entry dnsCacheEntry
	for _, cached := range r.cache {
		entry = cached
	}
	r.mu.Unlock()
	if flight == nil || !entry.created.Equal(flight.completedAt) || !entry.expires.Equal(flight.completedAt.Add(60*time.Second)) {
		t.Fatal("cache TTL restarted after delivering shared answer")
	}
}
