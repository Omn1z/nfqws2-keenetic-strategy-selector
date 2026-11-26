package dnsroute

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func shadowNativeStoredFixture(t *testing.T) ([]byte, shadowBootClock, map[string]shadowRememberedLease) {
	t.Helper()
	observed := time.Date(2026, 10, 4, 4, 10, 0, 123456789, time.UTC)
	clock := shadowBootClock{bootID: "01234567-89ab-cdef-0123-456789abcdef", uptime: 12*time.Hour + 123*time.Millisecond, now: observed.Add(17*time.Minute + 111*time.Nanosecond)}
	leases := map[string]shadowRememberedLease{"GigabitEthernet1": {
		wanKey: "ip=10.101.48.55|route=eth3/10.101.48.1", clientIP: net.ParseIP("10.101.48.55"),
		servers: []string{"192.0.2.53:53", "198.51.100.53:53"}, leaseSeconds: 3600,
		observedAt: observed, expires: observed.Add(time.Hour),
	}}
	data, err := encodeShadowLeases(leases, clock)
	if err != nil {
		t.Fatal(err)
	}
	return data, clock, leases
}

func TestShadowNativeLeaseStorePreservesObservedAtAndExactExpiry(t *testing.T) {
	data, saved, leases := shadowNativeStoredFixture(t)
	later := saved
	later.now, later.uptime = saved.now.Add(12*time.Minute+719*time.Nanosecond), saved.uptime+12*time.Minute+719*time.Nanosecond
	got, err := decodeShadowLeases(data, later)
	if err != nil {
		t.Fatal(err)
	}
	want, restored := leases["GigabitEthernet1"], got["GigabitEthernet1"]
	if len(got) != 1 || restored.stamp != "" || !sameShadowLease(restored, want) || !restored.observedAt.Equal(want.observedAt) || !restored.expires.Equal(want.expires) {
		t.Fatalf("native observation changed across restart: got=%+v want=%+v", restored, want)
	}
	if shadowLeaseDigest(got) != shadowLeaseDigest(leases) {
		t.Fatal("unchanged native observation would rewrite persistent storage")
	}
	// The absolute observation must not become a fresh full lease when saved
	// after a restart, even though it has no historical text-log timestamp.
	resaved, err := encodeShadowLeases(got, later)
	if err != nil {
		t.Fatal(err)
	}
	atExpiry := later
	atExpiry.now = want.expires
	atExpiry.uptime = saved.uptime + want.expires.Sub(saved.now)
	if expired, err := decodeShadowLeases(resaved, atExpiry); err != nil || len(expired) != 0 {
		t.Fatalf("resaving renewed an expired DHCP observation: %+v %v", expired, err)
	}
}

func TestShadowNativeLeaseStoreRejectsRollbackAndReboot(t *testing.T) {
	data, saved, _ := shadowNativeStoredFixture(t)
	for name, mutate := range map[string]func(*shadowBootClock){
		"wall rollback": func(c *shadowBootClock) { c.now = c.now.Add(-time.Nanosecond) },
		"boot rollback": func(c *shadowBootClock) { c.uptime -= time.Nanosecond },
		"reboot":        func(c *shadowBootClock) { c.bootID = "11234567-89ab-cdef-0123-456789abcdef" },
	} {
		t.Run(name, func(t *testing.T) {
			clock := saved
			mutate(&clock)
			if got, err := decodeShadowLeases(data, clock); err == nil {
				t.Fatalf("unsafe clock accepted: %+v", got)
			}
		})
	}
	// An NTP rollback that is still later than saved_at must shorten the
	// reconstructed wall expiry to the boot-clock bound, never extend it.
	partial := saved
	partial.now, partial.uptime = saved.now.Add(5*time.Minute), saved.uptime+10*time.Minute
	got, err := decodeShadowLeases(data, partial)
	if err != nil {
		t.Fatal(err)
	}
	wantRemaining := 33*time.Minute - 111*time.Nanosecond
	if actual := got["GigabitEthernet1"].expires.Sub(partial.now); actual != wantRemaining {
		t.Fatalf("boot clock did not bound native observation: got=%s want=%s", actual, wantRemaining)
	}
}

func TestShadowNativeLeaseStoreRejectsInvalidObservationBounds(t *testing.T) {
	data, clock, _ := shadowNativeStoredFixture(t)
	for name, mutate := range map[string]func(*shadowLeaseDocument){
		"future observed": func(d *shadowLeaseDocument) { at := d.SavedAt.Add(time.Nanosecond); d.Leases[0].ObservedAt = &at },
		"zero observed":   func(d *shadowLeaseDocument) { d.Leases[0].ObservedAt = new(time.Time) },
		"expiry after observed lease": func(d *shadowLeaseDocument) {
			d.Leases[0].Expires = d.Leases[0].Expires.Add(time.Nanosecond)
			d.Leases[0].ExpiresBootNS++
		},
		"claimed observation too old": func(d *shadowLeaseDocument) {
			at := d.Leases[0].ObservedAt.Add(-time.Nanosecond)
			d.Leases[0].ObservedAt = &at
		},
		"missing observed and text stamp": func(d *shadowLeaseDocument) { d.Leases[0].ObservedAt = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var document shadowLeaseDocument
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			mutate(&document)
			modified, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if leases, err := decodeShadowLeases(modified, clock); err == nil {
				t.Fatalf("invalid native observation accepted: %+v", leases)
			}
		})
	}
	// Existing log-based files without observed_at remain supported when their
	// lease has its original, valid timestamp. Empty text stamps are native-only.
	var legacy shadowLeaseDocument
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.Leases[0].ObservedAt = nil
	legacy.Leases[0].Stamp = "Oct  4 04:10:00"
	legacyData, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeShadowLeases(legacyData, clock); err != nil || len(got) != 1 || !got["GigabitEthernet1"].observedAt.IsZero() {
		t.Fatalf("legacy lease compatibility lost: %+v %v", got, err)
	}
}

func TestShadowNativeLeaseStoreMonotonicReconstructionDoesNotExtendExpiry(t *testing.T) {
	// Real time.Now values carry a monotonic anchor; JSON removes that anchor.
	// Comparing reconstructed anchors is unsafe under clock slewing, so test
	// the persisted wall instants and repeat actual encode/decode cycles.
	observed := time.Now()
	wantExpiry := observed.Add(time.Hour).Round(0)
	clock := shadowBootClock{bootID: "01234567-89ab-cdef-0123-456789abcdef", uptime: 12 * time.Hour, now: observed}
	leases := map[string]shadowRememberedLease{"ISP": {
		wanKey: "ip=192.0.2.2|route=eth3/192.0.2.1", clientIP: net.ParseIP("192.0.2.2"), servers: []string{"192.0.2.53:53"},
		observedAt: observed, expires: observed.Add(time.Hour), leaseSeconds: 3600,
	}}
	initialDigest := shadowLeaseDigest(leases)
	for n := 0; n < 20; n++ {
		encoded, err := encodeShadowLeases(leases, clock)
		if err != nil {
			t.Fatal(err)
		}
		step := 101*time.Millisecond + time.Duration(n)*time.Nanosecond
		clock.now, clock.uptime = clock.now.Add(step), clock.uptime+step
		leases, err = decodeShadowLeases(encoded, clock)
		if err != nil {
			t.Fatalf("cycle %d rejected a valid native expiry: %v", n, err)
		}
		got := leases["ISP"]
		if !got.expires.Round(0).Equal(wantExpiry) || !got.observedAt.Round(0).Equal(observed.Round(0)) || shadowLeaseDigest(leases) != initialDigest {
			t.Fatalf("cycle %d changed the exact native observation: %+v", n, got)
		}
	}
}

func TestShadowNativeLeaseIdentityIncludesObservationTime(t *testing.T) {
	_, _, fixtures := shadowNativeStoredFixture(t)
	a := fixtures["GigabitEthernet1"]
	b := a
	b.observedAt = b.observedAt.Add(time.Nanosecond)
	if sameShadowLease(a, b) {
		t.Fatal("a later native ACK was mistaken for the same lease observation")
	}
	if shadowLeaseDigest(map[string]shadowRememberedLease{"ISP": a}) == shadowLeaseDigest(map[string]shadowRememberedLease{"ISP": b}) {
		t.Fatal("a new native observation would not be persisted")
	}
}
