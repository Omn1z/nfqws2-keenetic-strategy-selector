package netmon

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSystemSamplerReusesMinimumIntervalAndRefreshesAtExpiry(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var reads int
	s := systemSampler{now: func() time.Time { return now }, load: func() SystemStats {
		reads++
		return SystemStats{CPUPercent: float64(reads), UptimeSec: int64(reads)}
	}}
	first := s.snapshot()
	for i := 0; i < 12; i++ {
		now = now.Add(30 * time.Millisecond)
		if got := s.snapshot(); got.UptimeSec != first.UptimeSec || got.CPUPercent != first.CPUPercent {
			t.Fatalf("rapid poll %d advanced the CPU sample: %+v", i, got)
		}
	}
	now = s.sampledAt.Add(systemSampleInterval - time.Nanosecond)
	if s.snapshot().UptimeSec != 1 || reads != 1 {
		t.Fatal("scan repeated before minimum interval expired")
	}
	now = s.sampledAt.Add(systemSampleInterval)
	if s.snapshot().UptimeSec != 2 || reads != 2 {
		t.Fatal("expired sample was not refreshed exactly once")
	}
	if s.snapshot().UptimeSec != 2 || reads != 2 {
		t.Fatal("second poll after refresh repeated the scan")
	}
	// An injected clock reset must not retain the old snapshot indefinitely.
	now = now.Add(-time.Hour)
	if s.snapshot().UptimeSec != 3 || reads != 3 {
		t.Fatal("clock rollback retained an unbounded stale sample")
	}
}

func TestSystemSamplerIntervalBeginsAfterSlowRead(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var reads int
	s := systemSampler{now: func() time.Time { return now }, load: func() SystemStats {
		reads++
		now = now.Add(3 * time.Second)
		return SystemStats{UptimeSec: int64(reads)}
	}}
	if s.snapshot().UptimeSec != 1 {
		t.Fatal("cold sample failed")
	}
	now = now.Add(500 * time.Millisecond)
	if s.snapshot().UptimeSec != 1 || reads != 1 {
		t.Fatal("slow read caused the next poll to rescan immediately")
	}
	now = now.Add(500 * time.Millisecond)
	if s.snapshot().UptimeSec != 2 || reads != 2 {
		t.Fatal("completed read was never refreshed")
	}
}

func TestSystemSamplerConcurrentPollersShareOneScanAndOwnTheirSlices(t *testing.T) {
	const clients = 24
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	started, release := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	original := SystemStats{CPUPercent: 12.5, Services: []ServiceStat{{Name: "amneziawg", PID: 10, RSSKB: 4000}}, Temps: []TempZone{{Label: "soc", C: 40}}}
	s := systemSampler{now: func() time.Time { return now }, load: func() SystemStats {
		if reads.Add(1) == 1 {
			close(started)
			<-release
		}
		return original
	}}
	results := make(chan SystemStats, clients)
	for i := 0; i < clients; i++ {
		go func() { results <- s.snapshot() }()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("cold poll never entered the loader")
	}
	unblock()
	for i := 0; i < clients; i++ {
		select {
		case got := <-results:
			if got.CPUPercent != 12.5 || got.Services[0].Name != "amneziawg" || got.Temps[0].C != 40 {
				t.Fatalf("caller inherited another caller's mutation: %+v", got)
			}
			got.Services[0].Name = "mutated by caller"
			got.Temps[0].C = 999
		case <-time.After(time.Second):
			t.Fatal("concurrent poll stayed blocked")
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("24 simultaneous pollers performed %d scans", reads.Load())
	}
	original.Services[0].Name, original.Temps[0].C = "mutated loader slice", -999
	if got := s.snapshot(); got.Services[0].Name != "amneziawg" || got.Temps[0].C != 40 {
		t.Fatalf("cached sample shares its loader/caller slices: %+v", got)
	}
	original.Services[0].Name, original.Temps[0].C = "amneziawg", 40
	now = now.Add(time.Second)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.snapshot() }()
	}
	wg.Wait()
	if reads.Load() != 2 {
		t.Fatalf("24 concurrent expiry pollers performed %d scans instead of two total", reads.Load())
	}
}

func TestSystemSamplerPreservesEmptyAndNilSlices(t *testing.T) {
	for _, input := range []SystemStats{{}, {Services: []ServiceStat{}, Temps: []TempZone{}}} {
		s := systemSampler{now: time.Now, load: func() SystemStats { return input }}
		got := s.snapshot()
		if (got.Services == nil) != (input.Services == nil) || (got.Temps == nil) != (input.Temps == nil) {
			t.Fatal("sampling changed empty array JSON shape")
		}
	}
}

func TestSystemCPUParsesIOWaitAndDoesNotDoubleCountGuest(t *testing.T) {
	last, ok := parseCPUSample("cpu 100 20 30 400 50 5 10 0 60 5")
	if !ok || last != (cpuSample{total: 615, idle: 450}) {
		t.Fatalf("idle/iowait/guest accounting wrong: %+v %v", last, ok)
	}
	current, ok := parseCPUSample("cpu\t200 20 30 460 90 5 10 0 160 5")
	if !ok || current != (cpuSample{total: 815, idle: 550}) || aggregateCPUPercent(last, current, time.Second) != 50 {
		t.Fatalf("guest delta inflated execution load: %+v %v", current, ok)
	}
	iowait, ok := parseCPUSample("cpu 0 0 0 0 100 0 0 0 0 0")
	if !ok || aggregateCPUPercent(cpuSample{}, iowait, time.Second) != 0 {
		t.Fatal("I/O waiting was reported as executing CPU work")
	}
	for _, malformed := range []string{"", "cpu0 1 2 3 4", "cpu 1 2 3", "cpu 1 x 3 4", "cpu 1 -2 3 4", "cpu 9223372036854775807 1 0 0"} {
		if _, ok := parseCPUSample(malformed); ok {
			t.Errorf("accepted malformed counter line %q", malformed)
		}
	}
}

func TestSystemCPURejectsStaleResetOrInvalidTimeSamples(t *testing.T) {
	last := cpuSample{total: 100, idle: 60}
	for _, tc := range []struct {
		current cpuSample
		elapsed time.Duration
		want    float64
	}{
		{cpuSample{total: 200, idle: 120}, time.Second, 40},
		{cpuSample{total: 200, idle: 160}, time.Second, 0},
		{cpuSample{total: 200, idle: 200}, time.Second, 0},
		{cpuSample{total: 200, idle: 60}, time.Second, 100},
		{last, time.Second, -1},
		{cpuSample{total: 200, idle: 120}, 0, -1},
		{cpuSample{total: 200, idle: 120}, -time.Second, -1},
		{cpuSample{total: 200, idle: 120}, 31 * time.Second, -1},
		{cpuSample{total: 90, idle: 20}, time.Second, -1},
		{cpuSample{total: 200, idle: 50}, time.Second, -1},
	} {
		if got := aggregateCPUPercent(last, tc.current, tc.elapsed); got != tc.want {
			t.Errorf("current=%+v elapsed=%v: got %v want %v", tc.current, tc.elapsed, got, tc.want)
		}
	}
}

func TestSystemProcessCPURejectsPIDReuseButPreservesMulticoreUsage(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	last := procCPUSample{ticks: 100, start: 500, at: at}
	current := procCPUSample{ticks: 400, start: 500, at: at.Add(2 * time.Second)}
	if got := processCPUPercent(last, current, 100); math.Abs(got-150) > 1e-9 {
		t.Fatalf("process usage was clipped to one core: %v", got)
	}
	// Reused PID can accumulate more ticks than the old process; checking
	// only a nonnegative tick delta silently joins two different processes.
	reused := current
	reused.start = 1500
	if got := processCPUPercent(last, reused, 100); got != -1 {
		t.Fatalf("reused PID inherited old process CPU sample: %v", got)
	}
	for _, tc := range []struct {
		current procCPUSample
		clock   int64
	}{
		{procCPUSample{ticks: 99, start: 500, at: current.at}, 100},
		{procCPUSample{ticks: 400, start: 500, at: at}, 100},
		{procCPUSample{ticks: 400, start: 500, at: at.Add(-time.Second)}, 100},
		{procCPUSample{ticks: 400, start: 500, at: at.Add(31 * time.Second)}, 100},
		{current, 0},
		{current, -1},
	} {
		if got := processCPUPercent(last, tc.current, tc.clock); got != -1 {
			t.Errorf("invalid process sample %+v clock %d returned %v", tc.current, tc.clock, got)
		}
	}
}
