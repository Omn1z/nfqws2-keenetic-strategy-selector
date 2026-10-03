package netmon

import (
	"sync"
	"time"
)

// SystemStats is a snapshot of router-wide load shown on the dashboard.
// The memory buckets distinguish userspace RSS, unreclaimable kernel slab,
// and reclaimable buffers/cache. MemUsedKB is retained for older clients.
type SystemStats struct {
	CPUPercent  float64       `json:"cpu_percent"` // -1 until a second sample
	LoadAvg     [3]float64    `json:"load_avg"`
	MemTotalKB  int64         `json:"mem_total_kb"`
	MemFreeKB   int64         `json:"mem_free_kb"`
	MemAvailKB  int64         `json:"mem_avail_kb"`
	MemUsedKB   int64         `json:"mem_used_kb"`
	MemAppsKB   int64         `json:"mem_apps_kb"`
	MemKernelKB int64         `json:"mem_kernel_kb"`
	MemCacheKB  int64         `json:"mem_cache_kb"`
	SwapTotalKB int64         `json:"swap_total_kb"`
	SwapFreeKB  int64         `json:"swap_free_kb"`
	UptimeSec   int64         `json:"uptime_sec"`
	Temps       []TempZone    `json:"temps"`
	Services    []ServiceStat `json:"services"`
}

type TempZone struct {
	Label string `json:"label"`
	C     int    `json:"c"`
}

// CPUPercent is relative to one core, so a multithreaded process can exceed
// 100%. RSSKB is the resident set; UptimeSec is seconds since process start.
type ServiceStat struct {
	Name       string  `json:"name"`
	PID        int     `json:"pid"`
	CPUPercent float64 `json:"cpu_percent"`
	RSSKB      int64   `json:"rss_kb"`
	UptimeSec  int64   `json:"uptime_sec"`
}

const systemSampleInterval = time.Second

type systemSampler struct {
	mu        sync.Mutex
	now       func() time.Time
	load      func() SystemStats
	sample    SystemStats
	sampledAt time.Time
	hasSample bool
}

var sharedSystemSampler = systemSampler{now: time.Now, load: readSystem}

// System shares one bounded process/CPU snapshot across HTTP pollers. Repeated
// requests within a second do not reread /proc or advance the CPU delta window.
// Each caller owns its slices and cannot mutate another caller's snapshot.
func System() SystemStats { return sharedSystemSampler.snapshot() }

func (s *systemSampler) snapshot() SystemStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.hasSample || now.Before(s.sampledAt) || now.Sub(s.sampledAt) >= systemSampleInterval {
		// Serialize the actual read as well as publication: simultaneous cold
		// pollers must not independently scan every process. Start the next
		// interval after this read completes, even if reading /proc was slow.
		s.sample = cloneSystemStats(s.load())
		s.sampledAt = s.now()
		s.hasSample = true
	}
	return cloneSystemStats(s.sample)
}

func cloneSystemStats(s SystemStats) SystemStats {
	if s.Temps != nil {
		s.Temps = append([]TempZone{}, s.Temps...)
	}
	if s.Services != nil {
		s.Services = append([]ServiceStat{}, s.Services...)
	}
	return s
}
