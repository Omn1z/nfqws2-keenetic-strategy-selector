//go:build !linux

package netmon

// SystemStats / TempZone / ServiceStat live in system_linux.go on Linux. The
// dev-machine builds (macOS / Windows) get stub-only copies of the types so the
// dashboard JSON shape stays identical and the React types compile.

// SystemStats is a zero-valued snapshot off-router so the dashboard still renders.
type SystemStats struct {
	CPUPercent  float64       `json:"cpu_percent"`
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

type ServiceStat struct {
	Name       string  `json:"name"`
	PID        int     `json:"pid"`
	CPUPercent float64 `json:"cpu_percent"`
	RSSKB      int64   `json:"rss_kb"`
	UptimeSec  int64   `json:"uptime_sec"`
}

// System returns an empty snapshot on non-Linux builds.
func System() SystemStats { return SystemStats{CPUPercent: -1} }
