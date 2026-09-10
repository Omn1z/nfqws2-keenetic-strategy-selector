//go:build linux

package netmon

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemStats is a snapshot of router-wide load shown on the dashboard.
//
// Memory split into three honest buckets so the user can see WHERE the RAM
// went — `free -h`'s single "used" number lies on this router because most of
// it is the kernel's iptables/ipset slab (the ~14 k RU-bypass entries cost
// ~220 MB of SUnreclaim), not actual applications. The dashboard shows:
//   - MemAppsKB   — userspace RSS sum (the "apps actually" you can blame)
//   - MemKernelKB — SUnreclaim kernel slab (mostly ipset/conntrack)
//   - MemCacheKB  — reclaimable buffers + cache + SReclaimable
type SystemStats struct {
	CPUPercent  float64       `json:"cpu_percent"` // 0..100 averaged over the diff window; -1 on first call
	LoadAvg     [3]float64    `json:"load_avg"`    // 1, 5, 15-minute averages from /proc/loadavg
	MemTotalKB  int64         `json:"mem_total_kb"`
	MemFreeKB   int64         `json:"mem_free_kb"`
	MemAvailKB  int64         `json:"mem_avail_kb"`
	MemUsedKB   int64         `json:"mem_used_kb"`   // `free -h` used (apps + kernel). Kept for back-compat.
	MemAppsKB   int64         `json:"mem_apps_kb"`   // sum of userspace process RSS
	MemKernelKB int64         `json:"mem_kernel_kb"` // SUnreclaim — kernel slab (ipset/conntrack/etc.)
	MemCacheKB  int64         `json:"mem_cache_kb"`  // buff + cache + sreclaimable; reclaimable when apps need it
	SwapTotalKB int64         `json:"swap_total_kb"`
	SwapFreeKB  int64         `json:"swap_free_kb"`
	UptimeSec   int64         `json:"uptime_sec"`
	Temps       []TempZone    `json:"temps"`    // thermal zones, °C
	Services    []ServiceStat `json:"services"` // top-N processes by RSS
}

// TempZone is one thermal sensor reading.
type TempZone struct {
	Label string `json:"label"`
	C     int    `json:"c"`
}

// ServiceStat is the per-process snapshot for the dashboard's «Сервисы» row.
// CPUPercent is delta-based like the global one (-1 on first sample); RSSKB is
// the resident set; UptimeSec is wall-clock seconds since the process started.
type ServiceStat struct {
	Name       string  `json:"name"`
	PID        int     `json:"pid"`
	CPUPercent float64 `json:"cpu_percent"`
	RSSKB      int64   `json:"rss_kb"`
	UptimeSec  int64   `json:"uptime_sec"`
}

type cpuSample struct {
	total, idle int64
}

var (
	cpuMu   sync.Mutex
	cpuLast cpuSample
	cpuTS   time.Time
)

// System returns the current SystemStats snapshot. CPUPercent uses a delta
// between successive calls; the first call after process start returns -1
// (the UI hides the bar in that case). Best-effort: every field that fails to
// parse stays at its zero value, so the response always renders.
func System() SystemStats {
	var s SystemStats
	s.LoadAvg = readLoadAvg()
	mi := readMemInfo()
	s.MemTotalKB = mi["MemTotal:"]
	s.MemFreeKB = mi["MemFree:"]
	s.MemAvailKB = mi["MemAvailable:"]
	s.SwapTotalKB = mi["SwapTotal:"]
	s.SwapFreeKB = mi["SwapFree:"]
	cache := mi["Buffers:"] + mi["Cached:"] + mi["SReclaimable:"] - mi["Shmem:"]
	if cache < 0 {
		cache = 0
	}
	s.MemCacheKB = cache
	s.MemKernelKB = mi["SUnreclaim:"] // kernel slab — ipset/conntrack/etc.
	used := s.MemTotalKB - s.MemFreeKB - cache
	if used < 0 {
		used = 0
	}
	s.MemUsedKB = used
	s.UptimeSec = readUptime()
	s.Temps = readThermalZones()
	s.CPUPercent = readCPUPercent()
	s.Services, s.MemAppsKB = readServiceStats(s.UptimeSec)
	return s
}

// Top-N processes shown in the dashboard, sorted by RSS desc. Hardcoded service
// allowlists lie: this router runs dozens of XiaoMi/Keenetic daemons and Docker
// containers we couldn't possibly enumerate, and the user (rightly) wants to
// SEE where the RAM is going. So we just scan /proc, drop kernel threads, sort
// by resident size, and keep the top few — same approach `htop` takes.
const (
	topProcN      = 10            // cards on the dashboard
	topProcMinKB  = 1024          // ignore processes smaller than ~1 MB so the list isn't 50 tiny rows
)

var (
	procCPUMu   sync.Mutex
	procCPULast = map[int]procCPUSample{}
)

type procCPUSample struct {
	ticks int64 // utime + stime
	at    time.Time
}

// readServiceStats finds each named process (by Comm field of /proc/[pid]/stat,
// which is what `ps` shows in the COMMAND column) and emits one ServiceStat.
// CPUPercent uses the same delta-between-calls technique as the global one.
// Returns the top-N processes by RSS, sorted desc, skipping kernel threads
// (those have empty cmdline) and processes smaller than topProcMinKB.
// Also returns the SUM of every userspace RSS we saw — that's the honest
// "apps actually using RAM" number the dashboard splits out from kernel slab.
func readServiceStats(sysUptime int64) ([]ServiceStat, int64) {
	pids, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0
	}
	clk := readClockTicks()
	now := time.Now()
	procCPUMu.Lock()
	defer procCPUMu.Unlock()
	live := map[int]bool{}

	all := make([]ServiceStat, 0, 64)
	var totalRSS int64
	for _, e := range pids {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		live[pid] = true
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// Format: pid (comm) state ppid ... — `comm` may contain spaces and
		// parens. Use last ')' as the close to handle that.
		lp := strings.LastIndexByte(string(stat), ')')
		if lp < 0 {
			continue
		}
		op := strings.IndexByte(string(stat), '(')
		if op < 0 || op > lp {
			continue
		}
		comm := string(stat[op+1 : lp])
		fs := strings.Fields(strings.TrimSpace(string(stat[lp+1:])))
		// Columns after `state` (index 0 here is "state"):
		//   13: utime, 14: stime, 21: starttime (jiffies since boot)
		if len(fs) < 22 {
			continue
		}
		// Kernel threads have flag bit 21 (PF_KTHREAD) set in field 9 (after the
		// 0-based state). We don't need exact decoding — they ALSO have a zero
		// RSS, so the rss filter below drops them naturally. Keep the simple path.
		utime, _ := strconv.ParseInt(fs[11], 10, 64)
		stime, _ := strconv.ParseInt(fs[12], 10, 64)
		start, _ := strconv.ParseInt(fs[19], 10, 64)
		totalTicks := utime + stime

		var rssKB int64
		if statm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "statm")); err == nil {
			f := strings.Fields(string(statm))
			if len(f) >= 2 {
				rss, _ := strconv.ParseInt(f[1], 10, 64)
				rssKB = rss * int64(os.Getpagesize()) / 1024
			}
		}
		// Userspace RSS sum across ALL processes (no minimum filter — even the
		// dozens of 200 KB busybox spawns add up to real numbers on a router).
		totalRSS += rssKB
		if rssKB < topProcMinKB {
			continue
		}

		cpuPct := -1.0
		if last, ok := procCPULast[pid]; ok && now.Sub(last.at) < 30*time.Second && now.After(last.at) {
			dt := totalTicks - last.ticks
			elapsed := now.Sub(last.at).Seconds()
			if elapsed > 0 && dt >= 0 {
				cpuPct = float64(dt) / float64(clk) / elapsed * 100
				if cpuPct < 0 {
					cpuPct = 0
				}
			}
		}
		procCPULast[pid] = procCPUSample{ticks: totalTicks, at: now}

		uptimeSec := sysUptime - start/int64(clk)
		if uptimeSec < 0 {
			uptimeSec = 0
		}
		all = append(all, ServiceStat{
			Name:       comm,
			PID:        pid,
			CPUPercent: cpuPct,
			RSSKB:      rssKB,
			UptimeSec:  uptimeSec,
		})
	}
	// Prune CPU samples for processes that died (avoid unbounded growth).
	for pid := range procCPULast {
		if !live[pid] {
			delete(procCPULast, pid)
		}
	}
	// Top-N by RSS desc. (Linux's /proc enumeration order is pid-ascending, so
	// this also gives a deterministic tiebreak when multiple procs match.)
	sort.SliceStable(all, func(i, j int) bool { return all[i].RSSKB > all[j].RSSKB })
	if len(all) > topProcN {
		all = all[:topProcN]
	}
	return all, totalRSS
}

// readClockTicks returns the kernel CLK_TCK (USER_HZ) — typically 100 on Linux.
// We cache it on first call since it never changes.
var (
	clockTicksOnce sync.Once
	clockTicks     int64 = 100
)

func readClockTicks() int64 {
	clockTicksOnce.Do(func() {
		// Reading USER_HZ portably from Go without cgo is awkward; 100 is
		// universal on every kernel anyone runs on a router. If we ever ship
		// to weirder hardware, a getconf(_SC_CLK_TCK) probe could refine this.
	})
	return clockTicks
}

func readLoadAvg() [3]float64 {
	var out [3]float64
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return out
	}
	fs := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(fs); i++ {
		out[i], _ = parseFloat(fs[i])
	}
	return out
}

// readMemInfo returns a map of /proc/meminfo keys (with the trailing colon kept,
// to match what's grep-friendly on the original file) to their kB values. Only
// the keys actually used by the dashboard are kept; everything else is dropped
// so the map stays small enough that a tight switch on prefix is faster than a
// generic parse-all.
func readMemInfo() map[string]int64 {
	out := map[string]int64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return out
	}
	defer f.Close()
	keep := map[string]bool{
		"MemTotal:":     true,
		"MemFree:":      true,
		"MemAvailable:": true,
		"Buffers:":      true,
		"Cached:":       true,
		"SReclaimable:": true,
		"SUnreclaim:":   true,
		"Shmem:":        true,
		"SwapTotal:":    true,
		"SwapFree:":     true,
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		sp := strings.IndexByte(ln, ':')
		if sp < 0 {
			continue
		}
		key := ln[:sp+1]
		if !keep[key] {
			continue
		}
		fs := strings.Fields(ln[sp+1:])
		if len(fs) == 0 {
			continue
		}
		out[key] = atoi64(fs[0])
	}
	return out
}

func readUptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return 0
	}
	v, _ := parseFloat(fs[0])
	return int64(v)
}

// readThermalZones returns up to 8 hottest sensors (clipped to keep the JSON
// small — the router has 20+ tsens entries with near-identical readings).
func readThermalZones() []TempZone {
	matches, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	var zones []TempZone
	for _, p := range matches {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v := int64(atoi64(strings.TrimSpace(string(raw))))
		// Most kernels report millicelsius; this router quirk reports celsius
		// directly. Anything bigger than 1000 we interpret as milli-°C.
		if v >= 1000 {
			v /= 1000
		}
		label := filepath.Base(filepath.Dir(p))
		tb, err := os.ReadFile(filepath.Join(filepath.Dir(p), "type"))
		if err == nil {
			label = strings.TrimSpace(string(tb))
		}
		zones = append(zones, TempZone{Label: label, C: int(v)})
	}
	// Sort by temperature descending so the hottest sensor shows first.
	for i := 1; i < len(zones); i++ {
		for j := i; j > 0 && zones[j].C > zones[j-1].C; j-- {
			zones[j], zones[j-1] = zones[j-1], zones[j]
		}
	}
	if len(zones) > 8 {
		zones = zones[:8]
	}
	return zones
}

// readCPUPercent diffs the aggregate /proc/stat cpu line between calls. Returns
// -1 the first time so the UI knows to wait for the next sample.
func readCPUPercent() float64 {
	cpuMu.Lock()
	defer cpuMu.Unlock()

	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return -1
	}
	ln := strings.SplitN(string(b), "\n", 2)[0]
	if !strings.HasPrefix(ln, "cpu ") && !strings.HasPrefix(ln, "cpu\t") {
		return -1
	}
	fs := strings.Fields(ln)[1:]
	var total, idle int64
	for i, f := range fs {
		v := int64(atoi64(f))
		total += v
		if i == 3 { // idle column (user, nice, system, IDLE, iowait, ...)
			idle = v
		}
	}
	now := time.Now()
	last := cpuLast
	lastTS := cpuTS
	cpuLast = cpuSample{total: total, idle: idle}
	cpuTS = now
	if last.total == 0 || now.Sub(lastTS) > 30*time.Second {
		return -1 // first sample, or too stale
	}
	dt := float64(total - last.total)
	di := float64(idle - last.idle)
	if dt <= 0 {
		return -1
	}
	busy := 100 * (dt - di) / dt
	if busy < 0 {
		busy = 0
	}
	if busy > 100 {
		busy = 100
	}
	return busy
}

func parseFloat(s string) (float64, error) {
	// strconv.ParseFloat would do — keeping it tiny avoids another import here.
	var f float64
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		v := atoi64(s)
		f = float64(v)
	} else {
		whole := atoi64(s[:dot])
		frac := s[dot+1:]
		fracV := atoi64(frac)
		div := 1.0
		for range frac {
			div *= 10
		}
		f = float64(whole) + float64(fracV)/div
	}
	if neg {
		f = -f
	}
	return f, nil
}
