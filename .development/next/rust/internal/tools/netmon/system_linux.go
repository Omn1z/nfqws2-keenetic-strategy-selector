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

var (
	cpuMu   sync.Mutex
	cpuLast cpuSample
	cpuTS   time.Time
)

// readSystem performs one best-effort OS sample. System throttles this scan
// across all pollers so CPU deltas are not taken a few milliseconds apart.
func readSystem() SystemStats {
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
	topProcN     = 10   // cards on the dashboard
	topProcMinKB = 1024 // ignore processes smaller than ~1 MB so the list isn't 50 tiny rows
)

var (
	procCPUMu   sync.Mutex
	procCPULast = map[int]procCPUSample{}
)

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
		// Field offsets after state (index 0): utime 11, stime 12,
		// starttime 19 (jiffies since boot).
		if len(fs) < 22 {
			continue
		}
		// Kernel threads have flag bit 21 (PF_KTHREAD) set in field 9 (after the
		// 0-based state). We don't need exact decoding — they ALSO have a zero
		// RSS, so the rss filter below drops them naturally. Keep the simple path.
		utime, _ := strconv.ParseInt(fs[11], 10, 64)
		stime, _ := strconv.ParseInt(fs[12], 10, 64)
		start, parseErr := strconv.ParseInt(fs[19], 10, 64)
		if parseErr != nil || start < 0 {
			continue
		}
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
		current := procCPUSample{ticks: totalTicks, start: start, at: now}
		if last, ok := procCPULast[pid]; ok {
			cpuPct = processCPUPercent(last, current, clk)
		}
		procCPULast[pid] = current

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
	current, ok := parseCPUSample(ln)
	if !ok {
		return -1
	}
	now := time.Now()
	last := cpuLast
	lastTS := cpuTS
	cpuLast = current
	cpuTS = now
	if lastTS.IsZero() {
		return -1
	}
	return aggregateCPUPercent(last, current, now.Sub(lastTS))
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
