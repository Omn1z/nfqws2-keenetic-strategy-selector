package netmon

import (
	"math"
	"strconv"
	"strings"
	"time"
)

type cpuSample struct {
	total, idle int64
}

type procCPUSample struct {
	ticks int64 // utime + stime
	start int64 // starttime identifies the process independently of PID reuse
	at    time.Time
}

func parseCPUSample(line string) (cpuSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, false
	}
	var sample cpuSample
	// Linux guest/guest_nice are already included in user/nice. Adding the
	// guest columns again biases both the denominator and the busy estimate.
	for i, field := range fields[1:] {
		if i == 8 {
			break
		}
		value, err := strconv.ParseInt(field, 10, 64)
		if err != nil || value < 0 || value > math.MaxInt64-sample.total {
			return cpuSample{}, false
		}
		sample.total += value
		if i == 3 || i == 4 { // idle + iowait are not executing CPU work
			sample.idle += value
		}
	}
	return sample, true
}

func aggregateCPUPercent(last, current cpuSample, elapsed time.Duration) float64 {
	if elapsed <= 0 || elapsed > 30*time.Second {
		return -1
	}
	total, idle := current.total-last.total, current.idle-last.idle
	if total <= 0 || idle < 0 {
		return -1
	}
	busy := 100 * float64(total-idle) / float64(total)
	if busy < 0 {
		return 0
	}
	if busy > 100 {
		return 100
	}
	return busy
}

func processCPUPercent(last, current procCPUSample, clockTicks int64) float64 {
	elapsed := current.at.Sub(last.at)
	if last.start != current.start || elapsed <= 0 || elapsed > 30*time.Second || clockTicks <= 0 || current.ticks < last.ticks {
		return -1
	}
	return float64(current.ticks-last.ticks) / float64(clockTicks) / elapsed.Seconds() * 100
}
