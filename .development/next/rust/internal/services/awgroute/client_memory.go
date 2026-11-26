package awgroute

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// AWG has one Go runtime per tunnel. These are soft per-process heap limits,
// not reservations or router-wide RSS limits; leave room for the panel, kernel
// and other tunnels on smaller devices. Apply a policy only when starting a
// daemon: changing its GC policy must never replace a working tunnel.
type awgDaemonMemoryProfile struct {
	limitMiB  int
	gcPercent int
}

func awgDaemonMemoryForRAM(totalKB uint64) awgDaemonMemoryProfile {
	switch {
	case totalKB == 0:
		// Missing /proc data must not silently select the largest-device policy.
		return awgDaemonMemoryProfile{64, 50}
	case totalKB <= 256*1024:
		return awgDaemonMemoryProfile{48, 50}
	case totalKB <= 512*1024:
		return awgDaemonMemoryProfile{64, 50}
	case totalKB <= 1024*1024:
		return awgDaemonMemoryProfile{96, 75}
	default:
		return awgDaemonMemoryProfile{128, 100}
	}
}

func awgMemTotalKB(meminfo []byte) uint64 {
	for _, line := range strings.Split(string(meminfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
			continue
		}
		total, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return total
	}
	return 0
}

func awgDaemonMemoryEnvironment(meminfo []byte) string {
	profile := awgDaemonMemoryForRAM(awgMemTotalKB(meminfo))
	return fmt.Sprintf("GOMEMLIMIT=%dMiB GOGC=%d GODEBUG=madvdontneed=1", profile.limitMiB, profile.gcPercent)
}

func awgDaemonMemoryEnvironmentOS() string {
	meminfo, _ := os.ReadFile("/proc/meminfo")
	return awgDaemonMemoryEnvironment(meminfo)
}
