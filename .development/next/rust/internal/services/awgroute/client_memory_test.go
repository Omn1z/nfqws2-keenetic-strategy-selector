package awgroute

import "testing"

func TestAWGDaemonMemoryBudgetScalesWithRouterRAM(t *testing.T) {
	for _, tc := range []struct {
		name    string
		totalKB uint64
		want    awgDaemonMemoryProfile
	}{
		{"unknown", 0, awgDaemonMemoryProfile{64, 50}},
		{"128 MiB", 128 * 1024, awgDaemonMemoryProfile{48, 50}},
		{"256 MiB boundary", 256 * 1024, awgDaemonMemoryProfile{48, 50}},
		{"Keenetic 512 MiB physical RAM", 497676, awgDaemonMemoryProfile{64, 50}},
		{"512 MiB boundary", 512 * 1024, awgDaemonMemoryProfile{64, 50}},
		{"BE7000", 800 * 1024, awgDaemonMemoryProfile{96, 75}},
		{"1 GiB boundary", 1024 * 1024, awgDaemonMemoryProfile{96, 75}},
		{"large router", 2 * 1024 * 1024, awgDaemonMemoryProfile{128, 100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := awgDaemonMemoryForRAM(tc.totalKB); got != tc.want {
				t.Fatalf("memory policy for %d kB = %+v, want %+v", tc.totalKB, got, tc.want)
			}
		})
	}
}

func TestAWGDaemonMemoryEnvironmentUsesTotalRAMNotMomentaryFreeMemory(t *testing.T) {
	for _, free := range []string{"0", "1000", "400000"} {
		meminfo := []byte("MemTotal:       497676 kB\nMemAvailable: " + free + " kB\n")
		if got, want := awgDaemonMemoryEnvironment(meminfo), "GOMEMLIMIT=64MiB GOGC=50 GODEBUG=madvdontneed=1"; got != want {
			t.Fatalf("env with %s kB available = %q, want %q", free, got, want)
		}
	}
}

func TestAWGDaemonMemoryMalformedMeminfoUsesConservativePolicy(t *testing.T) {
	for _, meminfo := range []string{"", "MemAvailable: 900000 kB\n", "MemTotal: -1 kB\n", "MemTotal: 900000 bytes\n", "MemTotal: 18446744073709551616 kB\n"} {
		if got := awgDaemonMemoryEnvironment([]byte(meminfo)); got != "GOMEMLIMIT=64MiB GOGC=50 GODEBUG=madvdontneed=1" {
			t.Fatalf("unexpected fallback for %q: %q", meminfo, got)
		}
	}
}
