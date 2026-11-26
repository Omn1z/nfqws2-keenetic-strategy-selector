package awgroute

import (
	"fmt"
	"strings"
)

const connectionProbeMark = 0x60000000 // includes the diagnostic bypass bit
const connectionProbeTable = "997"
const connectionProbeRule = "pref 65 fwmark 0x60000000/0xe0000000 table " + connectionProbeTable

// A private marked route makes a cold reserve testable before it has any LAN
// rules. The blackhole forbids falling through to WAN if its device disappears.
// These entries are scoped to diagnostic sockets and never match LAN traffic.
func prepareConnectionProbe(iface string, run func(string) (string, error)) (func(), error) {
	if _, err := ValidateSpeedTestIface(iface); err != nil || iface == "" {
		return nil, fmt.Errorf("некорректный интерфейс проверки AWG")
	}
	cleanup := func() {
		_, _ = run("ip rule del " + connectionProbeRule + " 2>/dev/null")
		_, _ = run("ip route flush table " + connectionProbeTable)
	}
	// Reclaim only an interrupted probe's exact selector. Refuse to overwrite
	// an unrelated populated table if the reserved selector is not present.
	rules, err := run("ip rule show")
	if err != nil {
		return nil, err
	}
	owned := false
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 7 && strings.Join(fields, " ") == "65: from all fwmark 0x60000000/0xe0000000 lookup "+connectionProbeTable {
			owned = true
		}
	}
	if owned {
		cleanup()
	}
	routes, err := run("ip route show table " + connectionProbeTable)
	if err != nil {
		// An unused numeric table can report ENOENT on some iproute2 builds.
		if !strings.Contains(routes, "FIB table does not exist") {
			return nil, fmt.Errorf("таблица проверки AWG: %w", err)
		}
	}
	if strings.TrimSpace(routes) != "" && !strings.Contains(routes, "FIB table does not exist") {
		return nil, fmt.Errorf("таблица %s уже занята; проверка AWG не изменяла её", connectionProbeTable)
	}
	for _, cmd := range []string{
		"ip route add blackhole default table " + connectionProbeTable + " metric 1000",
		"ip route add default dev " + iface + " table " + connectionProbeTable + " metric 1",
		"ip rule add " + connectionProbeRule,
	} {
		if output, err := run(cmd); err != nil {
			cleanup()
			return nil, fmt.Errorf("маршрут проверки AWG: %w: %s", err, strings.TrimSpace(output))
		}
	}
	return cleanup, nil
}
