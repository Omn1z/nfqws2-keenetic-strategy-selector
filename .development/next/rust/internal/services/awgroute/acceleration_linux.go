//go:build linux

package awgroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"nfqws2strategy/internal/tools/logbuf"
	routerpath "nfqws2strategy/internal/tools/path"
)

const awgPPEIn = "N2S_AWGPPE_IN"
const awgPPEForward = "N2S_AWGPPE_FWD"
const awgPPEOut = "N2S_AWGPPE_OUT"
const awgSelectiveAccelerationEnv = "N2S_AWG_SELECTIVE_ACCEL"
const awgNativeNDMC = "LD_PRELOAD= LD_LIBRARY_PATH=/lib:/usr/lib ndmc"
const awgPPEInitialPackets = 32

func (state *awgAccelerationState) read(path string) ([]byte, error) {
	if state.readFile != nil {
		return state.readFile(path)
	}
	return os.ReadFile(path)
}
func (state *awgAccelerationState) execute(script string) (string, error) {
	if state.run != nil {
		return state.run(script)
	}
	return awgRun(script)
}

func syncAWGAccelerationDir(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		err = nil
	}
	return errors.Join(err, closeErr)
}

func saveAWGAccelerationJournal(path string, journal *awgAccelerationJournal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	// The service data directory is created durably by its store, not among
	// executable firewall hooks. Do not manufacture a new recovery root here.
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || !info.IsDir() {
		if err != nil {
			return fmt.Errorf("AWG acceleration data directory unavailable: %w", err)
		}
		return fmt.Errorf("AWG acceleration data path is not a directory")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".awg-acceleration-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncAWGAccelerationDir(filepath.Dir(path))
}

func (svc *Service) awgAccelerationJournalPath() string {
	if svc.cfg == nil || strings.TrimSpace(svc.cfg.DataDir) == "" {
		return ""
	}
	return filepath.Join(svc.cfg.DataDir, awgAccelerationJournalName)
}

func (state *awgAccelerationState) nativePreferences() (map[string]bool, error) {
	out, err := state.execute("if command -v ndmc >/dev/null 2>&1; then n2s_native_config=$(" + awgNativeNDMC + " -c 'show running-config') || exit $?; printf '%s\\n' \"$n2s_native_config\" | awk '/^[[:space:]]*(no )?ppe (hardware|software)$/ {print}'; fi")
	if err != nil {
		return nil, fmt.Errorf("read native PPE preferences: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	result := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		on := true
		if len(fields) > 0 && fields[0] == "no" {
			on = false
			fields = fields[1:]
		}
		if len(fields) != 2 || fields[0] != "ppe" || (fields[1] != "hardware" && fields[1] != "software") {
			return nil, fmt.Errorf("unrecognized native PPE preferences")
		}
		if _, duplicate := result[fields[1]]; duplicate {
			return nil, fmt.Errorf("duplicate native PPE preference")
		}
		result[fields[1]] = on
	}
	return result, nil
}

func (svc *Service) awgLoadAccelerationLocked(capture bool) error {
	state := &svc.acceleration
	if state.journal != nil {
		return nil
	}
	path := svc.awgAccelerationJournalPath()
	if path == "" {
		if capture {
			return fmt.Errorf("AWG acceleration recovery directory is unavailable")
		}
		return nil
	}
	boot, err := state.read("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	bootID := strings.TrimSpace(string(boot))
	if bootID == "" {
		return fmt.Errorf("kernel boot identity unavailable")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > 64<<10 {
			return fmt.Errorf("invalid AWG acceleration journal path")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		data, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		journal, e := decodeAWGAccelerationJournal(data)
		if e != nil {
			return e
		}
		if journal.BootID == bootID {
			state.journal = journal
			return nil
		}
		state.previousBootOwned = journal.Guarded
	} else if !os.IsNotExist(err) {
		return err
	}
	if !capture {
		return nil
	} // An older boot's running preferences are not today's baseline.
	// A missing journal must never turn already-managed native settings into
	// a made-up administrator baseline after a crash or manual file removal.
	if out, _ := state.execute("iptables -t mangle -S 2>/dev/null"); !state.previousBootOwned && (strings.Contains(out, "-N "+awgPPEIn) || strings.Contains(out, "-N "+awgPPEForward) || strings.Contains(out, "-N "+awgPPEOut)) {
		return fmt.Errorf("AWG PPE guards exist without a current recovery journal")
	}
	journal := &awgAccelerationJournal{Owner: awgAccelerationOwner, Version: 1, BootID: bootID, Sysctls: map[string]string{}}
	for _, key := range awgAccelSysctls {
		value, e := state.read("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		text := strings.TrimSpace(string(value))
		if _, e := strconv.ParseUint(text, 10, 32); e != nil {
			return fmt.Errorf("invalid acceleration value for %s", key)
		}
		journal.Sysctls[key] = text
	}
	journal.Native, err = state.nativePreferences()
	if err != nil {
		return err
	}
	if err = saveAWGAccelerationJournal(path, journal); err != nil {
		return err
	}
	state.journal = journal
	return nil
}

// Native commands are deliberately absent from persistent ndm hooks. Calling
// ndmc from its own firewall event can recursively queue another event.
func awgAccelerationSysctlScript(values map[string]string, reset bool) string {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, key := range keys {
		path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		b.WriteString("if [ -e " + path + " ]; then sysctl -w " + key + "=" + values[key] + " >/dev/null; fi\n")
	}
	if reset {
		b.WriteString("if [ -e /proc/sys/net/core/swnat_reset ]; then sysctl -w net.core.swnat_reset=1 >/dev/null; fi\n")
	}
	return b.String()
}

func awgAccelerationOffValues() map[string]string {
	values := map[string]string{}
	for _, key := range awgAccelSysctls {
		values[key] = "0"
	}
	return values
}

func awgSelectiveAccelerationValues() map[string]string {
	values := awgAccelerationOffValues()
	values["net.core.swnat"] = "1"
	values["net.hwnat.extif_offload"] = "1"
	values["net.hwnat.ppe_enabled"] = "1"
	return values
}

func (state *awgAccelerationState) setNative(desired map[string]bool) error {
	state.nativeChanged = false
	if len(desired) == 0 {
		return nil
	}
	current, err := state.nativePreferences()
	if err != nil {
		return err
	}
	for _, key := range []string{"hardware", "software"} {
		want, exists := desired[key]
		if !exists {
			continue
		}
		if have, known := current[key]; known && have == want {
			continue
		}
		command := "ppe " + key
		if !want {
			command = "no " + command
		}
		if _, err := state.execute(awgNativeNDMC + " -c '" + command + "' >/dev/null"); err != nil {
			return fmt.Errorf("set native PPE %s: %w", key, err)
		}
		state.nativeChanged = true
	}
	return nil
}

func (state *awgAccelerationState) valuesIntact(values map[string]string, native map[string]bool) bool {
	for key, want := range values {
		data, err := state.read("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if os.IsNotExist(err) {
			if want != "0" {
				return false
			}
			continue
		}
		if err != nil || strings.TrimSpace(string(data)) != want {
			return false
		}
	}
	if len(native) > 0 {
		actual, err := state.nativePreferences()
		if err != nil {
			return false
		}
		for key, want := range native {
			if have, known := actual[key]; !known || have != want {
				return false
			}
		}
	}
	return true
}

func (state *awgAccelerationState) disable() error {
	native := map[string]bool{}
	current, readErr := state.nativePreferences()
	for key := range current {
		native[key] = false
	}
	if state.journal != nil {
		for key := range state.journal.Native {
			native[key] = false
		}
	}
	err := state.setNative(native)
	if readErr != nil {
		_, err = state.execute("if command -v ndmc >/dev/null 2>&1; then " + awgNativeNDMC + " -c 'no ppe hardware' >/dev/null && " + awgNativeNDMC + " -c 'no ppe software' >/dev/null; fi")
	}
	_, sysErr := state.execute(awgAccelerationSysctlScript(awgAccelerationOffValues(), true))
	if readErr != nil || !state.valuesIntact(awgAccelerationOffValues(), native) {
		state.mode = "unsafe"
		return errors.Join(readErr, err, sysErr, fmt.Errorf("acceleration disable could not be verified"))
	}
	state.mode = "conservative"
	return errors.Join(err, sysErr)
}

func (svc *Service) awgBeginAccelerationTransition() error {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := svc.awgLoadAccelerationLocked(true); err != nil {
		return errors.Join(err, state.disable())
	}
	if state.capable && (state.mode == "selective" || state.mode == "paused") {
		if err := state.pauseSelectiveDataPath(); err != nil {
			return errors.Join(err, state.disable())
		}
		return nil
	}
	return state.disable()
}

func (svc *Service) awgSuspendAcceleration() error {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := svc.awgLoadAccelerationLocked(false); err != nil {
		return err
	}
	if state.journal == nil {
		if state.mode == "unsafe" {
			return state.disable()
		}
		return nil
	}
	return state.disable()
}

func (svc *Service) awgSelectiveCapableLocked() bool {
	state := &svc.acceleration
	if state.capChecked {
		return state.capable
	}
	state.capChecked = true
	if state.environment(awgSelectiveAccelerationEnv) != "1" || routerpath.IsOpenWrt() || state.journal == nil || len(state.journal.Native) != 2 {
		return false
	}
	compatible, err := state.read("/proc/device-tree/compatible")
	if err != nil {
		return false
	}
	parts := bytes.Split(compatible, []byte{0})
	model, soc := false, false
	for _, part := range parts {
		model = model || string(part) == "keenetic,kn-1012"
		soc = soc || string(part) == "mediatek,mt7981"
	}
	if !model || !soc {
		return false
	}
	_, err = state.execute(`set -e
p=N2S_PPE_CAP_$$
v4=0; v6=0
cleanup() {
 [ "$v4" != 1 ] || { iptables -w -t mangle -F "$p"; iptables -w -t mangle -X "$p"; }
 [ "$v6" != 1 ] || { ip6tables -w -t mangle -F "$p"; ip6tables -w -t mangle -X "$p"; }
}
trap cleanup EXIT
iptables -w -t mangle -N "$p"; v4=1
iptables -w -t mangle -A "$p" -j PPE
ip6tables -w -t mangle -N "$p"; v6=1
ip6tables -w -t mangle -A "$p" -j PPE
`)
	state.capable = err == nil
	return state.capable
}

func awgPPEGuardDocument(ifaces []string) string {
	var b strings.Builder
	b.WriteString("*mangle\n")
	for _, chain := range []string{awgPPEIn, awgPPEForward, awgPPEOut} {
		b.WriteString(":" + chain + " - [0:0]\n")
	}
	for _, chain := range []string{awgPPEIn, awgPPEForward, awgPPEOut} {
		for _, direction := range []string{"original", "reply"} {
			b.WriteString(fmt.Sprintf("-A %s -m connbytes --connbytes 1:%d --connbytes-mode packets --connbytes-dir %s -j PPE\n", chain, awgPPEInitialPackets, direction))
		}
		for _, flag := range []string{"SYN", "FIN", "RST"} {
			b.WriteString("-A " + chain + " -p tcp -m tcp --tcp-flags " + flag + " " + flag + " -j PPE\n")
		}
	}
	for _, iface := range ifaces {
		b.WriteString("-A " + awgPPEIn + " -i " + iface + " -j PPE\n")
		b.WriteString("-A " + awgPPEForward + " -i " + iface + " -j PPE\n-A " + awgPPEForward + " -o " + iface + " -j PPE\n")
		b.WriteString("-A " + awgPPEOut + " -o " + iface + " -j PPE\n")
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func awgPPEGuardShell(ifaces []string) string {
	var b strings.Builder
	for _, family := range []string{"iptables", "ip6tables"} {
		function := "n2s_ppe_" + strings.ReplaceAll(family, "6", "v6")
		b.WriteString(awgFirewallRestoreShell(function, family+"-restore", "N2SPPE", awgPPEGuardDocument(ifaces)))
		b.WriteString(function + "\n")
		for _, pair := range [][2]string{{"PREROUTING", awgPPEIn}, {"FORWARD", awgPPEForward}, {"POSTROUTING", awgPPEOut}} {
			position := "1"
			if family == "iptables" && pair[0] == "PREROUTING" {
				b.WriteString("N2S_PPE_POSITION=1\nif iptables -w -t mangle -S PREROUTING | awk '$1 == \"-A\" {ok = ($3 == \"-j\" && $4 == \"AWG2_MULTI\"); exit} END {exit !ok}'; then N2S_PPE_POSITION=2; fi\n")
				position = "$N2S_PPE_POSITION"
			}
			b.WriteString(family + " -w -t mangle -C " + pair[0] + " -j " + pair[1] + " 2>/dev/null || " + family + " -w -t mangle -I " + pair[0] + " " + position + " -j " + pair[1] + "\n")
		}
	}
	return b.String()
}

func awgPPEGuardsIntact(snapshot string, ifaces []string, allowPolicyPrefix bool) bool {
	expected := map[string][]string{}
	actual := map[string][]string{}
	for _, line := range strings.Split(awgPPEGuardDocument(ifaces), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 3 && fields[0] == "-A" {
			expected[fields[1]] = append(expected[fields[1]], awgCanonicalFirewallRule(line))
		}
	}
	// Real save output includes Generated/Completed comments after COMMIT.
	table := ""
	mangleCommitted := false
	for _, line := range strings.Split(snapshot, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			if table != "" {
				return false
			}
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if line == "COMMIT" {
			if table == "mangle" {
				mangleCommitted = true
			}
			table = ""
			continue
		}
		if table != "mangle" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 3 && fields[0] == "-A" {
			actual[fields[1]] = append(actual[fields[1]], awgCanonicalFirewallRule(line))
		}
	}
	for chain, rules := range expected {
		if len(actual[chain]) != len(rules) {
			return false
		}
		for i, rule := range rules {
			if actual[chain][i] != rule {
				return false
			}
		}
	}
	for _, pair := range [][2]string{{"PREROUTING", awgPPEIn}, {"FORWARD", awgPPEForward}, {"POSTROUTING", awgPPEOut}} {
		rules := actual[pair[0]]
		index := 0
		if allowPolicyPrefix && pair[0] == "PREROUTING" && len(rules) > 0 && rules[0] == "-A PREROUTING -j AWG2_MULTI" {
			index = 1
		}
		if len(rules) <= index || rules[index] != "-A "+pair[0]+" -j "+pair[1] {
			return false
		}
	}
	return len(ifaces) > 0 && mangleCommitted && table == ""
}

func (state *awgAccelerationState) guardsIntact() bool {
	if !state.accountingEnabled() {
		return false
	}
	for _, family := range []string{"iptables", "ip6tables"} {
		snapshot, err := state.execute(family + "-save")
		if err != nil || !awgPPEGuardsIntact(snapshot, state.ifaces, family == "iptables") || !awgNFQUEUEWindowSafe(snapshot, state.queue) {
			return false
		}
	}
	return true
}

func (state *awgAccelerationState) accountingEnabled() bool {
	value, err := state.read("/proc/sys/net/netfilter/nf_conntrack_acct")
	if err == nil {
		return strings.TrimSpace(string(value)) == "1"
	}
	// The verified Keenetic vendor kernel has compile-time accounting and no
	// writable acct switch. Never generalize ENOENT to an unverified kernel,
	// and never override an explicit zero or a real read failure.
	if !os.IsNotExist(err) || !state.capable {
		return false
	}
	if state.accountingProven {
		return true
	}
	for _, path := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"} {
		var data []byte
		if state.readFile != nil {
			data, err = state.read(path)
		} else {
			var f *os.File
			f, err = os.Open(path)
			if err == nil {
				data, err = io.ReadAll(io.LimitReader(f, 64<<10))
				closeErr := f.Close()
				if err == nil {
					err = closeErr
				}
			}
		}
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false
		}
		state.accountingProven = awgConntrackAccountingEvidence(data)
		return state.accountingProven
	}
	return false
}

func awgConntrackAccountingEvidence(data []byte) bool {
	// A bounded proc read can end inside its last row; discard that partial
	// row. All complete TCP/UDP flows must expose BOTH direction counters.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		if end := bytes.LastIndexByte(data, '\n'); end >= 0 {
			data = data[:end+1]
		} else {
			return false
		}
	}
	seen := map[string]bool{}
	anyPackets := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		tcpudp := false
		for i, field := range fields {
			if i > 3 {
				break
			}
			tcpudp = tcpudp || field == "tcp" || field == "udp"
		}
		if !tcpudp {
			continue
		}
		packets, byteCounters := 0, 0
		positive := false
		var tuple []string
		for _, field := range fields {
			if strings.HasPrefix(field, "packets=") {
				n, e := strconv.ParseUint(strings.TrimPrefix(field, "packets="), 10, 64)
				if e != nil {
					return false
				}
				packets++
				positive = positive || n > 0
			}
			if strings.HasPrefix(field, "bytes=") {
				if _, e := strconv.ParseUint(strings.TrimPrefix(field, "bytes="), 10, 64); e != nil {
					return false
				}
				byteCounters++
			}
			if len(tuple) < 4 && (strings.HasPrefix(field, "src=") || strings.HasPrefix(field, "dst=") || strings.HasPrefix(field, "sport=") || strings.HasPrefix(field, "dport=")) {
				tuple = append(tuple, field)
			}
		}
		if packets != 2 || byteCounters != 2 || len(tuple) != 4 {
			return false
		}
		anyPackets = anyPackets || positive
		seen[strings.Join(tuple, " ")] = true
	}
	return len(seen) >= 2 && anyPackets
}

func (svc *Service) awgAccelerationHook(body string, tunnels []awgMultiTunnel) string {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	state.ifaces = nil
	state.queue = 300
	if svc.cfg != nil {
		state.queue = svc.cfg.MainQueue
	}
	seen := map[string]bool{}
	for _, tunnel := range tunnels {
		if validAWGClientIfaceName(tunnel.Iface) && !seen[tunnel.Iface] {
			seen[tunnel.Iface] = true
			state.ifaces = append(state.ifaces, tunnel.Iface)
		}
	}
	prefix := "#!/bin/sh\n# NFQWS AWG acceleration: guarded native PPE\n" + awgAccelerationSysctlScript(awgAccelerationOffValues(), true)
	if svc.awgSelectiveCapableLocked() {
		if !state.journal.Guarded {
			state.journal.Guarded = true
			if err := saveAWGAccelerationJournal(svc.awgAccelerationJournalPath(), state.journal); err != nil {
				state.journal.Guarded = false
				state.capable = false
				logbuf.Append("awg2", "warn", "Не удалось сохранить состояние PPE; оставлен консервативный режим: "+err.Error())
			}
		}
		if state.capable {
			prefix += awgPPEGuardShell(state.ifaces)
		}
	}
	return prefix + strings.TrimPrefix(body, "#!/bin/sh\n")
}

func (state *awgAccelerationState) enableSelective() error {
	if !state.guardsIntact() {
		return fmt.Errorf("selective PPE guards are incomplete")
	}
	if err := state.setNative(map[string]bool{"hardware": true, "software": true}); err != nil {
		return err
	}
	// Native configuration can acknowledge before hw_nat's sysctls appear.
	// Let its queued firewall event finish, then require the actual data plane.
	if state.nativeChanged {
		if _, err := state.execute("sleep 1"); err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 5; attempt++ {
		ready := true
		for _, path := range []string{"/proc/sys/net/hwnat/ppe_enabled", "/proc/sys/net/hwnat/extif_offload"} {
			if _, err := state.read(path); err != nil {
				ready = false
			}
		}
		if ready {
			ready = state.nativeFlushAvailable()
		}
		if ready {
			return state.enableSelectiveDataPath()
		}
		if _, err := state.execute("sleep 1"); err != nil {
			return err
		}
	}
	return fmt.Errorf("native PPE data plane did not become available")
}

// Keenetic exposes ppe_flush as a write-only sysctl. A read returning EACCES
// does not indicate a missing capability; require a writable kernel node and
// check the actual write when invalidating instead.
func (state *awgAccelerationState) nativeFlushAvailable() bool {
	_, err := state.execute("test -e /proc/sys/net/hwnat/ppe_flush && test -w /proc/sys/net/hwnat/ppe_flush")
	return err == nil
}

func (state *awgAccelerationState) waitNativeRestoreSysctls(values map[string]string) error {
	var paths []string
	for _, key := range []string{"net.hwnat.ppe_enabled", "net.hwnat.extif_offload"} {
		if value, present := values[key]; present && value != "0" {
			paths = append(paths, "/proc/sys/"+strings.ReplaceAll(key, ".", "/"))
		}
	}
	if len(paths) == 0 {
		return nil
	}
	// Restoring native ON can acknowledge before its queued module/firewall
	// work finishes, just as initial selective activation can.
	if _, err := state.execute("sleep 1"); err != nil {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		ready := true
		for _, path := range paths {
			if _, err := state.read(path); err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("read original native PPE data plane: %w", err)
				}
				ready = false
			}
		}
		if ready {
			return nil
		}
		if attempt < 4 {
			if _, err := state.execute("sleep 1"); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("original native PPE data plane did not become available")
}

// Policy replacement and learned-IP updates need a cache boundary, not native
// configuration changes. Keep the module loaded while all forwarding uses the
// CPU, and leave re-enabling to the caller after its mutation is complete.
func (state *awgAccelerationState) pauseSelectiveDataPath() error {
	if !state.nativeFlushAvailable() {
		return fmt.Errorf("native PPE cache flush unavailable")
	}
	flush := awgAccelerationSysctlScript(awgAccelerationOffValues(), true) + "sysctl -w net.hwnat.ppe_flush=1 >/dev/null\n"
	if _, err := state.execute(flush); err != nil {
		return err
	}
	if !state.valuesIntact(awgAccelerationOffValues(), nil) || !state.guardsIntact() {
		return fmt.Errorf("PPE cache flush could not be verified")
	}
	state.mode = "paused"
	return nil
}

func (state *awgAccelerationState) enableSelectiveDataPath() error {
	values := awgSelectiveAccelerationValues()
	if _, err := state.execute(awgAccelerationSysctlScript(values, false)); err != nil {
		return err
	}
	if !state.valuesIntact(values, map[string]bool{"hardware": true, "software": true}) || !state.guardsIntact() {
		return fmt.Errorf("selective PPE state could not be verified")
	}
	state.mode = "selective"
	return nil
}

func (svc *Service) awgFinishAccelerationTransition() error {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.nfqwsChanges > 0 {
		return state.disable()
	}
	if svc.awgSelectiveCapableLocked() {
		if err := state.enableSelective(); err == nil {
			state.nfqwsDirty = false
			if state.lastMessage != "selective" {
				logbuf.Append("awg2", "info", "Ускорение прямого трафика включено; интерфейсы Amnezia исключены из PPE")
				state.lastMessage = "selective"
			}
			return nil
		} else {
			fallback := state.disable()
			if fallback == nil {
				state.nfqwsDirty = false
			}
			logbuf.Append("awg2", "warn", "Selective PPE недоступен; включён консервативный режим: "+err.Error())
			return fallback
		}
	}
	err := state.disable()
	if err == nil {
		state.nfqwsDirty = false
	}
	return err
}

func (svc *Service) awgSelectiveAccelerationActive() bool {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.mode == "selective" || state.mode == "paused" || state.mode == "unsafe"
}

func (svc *Service) awgInvalidateAccelerationCache() error {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.mode != "selective" && state.mode != "paused" && state.mode != "unsafe" {
		return nil
	}
	if (state.mode != "selective" && state.mode != "paused") || !state.capable {
		return state.disable()
	}
	if !state.nativeFlushAvailable() {
		return state.disable()
	}
	// Flush native cache entries without unloading hw_nat or changing ndm
	// preferences: native toggles here would rebuild the firewall on each new
	// learned IP, causing an event storm and repeated module removal.
	wasPaused := state.mode == "paused"
	if err := state.pauseSelectiveDataPath(); err != nil {
		return errors.Join(err, state.disable())
	}
	if wasPaused {
		return nil
	}
	if err := state.enableSelectiveDataPath(); err != nil {
		return errors.Join(err, state.disable())
	}
	return nil
}

func (svc *Service) awgAccelerationIntact() bool {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.nfqwsDirty && state.nfqwsChanges == 0 && state.journal != nil {
		return false
	}
	if state.mode == "selective" {
		values := awgSelectiveAccelerationValues()
		return state.valuesIntact(values, map[string]bool{"hardware": true, "software": true}) && state.guardsIntact()
	}
	if state.mode == "unsafe" {
		return false
	}
	if state.mode == "paused" {
		return false
	}
	current, err := state.nativePreferences()
	if err != nil {
		return false
	}
	native := map[string]bool{}
	for key := range current {
		native[key] = false
	}
	return state.valuesIntact(awgAccelerationOffValues(), native)
}

func (svc *Service) awgRestoreAcceleration() error {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := svc.awgLoadAccelerationLocked(false); err != nil {
		return err
	}
	if state.journal == nil && !state.previousBootOwned {
		return nil
	}
	journal := state.journal
	if journal != nil {
		if err := state.setNative(journal.Native); err != nil {
			state.mode = "unsafe"
			return err
		}
		if state.nativeChanged && (journal.Native["hardware"] || journal.Native["software"]) {
			if err := state.waitNativeRestoreSysctls(journal.Sysctls); err != nil {
				state.mode = "unsafe"
				return err
			}
		}
		if _, err := state.execute(awgAccelerationSysctlScript(journal.Sysctls, true)); err != nil {
			state.mode = "unsafe"
			return err
		}
		if !state.valuesIntact(journal.Sysctls, journal.Native) {
			state.mode = "unsafe"
			return fmt.Errorf("original acceleration state restoration could not be verified")
		}
	}
	needGuards := state.previousBootOwned || (journal != nil && journal.Guarded)
	var cleanup strings.Builder
	if needGuards {
		for _, family := range []string{"iptables", "ip6tables"} {
			for _, pair := range [][2]string{{"PREROUTING", awgPPEIn}, {"FORWARD", awgPPEForward}, {"POSTROUTING", awgPPEOut}} {
				cleanup.WriteString("while " + family + " -w -t mangle -D " + pair[0] + " -j " + pair[1] + " 2>/dev/null; do :; done\n" + family + " -w -t mangle -F " + pair[1] + " 2>/dev/null || true\n" + family + " -w -t mangle -X " + pair[1] + " 2>/dev/null || true\n")
			}
		}
	}
	if needGuards {
		if _, err := state.execute(cleanup.String()); err != nil {
			return err
		}
		for _, family := range []string{"iptables", "ip6tables"} {
			snapshot, err := state.execute(family + " -w -t mangle -S")
			if err != nil {
				return err
			}
			for _, chain := range []string{awgPPEIn, awgPPEForward, awgPPEOut} {
				if strings.Contains(snapshot, "-N "+chain) || strings.Contains(snapshot, "-j "+chain) {
					return fmt.Errorf("PPE cleanup remains incomplete; recovery journal retained")
				}
			}
		}
	}
	if err := os.Remove(svc.awgAccelerationJournalPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncAWGAccelerationDir(filepath.Dir(svc.awgAccelerationJournalPath())); err != nil {
		return err
	}
	state.journal = nil
	state.mode = ""
	state.capChecked = false
	state.capable = false
	state.accountingProven = false
	state.ifaces = nil
	state.previousBootOwned = false
	state.nfqwsDirty = false
	return nil
}

// NFQWS lifecycle changes are bracketed by the app. Do not let a watchdog or
// DNS cache update re-enable native PPE while its queue rules are incomplete.
func (svc *Service) SuspendAccelerationForNFQWSChange() error {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	state.nfqwsChanges++
	state.nfqwsDirty = true
	if state.journal == nil {
		return nil
	}
	if err := state.disable(); err != nil {
		state.nfqwsChanges--
		return err
	}
	return nil
}
func (svc *Service) ResumeAccelerationAfterNFQWSChange() {
	state := &svc.acceleration
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.nfqwsChanges > 0 {
		state.nfqwsChanges--
	}
	// The next policy audit rebuilds the saved hook and verifies current queue
	// windows before enabling. No assumptions about changed engine rules here.
}

func awgNFQUEUEWindowSafe(snapshot string, mainQueue int) bool {
	if mainQueue < 0 || mainQueue > 65535 {
		return false
	}
	for _, line := range strings.Split(snapshot, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "-A ") {
			continue
		}
		fields, valid := awgAccelerationRuleTokens(line)
		if !valid {
			return false
		}
		var filtered []string
		for i := 0; i < len(fields); i++ {
			if fields[i] == "--comment" {
				if i+1 >= len(fields) {
					return false
				}
				i++
				continue
			}
			filtered = append(filtered, fields[i])
		}
		fields = filtered
		queueRule := false
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "-j" && fields[i+1] == "NFQUEUE" {
				queueRule = true
			}
		}
		if !queueRule {
			continue
		}
		queue := -1
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "--queue-num" {
				value, e := strconv.Atoi(fields[i+1])
				if e != nil {
					return false
				}
				queue = value
			}
		}
		if queue < 0 || queue > 65535 {
			return false
		}
		bounded, control := false, false
		var window, mode, direction string
		negatedWindow := false
		tcp := false
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "-p" && fields[i+1] == "tcp" && !(i > 0 && fields[i-1] == "!") {
				tcp = true
			}
		}
		for i := 0; i < len(fields); i++ {
			switch fields[i] {
			case "--connbytes":
				if i+1 < len(fields) {
					window = fields[i+1]
					negatedWindow = (i > 0 && fields[i-1] == "!") || window == "!"
				}
			case "--connbytes-mode":
				if i > 0 && fields[i-1] == "!" {
					negatedWindow = true
				}
				if i+1 < len(fields) {
					mode = fields[i+1]
				}
			case "--connbytes-dir":
				if i > 0 && fields[i-1] == "!" {
					negatedWindow = true
				}
				if i+1 < len(fields) {
					direction = fields[i+1]
				}
			case "--tcp-flags":
				if i+2 < len(fields) && !(i > 0 && fields[i-1] == "!") {
					mask, e := strconv.ParseUint(awgCanonicalTCPFlags(fields[i+1]), 16, 8)
					flags, e2 := strconv.ParseUint(awgCanonicalTCPFlags(fields[i+2]), 16, 8)
					control = tcp && e == nil && e2 == nil && flags&mask&7 != 0
				}
			}
		}
		parts := strings.Split(window, ":")
		if !negatedWindow && len(parts) == 2 && mode == "packets" && (direction == "original" || direction == "reply") {
			lower, e := strconv.Atoi(parts[0])
			upper, e2 := strconv.Atoi(parts[1])
			bounded = e == nil && e2 == nil && lower >= 1 && upper >= lower && upper <= awgPPEInitialPackets
		}
		if !bounded && !control {
			return false
		}
	}
	return true
}

// iptables-save quotes comments. Tokenize without executing/expanding anything
// so option-looking text inside --comment can never grant NFQUEUE coverage.
func awgAccelerationRuleTokens(line string) ([]string, bool) {
	var result []string
	var word strings.Builder
	quote := byte(0)
	escaped, active := false, false
	flush := func() {
		if active {
			result = append(result, word.String())
			word.Reset()
			active = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			word.WriteByte(c)
			escaped = false
			active = true
			continue
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			active = true
			continue
		}
		if c == '\\' {
			escaped = true
			active = true
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			active = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			active = true
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			flush()
			continue
		}
		word.WriteByte(c)
		active = true
	}
	if quote != 0 || escaped {
		return nil, false
	}
	flush()
	return result, true
}
