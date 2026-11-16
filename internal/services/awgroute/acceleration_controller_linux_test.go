//go:build linux

package awgroute

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

type accelerationFixture struct {
	svc                                              *Service
	flags                                            map[string]string
	native                                           map[string]bool
	boot, compatible, optin                          string
	guards, failNativeRead, failNativeOff, failProbe bool
	flushMissing, flushFailure                       bool
	acctMissing                                      bool
	acctValue                                        string
	acctErr                                          error
	conntrack                                        string
	commands                                         []string
}

func newAccelerationFixture(t *testing.T) *accelerationFixture {
	t.Helper()
	f := &accelerationFixture{flags: map[string]string{}, native: map[string]bool{"hardware": true, "software": false}, boot: "test-boot", compatible: "keenetic,kn-1012\x00mediatek,mt7981\x00", optin: "1"}
	for _, key := range awgAccelSysctls {
		f.flags[key] = "0"
	}
	f.flags["net.netfilter.nf_conntrack_fastnat"] = "1"
	f.flags["net.core.swnat"] = "1"
	f.flags["net.hwnat.extif_offload"] = "1"
	f.flags["net.hwnat.ppe_enabled"] = "1"
	f.svc = &Service{cfg: &config.Config{DataDir: t.TempDir(), MainQueue: 300}}
	f.attach(f.svc)
	return f
}

func (f *accelerationFixture) attach(svc *Service) {
	svc.acceleration.getenv = func(string) string { return f.optin }
	svc.acceleration.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/sys/kernel/random/boot_id":
			return []byte(f.boot), nil
		case "/proc/device-tree/compatible":
			return []byte(f.compatible), nil
		case "/proc/sys/net/netfilter/nf_conntrack_acct":
			if f.acctErr != nil {
				return nil, f.acctErr
			}
			if f.acctMissing {
				return nil, os.ErrNotExist
			}
			if f.acctValue != "" {
				return []byte(f.acctValue), nil
			}
			return []byte("1"), nil
		case "/proc/net/nf_conntrack":
			return []byte(f.conntrack), nil
		}
		key := strings.ReplaceAll(strings.TrimPrefix(path, "/proc/sys/"), "/", ".")
		if value, ok := f.flags[key]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}
	svc.acceleration.run = func(script string) (string, error) {
		f.commands = append(f.commands, script)
		if strings.HasPrefix(script, "test -e /proc/sys/net/hwnat/ppe_flush") {
			if f.flushMissing {
				return "", os.ErrNotExist
			}
			return "", nil
		}
		if f.flushFailure && strings.Contains(script, "sysctl -w net.hwnat.ppe_flush=1") {
			return "", errors.New("hardware cache flush failed")
		}
		if strings.Contains(script, "show running-config") {
			if f.failNativeRead {
				return "", errors.New("native status unavailable")
			}
			var lines []string
			for _, key := range []string{"hardware", "software"} {
				if on, exists := f.native[key]; exists {
					prefix := ""
					if !on {
						prefix = "no "
					}
					lines = append(lines, prefix+"ppe "+key)
				}
			}
			return strings.Join(lines, "\n"), nil
		}
		if strings.Contains(script, "p=N2S_PPE_CAP_") {
			if f.failProbe {
				return "", errors.New("IPv6 PPE unsupported")
			}
			return "", nil
		}
		if strings.HasPrefix(script, "iptables-save") || strings.HasPrefix(script, "ip6tables-save") {
			if !f.guards {
				return "*mangle\nCOMMIT\n", nil
			}
			ifaces := svc.acceleration.ifaces
			if len(ifaces) == 0 {
				ifaces = []string{"awg0"}
			}
			doc := awgPPEGuardDocument(ifaces)
			parents := "-A PREROUTING -j " + awgPPEIn + "\n-A FORWARD -j " + awgPPEForward + "\n-A POSTROUTING -j " + awgPPEOut + "\n"
			if strings.HasPrefix(script, "iptables-save") {
				parents = "-A PREROUTING -j AWG2_MULTI\n" + parents
			}
			parents += "-A nfqws_post -p tcp -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 300\n"
			return strings.Replace(doc, "COMMIT\n", parents+"COMMIT\n", 1), nil
		}
		if strings.Contains(script, " -t mangle -S") {
			if f.guards {
				return "-N " + awgPPEIn + "\n-N " + awgPPEForward + "\n-N " + awgPPEOut + "\n", nil
			}
			return "", nil
		}
		for _, key := range []string{"hardware", "software"} {
			if strings.Contains(script, " -c 'no ppe "+key+"'") {
				if f.failNativeOff {
					return "", errors.New("native disable failed")
				}
				f.native[key] = false
			}
			if strings.Contains(script, " -c 'ppe "+key+"'") {
				f.native[key] = true
			}
		}
		for _, match := range regexp.MustCompile(`sysctl -w ([a-z0-9_.]+)=([0-9]+)`).FindAllStringSubmatch(script, -1) {
			if _, exists := f.flags[match[1]]; exists {
				f.flags[match[1]] = match[2]
			}
		}
		if strings.Contains(script, "-D PREROUTING -j "+awgPPEIn) {
			f.guards = false
		}
		return "", nil
	}
}

func (f *accelerationFixture) beginSelective(t *testing.T) {
	t.Helper()
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	f.svc.awgAccelerationHook("#!/bin/sh\n# policy fixture\n", []awgMultiTunnel{{Iface: "awg0"}, {Iface: "awg1"}})
	f.guards = true
	if err := f.svc.awgFinishAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	if f.svc.acceleration.mode != "selective" {
		t.Fatalf("selective mode unavailable: %s", f.svc.acceleration.mode)
	}
}

func TestAccelerationJournalPreservesOriginalAcrossRefreshAndProcessRestart(t *testing.T) {
	f := newAccelerationFixture(t)
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	path := f.svc.awgAccelerationJournalPath()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("refresh replaced original settings with managed settings")
	}
	next := &Service{cfg: f.svc.cfg}
	f.attach(next)
	if err := next.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	if err := next.awgRestoreAcceleration(); err != nil {
		t.Fatal(err)
	}
	if !f.native["hardware"] || f.native["software"] || f.flags["net.netfilter.nf_conntrack_fastnat"] != "1" || f.flags["net.core.swnat"] != "1" {
		t.Fatalf("original settings not restored: native=%v flags=%v", f.native, f.flags)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("completed journal remains: %v", err)
	}
}

func TestAccelerationRestoreWaitsForOriginalHardwareNodes(t *testing.T) {
	f := newAccelerationFixture(t)
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	read, run := f.svc.acceleration.readFile, f.svc.acceleration.run
	sleeps := 0
	f.svc.acceleration.readFile = func(path string) ([]byte, error) {
		if strings.HasPrefix(path, "/proc/sys/net/hwnat/") && sleeps < 2 {
			return nil, os.ErrNotExist
		}
		return read(path)
	}
	f.svc.acceleration.run = func(script string) (string, error) {
		if script == "sleep 1" {
			sleeps++
		}
		return run(script)
	}
	if err := f.svc.awgRestoreAcceleration(); err != nil {
		t.Fatal(err)
	}
	if sleeps != 2 || !f.native["hardware"] || f.native["software"] || f.flags["net.hwnat.ppe_enabled"] != "1" || f.flags["net.hwnat.extif_offload"] != "1" {
		t.Fatalf("delayed original hardware state was not restored: waits=%d native=%v flags=%v", sleeps, f.native, f.flags)
	}
	if _, err := os.Stat(f.svc.awgAccelerationJournalPath()); !os.IsNotExist(err) {
		t.Fatalf("completed restoration retained its journal: %v", err)
	}
}

func TestAccelerationRestoreRetainsJournalWhenHardwareDoesNotReturn(t *testing.T) {
	f := newAccelerationFixture(t)
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	read, run := f.svc.acceleration.readFile, f.svc.acceleration.run
	sleeps, start := 0, len(f.commands)
	f.svc.acceleration.readFile = func(path string) ([]byte, error) {
		if strings.HasPrefix(path, "/proc/sys/net/hwnat/") {
			return nil, os.ErrNotExist
		}
		return read(path)
	}
	f.svc.acceleration.run = func(script string) (string, error) {
		if script == "sleep 1" {
			sleeps++
		}
		return run(script)
	}
	if err := f.svc.awgRestoreAcceleration(); err == nil {
		t.Fatal("missing original hardware was reported as restored")
	}
	if sleeps == 0 || sleeps > 5 || f.svc.acceleration.mode != "unsafe" {
		t.Fatalf("missing hardware did not stop within its bounded wait: waits=%d mode=%s", sleeps, f.svc.acceleration.mode)
	}
	if _, err := os.Stat(f.svc.awgAccelerationJournalPath()); err != nil {
		t.Fatalf("failed restoration lost its recovery journal: %v", err)
	}
	if strings.Contains(strings.Join(f.commands[start:], "\n"), "sysctl -w net.hwnat.ppe_enabled=1") {
		t.Fatal("hardware preferences were written before their nodes appeared")
	}
	f.svc.acceleration.readFile = read
	if err := f.svc.awgRestoreAcceleration(); err != nil {
		t.Fatalf("restoration did not recover when its hardware returned: %v", err)
	}
}

func TestAccelerationRestoreDoesNotWaitForUnchangedOffOrUnsupportedHardware(t *testing.T) {
	for _, scenario := range []string{"native off", "hardware nodes unsupported", "native already restored"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAccelerationFixture(t)
			if scenario == "native off" {
				f.native = map[string]bool{"hardware": false, "software": false}
				f.flags["net.hwnat.ppe_enabled"] = "0"
				f.flags["net.hwnat.extif_offload"] = "0"
			}
			if scenario == "hardware nodes unsupported" {
				delete(f.flags, "net.hwnat.ppe_enabled")
				delete(f.flags, "net.hwnat.extif_offload")
			}
			if err := f.svc.awgBeginAccelerationTransition(); err != nil {
				t.Fatal(err)
			}
			if scenario == "native already restored" {
				f.native["hardware"] = true
			}
			start := len(f.commands)
			if err := f.svc.awgRestoreAcceleration(); err != nil {
				t.Fatal(err)
			}
			for _, command := range f.commands[start:] {
				if command == "sleep 1" {
					t.Fatal("restoration waited without a changed native ON hardware requirement")
				}
			}
		})
	}
}

func TestAccelerationSelectiveRequiresOptinModelBothFamiliesAndGuards(t *testing.T) {
	for _, scenario := range []string{"enabled", "no optin", "different model", "IPv6 unsupported", "missing guards"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAccelerationFixture(t)
			switch scenario {
			case "no optin":
				f.optin = ""
			case "different model":
				f.compatible = "keenetic,other\x00mediatek,mt7981\x00"
			case "IPv6 unsupported":
				f.failProbe = true
			}
			if err := f.svc.awgBeginAccelerationTransition(); err != nil {
				t.Fatal(err)
			}
			hook := f.svc.awgAccelerationHook("#!/bin/sh\n# fixture\n", []awgMultiTunnel{{Iface: "awg0"}})
			if strings.Contains(hook, "ndmc") {
				t.Fatal("persistent ndm hook invokes native commands recursively")
			}
			f.guards = scenario != "missing guards"
			if err := f.svc.awgFinishAccelerationTransition(); err != nil {
				t.Fatal(err)
			}
			if scenario == "enabled" {
				if !f.svc.awgSelectiveAccelerationActive() || !f.svc.awgAccelerationIntact() || !f.native["hardware"] || !f.native["software"] || f.flags["net.core.swnat"] != "1" {
					t.Fatal("validated selective state was not enabled")
				}
				for key, want := range awgSelectiveAccelerationValues() {
					if f.flags[key] != want {
						t.Fatalf("selective accelerator %s=%s, want %s", key, f.flags[key], want)
					}
				}
			} else if f.svc.awgSelectiveAccelerationActive() || f.native["hardware"] || f.native["software"] || f.flags["net.core.swnat"] != "0" {
				t.Fatal("unsupported/unprotected configuration left acceleration active")
			}
		})
	}
}

func TestAccelerationFallbackNeverLabelsUnverifiedNativeStateSafe(t *testing.T) {
	f := newAccelerationFixture(t)
	if err := os.WriteFile(filepath.Join(f.svc.cfg.DataDir, awgAccelerationJournalName), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	f.failNativeRead = true
	if err := f.svc.awgBeginAccelerationTransition(); err == nil {
		t.Fatal("corrupt journal/native failure was hidden")
	}
	if f.svc.acceleration.mode != "unsafe" || !f.svc.awgSelectiveAccelerationActive() {
		t.Fatal("unknown native state was advertised as conservative")
	}
	if err := f.svc.awgInvalidateAccelerationCache(); err == nil {
		t.Fatal("unverifiable native state cleared invalidation debt")
	}
	f.failNativeRead = false
	if err := f.svc.awgInvalidateAccelerationCache(); err != nil {
		t.Fatal(err)
	}
	if f.native["hardware"] || f.native["software"] || f.svc.awgSelectiveAccelerationActive() {
		t.Fatal("verified fallback did not disable native PPE")
	}
}

func TestAccelerationFallbackWithoutJournalStillDisablesNativePPE(t *testing.T) {
	f := newAccelerationFixture(t)
	f.guards = true
	if err := f.svc.awgBeginAccelerationTransition(); err == nil {
		t.Fatal("managed guards without journal accepted as administrator baseline")
	}
	if f.native["hardware"] || f.native["software"] || f.svc.acceleration.mode != "conservative" {
		t.Fatal("journal load failure left native acceleration enabled")
	}
}

func TestAccelerationCacheInvalidationChecksGuardsAndVerifiedFallback(t *testing.T) {
	f := newAccelerationFixture(t)
	f.beginSelective(t)
	start := len(f.commands)
	if err := f.svc.awgInvalidateAccelerationCache(); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(f.commands[start:], "\n")
	disable := strings.Index(commands, "sysctl -w net.hwnat.ppe_enabled=0")
	reset := strings.Index(commands, "sysctl -w net.hwnat.ppe_flush=1")
	enable := strings.Index(commands, "sysctl -w net.hwnat.ppe_enabled=1")
	if disable < 0 || reset < disable || enable < reset || !strings.Contains(commands, "swnat_reset=1") {
		t.Fatal("hardware data plane was not paused/flushed before re-enabling")
	}
	if strings.Contains(commands, "-c 'no ppe ") || strings.Contains(commands, "-c 'ppe ") || !f.native["hardware"] || !f.native["software"] {
		t.Fatal("DNS invalidation changed native preferences and triggered module churn")
	}
	f.guards = false
	if err := f.svc.awgInvalidateAccelerationCache(); err == nil {
		t.Fatal("missing guard repair failure was hidden")
	}
	if f.native["hardware"] || f.native["software"] || f.svc.awgSelectiveAccelerationActive() {
		t.Fatal("guard failure did not keep verified fallback")
	}
}

func TestAccelerationInPlacePolicyTransitionKeepsNativeModuleAndPausedRetrySafe(t *testing.T) {
	f := newAccelerationFixture(t)
	f.beginSelective(t)
	start := len(f.commands)
	for attempt := 0; attempt < 2; attempt++ {
		if err := f.svc.awgBeginAccelerationTransition(); err != nil {
			t.Fatal(err)
		}
		if f.svc.acceleration.mode != "paused" || !f.svc.awgSelectiveAccelerationActive() || f.svc.awgAccelerationIntact() {
			t.Fatal("incomplete policy interval did not remain paused and require repair")
		}
		if !f.native["hardware"] || !f.native["software"] || !f.svc.acceleration.valuesIntact(awgAccelerationOffValues(), nil) {
			t.Fatal("in-place policy transition changed native preferences or left data plane enabled")
		}
	}
	// Even an accidental invalidation while a writer is paused must not make
	// partially replaced routing eligible for hardware forwarding.
	if err := f.svc.awgInvalidateAccelerationCache(); err != nil {
		t.Fatal(err)
	}
	if f.svc.acceleration.mode != "paused" || !f.svc.acceleration.valuesIntact(awgAccelerationOffValues(), nil) {
		t.Fatal("invalidation re-enabled an incomplete policy")
	}
	f.commands = append(f.commands, "# route and set mutation")
	if err := f.svc.awgFinishAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(f.commands[start:], "\n")
	flush := strings.Index(commands, "sysctl -w net.hwnat.ppe_flush=1")
	mutation := strings.Index(commands, "# route and set mutation")
	enable := strings.Index(commands, "sysctl -w net.hwnat.ppe_enabled=1")
	if flush < 0 || mutation < flush || enable < mutation {
		t.Fatal("cache boundary did not surround the policy mutation")
	}
	if strings.Contains(commands, "-c 'no ppe ") || strings.Contains(commands, "-c 'ppe ") {
		t.Fatal("healthy in-place recovery unloaded or reconfigured native PPE")
	}
	if f.svc.acceleration.mode != "selective" || !f.svc.awgAccelerationIntact() {
		t.Fatal("completed in-place recovery did not resume selective acceleration")
	}
}

func TestAccelerationInPlacePauseFailureUsesVerifiedNativeOff(t *testing.T) {
	for _, scenario := range []string{"missing guards", "missing flush", "failed flush"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAccelerationFixture(t)
			f.beginSelective(t)
			switch scenario {
			case "missing guards":
				f.guards = false
			case "missing flush":
				f.flushMissing = true
			case "failed flush":
				f.flushFailure = true
			}
			if err := f.svc.awgBeginAccelerationTransition(); err == nil {
				t.Fatal("failed cache boundary was hidden")
			}
			if f.native["hardware"] || f.native["software"] || f.svc.awgSelectiveAccelerationActive() {
				t.Fatal("failed in-place pause left native acceleration active")
			}
		})
	}
}

func TestAccelerationRequiresEnabledDataPlaneAndCheckedFlush(t *testing.T) {
	for _, scenario := range []string{"hardware missing", "flush missing", "flush write failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAccelerationFixture(t)
			f.beginSelective(t)
			switch scenario {
			case "hardware missing":
				delete(f.flags, "net.hwnat.ppe_enabled")
				if f.svc.awgAccelerationIntact() {
					t.Fatal("native preferences without enabled hardware data plane passed audit")
				}
				if err := f.svc.awgFinishAccelerationTransition(); err != nil {
					t.Fatal(err)
				}
			case "flush missing":
				f.flushMissing = true
				if err := f.svc.awgInvalidateAccelerationCache(); err != nil {
					t.Fatal(err)
				}
			case "flush write failure":
				f.flushFailure = true
				if err := f.svc.awgInvalidateAccelerationCache(); err == nil {
					t.Fatal("failed flush was hidden")
				}
			}
			if f.svc.awgSelectiveAccelerationActive() || f.native["hardware"] || f.native["software"] {
				t.Fatal("missing data plane/flush did not fall back to verified native off")
			}
		})
	}
}

func TestAccelerationNoPPEAndSoftwareOnlyFallbackRemainSupported(t *testing.T) {
	for _, native := range []map[string]bool{{}, {"software": true}} {
		t.Run(fmt.Sprint(native), func(t *testing.T) {
			f := newAccelerationFixture(t)
			f.native = native
			if err := f.svc.awgBeginAccelerationTransition(); err != nil {
				t.Fatal(err)
			}
			f.svc.awgAccelerationHook("#!/bin/sh\n", []awgMultiTunnel{{Iface: "awg0"}})
			if err := f.svc.awgFinishAccelerationTransition(); err != nil {
				t.Fatal(err)
			}
			if f.svc.awgSelectiveAccelerationActive() {
				t.Fatal("unsupported native subset activated selective mode")
			}
			if err := f.svc.awgRestoreAcceleration(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccelerationOldBootOwnedGuardsDoNotStrandNextStartup(t *testing.T) {
	f := newAccelerationFixture(t)
	journal := &awgAccelerationJournal{Owner: awgAccelerationOwner, Version: 1, BootID: "previous-boot", Sysctls: map[string]string{"net.core.swnat": "0"}, Native: map[string]bool{"hardware": false, "software": false}, Guarded: true}
	if err := saveAWGAccelerationJournal(f.svc.awgAccelerationJournalPath(), journal); err != nil {
		t.Fatal(err)
	}
	f.guards = true
	f.native = map[string]bool{"hardware": true, "software": true}
	if err := f.svc.awgSuspendAcceleration(); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.awgRestoreAcceleration(); err != nil {
		t.Fatal(err)
	}
	if f.guards || !f.native["hardware"] || !f.native["software"] {
		t.Fatal("old boot cleanup restored stale native preferences or retained guards")
	}
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatalf("new boot capture remained stranded: %v", err)
	}
	if f.svc.acceleration.journal.BootID != f.boot {
		t.Fatal("new boot did not capture its own observed settings")
	}
}

func TestAccelerationNFQWSUpdateSuspensionNestsEvenBeforeFirstCapture(t *testing.T) {
	f := newAccelerationFixture(t)
	if err := f.svc.SuspendAccelerationForNFQWSChange(); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SuspendAccelerationForNFQWSChange(); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	f.svc.awgAccelerationHook("#!/bin/sh\n", []awgMultiTunnel{{Iface: "awg0"}})
	f.guards = true
	if err := f.svc.awgFinishAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	if f.svc.awgSelectiveAccelerationActive() {
		t.Fatal("first capture ignored in-flight engine update")
	}
	f.svc.ResumeAccelerationAfterNFQWSChange()
	if err := f.svc.awgFinishAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	if f.svc.awgSelectiveAccelerationActive() {
		t.Fatal("inner resume released outer update inhibition")
	}
	f.svc.ResumeAccelerationAfterNFQWSChange()
	if f.svc.awgAccelerationIntact() {
		t.Fatal("completed engine update skipped fresh policy/window audit")
	}
	if err := f.svc.awgFinishAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	if !f.svc.awgSelectiveAccelerationActive() {
		t.Fatal("verified mode did not resume after outer update")
	}
}

func TestAccelerationVendorAccountingWithoutSysctlRequiresCounterEvidence(t *testing.T) {
	const one = "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.3.10 dst=203.0.113.1 sport=40000 dport=443 packets=4 bytes=300 src=203.0.113.1 dst=192.168.0.10 sport=443 dport=40000 packets=3 bytes=500 [ASSURED]\n"
	const two = "ipv4 2 udp 17 20 src=192.168.3.11 dst=203.0.113.2 sport=40001 dport=443 packets=2 bytes=100 src=203.0.113.2 dst=192.168.0.10 sport=443 dport=40001 packets=0 bytes=0 [UNREPLIED]\n"
	f := newAccelerationFixture(t)
	f.acctMissing = true
	f.conntrack = one + two
	f.beginSelective(t)
	if !f.svc.acceleration.accountingProven || !f.svc.awgAccelerationIntact() {
		t.Fatal("verified vendor counter capability was not accepted")
	}
	// A subsequently visible explicit switch remains authoritative even after
	// boot-static evidence was cached for the vendor kernel.
	f.acctMissing = false
	f.acctValue = "0"
	if f.svc.awgAccelerationIntact() {
		t.Fatal("explicit accounting=0 bypassed by cached evidence")
	}
	f.acctValue = ""
	f.acctErr = os.ErrPermission
	if f.svc.awgAccelerationIntact() {
		t.Fatal("real accounting read failure bypassed by counter evidence")
	}
	for name, data := range map[string]string{"valid": one + two, "one flow": one, "missing counters": one + strings.ReplaceAll(two, "packets=0 bytes=0 ", ""), "no flows": "", "invalid counter": one + strings.Replace(two, "bytes=100", "bytes=bad", 1)} {
		t.Run(name, func(t *testing.T) {
			if got := awgConntrackAccountingEvidence([]byte(data)); got != (name == "valid") {
				t.Fatalf("counter evidence=%v for %s", got, name)
			}
		})
	}
	other := newAccelerationFixture(t)
	other.acctMissing = true
	other.conntrack = one + two
	other.compatible = "keenetic,unverified\x00mediatek,mt7981\x00"
	if err := other.svc.awgBeginAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	other.svc.awgAccelerationHook("#!/bin/sh\n", []awgMultiTunnel{{Iface: "awg0"}})
	other.guards = true
	if err := other.svc.awgFinishAccelerationTransition(); err != nil {
		t.Fatal(err)
	}
	if other.svc.awgSelectiveAccelerationActive() {
		t.Fatal("unverified model used vendor-only accounting fallback")
	}
}
