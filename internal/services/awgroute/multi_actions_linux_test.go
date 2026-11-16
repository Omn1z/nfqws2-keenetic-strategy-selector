//go:build linux

package awgroute

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

// Interpret the emitted packet matches/verdicts without running a firewall.
// Expected routes below describe user policy, including ordered overlaps and
// the distinction between returning to the parent and terminating the table.
type multiActionPacket struct {
	src, dst string
	mark     uint32
	lookups  int
}

func evaluateMultiActionPolicy(t *testing.T, document string, packet *multiActionPacket, sets map[string][]string) string {
	t.Helper()
	chains := map[string][][]string{}
	for _, line := range strings.Split(document, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 3 && fields[0] == "-A" {
			chains[fields[1]] = append(chains[fields[1]], fields[2:])
		}
	}
	prefixContains := func(prefix, address string) bool {
		if !strings.Contains(prefix, "/") {
			prefix += "/32"
		}
		return netip.MustParsePrefix(prefix).Contains(netip.MustParseAddr(address))
	}
	markSelector := func(value string) (uint32, uint32) {
		parts := strings.Split(value, "/")
		mark, err := strconv.ParseUint(parts[0], 0, 32)
		if err != nil {
			t.Fatal(err)
		}
		mask := uint64(0xffffffff)
		if len(parts) > 1 {
			mask, err = strconv.ParseUint(parts[1], 0, 32)
			if err != nil {
				t.Fatal(err)
			}
		}
		return uint32(mark), uint32(mask)
	}
	var run func(string, int) string
	run = func(chain string, depth int) string {
		if depth > 4 {
			t.Fatal("policy chain loop")
		}
		for _, fields := range chains[chain] {
			matched, targetAt := true, -1
			for i := 0; i < len(fields); i++ {
				switch fields[i] {
				case "-s", "-d":
					address := packet.src
					if fields[i] == "-d" {
						address = packet.dst
					}
					matched = matched && prefixContains(fields[i+1], address)
					i++
				case "-m":
					i++
				case "--mark":
					mark, mask := markSelector(fields[i+1])
					matched = matched && packet.mark&mask == mark
					i++
				case "--match-set":
					if matched {
						packet.lookups++
						found := false
						for _, prefix := range sets[fields[i+1]] {
							found = found || prefixContains(prefix, packet.dst)
						}
						matched = found
					}
					i += 2
				case "-j", "-g":
					targetAt = i
					i = len(fields)
				default:
					t.Fatalf("unsupported policy fixture rule: %v", fields)
				}
			}
			if !matched {
				continue
			}
			if targetAt < 0 {
				t.Fatalf("missing action: %v", fields)
			}
			target := fields[targetAt+1]
			switch target {
			case "RETURN", "ACCEPT":
				return target
			case "MARK":
				if len(fields) != targetAt+4 || fields[targetAt+2] != "--set-xmark" {
					t.Fatalf("unexpected mark action: %v", fields)
				}
				mark, mask := markSelector(fields[targetAt+3])
				packet.mark = packet.mark&^mask ^ mark
			default:
				verdict := run(target, depth+1)
				if verdict != "RETURN" || fields[targetAt] == "-g" {
					return verdict
				}
			}
		}
		return "RETURN"
	}
	return run(awgMultiChain, 0)
}

func TestMultiActionChainsPreserveOrderedPolicyAndMarks(t *testing.T) {
	one := awgMultiTunnel{Mark: awgMultiMark(1), EndpointIP: "198.51.100.7"}
	two := awgMultiTunnel{Mark: awgMultiMark(2)}
	rules := []awgMultiRule{
		{Zone: awg.Zone{Route: "direct"}, Sources: []string{"192.168.3.10"}, SetName: "direct", HasDst: true},
		{Tunnel: &one, Sources: []string{"192.168.3.10", "192.168.3.11"}, SetName: "first", HasDst: true},
		{Tunnel: &two, SetName: "second", HasDst: true},
		{Tunnel: &one, SetName: "third", HasDst: true},
	}
	sets := map[string][]string{
		"direct": {"203.0.113.1"}, "first": {"203.0.113.0/24"},
		"second": {"203.0.113.1", "203.0.113.2", "192.0.2.2"}, "third": {"192.0.2.3"},
	}
	doc := awgMultiPolicyDocument([]awgMultiTunnel{one, two}, rules)
	const original uint32 = 0x8000d501
	for _, tc := range []struct {
		name, src, dst, verdict string
		mark, want              uint32
	}{
		{"first direct wins overlap", "192.168.3.10", "203.0.113.1", "RETURN", original, original},
		{"source tunnel wins overlap", "192.168.3.11", "203.0.113.1", "ACCEPT", original, original | 0x10100000},
		{"other source uses next tunnel", "192.168.3.12", "203.0.113.1", "ACCEPT", original, original | 0x10200000},
		{"second source selector", "192.168.3.10", "203.0.113.2", "ACCEPT", original, original | 0x10100000},
		{"reused first tunnel", "192.168.3.12", "192.0.2.3", "ACCEPT", original, original | 0x10100000},
		{"unlisted direct", "192.168.3.12", "192.0.2.9", "RETURN", original, original},
		{"probe keeps explicit mark", "192.168.3.11", "203.0.113.1", "RETURN", original | 0x20000000, original | 0x20000000},
		{"NFQWS bit preserved", "192.168.3.11", "203.0.113.1", "ACCEPT", original | 0x40000000, original | 0x40000000 | 0x10100000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := &multiActionPacket{src: tc.src, dst: tc.dst, mark: tc.mark}
			if verdict := evaluateMultiActionPolicy(t, doc, packet, sets); verdict != tc.verdict || packet.mark != tc.want {
				t.Fatalf("verdict=%s mark=%#x, want %s %#x", verdict, packet.mark, tc.verdict, tc.want)
			}
		})
	}
	if strings.Count(doc, ":AWG2_TO_") != 2 || strings.Count(doc, "--match-set first dst") != 2 {
		t.Fatal("source/domain rules did not share per-tunnel actions or repeated their packet match")
	}
	packet := &multiActionPacket{src: "192.168.3.12", dst: "192.0.2.9"}
	evaluateMultiActionPolicy(t, doc, packet, sets)
	if packet.lookups != 2 {
		t.Fatalf("unrelated direct packet performed %d ipset lookups, want one per applicable rule (2)", packet.lookups)
	}
}

func TestMultiActionCatchAllRetainsPrivateEndpointAndProbeExclusions(t *testing.T) {
	tunnel := awgMultiTunnel{Mark: awgMultiMark(1), EndpointIP: "198.51.100.7"}
	doc := awgMultiPolicyDocument([]awgMultiTunnel{tunnel}, []awgMultiRule{{Tunnel: &tunnel, CatchAll: true}})
	for _, dst := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.3.1", "100.64.0.1", tunnel.EndpointIP} {
		packet := &multiActionPacket{src: "192.168.3.12", dst: dst, mark: 0x8000d501}
		if got := evaluateMultiActionPolicy(t, doc, packet, nil); got != "RETURN" || packet.mark != 0x8000d501 {
			t.Fatalf("catch-all changed exclusion %s: %s %#x", dst, got, packet.mark)
		}
	}
	packet := &multiActionPacket{src: "192.168.3.12", dst: "203.0.113.1"}
	if got := evaluateMultiActionPolicy(t, doc, packet, nil); got != "ACCEPT" || packet.mark != 0x10100000 {
		t.Fatalf("catch-all did not mark and terminate: %s %#x", got, packet.mark)
	}
}

func TestMultiActionCleanupRemovesOnlyObsoleteOwnedChainsAtomically(t *testing.T) {
	for _, removePolicy := range []bool{false, true} {
		t.Run(fmt.Sprint(removePolicy), func(t *testing.T) {
			dir := t.TempDir()
			snapshot := "-N AWG2_MULTI\n-N AWG2_TO_10100000\n-N AWG2_TO_10200000\n-N AWG2_TO_foreign\n-N FOREIGN\n"
			listing := filepath.Join(dir, "listing")
			capture := filepath.Join(dir, "capture")
			if err := os.WriteFile(listing, []byte(snapshot), 0600); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"iptables":         "#!/bin/sh\ncase \"$*\" in '-w -t mangle -S') cat \"$AWG_ACTION_LISTING\" ;; '-w -t mangle -S AWG2_MULTI') grep -q '^-N AWG2_MULTI$' \"$AWG_ACTION_LISTING\" ;; *) exit 99 ;; esac\n",
				"iptables-restore": "#!/bin/sh\nif [ \"$1\" = --help ]; then printf 'usage: -w wait\\n'; exit 0; fi\ncat > \"$AWG_ACTION_CAPTURE.current\"\ncat \"$AWG_ACTION_CAPTURE.current\" >> \"$AWG_ACTION_CAPTURE\"\nwhile IFS=' ' read -r op chain; do\n if [ \"$op\" = -X ]; then\n  sed \"/^-N $chain$/d\" \"$AWG_ACTION_LISTING\" > \"$AWG_ACTION_LISTING.next\"\n  mv \"$AWG_ACTION_LISTING.next\" \"$AWG_ACTION_LISTING\"\n fi\ndone < \"$AWG_ACTION_CAPTURE.current\"\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			keep := []awgMultiTunnel{{Mark: awgMultiMark(1)}}
			if removePolicy {
				keep = nil
			}
			cmd := exec.Command(firewallRestoreTestShell(t))
			cleanup := awgMultiActionCleanupShell(keep, removePolicy)
			cmd.Stdin = strings.NewReader("set -e\n" + cleanup + cleanup)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "AWG_ACTION_LISTING="+listing, "AWG_ACTION_CAPTURE="+capture)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated cleanup: %v: %s", err, out)
			}
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			want := "*mangle\n-F AWG2_TO_10200000\n-X AWG2_TO_10200000\nCOMMIT\n"
			if removePolicy {
				want = "*mangle\n-F AWG2_MULTI\n-F AWG2_TO_10100000\n-X AWG2_TO_10100000\n-F AWG2_TO_10200000\n-X AWG2_TO_10200000\n-X AWG2_MULTI\nCOMMIT\n"
			}
			if string(data) != want {
				t.Fatalf("cleanup transaction:\n%s\nwant:\n%s", data, want)
			}
		})
	}
}

func TestMultiActionDocumentIsStableAcrossRefreshAndTunnelReuse(t *testing.T) {
	one, two := awgMultiTunnel{Mark: awgMultiMark(1)}, awgMultiTunnel{Mark: awgMultiMark(2)}
	rules := []awgMultiRule{{Tunnel: &one, SetName: "awgm_000", HasDst: true}, {Tunnel: &one, SetName: "awgm_001", HasDst: true}, {Tunnel: &two, SetName: "awgm_002", HasDst: true}}
	first := awgMultiPolicyDocument(nil, rules)
	if second := awgMultiPolicyDocument(nil, awgCloneMultiRules(rules)); first != second {
		t.Fatal("unchanged refresh changed action chain bindings")
	}
	if actions := awgMultiPolicyActions(rules); !reflect.DeepEqual(actions, []awgMultiTunnel{one, two}) {
		t.Fatalf("unexpected action chain reuse/order: %#v", actions)
	}
}

func TestMultiActionCleanupRetriesOnlyXtablesContentionWithoutWaitSupport(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		calls, exit int
	}{
		{"transient", 3, 0},
		{"always-busy", 5, 4},
		{"non-lock-resource-error", 1, 4},
		{"bad-rule-with-lock-text", 1, 2},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{
				"iptables": "#!/bin/sh\n[ \"$*\" = '-w -t mangle -S' ] || exit 99\nprintf '%s\\n' '-N AWG2_TO_10200000'\n",
				"iptables-restore": `#!/bin/sh
if [ "$1" = --help ]; then printf 'usage: --noflush\n'; exit 0; fi
count=$(cat "$AWG_ACTION_STATE" 2>/dev/null || printf 0)
count=$((count + 1))
printf '%s' "$count" > "$AWG_ACTION_STATE"
printf '%s\n' "$*" >> "$AWG_ACTION_STATE.args"
cat > "$AWG_ACTION_STATE.doc.$count"
case "$AWG_ACTION_MODE" in
  non-lock-resource-error) printf 'table allocation failed\n' >&2; exit 4 ;;
  bad-rule-with-lock-text) printf 'Bad argument: xtables lock is unrelated\n' >&2; exit 2 ;;
  always-busy) printf 'Another app is currently holding the xtables lock.\n' >&2; exit 4 ;;
esac
if [ "$count" -lt 3 ]; then
  printf 'Another app is currently holding the xtables lock.\n' >&2
  exit 4
fi
`,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			state := filepath.Join(dir, "state")
			continued := filepath.Join(dir, "continued")
			cmd := exec.Command(firewallRestoreTestShell(t))
			cmd.Stdin = strings.NewReader("set -e\nsleep() { :; }\n" + awgMultiActionCleanupShell(nil, false) + "printf ready > \"$AWG_ACTION_CONTINUED\"\n")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "AWG_ACTION_STATE="+state, "AWG_ACTION_MODE="+tc.mode, "AWG_ACTION_CONTINUED="+continued)
			out, err := cmd.CombinedOutput()
			exit := 0
			if err != nil {
				failure, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatalf("cleanup did not start: %v", err)
				}
				exit = failure.ExitCode()
			}
			if exit != tc.exit {
				t.Fatalf("cleanup exit=%d, want %d: %s", exit, tc.exit, out)
			}
			count, err := os.ReadFile(state)
			if err != nil || string(count) != strconv.Itoa(tc.calls) {
				t.Fatalf("cleanup attempts=%s, want %d: %v", count, tc.calls, err)
			}
			want := "*mangle\n-F AWG2_TO_10200000\n-X AWG2_TO_10200000\nCOMMIT\n"
			for attempt := 1; attempt <= tc.calls; attempt++ {
				data, err := os.ReadFile(fmt.Sprintf("%s.doc.%d", state, attempt))
				if err != nil || string(data) != want {
					t.Fatalf("retry changed cleanup transaction at attempt %d: %s: %v", attempt, data, err)
				}
			}
			args, err := os.ReadFile(state + ".args")
			if err != nil || string(args) != strings.Repeat("--noflush\n", tc.calls) {
				t.Fatalf("cleanup used unsupported wait or altered restore arguments: %s: %v", args, err)
			}
			_, continuedErr := os.Stat(continued)
			if (tc.exit == 0) != (continuedErr == nil) {
				t.Fatalf("hook continuation mismatch: exit=%d marker=%v", tc.exit, continuedErr)
			}
		})
	}
}
