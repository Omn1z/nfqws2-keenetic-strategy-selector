//go:build linux

package awgroute

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestEndpointPoolPinsBothFamiliesBeforeClassificationExclusions(t *testing.T) {
	var commands []string
	run := func(command string) (string, error) {
		commands = append(commands, command)
		switch command {
		case "ip route show default":
			return "default dev awg1\ndefault via 192.0.2.1 dev eth3\n", nil
		case "ip -6 route show default table main":
			return "default dev awg2\ndefault via fe80::1 dev eth4 metric 100\n", nil
		}
		return "", nil
	}
	if err := awgPinEndpointIPs([]string{"198.51.100.10", "2001:db8::20", "198.51.100.10"}, "2001:db8::20", run); err != nil {
		t.Fatal(err)
	}
	want := []string{"ip route show default", "ip route replace 198.51.100.10/32 via 192.0.2.1 dev eth3", "ip -6 route show default table main", "ip -6 route replace 2001:db8::20/128 via fe80::1 dev eth4"}
	if len(commands) != len(want)+1 || !reflect.DeepEqual(commands[:len(want)], want) {
		t.Fatalf("WAN pins use incorrect family/default or order: %v", commands)
	}
	exclusions := commands[len(want)]
	for _, clause := range []string{"-C AWG2_MULTI -d 198.51.100.10/32 -j RETURN", "-C AWG2_MARK -d 198.51.100.10/32 -j RETURN", "ip6tables -w -t mangle -C AWG2_MARK6 -d 2001:db8::20/128 -j RETURN"} {
		if !strings.Contains(exclusions, clause) {
			t.Fatalf("pre-UAPI exclusion missing %q", clause)
		}
	}
	if strings.Contains(exclusions, "2001:db8::20/32") {
		t.Fatal("IPv6 received an IPv4 prefix")
	}
}

func TestEndpointPoolUnavailableUnusedFamilyDoesNotBlockHealthyCandidate(t *testing.T) {
	for _, selected := range []string{"198.51.100.10", "2001:db8::20"} {
		err := awgPinEndpointIPs([]string{"198.51.100.10", "2001:db8::20"}, selected, func(command string) (string, error) {
			if command == "ip route show default" {
				return "default dev eth3\n", nil
			}
			return "", nil
		})
		if (err != nil) != (selected == "2001:db8::20") {
			t.Fatalf("selected=%s, unavailable IPv6 error=%v", selected, err)
		}
	}
}

func TestEndpointPoolPinFailurePreventsAttemptAndRejectsInvalidSelectedIP(t *testing.T) {
	failure := errors.New("route failed")
	var exclusionAttempt bool
	err := awgPinEndpointIPs([]string{"198.51.100.10"}, "198.51.100.10", func(command string) (string, error) {
		if command == "ip route show default" {
			return "default dev eth3", nil
		}
		if strings.HasPrefix(command, "set -e") {
			exclusionAttempt = true
			return "", nil
		}
		return "", failure
	})
	if err == nil || exclusionAttempt {
		t.Fatal("failed WAN pin did not stop pre-UAPI preparation")
	}
	if err := awgPinEndpointIPs(nil, "198.51.100.10; injected", func(string) (string, error) { t.Fatal("invalid selected address reached shell"); return "", nil }); err == nil {
		t.Fatal("invalid selected address accepted")
	}
}

func TestEndpointPoolCandidatesRemainOutsideCatchAllPolicy(t *testing.T) {
	tunnel := awgMultiTunnel{Iface: "awg0", EndpointIP: "2001:db8::20", EndpointIPs: []string{"198.51.100.10", "198.51.100.11", "2001:db8::20"}, Mark: awgMultiMark(1), Table: 901}
	rules := []awgMultiRule{{Tunnel: &tunnel, CatchAll: true, Zone: awg.Zone{Route: "tunnel"}}}
	doc := awgMultiPolicyDocument([]awgMultiTunnel{tunnel}, rules)
	for _, ip := range []string{"198.51.100.10", "198.51.100.11"} {
		if at := strings.Index(doc, "-d "+ip+"/32 -j RETURN"); at < 0 || at > strings.Index(doc, "-g AWG2_TO_") {
			t.Fatalf("endpoint %s enters catch-all tunnel", ip)
		}
	}
	if strings.Contains(doc, "2001:db8::20/32") {
		t.Fatal("IPv6 was emitted into IPv4 policy")
	}
	hook := awgFirewallHook("full", tunnel.EndpointIP, "eth4", 1280, false, true, nil, tunnel.EndpointIPs...)
	for _, rule := range []string{"-A AWG2_MARK -d 198.51.100.10/32 -j RETURN", "-A AWG2_MARK -d 198.51.100.11/32 -j RETURN", "-A AWG2_MARK6 -d 2001:db8::20/128 -j RETURN"} {
		if !strings.Contains(hook, rule) {
			t.Fatalf("legacy endpoint exclusion missing %s", rule)
		}
	}
}

func TestEndpointPoolIPHintsKeepPrimaryAndSelectedBackupSeparate(t *testing.T) {
	am := awg.NewManager(&awg.ServerConfig{Endpoint: "primary.example:51820", Client: awg.ClientConfig{EndpointBackups: []string{"198.51.100.11:51820", "[2001:db8::20]:443"}}})
	svc := &Service{}
	svc.rememberPolicyEndpointIP("primary.example", "198.51.100.10")
	if !am.SelectClientEndpoint(2) {
		t.Fatal("backup selection failed")
	}
	want := []string{"198.51.100.10", "198.51.100.11", "2001:db8::20"}
	if got := svc.awgClientEndpointIPs(am); !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoint escape hints=%v, want %v", got, want)
	}
	if am.Config().Endpoint != "primary.example:51820" || svc.cachedPolicyEndpointIP("primary.example") != "198.51.100.10" {
		t.Fatal("runtime backup replaced primary endpoint/DNS identity")
	}
}

func TestEndpointExclusionsDistinguishMissingChainsFromKernelReadFailure(t *testing.T) {
	for _, scenario := range []string{"absent", "present", "lock", "read failure", "kernel family absent"} {
		t.Run(scenario, func(t *testing.T) {
			var output string
			err := awgEnsureEndpointExclusions([]string{"198.51.100.10"}, func(script string) (string, error) {
				// Isolate the table-name evidence from the host running the
				// fixture: CI can have no real legacy mangle table at all.
				script = strings.ReplaceAll(script, "/proc/net/ip_tables_names", "/dev/null")
				mock := "grep() { return 0; }\n"
				if scenario == "kernel family absent" {
					mock = "grep() { return 1; }\n"
				}
				mock += "iptables() { case \" $* \" in *' -S '*) "
				switch scenario {
				case "absent":
					mock += "return 0"
				case "present":
					mock += "printf '%s\\n' '-N AWG2_MULTI'"
				case "lock":
					mock += "return 4"
				case "read failure", "kernel family absent":
					mock += "return 1"
				}
				mock += ";; *' -C '*) return 1;; *' -I '*) echo inserted;; esac; }\n"
				bytes, err := exec.Command("sh", "-c", mock+script).CombinedOutput()
				output = string(bytes)
				return output, err
			})
			if (err == nil) != (scenario == "absent" || scenario == "present" || scenario == "kernel family absent") {
				t.Fatalf("scenario=%s, error=%v, output=%s", scenario, err, output)
			}
			if strings.Contains(output, "inserted") != (scenario == "present") {
				t.Fatalf("unexpected mutation after table inspection: %s", output)
			}
		})
	}
}
