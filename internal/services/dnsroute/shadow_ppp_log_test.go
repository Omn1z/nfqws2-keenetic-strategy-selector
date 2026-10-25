package dnsroute

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func shadowPPPLog(pid, message string) string {
	return "I [Oct 25 18:21:06] pppd[" + pid + "]: " + message + "\n"
}

func shadowPPPLogFixture(pid, device, id, address, primary, secondary string) string {
	result := shadowPPPLog(pid, "PPP session is "+id) +
		shadowPPPLog(pid, "Using interface "+device) +
		shadowPPPLog(pid, "Connect: "+device+" <--> eth3") +
		shadowPPPLog(pid, "PAP authentication succeeded") +
		shadowPPPLog(pid, "local  IP address "+address) +
		shadowPPPLog(pid, "remote IP address 100.66.0.1")
	if primary != "" {
		result += shadowPPPLog(pid, "primary   DNS address "+primary)
	}
	if secondary != "" {
		result += shadowPPPLog(pid, "secondary DNS address "+secondary)
	}
	return result
}

func TestShadowPPPLogReadsPeerDNSBeforeIgnoredSystemRecords(t *testing.T) {
	fixture := shadowPPPLogFixture("30539", "ppp0", "12650", "100.66.1.244", "46.61.250.142", "46.61.250.143") +
		"I [Oct 25 18:21:06] ndm: Network::Interface::Base: \"PPPoE0\": interface is up.\n" +
		"W [Oct 25 18:21:06] ndm: Dns::InterfaceSpecific: name server 46.61.250.142 is ignored.\n" +
		"W [Oct 25 18:21:06] ndm: Dns::InterfaceSpecific: name server 203.0.113.53 is ignored.\n"
	got := parseKeeneticShadowPPPSessions(fixture)
	if len(got) != 1 || got[0].pid != "30539" || got[0].device != "ppp0" || got[0].sessionID != 12650 || got[0].clientIP.String() != "100.66.1.244" || got[0].stamp != "Oct 25 18:21:06" || !reflect.DeepEqual(got[0].servers, []string{"46.61.250.142", "46.61.250.143"}) {
		t.Fatalf("PPP peer evidence lost or generic DNS trusted: %+v", got)
	}
	if got := parseKeeneticShadowPPPSessions(strings.ReplaceAll(fixture, "pppd[30539]", "other[30539]")); len(got) != 0 {
		t.Fatalf("unattributed ignored DNS became PPP evidence: %+v", got)
	}
}

func TestShadowPPPLogSeparatesInterleavedProcesses(t *testing.T) {
	first := strings.Split(strings.TrimSuffix(shadowPPPLogFixture("10", "ppp0", "100", "192.0.2.10", "192.0.2.53", ""), "\n"), "\n")
	second := strings.Split(strings.TrimSuffix(shadowPPPLogFixture("20", "ppp1", "200", "198.51.100.10", "198.51.100.53", ""), "\n"), "\n")
	var fixture strings.Builder
	for i := range first {
		fixture.WriteString(first[i] + "\n" + second[i] + "\n")
	}
	got := parseKeeneticShadowPPPSessions(fixture.String())
	if len(got) != 2 || got[0].device != "ppp0" || got[0].clientIP.String() != "192.0.2.10" || got[0].sessionID != 100 || !reflect.DeepEqual(got[0].servers, []string{"192.0.2.53"}) || got[1].device != "ppp1" || got[1].clientIP.String() != "198.51.100.10" || got[1].sessionID != 200 || !reflect.DeepEqual(got[1].servers, []string{"198.51.100.53"}) {
		t.Fatalf("interleaved pppd records were mixed: %+v", got)
	}
}

func TestShadowPPPLogLatestSessionReplacesOldEvidence(t *testing.T) {
	old := shadowPPPLogFixture("10", "ppp0", "100", "192.0.2.10", "192.0.2.53", "192.0.2.54")
	for _, pid := range []string{"10", "20"} {
		for _, address := range []string{"192.0.2.10", "198.51.100.10"} {
			t.Run(pid+"/"+address, func(t *testing.T) {
				withoutDNS := shadowPPPLogFixture(pid, "ppp0", "200", address, "", "")
				if got := parseKeeneticShadowPPPSessions(old + withoutDNS); len(got) != 0 {
					t.Fatalf("a session without DNS retained older resolver addresses: %+v", got)
				}
				newSession := shadowPPPLogFixture(pid, "ppp0", "200", address, "198.51.100.53", "")
				got := parseKeeneticShadowPPPSessions(old + newSession)
				if len(got) != 1 || got[0].sessionID != 200 || got[0].clientIP.String() != address || !reflect.DeepEqual(got[0].servers, []string{"198.51.100.53"}) {
					t.Fatalf("new session retained old DNS: %+v", got)
				}
			})
		}
	}
	newSession := shadowPPPLogFixture("20", "ppp0", "200", "192.0.2.10", "198.51.100.53", "")
	got := parseKeeneticShadowPPPSessions(old + newSession + shadowPPPLog("10", "Connection terminated."))
	if len(got) != 1 || got[0].pid != "20" {
		t.Fatalf("late termination from a superseded process erased the new session: %+v", got)
	}
}

func TestShadowPPPLogLifecycleWithdrawsDNS(t *testing.T) {
	fixture := shadowPPPLogFixture("10", "ppp0", "100", "192.0.2.10", "192.0.2.53", "")
	for _, message := range []string{
		"PPP session is 200", "PPP session is nonsense", "PPP session is 0", "PPP session is 65536",
		"Using interface ppp0", "Using interface ppp1", "Using interface", "Using interface wg0",
		"Connect: ppp0 <--> eth3", "Connect: invalid", "local IP address 192.0.2.10", "local IP address 198.51.100.10", "local IP address bad",
		"Connection terminated.", "Modem hangup", "LCP terminated by peer", "IPCP terminated by peer", "Terminating on signal 15", "No network protocols running", "Exit. reconnecting.",
		"pppd 2.4.4-4 started by root, uid 0", "Plugin rp-pppoe.so loaded.",
	} {
		t.Run(message, func(t *testing.T) {
			if got := parseKeeneticShadowPPPSessions(fixture + shadowPPPLog("10", message)); len(got) != 0 {
				t.Fatalf("lifecycle event retained old DNS: %+v", got)
			}
		})
	}
	// A dual-stack PPP link may log IPv6 link-local addresses after IPv4 IPCP.
	if got := parseKeeneticShadowPPPSessions(fixture + shadowPPPLog("10", "local  LL address fe80::1")); len(got) != 1 {
		t.Fatal("IPv6 negotiation discarded independent IPv4 IPCP evidence")
	}
}

func TestShadowPPPLogRejectsIncompleteOrMalformedPeerEvidence(t *testing.T) {
	fixture := shadowPPPLogFixture("10", "ppp0", "100", "192.0.2.10", "192.0.2.53", "192.0.2.54")
	for _, replacement := range [][2]string{
		{"PPP session is 100", "PPP session is bad"},
		{"PPP session is 100", "PPP session is 0"},
		{"Using interface ppp0", "Using interface ppp00"},
		{"Connect: ppp0 <--> eth3", "Connect: ppp1 <--> eth3"},
		{"Connect: ppp0 <--> eth3", "Connect: ppp0 <--> eth3 extra"},
		{"local  IP address 192.0.2.10", "local IP address 127.0.0.1"},
		{"local  IP address 192.0.2.10", "local IP address 0.0.0.0"},
		{"local  IP address 192.0.2.10", "local IP address 2001:db8::1"},
		{"local  IP address 192.0.2.10", "local IP address 192.0.2.10 extra"},
		{"primary   DNS address 192.0.2.53", "primary DNS address dns.example"},
		{"primary   DNS address 192.0.2.53", "primary DNS address 127.0.0.1"},
		{"primary   DNS address 192.0.2.53", "primary DNS address 169.254.1.1"},
		{"primary   DNS address 192.0.2.53", "primary DNS address 224.0.0.1"},
		{"secondary DNS address 192.0.2.54", "secondary DNS address 2001:db8::53"},
		{"secondary DNS address 192.0.2.54", "secondary DNS address 192.0.2.54 extra"},
		{"pppd[10]", "pppd[00010]"},
		{"[Oct 25 18:21:06]", "[not a timestamp]"},
	} {
		t.Run(replacement[1], func(t *testing.T) {
			if got := parseKeeneticShadowPPPSessions(strings.ReplaceAll(fixture, replacement[0], replacement[1])); len(got) != 0 {
				t.Fatalf("malformed peer evidence accepted: %+v", got)
			}
		})
	}
	for _, missing := range []string{"PPP session is 100", "Using interface ppp0", "Connect: ppp0 <--> eth3", "local  IP address 192.0.2.10"} {
		if got := parseKeeneticShadowPPPSessions(strings.Replace(fixture, shadowPPPLog("10", missing), "", 1)); len(got) != 0 {
			t.Fatalf("missing %q still yielded DNS: %+v", missing, got)
		}
	}
}

func TestShadowPPPLogWrapsAndBoundsEvidence(t *testing.T) {
	fixture := shadowPPPLogFixture("10", "ppp0", "100", "192.0.2.10", "192.0.2.53", "192.0.2.54")
	wrapped := strings.Replace(fixture, "primary   DNS address 192.0.2.53", "primary   DNS address\n                    192.0.2.53", 1)
	wrapped = strings.ReplaceAll(wrapped, "\n", "\x1b[K\r\n")
	if got := parseKeeneticShadowPPPSessions(wrapped); len(got) != 1 || !reflect.DeepEqual(got[0].servers, []string{"192.0.2.53", "192.0.2.54"}) {
		t.Fatalf("wrapped native output rejected: %+v", got)
	}
	for _, huge := range []string{
		shadowPPPLog("10", strings.Repeat("x", shadowNativeLogRecord+1)),
		shadowPPPLog("10", "primary DNS address") + "                    " + strings.Repeat("x", shadowNativeLogRecord+1) + "\n",
		"I [Oct 25 18:21:06] pppd[bad]: invalid PID\n",
	} {
		if got := parseKeeneticShadowPPPSessions(fixture + huge + shadowPPPLog("10", "secondary DNS address 192.0.2.54")); len(got) != 0 {
			t.Fatalf("discarded record bridged earlier evidence: %+v", got)
		}
		if got := parseKeeneticShadowPPPSessions(huge + fixture); len(got) != 1 {
			t.Fatal("later complete evidence was lost after a discarded record")
		}
	}
	filler := strings.Repeat("I [Oct 25 18:21:06] ndm: unrelated log entry.\n", shadowNativeLogBytes/40)
	if got := parseKeeneticShadowPPPSessions(shadowPPPLog("10", "PPP session is 100") + filler + strings.TrimPrefix(fixture, shadowPPPLog("10", "PPP session is 100"))); len(got) != 0 {
		t.Fatalf("session outside the bounded window supplied identity: %+v", got)
	}
	if got := parseKeeneticShadowPPPSessions(filler + fixture); len(got) != 1 {
		t.Fatal("bounded tail lost a complete current session")
	}
	var manyProcesses strings.Builder
	manyProcesses.WriteString(fixture)
	for pid := 1000; pid < 1064; pid++ {
		manyProcesses.WriteString(shadowPPPLog(fmt.Sprint(pid), "unrelated pppd record"))
	}
	if got := parseKeeneticShadowPPPSessions(manyProcesses.String()); len(got) != 0 {
		t.Fatal("process tracking exceeded its bound")
	}
}
