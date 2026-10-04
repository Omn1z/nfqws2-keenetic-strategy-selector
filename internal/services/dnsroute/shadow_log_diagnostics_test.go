package dnsroute

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func nativeLogDiagnosticsForTest(t *testing.T, log string, leases []keeneticShadowLease, now time.Time) []ShadowDiagnosticEvent {
	t.Helper()
	var state shadowDiagnosticState
	ctx, finish := state.begin(context.Background())
	logShadowNativeLeases(ctx, log, leases, now)
	finish(nil, nil, time.Time{})
	return state.snapshot().Attempts[0].Events
}

func TestShadowNativeLogDiagnosticsExplainsMissingAndExpiredDNS(t *testing.T) {
	log := `I [Oct  4 03:00:00] ndhcpc: GigabitEthernet1: received ACK for 10.101.48.55 from 1.1.1.2 lease 3600 sec.
I [Oct  3 03:00:00] ndhcpc: GigabitEthernet2: received ACK for 192.0.2.2 from 192.0.2.1 lease 3600 sec.`
	now := time.Date(2026, 10, 4, 3, 10, 0, 0, time.UTC)
	events := nativeLogDiagnosticsForTest(t, log, parseKeeneticShadowLeases(log), now)
	if len(events) != 3 {
		t.Fatalf("events: %+v", events)
	}
	for _, expected := range []string{"ACK=2", "obtained=0", "ignored DNS=0", "последних аренд=2"} {
		if !strings.Contains(events[0].Message, expected) {
			t.Fatalf("missing %q in %s", expected, events[0].Message)
		}
	}
	for _, expected := range []string{"возраст=600 с", "lease=3600 с", "остаток=3000 с", "DNS=0", "DNS не связаны с последним ACK"} {
		if !strings.Contains(events[1].Message, expected) {
			t.Fatalf("missing %q in %s", expected, events[1].Message)
		}
	}
	if !strings.Contains(events[2].Message, "остаток=0 с") || !strings.Contains(events[2].Message, "аренда истекла") {
		t.Fatal(events[2].Message)
	}
}

func TestShadowNativeLogDiagnosticsOnlyExportsMetadata(t *testing.T) {
	log := `I [Oct  4 03:00:00] auth: password=TOP-SECRET username=PRIVATE-USER
                    cookie=PRIVATE-COOKIE
I [Oct  4 03:00:00] ndhcpc: GigabitEthernet1: received ACK for 10.101.48.55
                    from 1.1.1.2 lease 3600 sec.
I [Oct  4 03:00:00] ndm: Dhcp::Client: obtained IP address 10.101.48.55/23.
W [Oct  4 03:00:00] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is
                    ignored.
W [Oct  4 03:00:01] ndm: Dns::InterfaceSpecific: name server 198.51.100.53 is ignored.
W [secret-stamp] ndm: Dns::InterfaceSpecific: name server 203.0.113.53 is ignored.
W [Oct  4 03:00:01] ndm: Dns::InterfaceSpecific: name server token=PRIVATE-TOKEN is ignored.
I [Oct  4 03:00:01] http: Authorization: PRIVATE-AUTH`
	now := time.Date(2026, 10, 4, 3, 10, 0, 0, time.UTC)
	events := nativeLogDiagnosticsForTest(t, log, parseKeeneticShadowLeases(log), now)
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"TOP-SECRET", "PRIVATE-", "secret-stamp", "Authorization", "cookie=", "password="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("leaked native log text %q: %s", forbidden, text)
		}
	}
	for _, expected := range []string{"ACK=1", "obtained=1", "ignored DNS=3", "связанных ignored DNS=1", "DNS=1", "адрес=192.0.2.53; связь с ACK=GigabitEthernet1", "адрес=198.51.100.53; связь с ACK=нет", "время=невалидное время; адрес=203.0.113.53"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q: %s", expected, text)
		}
	}
}

func TestShadowNativeLogDiagnosticsDoesNotInventAssociation(t *testing.T) {
	ack := "I [Oct  4 03:00:00] ndhcpc: GigabitEthernet1: received ACK for 10.101.48.55 from 1.1.1.2 lease 3600 sec.\n"
	obtained := "I [Oct  4 03:00:00] ndm: Dhcp::Client: obtained IP address 10.101.48.55/23.\n"
	ignored := "W [Oct  4 03:00:00] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.\n"
	for name, log := range map[string]string{
		"no obtained":  ack + ignored,
		"wrong client": ack + strings.Replace(obtained, "48.55", "48.56", 1) + ignored,
		"wrong time":   ack + obtained + strings.Replace(ignored, "03:00:00", "03:00:01", 1),
		"too distant":  ack + obtained + strings.Repeat("I [Oct  4 03:00:00] other: unrelated\n", 15) + ignored,
		"other DHCP":   ack + obtained + "I [Oct  4 03:00:00] ndhcpc: ISP: renewing lease\n" + ignored,
	} {
		t.Run(name, func(t *testing.T) {
			events := nativeLogDiagnosticsForTest(t, log, parseKeeneticShadowLeases(log), time.Date(2026, 10, 4, 3, 10, 0, 0, time.UTC))
			if !strings.Contains(events[0].Message, "связанных ignored DNS=0") {
				t.Fatal(events)
			}
			for _, event := range events {
				if strings.HasPrefix(event.Message, "ignored DNS:") && !strings.Contains(event.Message, "связь с ACK=нет") {
					t.Fatal(event)
				}
			}
		})
	}
}

func TestShadowNativeLogDiagnosticsBoundsDetailsAndRetainsCounts(t *testing.T) {
	var output strings.Builder
	for n := 1; n <= 20; n++ {
		fmt.Fprintf(&output, "I [Oct  4 03:00:00] ndhcpc: GigabitEthernet%d: received ACK for 192.0.2.%d from 192.0.2.254 lease 3600 sec.\n", n, n)
		fmt.Fprintf(&output, "I [Oct  4 03:00:00] ndm: Dhcp::Client: obtained IP address 192.0.2.%d/24.\n", n)
		fmt.Fprintf(&output, "W [Oct  4 03:00:00] ndm: Dns::InterfaceSpecific: name server 198.51.100.%d is ignored.\n", n)
	}
	log := output.String()
	events := nativeLogDiagnosticsForTest(t, log, parseKeeneticShadowLeases(log), time.Date(2026, 10, 4, 3, 10, 0, 0, time.UTC))
	if len(events) != 1+shadowNativeLogLeases+shadowNativeLogDetails {
		t.Fatalf("unbounded event count: %d", len(events))
	}
	if !strings.Contains(events[0].Message, "ACK=20; obtained=20; ignored DNS=20") || !strings.Contains(events[0].Message, "показано 4") {
		t.Fatal(events[0].Message)
	}
	if !strings.Contains(events[len(events)-1].Message, "адрес=198.51.100.20; связь с ACK=GigabitEthernet20") {
		t.Fatal(events[len(events)-1])
	}
	for _, event := range events {
		if len(event.Message) > shadowDiagnosticMessageBytes {
			t.Fatal("unbounded message")
		}
	}
}

func TestShadowNativeLogDiagnosticsBoundsInputAndRejectsOversizedRecords(t *testing.T) {
	log := strings.Repeat("unrelated-private-data\n", shadowNativeLogBytes/10) + "I [Oct  4 03:00:00] " + strings.Repeat("private-data", shadowNativeLogRecord) + "\n" +
		"W [Oct  4 03:00:00] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.\n"
	events := nativeLogDiagnosticsForTest(t, log, nil, time.Time{})
	if len(events) != 2 || !strings.Contains(events[0].Message, "часть журнала пропущена=true; слишком длинных записей=1") {
		t.Fatal(events)
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), "private-data") {
		t.Fatal("oversized native output leaked")
	}
}

func TestShadowNativeLogDiagnosticsUnknownClockAndInvalidMetadata(t *testing.T) {
	leases := []keeneticShadowLease{{iface: "ISP;password=SECRET", clientIP: net.ParseIP("192.0.2.2"), stamp: "SECRET-STAMP", leaseSeconds: 3600}}
	events := nativeLogDiagnosticsForTest(t, "", leases, time.Time{})
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), "SECRET") || !strings.Contains(events[1].Message, "недоступно время роутера или timestamp ACK") || !strings.Contains(events[1].Message, "возраст=неизвестен") {
		t.Fatal(string(encoded))
	}
	// No diagnostics collector means no log scan or attempt creation.
	logShadowNativeLeases(context.Background(), "", nil, time.Time{})
}
