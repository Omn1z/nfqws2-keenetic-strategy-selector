package arpspoof

import (
	"fmt"
	"strings"
	"testing"
)

func keeneticStatusFixture(id, kind, mac string) string {
	return "\x1b[K\r\n" + fmt.Sprintf("%17s: %s\n%17s: Home\n%17s: %s\n%17s: \n%25s: unrelated\n%17s: %s\n",
		"id", id, "interface-name", "type", kind, "ipv6", "mac", "mac", mac)
}

func TestKeeneticBridgeIdentityAndMAC(t *testing.T) {
	for _, name := range []string{"br0", "br2", "br123"} {
		id, err := keeneticBridgeID(name)
		if err != nil {
			t.Fatal(err)
		}
		mac, err := parseKeeneticBridgeMAC(keeneticStatusFixture(id, "Bridge", strings.ToLower(testFakeMAC)), id)
		if err != nil || mac != testFakeMAC {
			t.Fatalf("parse %s: %s %v", name, mac, err)
		}
	}
	for _, name := range []string{"eth3", "ra0", "br-lan", "br0;reboot", "br00", "Bridge0"} {
		if _, err := keeneticBridgeID(name); err == nil {
			t.Fatalf("unsafe native interface mapping: %q", name)
		}
	}
}

func TestKeeneticRejectsAmbiguousOrWrongStatus(t *testing.T) {
	for _, output := range []string{
		keeneticStatusFixture("Bridge1", "Bridge", testFakeMAC),
		keeneticStatusFixture("Bridge0", "Ethernet", testFakeMAC),
		keeneticStatusFixture("Bridge0", "Bridge", ""),
		keeneticStatusFixture("Bridge0", "Bridge", "01:00:5E:00:00:01"),
		keeneticStatusFixture("Bridge0", "Bridge", testFakeMAC) + fmt.Sprintf("%17s: %s\n", "mac", testFakeMAC),
		"Command::Base error[7405602]: argument parse error.",
	} {
		if _, err := parseKeeneticBridgeMAC(output, "Bridge0"); err == nil {
			t.Fatalf("accepted invalid native interface status: %q", output)
		}
	}
}

func TestKeeneticDetectsErrorsDespiteZeroExitStatus(t *testing.T) {
	for _, output := range []string{
		"Command::Base error[7405602]: argument parse error.",
		"\x1b[K\r\nNetwork::Interface::Mac error[123]: denied.",
		"error: denied", "%Error: invalid command",
	} {
		if !hasKeeneticCommandError(output) {
			t.Fatalf("missed native command failure: %q", output)
		}
	}
	for _, output := range []string{
		`Network::Interface::Mac: "Bridge0": MAC address is 64:6e:ea:f1:7b:ef.`,
		keeneticStatusFixture("Bridge0", "Bridge", testFakeMAC),
		"      description: error-test-network",
	} {
		if hasKeeneticCommandError(output) {
			t.Fatalf("false native error: %q", output)
		}
	}
}
