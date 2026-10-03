package arpblock

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const nativeConfigFixture = `! $$$ Model: Keenetic
system
    hostname Keenetic
    password SECRET_SYSTEM
!
interface GigabitEthernet1
    rename ISP
    security-level public
    ip address dhcp
    ip global 700
    up
!
interface Wireguard0
    description "Wireguard"
    ip address 10.0.0.2 255.255.255.255
    wireguard private-key SECRET_WG
    up
!
interface WifiMaster0/AccessPoint1
    rename GuestWiFi
    description "Home Wi-Fi"
    ssid "Keenetic Home"
    authentication wpa-psk SECRET_WIFI
    up
!
interface WifiMaster0/AccessPoint2
    ssid "Keenetic DE"
    authentication
        password SECRET_AP
        up
    no up
!
interface Bridge0
    rename Home
    description "Home network"
    include GuestWiFi
    include GigabitEthernet0/Vlan1
    security-level private
    ip address 192.168.3.1 255.255.255.0
    peer-isolation
    up
!
interface Bridge1
    rename Guest
    security-level protected
    ip address 10.1.30.1 255.255.255.0
    no up
!
interface Bridge2
    description "VPN"
    include GigabitEthernet0/Vlan2
    include WifiMaster0/AccessPoint2
    include WifiMaster1/AccessPoint2
    security-level protected
    ip address 192.168.2.1 255.255.255.0
    no peer-isolation
    up
!
`

func statusFixture(id, alias string) string {
	return fmt.Sprintf("\x1b[K\r\n%17s: %s\r\n%17s: %s\r\n%17s: Bridge\r\n%17s: up\r\n%17s: private\r\n%17s: 192.168.3.1\r\n%17s: 255.255.255.0\r\n%17s: no\r\n%17s:\r\n%25s: wrong-nested-id\r\n%25s: yes\r\n", "id", id, "interface-name", alias, "type", "state", "security-level", "address", "mask", "global", "ipv6", "id", "global")
}

func TestNativeConfigParsesTopologyWithoutSecrets(t *testing.T) {
	c, err := ParseKeeneticConfig(nativeConfigFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Bridges) != 3 || len(c.AccessPoints) != 2 {
		t.Fatalf("wrong topology: %+v", c)
	}
	home := c.Bridges[0]
	if home.ID != "Bridge0" || home.Rename != "Home" || home.Description != "Home network" || !home.Up || !home.PeerIsolation || !home.PeerIsolationExplicit || !home.ExplicitSecurity || home.SecurityLevel != "private" || home.Address != "192.168.3.1" || home.Mask != "255.255.255.0" || len(home.Members) != 2 {
		t.Fatalf("wrong home: %+v", home)
	}
	if c.Bridges[1].Up || len(c.Bridges[1].Members) != 0 {
		t.Fatal("empty disabled guest changed")
	}
	if c.AccessPoints[1].Up || c.AccessPoints[1].SSID != "Keenetic DE" {
		t.Fatalf("nested up polluted AP: %+v", c.AccessPoints[1])
	}
	if !c.IsolatePrivate || c.IsolatePrivateExplicit {
		t.Fatal("wrong documented isolate-private default")
	}
	data, _ := json.Marshal(c)
	if strings.Contains(string(data), "SECRET_") {
		t.Fatal("credentials leaked into parsed config")
	}
}

func TestNativeConfigFlagsQuotingAndLegacyNames(t *testing.T) {
	input := strings.Replace(nativeConfigFixture, "rename Home", `name Home`, 1)
	input = strings.Replace(input, `description "VPN"`, `description "My \"IoT\" network"`, 1)
	input = strings.Replace(input, "    no peer-isolation", "    ip global 700\n    no peer-isolation", 1)
	c, err := ParseKeeneticConfig("\x1b[Kno isolate-private\r\n" + strings.ReplaceAll(input, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.IsolatePrivate || !c.IsolatePrivateExplicit || !c.Bridges[2].Global || c.Bridges[2].PeerIsolation || !c.Bridges[2].PeerIsolationExplicit || c.Bridges[2].Description != `My "IoT" network` {
		t.Fatalf("bad parsed flags: %+v", c)
	}
}

func TestNativeConfigDecodesNativeHexEscapedNames(t *testing.T) {
	input := strings.Replace(nativeConfigFixture, `description "VPN"`, `description "\xd0\x94\xd0\xbe\xd0\xbc \\ IoT"`, 1)
	c, err := ParseKeeneticConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if c.Bridges[2].Description != `Дом \ IoT` {
		t.Fatalf("incorrect native hex decoding: %q", c.Bridges[2].Description)
	}
	parts, err := nativeWords(`description "folder\unknown"`)
	if err != nil || len(parts) != 2 || parts[1] != `folder\unknown` {
		t.Fatalf("unknown escape changed: %q %v", parts, err)
	}
	for _, value := range []string{`"bad\x00name"`, `"bad\x0aname"`} {
		if _, err := nativeWords("description " + value); err == nil {
			t.Fatal("escaped control accepted")
		}
	}
}

func TestNativeConfigRejectsAmbiguityAndMalformedKnownFields(t *testing.T) {
	for name, input := range map[string]string{
		"empty":               "",
		"error":               "Command::Base error[1]: rejected",
		"no bridge":           "interface GigabitEthernet0\n    up\n",
		"header command":      nativeConfigFixture + "interface Bridge3 peer-isolation\n",
		"duplicate block":     nativeConfigFixture + "interface Bridge0\n    up\n",
		"duplicate security":  strings.Replace(nativeConfigFixture, "    security-level private", "    security-level private\n    security-level protected", 1),
		"duplicate isolation": strings.Replace(nativeConfigFixture, "    peer-isolation", "    peer-isolation\n    no peer-isolation", 1),
		"duplicate global":    "no isolate-private\nisolate-private\n" + nativeConfigFixture,
		"duplicate member":    strings.Replace(nativeConfigFixture, "    include GuestWiFi", "    include GuestWiFi\n    include GuestWiFi", 1),
		"alias collision":     strings.Replace(nativeConfigFixture, "rename Guest\n", "rename Home\n", 1),
		"quote":               strings.Replace(nativeConfigFixture, `description "VPN"`, `description "SECRET_UNFINISHED`, 1),
		"bad mask":            strings.Replace(nativeConfigFixture, "192.168.3.1 255.255.255.0", "192.168.3.1 255.0.255.0", 1),
		"bad member":          strings.Replace(nativeConfigFixture, "include GuestWiFi", "include GuestWiFi;reboot", 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKeeneticConfig(input)
			if err == nil {
				t.Fatal("accepted unsafe or ambiguous config")
			}
			if strings.Contains(err.Error(), "SECRET_") {
				t.Fatal("error leaks raw config")
			}
		})
	}
}

func TestNativeConfigSkipsNestedLookalikeDirectives(t *testing.T) {
	input := strings.Replace(nativeConfigFixture, "    description \"VPN\"", "    description \"VPN\"\n    ipv6\n        security-level public\n        peer-isolation\n        include UNKNOWN\n        ip address 1.2.3.4 255.0.0.0", 1)
	c, err := ParseKeeneticConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if c.Bridges[2].SecurityLevel != "protected" || c.Bridges[2].PeerIsolation || len(c.Bridges[2].Members) != 3 {
		t.Fatalf("nested directives escaped: %+v", c.Bridges[2])
	}
}

func TestNativeInterfaceStatusIgnoresNestedFields(t *testing.T) {
	s, err := ParseKeeneticInterfaceStatus(statusFixture("Bridge0", "Home"), "Bridge0")
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "Bridge0" || s.Type != "Bridge" || s.InterfaceName != "Home" || s.Global || !s.GlobalExplicit || s.State != "up" {
		t.Fatalf("bad status: %+v", s)
	}
}

func TestNativeInterfaceStatusRejectsWrongOrAmbiguousIdentity(t *testing.T) {
	for _, input := range []string{statusFixture("Bridge2", "Home"), strings.Replace(statusFixture("Bridge0", "Home"), "type: Bridge", "type: Ethernet", 1), statusFixture("Bridge0", "Home") + fmt.Sprintf("%17s: Bridge0\n", "id"), statusFixture("Bridge0", "Home") + fmt.Sprintf("%17s: no\n", "global"), strings.Replace(statusFixture("Bridge0", "Home"), "global: no", "global: unknown", 1), "error: unavailable"} {
		if _, err := ParseKeeneticInterfaceStatus(input, "Bridge0"); err == nil {
			t.Fatal("accepted unsafe status")
		}
	}
	if _, err := ParseKeeneticInterfaceStatus(statusFixture("Bridge0", "Home"), "Bridge0;reboot"); err == nil {
		t.Fatal("accepted injected native id")
	}
}

func TestValidatePeerIsolationHomeAllowedButWANAndStaleTargetsRejected(t *testing.T) {
	c, err := ParseKeeneticConfig(nativeConfigFixture)
	if err != nil {
		t.Fatal(err)
	}
	b := c.Bridges[0]
	s, err := ParseKeeneticInterfaceStatus(statusFixture(b.ID, b.Rename), b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePeerIsolationTarget(b, s); err != nil {
		t.Fatalf("existing Home should support explicit whole-segment isolation: %v", err)
	}
	for name, change := range map[string]func(*NativeBridgeConfig, *NativeBridgeStatus){
		"global-config":  func(b *NativeBridgeConfig, s *NativeBridgeStatus) { b.Global = true },
		"global-status":  func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.Global = true },
		"global-unknown": func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.GlobalExplicit = false },
		"public": func(b *NativeBridgeConfig, s *NativeBridgeStatus) {
			b.SecurityLevel = "public"
			s.SecurityLevel = "public"
		},
		"implicit-security": func(b *NativeBridgeConfig, s *NativeBridgeStatus) { b.ExplicitSecurity = false },
		"changed-security":  func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.SecurityLevel = "protected" },
		"down-config":       func(b *NativeBridgeConfig, s *NativeBridgeStatus) { b.Up = false },
		"down-status":       func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.State = "down" },
		"empty":             func(b *NativeBridgeConfig, s *NativeBridgeStatus) { b.Members = nil },
		"changed-alias":     func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.InterfaceName = "IoT" },
		"changed-address":   func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.Address = "192.168.5.1" },
		"wrong-id":          func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.ID = "Bridge2" },
		"wrong-type":        func(b *NativeBridgeConfig, s *NativeBridgeStatus) { s.Type = "Ethernet" },
	} {
		t.Run(name, func(t *testing.T) {
			bc, sc := b, s
			change(&bc, &sc)
			if err := ValidatePeerIsolationTarget(bc, sc); err == nil {
				t.Fatal("unsafe target permitted")
			}
		})
	}
}
