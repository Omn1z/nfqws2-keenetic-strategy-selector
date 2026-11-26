package arpspoof

import "testing"

func TestGenerateMACUsesPrefix(t *testing.T) {
	mac, err := generateMAC("64:6e:ea")
	if err != nil {
		t.Fatal(err)
	}
	if mac[:8] != "64:6E:EA" {
		t.Fatalf("mac %q does not use prefix", mac)
	}
}

func TestNormalizeMACRejectsMulticast(t *testing.T) {
	if _, err := normalizeMAC("01:00:5E:00:00:01"); err == nil {
		t.Fatal("expected multicast MAC to be rejected")
	}
}

func TestNormalizePrefixAllowsOneToThreeBytes(t *testing.T) {
	for _, in := range []string{"64", "64:6e", "646eea"} {
		if _, err := normalizePrefix(in); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
	}
}
