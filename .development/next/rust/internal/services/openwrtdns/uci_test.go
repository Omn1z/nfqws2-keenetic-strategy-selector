package openwrtdns

import (
	"reflect"
	"testing"
)

func TestParseExportPreservesKindsQuotesAndAnonymousOrdinals(t *testing.T) {
	c, err := parseExport("package dhcp\nconfig dnsmasq 'named'\n option domain 'a'\\''b'\nconfig dnsmasq\n list server '/corp/1.2.3.4'\n list server '/lan/'\n option empty ''\n", "dhcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sections) != 2 || c.Sections[1].ID != "@dnsmasq[1]" || c.Sections[0].scalar("domain") != "a'b" {
		t.Fatalf("parsed %+v", c)
	}
	if !reflect.DeepEqual(c.Sections[1].Options["empty"], scalar("")) {
		t.Fatal("lost empty option")
	}
}
func TestParseExportRejectsAmbiguousOrIncompleteInput(t *testing.T) {
	for _, raw := range []string{"package other\n", "config dnsmasq 'x'\noption x '1'\noption x '2'\n", "config dnsmasq 'x'\noption x '1'\nlist x '2'\n", "config dnsmasq 'a.b'\n", "config dnsmasq\noption server 'unfinished\n", "config dnsmasq 'same'\nconfig dnsmasq 'same'\n"} {
		if _, err := parseExport(raw, "dhcp"); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
func TestConditionalServers(t *testing.T) {
	for _, v := range []string{"/corp/10.0.0.1", "/lan/", "//192.168.1.2", "/a/b/1.1.1.1"} {
		if !conditionalServer(v) {
			t.Fatalf("lost conditional %q", v)
		}
	}
	for _, v := range []string{"1.1.1.1", "127.0.0.1#5053", "/#/1.1.1.1", "/corp/#/1.1.1.1", "/"} {
		if conditionalServer(v) {
			t.Fatalf("kept global %q", v)
		}
	}
}
func TestInstanceSelectorValidation(t *testing.T) {
	for _, s := range []string{"cfg123456", "dnsmain", "@dnsmasq[0]", "@dnsmasq[15]"} {
		if !validInstance(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"@dnsmasq[-1]", "@dnsmasq[00]", "@dnsmasq[1024]", "@interface[0]", "@dnsmasq[0].server", "@dnsmasq[0];reboot", ""} {
		if validInstance(s) {
			t.Fatalf("accepted %q", s)
		}
	}
}
