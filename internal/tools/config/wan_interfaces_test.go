package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeWANInterfaces(t *testing.T) {
	tests := []struct {
		name, source, want string
		ifaces             []string
	}{
		{"Keenetic Ultra", "ISP_INTERFACE=\"eth4,eth3,eth2.4\"\n", "ISP_INTERFACE=\"eth4 eth3 eth2.4\"\n", []string{"eth4", "eth3", "eth2.4"}},
		{"mixed separators and duplicates", "ISP_INTERFACE=\" eth4, eth3\teth2.4,,eth4 \"\n", "ISP_INTERFACE=\"eth4 eth3 eth2.4\"\n", []string{"eth4", "eth3", "eth2.4"}},
		{"single", "ISP_INTERFACE=\"eth2.4\"\n", "ISP_INTERFACE=\"eth2.4\"\n", []string{"eth2.4"}},
		{"single quoted", "ISP_INTERFACE='eth4,eth3,eth2.4'", "ISP_INTERFACE='eth4 eth3 eth2.4'", []string{"eth4", "eth3", "eth2.4"}},
		{"bare list gets quotes", "ISP_INTERFACE=eth4,eth3,eth2.4\n", "ISP_INTERFACE=\"eth4 eth3 eth2.4\"\n", []string{"eth4", "eth3", "eth2.4"}},
		{"bare single", "ISP_INTERFACE=pppoe-wan\n", "ISP_INTERFACE=pppoe-wan\n", []string{"pppoe-wan"}},
		{"export comment and CRLF", "  export ISP_INTERFACE='eth4,eth3' \t# eth4,eth3\r\n", "  export ISP_INTERFACE='eth4 eth3' \t# eth4,eth3\r\n", []string{"eth4", "eth3"}},
		{"multiline list", "ISP_INTERFACE=\"eth4,\neth3\neth2.4\"\n", "ISP_INTERFACE=\"eth4 eth3 eth2.4\"\n", []string{"eth4", "eth3", "eth2.4"}},
		{"continuation", "ISP_INTERFACE=eth4,\\\neth3\n", "ISP_INTERFACE=\"eth4 eth3\"\n", []string{"eth4", "eth3"}},
		{"escaped comma", "ISP_INTERFACE=eth4\\,eth3\n", "ISP_INTERFACE=\"eth4 eth3\"\n", []string{"eth4", "eth3"}},
		{"escaped space", "ISP_INTERFACE=eth4\\ eth3\n", "ISP_INTERFACE=eth4\\ eth3\n", []string{"eth4", "eth3"}},
		{"prefix wildcard and aliases", "ISP_INTERFACE=\"eth+,eth2.4,br-wan,ppp0:1,+\"\n", "ISP_INTERFACE=\"eth+ eth2.4 br-wan ppp0:1 +\"\n", []string{"eth+", "eth2.4", "br-wan", "ppp0:1", "+"}},
		{"duplicate assignments", "ISP_INTERFACE=eth4,eth3\nISP_INTERFACE='eth2.4'\n", "ISP_INTERFACE=\"eth4 eth3\"\nISP_INTERFACE='eth2.4'\n", []string{"eth2.4"}},
		{"fifteen bytes", "ISP_INTERFACE=123456789012345\n", "ISP_INTERFACE=123456789012345\n", []string{"123456789012345"}},
		{"empty", "ISP_INTERFACE=\"\"\n", "ISP_INTERFACE=\"\"\n", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeWANInterfaces(tt.source)
			if err != nil || got != tt.want {
				t.Fatalf("NormalizeWANInterfaces() = %q, %v; want %q", got, err, tt.want)
			}
			for _, source := range []string{tt.source, got} {
				ifaces, err := WANInterfacesFromConf(source)
				if err != nil || !reflect.DeepEqual(ifaces, tt.ifaces) {
					t.Fatalf("WANInterfacesFromConf(%q) = %#v, %v; want %#v", source, ifaces, err, tt.ifaces)
				}
			}
			if again, err := NormalizeWANInterfaces(got); err != nil || again != got {
				t.Fatalf("not idempotent: %q, %v", again, err)
			}
		})
	}
}

func TestNormalizeWANInterfacesPreservesOtherAssignmentsAndMultilineContents(t *testing.T) {
	const prefix = "# ISP_INTERFACE=eth4,eth3\n" +
		"TCP_PORTS=\"80,443\"\nUDP_PORTS=\"443,50000:50100\"\n" +
		"NFQWS_ARGS='--filter-tcp=80,443\nISP_INTERFACE=\"eth8,eth9\"\n'\n" +
		"NFQWS_BASE_ARGS=\"--literal=\\\"text\\\"\nISP_INTERFACE='eth6,eth7'\n\"\n" +
		"NFQWS_EXTRA_ARGS=\"$MODE_LIST ${MODE_ALL}\"\n"
	source := prefix + "ISP_INTERFACE=\"eth4,eth3,eth2.4\" # retain comment\n"
	want := prefix + "ISP_INTERFACE=\"eth4 eth3 eth2.4\" # retain comment\n"
	got, err := NormalizeWANInterfaces(source)
	if err != nil || got != want {
		t.Fatalf("NormalizeWANInterfaces() = %q, %v; want %q", got, err, want)
	}
	ifaces, err := WANInterfacesFromConf(source)
	if err != nil || !reflect.DeepEqual(ifaces, []string{"eth4", "eth3", "eth2.4"}) {
		t.Fatalf("WANInterfacesFromConf() = %v, %v", ifaces, err)
	}
}

func TestWANInterfacesLeavesShellExpressionsUntouched(t *testing.T) {
	for _, source := range []string{
		"# ISP_INTERFACE=eth4,eth3\nTCP_PORTS=80,443\n",
		"ISP_INTERFACE=\"$WAN,eth3\"\n",
		"ISP_INTERFACE=\"${WAN},eth3\"\n",
		"ISP_INTERFACE=\"${WAN:-eth4,eth3}\"\n",
		"ISP_INTERFACE=~root\n",
		"ISP_INTERFACE=\"$(printf 'eth4,eth3')\"\n",
		"ISP_INTERFACE=`printf 'eth4,eth3'`\n",
		"ISP_INTERFACE=eth4,eth3 # candidate\nprintf '%s' changed\n",
		"if true; then\nISP_INTERFACE=eth4,eth3\nfi\n",
		"configure() {\nISP_INTERFACE=eth4,eth3\n}\n",
		"cat <<'EOF'\nISP_INTERFACE=eth4,eth3\nEOF\n",
		"ISP_INTERFACE=eth4,eth3; printf '%s' changed\n",
		"ISP_INTERFACE=eth4,eth3 command\n",
		"ISP_INTERFACE=\"eth4,eth3\n",
		"NFQWS_ARGS=\"$(printf '\nISP_INTERFACE=eth4,eth3\n')\"\n",
	} {
		t.Run(source, func(t *testing.T) {
			got, err := NormalizeWANInterfaces(source)
			if err != nil || got != source {
				t.Fatalf("modified shell expression: %q, %v", got, err)
			}
			ifaces, err := WANInterfacesFromConf(source)
			if err != nil || ifaces != nil {
				t.Fatalf("evaluated shell expression: %v, %v", ifaces, err)
			}
		})
	}
}

func TestWANInterfacesDynamicLastAssignment(t *testing.T) {
	const source = "ISP_INTERFACE=eth4,eth3\nISP_INTERFACE=\"$WAN\"\n"
	got, err := NormalizeWANInterfaces(source)
	if err != nil || got != "ISP_INTERFACE=\"eth4 eth3\"\nISP_INTERFACE=\"$WAN\"\n" {
		t.Fatalf("normalization: %q, %v", got, err)
	}
	ifaces, err := WANInterfacesFromConf(source)
	if err != nil || ifaces != nil {
		t.Fatalf("dynamic final value became static: %v, %v", ifaces, err)
	}
}

func TestWANInterfacesRejectsInvalidLiteralNames(t *testing.T) {
	for _, value := range []string{
		"eth4,1234567890123456,eth3",
		"eth4,bad/name,eth3",
		"eth4,eth+bad,eth3",
		"eth4,eth*,eth3",
		"eth4,eth?,eth3",
		"eth4,.,eth3",
		"eth4,..,eth3",
		"eth4,eth#0,eth3",
		"eth4,eth\\0,eth3",
		"eth4,eth\"0,eth3",
		"eth4,$WAN,eth3", // Single quotes make the dollar a literal name.
	} {
		t.Run(value, func(t *testing.T) {
			source := "ISP_INTERFACE='" + value + "'\n"
			got, err := NormalizeWANInterfaces(source)
			if err == nil || !strings.Contains(err.Error(), "ISP_INTERFACE") || got != source {
				t.Fatalf("invalid list modified or accepted: %q, %v", got, err)
			}
			if ifaces, err := WANInterfacesFromConf(source); err == nil || ifaces != nil {
				t.Fatalf("invalid list partially accepted: %v, %v", ifaces, err)
			}
		})
	}
}

func TestLoadFromNfqws2ConfUsesWANInterfaceParser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nfqws2.conf")
	conf := &Config{Nfqws2Conf: path, WANIfaces: []string{"default"}}
	for _, source := range []string{
		"ISP_INTERFACE=eth4,eth3,eth2.4\n",
		"export ISP_INTERFACE='eth4,eth3,eth2.4'\n",
		"ISP_INTERFACE=\"eth4,eth3,eth2.4\"\n",
	} {
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := conf.LoadFromNfqws2Conf(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(conf.WANIfaces, []string{"eth4", "eth3", "eth2.4"}) {
			t.Fatalf("WANIfaces = %v", conf.WANIfaces)
		}
	}
	for _, source := range []string{"ISP_INTERFACE=\"$WAN\"\n", "TCP_PORTS=80,443\n"} {
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := conf.LoadFromNfqws2Conf(); err != nil || !reflect.DeepEqual(conf.WANIfaces, []string{"eth4", "eth3", "eth2.4"}) {
			t.Fatalf("default value not preserved: %v, %v", conf.WANIfaces, err)
		}
	}
	if err := os.WriteFile(path, []byte("ISP_INTERFACE=\"eth4,1234567890123456\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conf.LoadFromNfqws2Conf(); err == nil {
		t.Fatal("invalid interface length was accepted")
	}
}
