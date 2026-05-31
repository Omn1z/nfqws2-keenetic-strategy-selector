package netmon

import (
	"strings"
	"testing"
)

// Verbatim rows captured from the dev router's /proc/net/nf_conntrack, plus one
// synthetic SYN_SENT row to exercise tcp failing-detection.
const sampleConntrack = `ipv4     2 tcp      6 1191 ESTABLISHED src=192.168.3.151 dst=199.232.210.172 sport=63854 dport=80 packets=6 bytes=815 src=199.232.210.172 dst=192.168.0.10 sport=80 dport=63854 packets=5 bytes=617 [ASSURED] [FASTNAT] [RTCACHE o33/r11] mark=0 nmark=0 sc=0 ifw=11 ifl=33 mac=f0:57:a6:d2:82:6e slan attrs= use=2
ipv4     2 tcp      6 1145 ESTABLISHED src=192.168.3.151 dst=160.79.104.10 sport=58163 dport=443 packets=309 bytes=365318 src=160.79.104.10 dst=10.8.1.7 sport=443 dport=58163 packets=109 bytes=21323 [ASSURED] [FASTNAT] [RTCACHE o33/r43] mark=268434095 nmark=0 sc=0 ifw=43 ifl=33 mac=f0:57:a6:d2:82:6e slan attrs= use=2
ipv6     10 udp      17 13 src=fe80:0000:0000:0000:aeba:c0ff:fe48:8a8e dst=ff02:0000:0000:0000:0000:0000:0000:00fb sport=5353 dport=5353 packets=15 bytes=7287 [UNREPLIED] src=ff02:0000:0000:0000:0000:0000:0000:00fb dst=fe80:0000:0000:0000:aeba:c0ff:fe48:8a8e sport=5353 dport=5353 packets=0 bytes=0 mark=0 nmark=0 sc=0 ifl=33 mac=ac:ba:c0:48:8a:8e slan attrs= use=2
ipv4     2 udp      17 11 src=127.0.0.1 dst=127.0.0.1 sport=60853 dport=54321 packets=2 bytes=122 src=127.0.0.1 dst=127.0.0.1 sport=54321 dport=60853 packets=2 bytes=320 mark=0 nmark=0 sc=0 nomac swan no_if attrs= use=2
ipv4     2 icmp     1 28 src=192.168.3.127 dst=213.180.193.230 type=8 code=0 id=1 packets=11063 bytes=309764 src=213.180.193.230 dst=192.168.0.10 type=0 code=0 id=0 packets=11063 bytes=309764 [FASTNAT] [RTCACHE o33/r11] mark=0 nmark=0 sc=0 ifw=11 ifl=33 mac=ac:ba:c0:48:8a:8e slan attrs= use=2
ipv4     2 tcp      6 30 SYN_SENT src=192.168.3.50 dst=1.2.3.4 sport=44444 dport=443 packets=3 bytes=180 [UNREPLIED] src=1.2.3.4 dst=192.168.3.50 sport=443 dport=44444 packets=0 bytes=0 mark=0 mac=aa:bb:cc:dd:ee:ff slan use=2`

func TestParseConntrack(t *testing.T) {
	conns, err := ParseConntrack(strings.NewReader(sampleConntrack))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(conns) != 6 {
		t.Fatalf("got %d conns, want 6", len(conns))
	}

	// Row 0: tcp ESTABLISHED, original tuple, FASTNAT+ASSURED, reply bytes captured.
	c := conns[0]
	if c.L3 != "ipv4" || c.Proto != "tcp" || c.State != "ESTABLISHED" || c.TTL != 1191 {
		t.Errorf("row0 header wrong: %+v", c)
	}
	if c.Src.String() != "192.168.3.151" || c.Dst.String() != "199.232.210.172" {
		t.Errorf("row0 tuple wrong: src=%s dst=%s", c.Src, c.Dst)
	}
	if c.SrcPort != 63854 || c.DstPort != 80 || c.Packets != 6 || c.Bytes != 815 || c.ReplyBytes != 617 {
		t.Errorf("row0 ports/counters wrong: %+v", c)
	}
	if !c.Assured || !c.FastNAT || c.Unreplied {
		t.Errorf("row0 flags wrong: %+v", c)
	}
	if c.MAC != "f0:57:a6:d2:82:6e" || c.Zone != "slan" {
		t.Errorf("row0 mac/zone wrong: mac=%q zone=%q", c.MAC, c.Zone)
	}
	if c.Failing() {
		t.Errorf("row0 should not be failing")
	}

	// Row 2: ipv6 udp mDNS, no state word, UNREPLIED -> failing at the raw level.
	c = conns[2]
	if c.Proto != "udp" || c.State != "" || !c.Unreplied || !c.Failing() {
		t.Errorf("row2 (ipv6 udp unreplied) wrong: %+v", c)
	}
	if c.Src.String() != "fe80::aeba:c0ff:fe48:8a8e" || c.DstPort != 5353 {
		t.Errorf("row2 ipv6 parse wrong: src=%s dport=%d", c.Src, c.DstPort)
	}

	// Row 3: loopback udp — parses, not failing, swan zone.
	c = conns[3]
	if c.Src.String() != "127.0.0.1" || c.Zone != "swan" || c.Failing() {
		t.Errorf("row3 loopback wrong: %+v", c)
	}

	// Row 4: icmp — no ports, FASTNAT, counters present.
	c = conns[4]
	if c.Proto != "icmp" || c.Src.String() != "192.168.3.127" || c.Dst.String() != "213.180.193.230" {
		t.Errorf("row4 icmp tuple wrong: %+v", c)
	}
	if c.DstPort != 0 || c.Packets != 11063 || !c.FastNAT {
		t.Errorf("row4 icmp fields wrong: %+v", c)
	}

	// Row 5: synthetic tcp SYN_SENT -> failing.
	c = conns[5]
	if c.State != "SYN_SENT" || !c.Failing() {
		t.Errorf("row5 SYN_SENT should be failing: %+v", c)
	}
}

func TestParseConntrackEdgeCases(t *testing.T) {
	conns, err := ParseConntrack(strings.NewReader("\ngarbage line with no fields x\nipv4 2\n"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// "ipv4 2" has <5 fields -> skipped; the garbage line has >=5 fields but a
	// non-numeric TTL at f[4] ("no") -> skipped. Empty line -> skipped.
	if len(conns) != 0 {
		t.Fatalf("got %d conns, want 0 (all malformed): %+v", len(conns), conns)
	}
}

func TestGroupDevices(t *testing.T) {
	conns, err := ParseConntrack(strings.NewReader(sampleConntrack))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	arp := []ARPEntry{} // exercise the conntrack-mac fallback path
	devs := GroupDevices(conns, arp)

	// Expect 3 LAN devices: .151 (2 working tcp), .127 (1 working icmp), .50 (1
	// failing tcp). The ipv6 link-local and the loopback rows are excluded.
	if len(devs) != 3 {
		t.Fatalf("got %d devices, want 3: %+v", len(devs), devs)
	}
	// Most-failing first.
	if devs[0].IP != "192.168.3.50" || devs[0].Failing != 1 || len(devs[0].FailingDsts) != 1 {
		t.Errorf("expected .50 first with 1 failing dst: %+v", devs[0])
	}
	if devs[0].FailingDsts[0] != "1.2.3.4:443" {
		t.Errorf("failing dst wrong: %v", devs[0].FailingDsts)
	}
	byIP := map[string]Device{}
	for _, d := range devs {
		byIP[d.IP] = d
	}
	if d := byIP["192.168.3.151"]; d.Total != 2 || d.Established != 2 || d.Failing != 0 || len(d.Working) != 2 {
		t.Errorf(".151 aggregate wrong: %+v", d)
	}
	if d := byIP["192.168.3.151"]; d.MAC != "f0:57:a6:d2:82:6e" {
		t.Errorf(".151 mac (from conntrack) wrong: %q", d.MAC)
	}
	if d := byIP["192.168.3.127"]; d.Established != 1 || len(d.Working) != 1 {
		t.Errorf(".127 (icmp) aggregate wrong: %+v", d)
	}
}

func TestGroupDevicesARPFallback(t *testing.T) {
	// A conn with no mac= must pick up MAC + bridge from the ARP table.
	const row = `ipv4 2 tcp 6 100 ESTABLISHED src=192.168.3.200 dst=8.8.8.8 sport=12345 dport=443 packets=1 bytes=60 src=8.8.8.8 dst=192.168.3.200 sport=443 dport=12345 packets=1 bytes=60 [ASSURED] mark=0 nomac slan use=2`
	conns, _ := ParseConntrack(strings.NewReader(row))
	arp, _ := ParseARP(strings.NewReader("IP address       HW type     Flags       HW address            Mask     Device\n192.168.3.200    0x1         0x2         AA:BB:CC:00:11:22     *        br0"))
	devs := GroupDevices(conns, arp)
	if len(devs) != 1 {
		t.Fatalf("want 1 device, got %d", len(devs))
	}
	if devs[0].MAC != "aa:bb:cc:00:11:22" || devs[0].Iface != "br0" {
		t.Errorf("ARP fallback failed: mac=%q iface=%q", devs[0].MAC, devs[0].Iface)
	}
}
