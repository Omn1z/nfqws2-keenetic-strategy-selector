package netmon

import (
	"strings"
	"testing"
)

func TestParseQueues(t *testing.T) {
	const sample = `64511    422     0 2    85     0     0   244733  1
64512    422     0 2   105     0     0   360511  1
  300  24795     0 2 65531     0     0   840605  1`
	qs, err := ParseQueues(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(qs) != 3 {
		t.Fatalf("got %d queues, want 3", len(qs))
	}
	var q300 *QueueStat
	for i := range qs {
		if qs[i].Queue == 300 {
			q300 = &qs[i]
		}
	}
	if q300 == nil {
		t.Fatal("queue 300 not found")
	}
	if q300.IDSeq != 840605 || q300.Queued != 0 || q300.QueueDrop != 0 || q300.UserDrop != 0 {
		t.Errorf("queue 300 fields wrong: %+v", *q300)
	}
}

func TestParseCount(t *testing.T) {
	n, err := ParseCount(strings.NewReader("252\n"))
	if err != nil || n != 252 {
		t.Fatalf("ParseCount = %d, %v; want 252, nil", n, err)
	}
}

func TestParseARP(t *testing.T) {
	const sample = `IP address       HW type     Flags       HW address            Mask     Device
192.168.3.114    0x1         0x0         e0:01:c7:b6:95:01     *        br0
192.168.2.17     0x1         0x0         AC:BA:C0:48:8A:8E     *        br2`
	es, err := ParseARP(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(es) != 2 {
		t.Fatalf("got %d entries, want 2 (header skipped)", len(es))
	}
	if es[0].IP.String() != "192.168.3.114" || es[0].MAC != "e0:01:c7:b6:95:01" || es[0].Device != "br0" {
		t.Errorf("entry0 wrong: %+v", es[0])
	}
	if es[1].MAC != "ac:ba:c0:48:8a:8e" { // lowercased
		t.Errorf("entry1 mac not lowercased: %q", es[1].MAC)
	}
}

func TestParseDev(t *testing.T) {
	const sample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth3: 123456789 100000    0    0    0     0          0         0 987654321  90000    0    0    0     0       0          0
    lo:    1234      10    0    0    0     0          0         0     1234      10    0    0    0     0       0          0`
	ifs, err := ParseDev(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(ifs) != 2 {
		t.Fatalf("got %d ifaces, want 2 (headers skipped)", len(ifs))
	}
	var eth3 *IfaceBytes
	for i := range ifs {
		if ifs[i].Iface == "eth3" {
			eth3 = &ifs[i]
		}
	}
	if eth3 == nil {
		t.Fatal("eth3 not found")
	}
	if eth3.RxBytes != 123456789 || eth3.RxPackets != 100000 || eth3.TxBytes != 987654321 || eth3.TxPackets != 90000 {
		t.Errorf("eth3 counters wrong: %+v", *eth3)
	}
}
