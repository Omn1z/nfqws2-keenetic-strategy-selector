// Package netmon reads and parses Linux /proc network state — conntrack,
// nfnetlink_queue stats, the ARP table and per-interface byte counters — for the
// monitoring dashboard, connections view and device-activity view.
//
// The parsers operate on an io.Reader and carry no build tag, so they unit-test
// on any OS. Only the thin file-opening layer (proc_linux.go) is Linux-only;
// proc_other.go returns ErrUnsupported so the project still builds and tests on
// the Windows dev box.
package netmon

import (
	"errors"
	"net/netip"
	"strconv"
)

// ErrUnsupported is returned by the /proc readers on non-Linux builds.
var ErrUnsupported = errors.New("netmon: /proc network state is only available on Linux")

// Conn is one parsed row of /proc/net/nf_conntrack.
//
// The original tuple (Src/Dst/...) is the first src=/dst= block — its src is the
// LAN initiator and its dst is the address that was dialed. The reply counters
// come from the second block.
//
// Packets/Bytes counters go stale under hardware offload ([FASTNAT]/[RTCACHE]):
// the kernel stops seeing offloaded packets, so treat the counters as display
// only and never infer activity or failure from them. The connection State and
// the Unreplied/Assured flags stay valid regardless of offload, so Failing() is
// reliable.
type Conn struct {
	L3    string `json:"l3"`    // ipv4 | ipv6
	Proto string `json:"proto"` // tcp | udp | icmp | ...
	State string `json:"state"` // tcp only (ESTABLISHED, SYN_SENT, ...); "" otherwise
	TTL   int    `json:"ttl"`   // seconds until this entry expires

	Src        netip.Addr `json:"src"` // original src = LAN initiator
	Dst        netip.Addr `json:"dst"` // original dst = destination dialed
	SrcPort    int        `json:"sport"`
	DstPort    int        `json:"dport"`
	Packets    int64      `json:"packets"` // original direction (may be stale under offload)
	Bytes      int64      `json:"bytes"`
	ReplyBytes int64      `json:"reply_bytes"`

	Assured   bool   `json:"assured"`
	Unreplied bool   `json:"unreplied"`
	FastNAT   bool   `json:"fastnat"`
	MAC       string `json:"mac"`
	Zone      string `json:"zone"` // slan | swan | ""
}

// Failing reports whether the connection looks like "couldn't connect": no reply
// was ever seen, or a TCP handshake is stuck in SYN_SENT. Safe under offload.
func (c Conn) Failing() bool {
	return c.Unreplied || (c.Proto == "tcp" && c.State == "SYN_SENT")
}

// QueueStat is one row of /proc/net/netfilter/nfnetlink_queue. IDSeq is a
// monotonic per-packet id, so it approximates the total packets handled by the
// queue; QueueDrop/UserDrop expose kernel- and userspace-side drops.
type QueueStat struct {
	Queue     int   `json:"queue"`
	PortID    int   `json:"portid"`
	Queued    int   `json:"queued"`
	CopyMode  int   `json:"copy_mode"`
	CopyRange int   `json:"copy_range"`
	QueueDrop int64 `json:"queue_drop"`
	UserDrop  int64 `json:"user_drop"`
	IDSeq     int64 `json:"id_seq"`
}

// ARPEntry maps a LAN IP to its MAC and the bridge it was seen on (br0=LAN,
// br2=guest, eth3=WAN on this router).
type ARPEntry struct {
	IP     netip.Addr `json:"ip"`
	MAC    string     `json:"mac"`
	Device string     `json:"device"`
}

// IfaceBytes holds cumulative byte/packet counters for one interface. The
// dashboard turns the byte counters into a rate by diffing successive samples.
type IfaceBytes struct {
	Iface     string `json:"iface"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
	RxPackets int64  `json:"rx_packets"`
	TxPackets int64  `json:"tx_packets"`
}

// Device aggregates a LAN device's connections, splitting destinations into ones
// that responded (Working) and ones that didn't (FailingDsts) — the latter feed
// the strategy-picking workflow.
type Device struct {
	IP          string   `json:"ip"`
	MAC         string   `json:"mac"`
	Iface       string   `json:"iface"`
	Total       int      `json:"total"`
	Established int      `json:"established"`
	Failing     int      `json:"failing"`
	Working     []string `json:"working"`
	FailingDsts []string `json:"failing_dsts"`
}

func atoi(s string) int     { n, _ := strconv.Atoi(s); return n }
func atoi64(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
