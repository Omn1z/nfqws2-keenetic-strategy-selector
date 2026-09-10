//go:build linux

package netmon

import "os"

const (
	pathConntrack = "/proc/net/nf_conntrack"
	pathCount     = "/proc/sys/net/netfilter/nf_conntrack_count"
	pathMax       = "/proc/sys/net/netfilter/nf_conntrack_max"
	pathQueue     = "/proc/net/netfilter/nfnetlink_queue"
	pathARP       = "/proc/net/arp"
	pathDev       = "/proc/net/dev"
)

// Conntrack reads and parses the live connection-tracking table.
func Conntrack() ([]Conn, error) {
	f, err := os.Open(pathConntrack)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseConntrack(f)
}

// Count returns the current and maximum conntrack table sizes.
func Count() (count, limit int, err error) {
	if count, err = readIntFile(pathCount); err != nil {
		return
	}
	limit, err = readIntFile(pathMax)
	return
}

// Queues reads the per-NFQUEUE statistics.
func Queues() ([]QueueStat, error) {
	f, err := os.Open(pathQueue)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseQueues(f)
}

// ARP reads the kernel ARP table (IP -> MAC -> bridge).
func ARP() ([]ARPEntry, error) {
	f, err := os.Open(pathARP)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseARP(f)
}

// Ifaces reads per-interface byte/packet counters.
func Ifaces() ([]IfaceBytes, error) {
	f, err := os.Open(pathDev)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseDev(f)
}

func readIntFile(p string) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return ParseCount(f)
}
