package netmon

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// ParseQueues parses /proc/net/netfilter/nfnetlink_queue. Columns:
// queue_num peer_portid queue_total copy_mode copy_range queue_dropped user_dropped id_sequence 1
func ParseQueues(r io.Reader) ([]QueueStat, error) {
	sc := bufio.NewScanner(r)
	var out []QueueStat
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		out = append(out, QueueStat{
			Queue:     atoi(f[0]),
			PortID:    atoi(f[1]),
			Queued:    atoi(f[2]),
			CopyMode:  atoi(f[3]),
			CopyRange: atoi(f[4]),
			QueueDrop: atoi64(f[5]),
			UserDrop:  atoi64(f[6]),
			IDSeq:     atoi64(f[7]),
		})
	}
	return out, sc.Err()
}

// ParseCount reads a single-integer /proc file (nf_conntrack_count / _max).
func ParseCount(r io.Reader) (int, error) {
	b, err := io.ReadAll(io.LimitReader(r, 64))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
