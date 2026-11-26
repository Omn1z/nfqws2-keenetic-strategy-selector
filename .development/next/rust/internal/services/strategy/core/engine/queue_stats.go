package engine

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const nfqueueStatsPath = "/proc/net/netfilter/nfnetlink_queue"

// QueuePackets returns the kernel packet-ID sequence for this worker's queue.
// It increments on enqueue, unlike queue_total (the current backlog), which can
// remain zero throughout a healthy test. Compare snapshots for inequality:
// uint32 wraparound from 0xffffffff to zero is valid traffic, not a decrease.
//
// This is queue-level evidence, not proof for every TCP connection. Call around
// one probe at a time per worker. Rules and worker source ports must remain
// isolated, and the nfqws listener must not be restarted between snapshots.
func (s *Sandbox) QueuePackets() (uint32, error) {
	var data []byte
	var err error
	if s.queueRead != nil {
		data, err = s.queueRead()
	} else {
		data, err = os.ReadFile(nfqueueStatsPath)
	}
	if err != nil {
		return 0, fmt.Errorf("read NFQUEUE counters: %w", err)
	}
	return parseQueuePackets(data, s.QNum)
}

func parseQueuePackets(data []byte, queue int) (uint32, error) {
	want := strconv.Itoa(queue)
	var sequence uint32
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != want {
			continue
		}
		if found {
			return 0, fmt.Errorf("duplicate NFQUEUE %d counter row", queue)
		}
		// Linux columns: queue, peer port ID, backlog, copy mode, copy range,
		// queue dropped, userspace dropped, packet-ID sequence, [flags].
		// Do not substitute backlog/drop counters when a row is incomplete.
		if len(fields) < 8 {
			return 0, fmt.Errorf("incomplete NFQUEUE %d counter row", queue)
		}
		for i := 0; i < 8; i++ {
			n, err := strconv.ParseUint(fields[i], 10, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid NFQUEUE %d counter column %d: %w", queue, i+1, err)
			}
			if i == 7 {
				sequence = uint32(n)
			}
		}
		found = true
	}
	if !found {
		return 0, fmt.Errorf("NFQUEUE %d is not bound", queue)
	}
	return sequence, nil
}
