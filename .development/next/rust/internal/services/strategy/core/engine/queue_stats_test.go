package engine

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestQueuePacketsLinuxProcFormat(t *testing.T) {
	// Real Linux seq_printf column layout: queue_total can be zero while the
	// packet-ID sequence advances. Other queues must never count for this worker.
	data := []byte("  200  23121     0 2 65531     3     4       27  1\n" +
		"  201  23122     8 2 65531     0     0      919  1\n" +
		"  300   8894     0 2 65531     0     0    98312  1\n")
	for queue, want := range map[int]uint32{200: 27, 201: 919, 300: 98312} {
		got, err := parseQueuePackets(data, queue)
		if err != nil || got != want {
			t.Fatalf("queue %d: got %d, %v; want %d", queue, got, err, want)
		}
	}
}

func TestQueuePacketsRejectsMissingOrMalformedTargetQueue(t *testing.T) {
	for name, text := range map[string]string{
		"empty":            "",
		"other_queue":      "300 99 0 2 65531 0 0 123 1\n",
		"queue_prefix":     "2000 99 0 2 65531 0 0 123 1\n",
		"truncated":        "200 99 0 2 65531 0 0\n",
		"bad_sequence":     "200 99 0 2 65531 0 0 invalid 1\n",
		"negative":         "200 99 0 2 65531 0 0 -1 1\n",
		"overflow":         "200 99 0 2 65531 0 0 4294967296 1\n",
		"hex_not_decimal":  "200 99 0 2 65531 0 0 0xff 1\n",
		"malformed_prefix": "200 bad 0 2 65531 0 0 19 1\n",
		"duplicate":        "200 99 0 2 65531 0 0 19 1\n200 99 0 2 65531 0 0 20 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseQueuePackets([]byte(text), 200); err == nil {
				t.Fatal("missing/malformed queue accepted as traffic evidence")
			}
		})
	}
}

func TestQueuePacketsZeroAndWraparound(t *testing.T) {
	for _, values := range [][2]uint32{{0, 0}, {0, 1}, {42, 42}, {42, 43}, {0xffffffff, 0}} {
		t.Run(fmt.Sprintf("%d_to_%d", values[0], values[1]), func(t *testing.T) {
			index := 0
			s := &Sandbox{QNum: 200, queueRead: func() ([]byte, error) {
				text := fmt.Sprintf("200 99 0 2 65531 0 0 %d 1\n", values[index])
				index++
				return []byte(text), nil
			}}
			before, err := s.QueuePackets()
			if err != nil {
				t.Fatal(err)
			}
			after, err := s.QueuePackets()
			if err != nil {
				t.Fatal(err)
			}
			if before != values[0] || after != values[1] || (before != after) != (values[0] != values[1]) {
				t.Fatalf("incorrect packet sequence snapshots: %d -> %d", before, after)
			}
		})
	}
}

func TestQueuePacketsReadErrorsFailClosed(t *testing.T) {
	for _, cause := range []error{os.ErrPermission, os.ErrNotExist} {
		s := &Sandbox{QNum: 200, queueRead: func() ([]byte, error) { return nil, cause }}
		if _, err := s.QueuePackets(); !errors.Is(err, cause) || !strings.Contains(err.Error(), "read NFQUEUE counters") {
			t.Fatalf("read error lost: %v", err)
		}
		if s.queueBound() {
			t.Fatal("unreadable queue reported as bound")
		}
	}
}

func TestQueueBoundRequiresValidWorkerCounter(t *testing.T) {
	for _, row := range []string{"200 99 0 2 65531 0 0 0 1\n", "200 99 0 2 65531 0 0 67 1\n"} {
		s := &Sandbox{QNum: 200, queueRead: func() ([]byte, error) { return []byte(row), nil }}
		if !s.queueBound() {
			t.Fatalf("valid zero-backlog queue not bound: %s", row)
		}
	}
	s := &Sandbox{QNum: 200, queueRead: func() ([]byte, error) { return []byte("300 99 0 2 65531 0 0 999 1\n"), nil }}
	if s.queueBound() {
		t.Fatal("another worker's queue reported as bound")
	}
}
