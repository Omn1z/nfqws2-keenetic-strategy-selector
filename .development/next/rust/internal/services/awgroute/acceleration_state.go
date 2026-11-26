package awgroute

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
)

const awgAccelerationJournalName = "awg-acceleration-state.json"
const awgAccelerationOwner = "nfqws2-strategy/awg-acceleration"

type awgAccelerationJournal struct {
	Owner   string            `json:"owner"`
	Version int               `json:"version"`
	BootID  string            `json:"boot_id"`
	Sysctls map[string]string `json:"sysctls"`
	Native  map[string]bool   `json:"native_ppe,omitempty"`
	Guarded bool              `json:"guards_owned,omitempty"`
}

// Original settings belong to one boot and survive a process crash. Runtime
// mode never substitutes for that snapshot: an attempted fallback may fail.
type awgAccelerationState struct {
	mu                  sync.Mutex
	journal             *awgAccelerationJournal
	mode                string
	ifaces              []string
	capChecked, capable bool
	accountingProven    bool
	nativeChanged       bool
	lastMessage         string
	previousBootOwned   bool
	queue, nfqwsChanges int
	nfqwsDirty          bool
	run                 func(string) (string, error)
	readFile            func(string) ([]byte, error)
	getenv              func(string) string
}

func decodeAWGAccelerationJournal(data []byte) (*awgAccelerationJournal, error) {
	var journal awgAccelerationJournal
	if len(data) > 64<<10 || json.Unmarshal(data, &journal) != nil || journal.Owner != awgAccelerationOwner || journal.Version != 1 || journal.BootID == "" {
		return nil, fmt.Errorf("invalid AWG acceleration recovery journal")
	}
	allowed := map[string]bool{}
	for _, key := range []string{"net.netfilter.nf_conntrack_fastnat", "net.netfilter.nf_conntrack_fastroute", "net.netfilter.nf_conntrack_fastnat_xfrm", "net.netfilter.nf_conntrack_fastpath_esp", "net.core.swnat", "net.hwnat.extif_offload", "net.hwnat.ppe_enabled"} {
		allowed[key] = true
	}
	for key, value := range journal.Sysctls {
		if _, err := strconv.ParseUint(value, 10, 32); !allowed[key] || err != nil {
			return nil, fmt.Errorf("invalid AWG acceleration sysctl snapshot")
		}
	}
	for key := range journal.Native {
		if key != "hardware" && key != "software" {
			return nil, fmt.Errorf("invalid native PPE snapshot")
		}
	}
	return &journal, nil
}

func (state *awgAccelerationState) environment(key string) string {
	if state.getenv != nil {
		return state.getenv(key)
	}
	return os.Getenv(key)
}
