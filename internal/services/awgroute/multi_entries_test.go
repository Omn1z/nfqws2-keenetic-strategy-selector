package awgroute

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestMultiRuleResolutionIsBoundedParallelAndSeedsCache(t *testing.T) {
	svc := &Service{}
	domains := make([]string, 64)
	for i := range domains {
		domains[i] = fmt.Sprintf("host%d.example", i)
	}
	domains = append(domains, "*.mask.example")
	var active, peak, called atomic.Int32
	live := func(name string) []string {
		called.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		index, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "host"), ".example"))
		if err != nil {
			return nil
		}
		return []string{fmt.Sprintf("198.51.100.%d", index+1)}
	}
	z := awg.Zone{Domains: domains}
	entries, catchAll, static := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(true, live))
	if catchAll || !static || len(entries) != 64 || called.Load() != 64 {
		t.Fatalf("unexpected result: entries=%d catchAll=%v static=%v calls=%d", len(entries), catchAll, static, called.Load())
	}
	if peak.Load() < 2 || peak.Load() > 32 {
		t.Fatalf("lookup concurrency=%d, want 2..32", peak.Load())
	}
	cached, _, _ := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(false, live))
	if !reflect.DeepEqual(cached, entries) || called.Load() != 64 {
		t.Fatal("recovery did not reuse complete DNS cache")
	}
}
