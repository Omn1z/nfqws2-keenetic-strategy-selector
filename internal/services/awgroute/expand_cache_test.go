package awgroute

import (
	"reflect"
	"testing"
)

func TestExpandCacheRetriesGenerationChangedDuringExpansion(t *testing.T) {
	svc := &Service{}
	calls := 0
	read := func([]string) ([]string, []string) {
		calls++
		if calls == 1 {
			svc.BumpZonesRevision()
			return []string{"old.example"}, []string{"192.0.2.1"}
		}
		return []string{"new.example"}, []string{"192.0.2.2"}
	}
	domains, ips := svc.expandEntriesFresh("list:sites", []string{"list:sites"}, read)
	if calls != 2 || !reflect.DeepEqual(domains, []string{"new.example"}) || !reflect.DeepEqual(ips, []string{"192.0.2.2"}) {
		t.Fatalf("did not expand the new generation: calls=%d domains=%v ips=%v", calls, domains, ips)
	}
	entry := svc.expandCache["list:sites"]
	if entry.rev != svc.zonesRevision.Load() || !reflect.DeepEqual(entry.domains, domains) || !reflect.DeepEqual(entry.ips, ips) {
		t.Fatalf("cache published stale content as new: %+v", entry)
	}
}

func TestExpandCacheContinuousEditsAreBoundedAndNeverRelabelOldContent(t *testing.T) {
	svc := &Service{}
	calls := 0
	read := func([]string) ([]string, []string) {
		calls++
		svc.BumpZonesRevision()
		return []string{"changing.example"}, nil
	}
	svc.expandEntriesFresh("list:sites", []string{"list:sites"}, read)
	if calls != 2 {
		t.Fatalf("generation retries were not bounded: calls=%d", calls)
	}
	if _, exists := svc.expandCache["list:sites"]; exists {
		t.Fatal("an unstable expansion must not be cached under the new revision")
	}
}

func TestExpandCacheOldComputationDoesNotEraseConcurrentNewResult(t *testing.T) {
	svc := &Service{}
	calls := 0
	read := func([]string) ([]string, []string) {
		calls++
		if calls == 1 {
			svc.BumpZonesRevision()
			svc.expandMu.Lock()
			svc.expandCache = map[string]expandCacheEntry{
				"list:other": {rev: svc.zonesRevision.Load(), domains: []string{"other-new.example"}},
			}
			svc.expandMu.Unlock()
			return []string{"sites-old.example"}, nil
		}
		return []string{"sites-new.example"}, nil
	}
	svc.expandEntriesFresh("list:sites", []string{"list:sites"}, read)
	if other, exists := svc.expandCache["list:other"]; !exists || !reflect.DeepEqual(other.domains, []string{"other-new.example"}) {
		t.Fatalf("a concurrent result was erased: %+v", svc.expandCache)
	}
	if sites := svc.expandCache["list:sites"]; !reflect.DeepEqual(sites.domains, []string{"sites-new.example"}) {
		t.Fatalf("old computation poisoned the cache: %+v", sites)
	}
}

func TestExpandCacheMemoHitDoesNotExpandStableListAgain(t *testing.T) {
	svc := &Service{}
	domains := []string{"cached.example"}
	ips := []string{"192.0.2.3"}
	svc.expandEntriesFresh("list:sites", []string{"list:sites"}, func([]string) ([]string, []string) {
		return domains, ips
	})
	gotDomains, gotIPs := svc.expandEntriesMemo([]string{"list:sites"})
	if len(gotDomains) != 1 || len(gotIPs) != 1 || &gotDomains[0] != &domains[0] || &gotIPs[0] != &ips[0] {
		t.Fatal("the hot path did not reuse the already expanded slices")
	}
}
