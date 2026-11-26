package awgroute

import (
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func revisionRouteFixture(name string) *routeTable {
	matchers, _ := awg.CompileMatcherSet([]string{name})
	return &routeTable{ordered: []orderedZoneMatcher{{Matchers: &matchers, Route: "tunnel", Index: 0}}}
}

func TestRouteTableRevisionInvalidatesUnchangedRuleText(t *testing.T) {
	svc := &Service{}
	cfg := &awg.ServerConfig{Routing: awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{{Name: "sites", Domains: []string{"list:sites"}, Enabled: true}}}}
	want := routeTableInputHash(cfg, false)
	old := revisionRouteFixture("old.example")
	old.hash = want
	svc.route.routeTable.Store(old)
	svc.BumpZonesRevision() // caller notified an update; list:sites text stayed the same
	newTable := svc.republishRouteTableFresh(want, func() *routeTable { return revisionRouteFixture("new.example") })
	if newTable == old || newTable.revision != svc.zonesRevision.Load() || svc.route.routeTable.Load() != newTable {
		t.Fatal("unchanged list reference kept the old cached route table")
	}
	if svc.routeFor("new.example", "").Route != RouteTunnel || svc.routeFor("old.example", "").Route != RouteUnknown {
		t.Fatal("the published decisions did not use the new list content")
	}
	if svc.republishRouteTable(cfg, false) != newTable {
		t.Fatal("an unchanged generation must reuse the published snapshot")
	}
}

func TestRouteTableRetriesChangeDuringColdBuild(t *testing.T) {
	svc := &Service{}
	calls := 0
	table := svc.republishRouteTableFresh("same-rule-hash", func() *routeTable {
		calls++
		if calls == 1 {
			svc.BumpZonesRevision()
			return revisionRouteFixture("old.example")
		}
		return revisionRouteFixture("new.example")
	})
	if calls != 2 || table.revision != svc.zonesRevision.Load() || svc.route.routeTable.Load() != table || svc.routeFor("old.example", "").Route != RouteUnknown {
		t.Fatal("a stale cold build was published under the new generation")
	}
}

func TestRouteTableContinuousEditsKeepExistingSnapshotAndBoundRetries(t *testing.T) {
	svc := &Service{}
	existing := revisionRouteFixture("existing.example")
	svc.route.routeTable.Store(existing)
	calls := 0
	table := svc.republishRouteTableFresh("new-rule-hash", func() *routeTable {
		calls++
		svc.BumpZonesRevision()
		return revisionRouteFixture("changing.example")
	})
	if calls != 2 || svc.route.routeTable.Load() != existing {
		t.Fatal("continuous edits caused unbounded rebuilding or overwrote a published snapshot")
	}
	if table.revision == svc.zonesRevision.Load() {
		t.Fatal("an unstable result must keep its original generation")
	}
}

func TestRouteTableConcurrentPublisherCannotBeOverwrittenByOldBuild(t *testing.T) {
	svc := &Service{}
	fresh := revisionRouteFixture("other.example")
	fresh.hash = "same-rule-hash"
	table := svc.republishRouteTableFresh("same-rule-hash", func() *routeTable {
		svc.route.routeTable.Store(fresh) // another builder completed during expansion
		return revisionRouteFixture("older.example")
	})
	if table != fresh || svc.route.routeTable.Load() != fresh || svc.routeFor("older.example", "").Route != RouteUnknown {
		t.Fatal("the old computation overwrote the concurrent published snapshot")
	}
}
