package awgroute

import (
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestDNSLogicalConnectionFollowsReserveAndReturnsToPrimary(t *testing.T) {
	svc, driver, servers := testSupervisedService(t)
	primary, reserve := servers[0], servers[1]
	pc, rc := primary.Manager.Config(), reserve.Manager.Config()
	pc.ClientIface, pc.Client.FallbackTunnelIDs = "awg1", []string{reserve.ID}
	rc.ClientIface, rc.Client.Standby = "awg2", true
	if err := primary.Manager.SetConfig(&pc); err != nil {
		t.Fatal(err)
	}
	if err := reserve.Manager.SetConfig(&rc); err != nil {
		t.Fatal(err)
	}
	svc.clients.standbyActive = map[*awg.Manager]bool{reserve.Manager: true}
	driver.states[reserve.Manager] = ClientStatus{Running: true, Connected: true}
	running := map[string]bool{"awg1": true, "awg2": true}
	routes := svc.dnsRouteCandidates(func(iface string) bool { return running[iface] })
	if len(routes) != 2 || routes[0].ID != primary.ID || routes[0].Interface != "awg2" || !routes[0].Available {
		t.Fatalf("explicit primary DNS route did not use reserve: %+v", routes)
	}
	driver.states[primary.Manager] = ClientStatus{Running: true, Connected: true}
	routes = svc.dnsRouteCandidates(func(iface string) bool { return running[iface] })
	if routes[0].Interface != "awg1" || !routes[0].Available {
		t.Fatalf("primary recovery did not restore DNS route: %+v", routes)
	}
	primary.Manager.SetEnabled(false)
	routes = svc.dnsRouteCandidates(func(iface string) bool { return running[iface] })
	if len(routes) != 1 || routes[0].ID != reserve.ID {
		t.Fatalf("disabled primary exposed a logical DNS route: %+v", routes)
	}
}

func TestDNSIdleConnectionRemainsUsableButDormantReserveDoesNot(t *testing.T) {
	svc, driver, servers := testSupervisedService(t)
	primary, reserve := servers[0], servers[1]
	pc, rc := primary.Manager.Config(), reserve.Manager.Config()
	pc.ClientIface, pc.Client.FallbackTunnelIDs = "awg1", []string{reserve.ID}
	rc.ClientIface, rc.Client.Standby = "awg2", true
	if err := primary.Manager.SetConfig(&pc); err != nil {
		t.Fatal(err)
	}
	if err := reserve.Manager.SetConfig(&rc); err != nil {
		t.Fatal(err)
	}
	// A leftover interface/status must not activate a reserve whose persisted
	// standby intent has not been demanded by a failing primary.
	driver.states[reserve.Manager] = ClientStatus{Running: true, Connected: true}
	routes := svc.dnsRouteCandidates(func(string) bool { return true })
	if len(routes) != 2 {
		t.Fatalf("expected primary and standby profiles: %+v", routes)
	}
	if got := []DNSRouteInfo{routes[0], routes[1]}; !reflect.DeepEqual(got, []DNSRouteInfo{
		{ID: primary.ID, Name: pc.Endpoint, Interface: "awg1", Available: true},
		{ID: reserve.ID, Name: rc.Endpoint, Interface: "awg2", Available: false},
	}) {
		t.Fatalf("idle primary or dormant reserve handled incorrectly: %+v", got)
	}
}
