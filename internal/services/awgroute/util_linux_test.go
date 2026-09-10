//go:build linux

package awgroute

import "testing"

func TestSelectDefaultRouteKeepsGatewayAndDeviceFromSameLine(t *testing.T) {
	for name, out := range map[string]string{
		"gateway-first": `default via 192.168.0.1 dev br0 metric 100
default dev nwg1 scope link metric 10`,
		"direct-first": `default dev nwg1 scope link metric 10
default via 192.168.0.1 dev br0 metric 100`,
	} {
		t.Run(name, func(t *testing.T) {
			gw, dev := selectDefaultRoute(out)
			if gw != "192.168.0.1" || dev != "br0" {
				t.Fatalf("selectDefaultRoute() gw=%q dev=%q, want gw=192.168.0.1 dev=br0", gw, dev)
			}
		})
	}
}

func TestEndpointRouteCmdAllowsDirectDevice(t *testing.T) {
	got := awgEndpointRouteCmd("138.124.229.182", "", "nwg1")
	want := "ip route replace 138.124.229.182/32 dev nwg1"
	if got != want {
		t.Fatalf("awgEndpointRouteCmd()=%q, want %q", got, want)
	}
}

func TestSelectDefaultRouteFallsBackToDirectDevice(t *testing.T) {
	gw, dev := selectDefaultRoute("default dev nwg1 scope link metric 10")
	if gw != "" || dev != "nwg1" {
		t.Fatalf("selectDefaultRoute() gw=%q dev=%q, want gw='' dev=nwg1", gw, dev)
	}
}
