//go:build linux

package awgroute

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestAWGRunShellDeadlineKillsChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := awgRunShell(ctx, "sleep 5 & wait", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shell error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shell waited for child after deadline: %s", elapsed)
	}
}

func TestAWGRunShellOrphanCannotHoldOutputPipe(t *testing.T) {
	start := time.Now()
	_, err := awgRunShell(context.Background(), "sleep 5 &", "")
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("shell error = %v, want output-pipe wait limit", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("orphan held output pipe for %s", elapsed)
	}
}

func TestAWGRunShellFeedsStdin(t *testing.T) {
	out, err := awgRunShell(context.Background(), "cat", "create awgm_000 hash:net\n")
	if err != nil || out != "create awgm_000 hash:net" {
		t.Fatalf("shell stdin got output %q, error %v", out, err)
	}
}

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
