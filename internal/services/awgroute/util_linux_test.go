//go:build linux

package awgroute

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestAWGRunShellInterpretsScriptDirectlyFromStdin(t *testing.T) {
	bin := t.TempDir()
	shell := "#!/bin/sh\n[ \"$#\" -eq 0 ] || exit 2\nexec /bin/sh\n"
	if err := os.WriteFile(filepath.Join(bin, "sh"), []byte(shell), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	// A large DNS membership batch can exceed the per-argument limit.
	script := strings.Repeat("# padding\n", 16*1024) + "printf 'present\\n'\n"
	out, err := awgRunShell(context.Background(), "sh", script)
	if err != nil || out != "present" {
		t.Fatalf("shell script got output %q, error %v", out, err)
	}
}

func TestFirewallRestoreRetriesRespectOuterCommandDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	script := "mock_restore() { if [ \"$1\" = --help ]; then echo usage; return 0; fi; cat >/dev/null; echo 'Another app is currently holding the xtables lock.' >&2; return 4; }\n"
	script += awgFirewallRestoreShell("awg_restore_test", "mock_restore", "TESTRESTORE", "*mangle\n:AWG2_MULTI -\nCOMMIT\n")
	script += "awg_restore_test\n"
	started := time.Now()
	_, err := awgRunShell(ctx, script, "")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatalf("restore retries outlived the shared command deadline: %v elapsed=%s", err, time.Since(started))
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
