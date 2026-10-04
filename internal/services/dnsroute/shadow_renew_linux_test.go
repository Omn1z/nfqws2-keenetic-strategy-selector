//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shadowRenewFixture(t *testing.T) (*Adapter, *shadowNativeFakeReader, func(context.Context, string, ...string) (string, error)) {
	t.Helper()
	a, reader, _ := shadowNativeFixture(t)
	a.runCtx = context.Background()
	a.shadowRenewal.platformOnce.Do(func() { a.shadowRenewal.supported = true })
	previous := command
	withClient := func(ctx context.Context, name string, args ...string) (string, error) {
		if filepath.Base(name) == "ndmc" && strings.Join(args, " ") == "-c show ip dhcp client GigabitEthernet1" {
			return "dhcp-client:\n id: GigabitEthernet1\n name: ISP\n service: running\n state: bound\n", nil
		}
		return previous(ctx, name, args...)
	}
	command = withClient
	return a, reader, withClient
}

func TestShadowRenewalUsesOneVerifiedNativeCommand(t *testing.T) {
	for _, kind := range []string{"ack", "ack_no_dns", "nak"} {
		t.Run(kind, func(t *testing.T) {
			a, reader, fallback := shadowRenewFixture(t)
			a.SetShadowDiagnostics(true)
			mutations := 0
			command = func(ctx context.Context, name string, args ...string) (string, error) {
				if len(args) == 2 && strings.HasPrefix(args[1], "interface ") {
					mutations++
					if filepath.Base(name) != "ndmc" || args[1] != "interface GigabitEthernet1 ip dhcp client renew" {
						t.Fatal(name, args)
					}
					if reader.stopped || a.shadow.native.reader != reader {
						t.Fatal("capture not active before renew")
					}
					if _, err := a.RenewShadowDNS(ctx); err == nil {
						t.Fatal("concurrent action accepted")
					}
					shadowNativeTestACK(reader, time.Now())
					reader.state.observation.Kind = kind
					if kind != "ack" {
						reader.state.observation.Servers = nil
					}
					return "Dhcp::Client: interface renewed.", nil
				}
				return fallback(ctx, name, args...)
			}
			result, err := a.RenewShadowDNS(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"ack": "resolved", "ack_no_dns": "no_dns", "nak": "nak"}[kind]
			if result.Status != want || result.Interface != "GigabitEthernet1" || mutations != 1 {
				t.Fatal(result, mutations)
			}
			if kind == "ack" && (len(result.Servers) != 1 || result.Servers[0] != "192.0.2.53:53") {
				t.Fatal(result)
			}
			if _, err := a.RenewShadowDNS(context.Background()); err == nil || mutations != 1 {
				t.Fatal("cooldown did not prevent duplicate", err, mutations)
			}
			diag := a.ShadowDiagnostics()
			if len(diag.Attempts) != 1 {
				t.Fatal("renew diagnostics split across discoveries", len(diag.Attempts))
			}
			found := false
			for _, event := range diag.Attempts[0].Events {
				found = found || event.Stage == "native.renew.command"
			}
			if !found {
				t.Fatal("mutation missing from diagnostics")
			}
		})
	}
}

func TestShadowRenewalAlreadyResolvedDoesNotRenew(t *testing.T) {
	a, reader, fallback := shadowRenewFixture(t)
	shadowNativeTestACK(reader, time.Now())
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		if len(args) == 2 && strings.HasPrefix(args[1], "interface ") {
			t.Fatal("unnecessary renewal")
		}
		return fallback(ctx, name, args...)
	}
	result, err := a.RenewShadowDNS(context.Background())
	if err != nil || result.Status != "resolved" || len(result.Servers) != 1 {
		t.Fatal(result, err)
	}
	if !a.shadowRenewal.next.IsZero() {
		t.Fatal("no-op consumed mutation cooldown")
	}
}

func TestShadowRenewalPreflightFailuresNeverMutate(t *testing.T) {
	for _, failure := range []string{"stopped", "dhcp_stopped", "dhcp_wrong_id", "wan_changed", "native_changed", "capture_closed", "client_error"} {
		t.Run(failure, func(t *testing.T) {
			a, reader, fallback := shadowRenewFixture(t)
			if failure == "stopped" {
				a.started = false
			}
			routeReads, interfaceReads := 0, 0
			command = func(ctx context.Context, name string, args ...string) (string, error) {
				op := strings.Join(args, " ")
				if len(args) == 2 && strings.HasPrefix(args[1], "interface ") {
					t.Fatal("unverified renewal", failure)
				}
				if op == "-4 route show table main default" {
					routeReads++
					if failure == "wan_changed" && routeReads > 1 {
						return "default via 198.51.100.1 dev other", nil
					}
				}
				if op == "-c show interface" {
					interfaceReads++
					if failure == "native_changed" && interfaceReads > 1 {
						return "", nil
					}
				}
				if op == "-c show ip dhcp client GigabitEthernet1" {
					switch failure {
					case "dhcp_stopped":
						return "id: GigabitEthernet1\nservice: stopped", nil
					case "dhcp_wrong_id":
						return "id: Home\nservice: running", nil
					case "capture_closed":
						reader.state.closed = true
					case "client_error":
						return "", errors.New("native unavailable")
					}
				}
				return fallback(ctx, name, args...)
			}
			if result, err := a.RenewShadowDNS(context.Background()); err == nil {
				t.Fatal("preflight accepted", failure, result)
			}
			if !a.shadowRenewal.next.IsZero() {
				t.Fatal("preflight consumed mutation cooldown")
			}
		})
	}
}

func TestShadowRenewalCommandFailureIsNotRetried(t *testing.T) {
	for _, failure := range []string{"error", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			a, _, fallback := shadowRenewFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			command = func(ctx context.Context, name string, args ...string) (string, error) {
				if len(args) == 2 && strings.HasPrefix(args[1], "interface ") {
					calls++
					if failure == "cancelled" {
						cancel()
						return "", context.Canceled
					}
					return "", fmt.Errorf("ambiguous native command result")
				}
				return fallback(ctx, name, args...)
			}
			if _, err := a.RenewShadowDNS(ctx); err == nil {
				t.Fatal("command error lost")
			}
			if _, err := a.RenewShadowDNS(context.Background()); err == nil || calls != 1 {
				t.Fatal("command retried", calls, err)
			}
		})
	}
}

func TestShadowRenewalWaitIsBoundedAndCancellable(t *testing.T) {
	reader := &shadowNativeFakeReader{}
	if got, err := waitShadowRenewal(context.Background(), reader, 0, time.Millisecond); err != nil || got.sequence != 0 {
		t.Fatal(got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitShadowRenewal(ctx, reader, 0, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	reader.state.closed = true
	if got, err := waitShadowRenewal(context.Background(), reader, 0, time.Hour); err != nil || !got.closed {
		t.Fatal(got, err)
	}
}

func TestShadowRenewalDHCPServiceParsing(t *testing.T) {
	for _, text := range []string{"id: GigabitEthernet1\nservice: stopped", "id: Other\nservice: running", "id: GigabitEthernet1\nservice: running\nid: Other", "id: GigabitEthernet1\nservice: running\nservice: stopped"} {
		if shadowNativeDHCPRunning(text, "GigabitEthernet1") {
			t.Fatal("unsafe service match", text)
		}
	}
	if !shadowNativeDHCPRunning("dhcp-client:\n id: GigabitEthernet1\n service: running\n state: renew", "GigabitEthernet1") {
		t.Fatal("native service not recognized")
	}
}

func TestShadowRenewalDoesNotApplyDNSAfterWANChanges(t *testing.T) {
	for _, kind := range []string{"ack", "nak"} {
		t.Run(kind, func(t *testing.T) {
			a, reader, fallback := shadowRenewFixture(t)
			renewed := false
			command = func(ctx context.Context, name string, args ...string) (string, error) {
				if len(args) == 2 && strings.HasPrefix(args[1], "interface ") {
					renewed = true
					shadowNativeTestACK(reader, time.Now())
					reader.state.observation.Kind = kind
					return "", nil
				}
				if renewed && strings.Join(args, " ") == "-4 route show table main default" {
					return "", nil
				}
				return fallback(ctx, name, args...)
			}
			result, err := a.RenewShadowDNS(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := "waiting"
			if kind == "nak" {
				want = "nak"
			}
			if result.Status != want || len(result.Servers) != 0 || !reader.stopped {
				t.Fatal(result, reader.stopped)
			}
		})
	}
}

func TestShadowRenewalDiscoveryMutexWaitHonorsCancellation(t *testing.T) {
	a, _, _ := shadowRenewFixture(t)
	a.shadow.discoveryMu.Lock()
	defer a.shadow.discoveryMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := a.RenewShadowDNS(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if !a.shadowRenewal.next.IsZero() {
		t.Fatal("waiting for discovery issued renewal")
	}
}
