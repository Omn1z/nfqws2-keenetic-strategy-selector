//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShadowFallbackDiscoveryOneProbePerPass(t *testing.T) {
	t.Run("multiple verified WAN peers", func(t *testing.T) {
		first, second := net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.10")
		state := shadowInformState{targets: map[string]shadowDHCPTarget{
			"ISP":  {wanKey: "two-wans", clientIP: first, serverIP: net.ParseIP("192.0.2.1")},
			"ISP2": {wanKey: "two-wans", clientIP: second, serverIP: net.ParseIP("198.51.100.1")},
		}}
		calls := 0
		state.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
			calls++
			return nil, fmt.Errorf("DHCP peer unreachable")
		}
		got, err := discoverShadowInform(context.Background(), &state, "two-wans", []net.IP{first, second}, nil,
			map[string]string{first.String(): "eth3", second.String(): "eth4"}, func(string, net.IP) bool { return true })
		if err == nil || len(got) != 0 || calls != 1 {
			t.Fatal("one discovery pass multiplied DHCP probes across WANs", got, err, calls)
		}
	})
	t.Run("pending fallback and another known peer", func(t *testing.T) {
		a, _, _ := shadowFallbackFixture(t)
		unicast, broadcast := 0, 0
		a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
			unicast++
			return nil, context.DeadlineExceeded
		}
		_, _ = a.ShadowDNSServers(context.Background())
		// A legacy persisted alias can coexist with the preferred broadcast
		// target. It must not cause a second network probe in the same pass.
		other := a.shadow.inform.targets["ISP"]
		other.serverIP, other.preferBroadcast = net.ParseIP("192.0.2.3"), false
		a.shadow.inform.targets["ZZZ"] = other
		a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
			broadcast++
			return nil, nil, context.DeadlineExceeded
		}
		previous := command
		command = func(ctx context.Context, name string, args ...string) (string, error) {
			if filepath.Base(name) == "ndmc" && strings.Join(args, " ") == "-c show interface ZZZ" {
				return previous(ctx, name, "-c", "show interface ISP")
			}
			return previous(ctx, name, args...)
		}
		shadowFallbackRetryNow(a)
		_, _ = a.ShadowDNSServers(context.Background())
		if unicast+broadcast != 2 {
			t.Fatal("second pass combined unicast with broadcast", unicast, broadcast)
		}
	})
}

func TestShadowFallbackNativeInspectionCannotReturnExpiredAnswer(t *testing.T) {
	a, _, native := shadowFallbackFixture(t)
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		return []string{"192.0.2.53"}, nil
	}
	if _, err := a.ShadowDNSServers(context.Background()); err != nil {
		t.Fatal(err)
	}
	target := a.shadow.inform.targets["ISP"]
	target.preferBroadcast = true
	a.shadow.inform.targets["ISP"] = target
	previous := command
	inspections := 0
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		if filepath.Base(name) == "ndmc" && strings.Join(args, " ") == "-c show interface" {
			inspections++
			time.Sleep(75 * time.Millisecond)
			return strings.ReplaceAll(*native, "security-level: public", "security-level: private"), nil
		}
		return previous(ctx, name, args...)
	}
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		t.Fatal("ineligible WAN caused a broadcast")
		return nil, nil, nil
	}
	answer := a.shadow.inform.answers["ISP"]
	answer.expires = time.Now().Add(50 * time.Millisecond)
	a.shadow.inform.answers["ISP"] = answer
	shadowFallbackRetryNow(a)
	if got, err := a.ShadowDNSServers(context.Background()); err == nil || len(got) != 0 || inspections != 1 {
		t.Fatal("DNS expired during native inspection but escaped TTL validation", got, err, inspections)
	}
}

func TestShadowFallbackNativeInspectionPreservesOuterDeadline(t *testing.T) {
	a, _, _ := shadowFallbackFixture(t)
	a.shadow.inform.probe = func(context.Context, string, net.IP, net.IP) ([]string, error) {
		return []string{"192.0.2.53"}, nil
	}
	if _, err := a.ShadowDNSServers(context.Background()); err != nil {
		t.Fatal(err)
	}
	target := a.shadow.inform.targets["ISP"]
	target.preferBroadcast = true
	a.shadow.inform.targets["ISP"] = target
	answer := a.shadow.inform.answers["ISP"]
	answer.expires = time.Now().Add(40 * time.Second)
	a.shadow.inform.answers["ISP"] = answer
	previous := command
	inspections := 0
	command = func(ctx context.Context, name string, args ...string) (string, error) {
		if filepath.Base(name) == "ndmc" && strings.Join(args, " ") == "-c show interface" {
			inspections++
			<-ctx.Done()
			return "", ctx.Err()
		}
		return previous(ctx, name, args...)
	}
	a.shadow.inform.probeDiscover = func(context.Context, string, net.IP) (net.IP, []string, error) {
		t.Fatal("expired discovery context caused a broadcast")
		return nil, nil, nil
	}
	shadowFallbackRetryNow(a)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, err := discoverShadowServersWithState(ctx, a.cfg.WANIfaces, a.shadow.leases, &a.shadow.inform)
	if !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 || inspections != 1 {
		t.Fatal("native inspection deadline returned cached DNS instead of cancellation", got, err, inspections)
	}
}
