package awgroute

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestPolicyResolverOnlyQueriesMissingFamily(t *testing.T) {
	for _, tc := range []struct {
		name    string
		native  []string
		network string
		want    []string
	}{
		{"both", []string{"192.0.2.10", "2001:db8::10"}, "", []string{"192.0.2.10", "2001:db8::10"}},
		{"v4", []string{"192.0.2.10", "bad", "192.0.2.10"}, "ip6", []string{"192.0.2.10", "2001:db8::10"}},
		{"v6", []string{"2001:db8::10"}, "ip4", []string{"2001:db8::10", "192.0.2.10"}},
		{"empty", nil, "ip", []string{"192.0.2.10", "2001:db8::10"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got := policyResolveDomainAll(context.Background(), "example.test", func(context.Context, string) []string { return tc.native }, func(ctx context.Context, network, name string) ([]net.IP, error) {
				calls++
				if network != tc.network || name != "example.test" {
					t.Fatalf("unexpected fallback query %s/%s", network, name)
				}
				if network == "ip6" {
					return []net.IP{net.ParseIP("2001:db8::10")}, nil
				}
				if network == "ip4" {
					return []net.IP{net.ParseIP("192.0.2.10")}, nil
				}
				return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}, nil
			})
			if !reflect.DeepEqual(got, tc.want) || (calls == 0) != (tc.network == "") {
				t.Fatalf("got %v calls=%d", got, calls)
			}
		})
	}
}

func TestPolicyResolverCancellationStopsGoFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	got := policyResolveDomainAll(ctx, "example.test", func(context.Context, string) []string { cancel(); return []string{"192.0.2.10"} }, func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("fallback ran after native deadline/cancellation")
		return nil, nil
	})
	if !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
		t.Fatalf("valid partial native hint lost: %v", got)
	}
	got = policyResolveDomainAll(ctx, "example.test", func(context.Context, string) []string { t.Fatal("native ran after cancellation"); return nil }, nil)
	if len(got) > 0 {
		t.Fatal("canceled lookup returned new addresses")
	}
}
