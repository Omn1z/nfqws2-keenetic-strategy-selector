package awgroute

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestEndpointICMPHintsRunInParallelAndKeepNegativeUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := []string{"192.0.2.1:443", "[2001:db8::2]:443", "vpn.example:443", "uncached.example:443"}
	started := make(chan string, 3)
	release := make(chan struct{})
	done := make(chan map[string]bool, 1)
	go func() {
		done <- parallelEndpointHints(ctx, pool, func(host string) string {
			if host == "vpn.example" {
				return "192.0.2.3"
			}
			return ""
		}, func(ctx context.Context, ip string) bool {
			started <- ip
			select {
			case <-release:
				return ip != "192.0.2.3"
			case <-ctx.Done():
				return false
			}
		})
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("IP probes waited serially for previous result")
		}
	}
	close(release)
	select {
	case result := <-done:
		if len(result) != 2 || !result[pool[0]] || !result[pool[1]] {
			t.Fatalf("ICMP hints=%v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("parallel scan failed to finish")
	}
}

func TestEndpointICMPHintsBoundWorkersAndHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := make([]string, 100)
	for i := range pool {
		pool[i] = "192.0.2.1:443"
	}
	started := make(chan struct{}, 9)
	done := make(chan map[string]bool, 1)
	var calls atomic.Int32
	go func() {
		done <- parallelEndpointHints(ctx, pool, func(string) string { return "" }, func(ctx context.Context, _ string) bool {
			calls.Add(1)
			started <- struct{}{}
			<-ctx.Done()
			return false
		})
	}()
	for i := 0; i < 9; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("bounded worker did not start")
		}
	}
	cancel()
	select {
	case result := <-done:
		if calls.Load() != 9 || len(result) != 0 {
			t.Fatal("unbounded scan or cancellation treated as success")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not release ICMP scan")
	}
}
