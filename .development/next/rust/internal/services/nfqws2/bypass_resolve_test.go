package nfqws2

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBypassDomainHost(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"img.reg.ru", "img.reg.ru"},
		{" IMG.REG.RU. # CDN ", "img.reg.ru"},
		{"https://img.reg.ru/news/picture.webp", "img.reg.ru"},
		{"https://img.reg.ru:443/news/picture.webp", "img.reg.ru"},
		{"*.reg.ru", ""},
		{"img.reg.ru/other", ""},
		{"img.reg.ru; comment", "img.reg.ru"},
		{"bad host.test", ""},
		{"https://", ""},
	} {
		if got := bypassDomainHost(tc.raw); got != tc.want {
			t.Errorf("bypassDomainHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestReadBypassDomainsDeduplicatesAndReportsBadLines(t *testing.T) {
	name := filepath.Join(t.TempDir(), "domains.list")
	if err := os.WriteFile(name, []byte("# note\nimg.reg.ru\nhttps://IMG.REG.RU/news/a.webp\n*.invalid.test\napi.reg.ru\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hosts, invalid, err := readBypassDomains(name)
	if err != nil || invalid != 1 || strings.Join(hosts, ",") != "img.reg.ru,api.reg.ru" {
		t.Fatalf("hosts=%v invalid=%d err=%v", hosts, invalid, err)
	}
}

func TestResolveBypassDomainsIsBoundedAndDeduplicatesIPs(t *testing.T) {
	hosts := []string{"a.example", "b.example", "c.example", "d.example"}
	var mu sync.Mutex
	active, maxActive := 0, 0
	lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		defer func() { mu.Lock(); active--; mu.Unlock() }()
		select {
		case <-time.After(15 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if host == "d.example" {
			return nil, errors.New("NXDOMAIN")
		}
		return []net.IPAddr{{IP: net.ParseIP("194.58.116.35")}}, nil
	}
	ips, failed := resolveBypassDomains(context.Background(), hosts, lookup)
	if failed != 1 || strings.Join(ips, ",") != "194.58.116.35" || maxActive < 2 || maxActive > bypassDNSWorkers {
		t.Fatalf("ips=%v failed=%d maxActive=%d", ips, failed, maxActive)
	}
}

func TestPrepareBypassResolvedReplacesCacheAndPreservesOnTotalDNSFailure(t *testing.T) {
	root := t.TempDir()
	listDir := filepath.Join(root, "lists")
	if err := os.MkdirAll(listDir, 0o755); err != nil {
		t.Fatal(err)
	}
	domains := filepath.Join(listDir, "nfqueue_bypass_domains.list")
	cache := filepath.Join(listDir, "nfqueue_bypass_resolved.list")
	if err := os.WriteFile(domains, []byte("img.reg.ru\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "img.reg.ru" {
			t.Fatalf("unexpected lookup %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("194.58.116.35")}}, nil
	}
	resolved, failed, invalid, err := prepareBypassResolved(root, lookup)
	if err != nil || resolved != 1 || failed != 0 || invalid != 0 {
		t.Fatalf("resolved=%d failed=%d invalid=%d err=%v", resolved, failed, invalid, err)
	}
	data, err := os.ReadFile(cache)
	if err != nil || string(data) != "194.58.116.35\n" {
		t.Fatalf("cache=%q err=%v", data, err)
	}
	_, _, _, err = prepareBypassResolved(root, func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("DNS unavailable") })
	if err == nil {
		t.Fatal("all DNS failures must be reported")
	}
	data, err = os.ReadFile(cache)
	if err != nil || string(data) != "194.58.116.35\n" {
		t.Fatalf("failed update replaced the last usable cache: %q err=%v", data, err)
	}
	if err := os.WriteFile(domains, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, failed, invalid, err = prepareBypassResolved(root, lookup)
	if err != nil || resolved != 0 || failed != 0 || invalid != 0 {
		t.Fatalf("clear: resolved=%d failed=%d invalid=%d err=%v", resolved, failed, invalid, err)
	}
	data, err = os.ReadFile(cache)
	if err != nil || len(data) != 0 {
		t.Fatalf("removed domains remain in cache: %q err=%v", data, err)
	}
}
