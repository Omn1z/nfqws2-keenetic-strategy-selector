package nfqws2

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	bypassDomainsMaxBytes = 1 << 20
	bypassDNSWorkers      = 16
	bypassDNSPerHost      = 2 * time.Second
	bypassDNSOverall      = 30 * time.Second
)

type bypassLookup func(context.Context, string) ([]net.IPAddr, error)

// bypassDomainHost accepts the plain hostnames used by NFQWS2 lists and also
// extracts the hostname from a pasted URL. A bypass always applies to the
// whole resolved IP address, never to one URL path.
func bypassDomainHost(line string) string {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return ""
		}
		line = u.Hostname()
	}
	line = strings.TrimSuffix(strings.ToLower(line), ".")
	if len(line) == 0 || len(line) > 253 || !strings.Contains(line, ".") {
		return ""
	}
	for _, label := range strings.Split(line, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return ""
			}
		}
	}
	return line
}

func readBypassDomains(name string) ([]string, int, error) {
	f, err := os.Open(name)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, bypassDomainsMaxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > bypassDomainsMaxBytes {
		return nil, 0, fmt.Errorf("NFQUEUE bypass domain list exceeds %d bytes", bypassDomainsMaxBytes)
	}
	seen := make(map[string]bool)
	var hosts []string
	invalid := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		host := bypassDomainHost(line)
		if host == "" {
			invalid++
			continue
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	return hosts, invalid, nil
}

// resolveBypassDomains uses a bounded worker pool because a sequential DNS
// pass over a large bypass list can exceed the API deadline by minutes. The
// firewall helper consumes only the resulting cache and never performs DNS.
func resolveBypassDomains(ctx context.Context, hosts []string, lookup bypassLookup) ([]string, int) {
	if len(hosts) == 0 {
		return nil, 0
	}
	workers := bypassDNSWorkers
	if len(hosts) < workers {
		workers = len(hosts)
	}
	type result struct {
		ips []net.IPAddr
		err error
	}
	jobs := make(chan string)
	results := make(chan result, len(hosts))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				hostCtx, cancel := context.WithTimeout(ctx, bypassDNSPerHost)
				ips, err := lookup(hostCtx, host)
				cancel()
				results <- result{ips: ips, err: err}
			}
		}()
	}
	go func() {
		for _, host := range hosts {
			jobs <- host
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	seen := make(map[string]bool)
	failed := 0
	for r := range results {
		if r.err != nil || len(r.ips) == 0 {
			failed++
			continue
		}
		for _, addr := range r.ips {
			if addr.IP == nil {
				continue
			}
			seen[addr.IP.String()] = true
		}
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, failed
}

func writeBypassResolved(name string, ips []string) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".nfqueue-bypass-resolved-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	for _, ip := range ips {
		if _, err := fmt.Fprintln(f, ip); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), name)
}

func prepareBypassResolved(confDir string, lookup bypassLookup) (resolved, failed, invalid int, err error) {
	listDir := filepath.Join(confDir, "lists")
	hosts, invalid, err := readBypassDomains(filepath.Join(listDir, "nfqueue_bypass_domains.list"))
	if err != nil {
		return 0, 0, invalid, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), bypassDNSOverall)
	defer cancel()
	ips, failed := resolveBypassDomains(ctx, hosts, lookup)
	if len(hosts) > 0 && len(ips) == 0 {
		return 0, failed, invalid, fmt.Errorf("none of %d NFQUEUE bypass domains resolved", len(hosts))
	}
	if len(hosts) == 0 && invalid > 0 {
		return 0, 0, invalid, fmt.Errorf("NFQUEUE bypass domain list has no valid hostnames")
	}
	if err := writeBypassResolved(filepath.Join(listDir, "nfqueue_bypass_resolved.list"), ips); err != nil {
		return 0, failed, invalid, err
	}
	return len(ips), failed, invalid, nil
}
