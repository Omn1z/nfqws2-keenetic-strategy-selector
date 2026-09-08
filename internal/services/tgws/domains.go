package tgws

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const cfProxyDomainsURL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

func normalizeDomainList(entries []string) []string {
	out := make([]string, 0)
	seen := make(map[string]bool)
	for _, entry := range entries {
		for _, domain := range strings.FieldsFunc(entry, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
		}) {
			domain = strings.ToLower(domain)
			if !seen[domain] {
				seen[domain] = true
				out = append(out, domain)
			}
		}
	}
	return out
}

func validDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !isAlpha(ch) && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	return len(tld) >= 2 && strings.ContainsFunc(tld, isAlpha)
}

// Never replace a working pool with an error page, duplicates or a partial
// response. Keep the bundled pool when GitHub cannot be reached.
func parseCFDomainPool(data string) []string {
	var domains []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			domain := strings.ToLower(decodeCFProxy(line))
			if validDomain(domain) {
				domains = append(domains, domain)
			}
		}
	}
	return normalizeDomainList(domains)
}

func refreshCFDomains(ctx context.Context, client *http.Client, source string, bal *domainBalancer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "n2s-tgws/"+UpstreamVersion)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	const limit = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return fmt.Errorf("domain list exceeds %d bytes", limit)
	}
	pool := parseCFDomainPool(string(data))
	if len(pool) < 3 {
		return fmt.Errorf("domain list contains fewer than 3 valid distinct domains")
	}
	bal.updatePool(pool)
	log.Printf("tgws: CF domain pool refreshed (%d domains)", len(pool))
	return nil
}

func runCFDomainRefresh(ctx context.Context, bal *domainBalancer) {
	// Match upstream's GitHub DNS fallback without disabling HTTPS verification.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if host == "raw.githubusercontent.com" {
			return dialer.DialContext(ctx, network, net.JoinHostPort("185.199.109.133", port))
		}
		return dialer.DialContext(ctx, network, addr)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	normalTransport := http.DefaultTransport.(*http.Transport).Clone()
	normalTransport.Proxy = nil
	defer normalTransport.CloseIdleConnections()
	normalClient := &http.Client{Timeout: 10 * time.Second, Transport: normalTransport}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if err := refreshCFWithFallback(ctx, client, normalClient, cfProxyDomainsURL, bal); err != nil && ctx.Err() == nil {
			log.Printf("tgws: CF domain refresh failed; keeping current pool: %s", censorDomains(err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func refreshCFWithFallback(ctx context.Context, pinned, normal *http.Client, source string, bal *domainBalancer) error {
	err := refreshCFDomains(ctx, pinned, source, bal)
	if err == nil || ctx.Err() != nil {
		return err
	}
	// Retry the whole request: a pinned IP can accept TCP but fail during TLS.
	return refreshCFDomains(ctx, normal, source, bal)
}

var logDomainPattern = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`)

// Match upstream's log filter locally, without changing logs of other services.
func censorDomains(message string) string {
	return logDomainPattern.ReplaceAllStringFunc(message, func(domain string) string {
		normal := strings.ToLower(domain)
		if normal == "telegram.org" || strings.HasSuffix(normal, ".telegram.org") || strings.HasSuffix(normal, ".log") {
			return domain
		}
		labels := strings.Split(domain, ".")
		for i := 0; i < len(labels)-1; i++ {
			n := len(labels[i]) / 2
			labels[i] = labels[i][:n] + strings.Repeat("*", len(labels[i])-n)
		}
		return strings.Join(labels, ".")
	})
}
