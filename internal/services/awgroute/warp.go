package awgroute

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
)

const (
	warpAPIURL        = "https://api.cloudflareclient.com"
	warpAPIVersion    = "v0a1922"
	warpDefaultDNS    = "1.1.1.1, 1.0.0.1"
	warpDefaultMTU    = 1280
	warpDefaultName   = "Cloudflare WARP"
	warpDefaultEP     = "188.114.97.100:2408"
	warpDefaultModel  = "Keenetic"
	warpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpDefaultI1     = "<b 0x494e56495445207369703a626f624062696c6f78692e636f6d205349502f322e300d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a4d61782d466f7277617264733a2037300d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e746163743a203c7369703a616c69636540706333332e61746c616e74612e636f6d3e0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f7364700d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>"
	warpDefaultI2     = "<b 0x5349502f322e302031303020547279696e670d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>"
)

var warpBootstrapEndpoints = []string{
	"188.114.97.100:2408",
	"188.114.96.100:2408",
	"162.159.193.1:2408",
	"162.159.192.1:2408",
	"162.159.193.10:2408",
	"162.159.195.100:2408",
	"162.159.195.250:2408",
	"162.159.195.50:2408",
	"162.159.193.100:2408",
	"162.159.195.1:2408",
	"engage.cloudflareclient.com:2408",
}

type WARPCreateOptions struct {
	Name      string
	Endpoint  string
	AcceptTOS bool
}

type warpRegisterRequest struct {
	FCMToken  string `json:"fcm_token"`
	InstallID string `json:"install_id"`
	Key       string `json:"key"`
	Locale    string `json:"locale"`
	Model     string `json:"model"`
	TOS       string `json:"tos"`
	Type      string `json:"type"`
}

type warpRegisterResponse struct {
	ID      string         `json:"id"`
	Token   string         `json:"token"`
	Account warpAccount    `json:"account"`
	Config  warpClientConf `json:"config"`
}

type warpAccount struct {
	AccountType string `json:"account_type"`
	WarpPlus    bool   `json:"warp_plus"`
}

type warpClientConf struct {
	Interface warpInterface `json:"interface"`
	Peers     []warpPeer    `json:"peers"`
}

type warpInterface struct {
	Addresses warpAddresses `json:"addresses"`
}

type warpAddresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type warpPeer struct {
	PublicKey string `json:"public_key"`
}

func (svc *Service) AWG2CreateWARP(ctx context.Context, opts WARPCreateOptions) (AWG2Status, error) {
	if !opts.AcceptTOS {
		return svc.AWG2StatusView(), fmt.Errorf("нужно подтвердить условия Cloudflare перед созданием WARP")
	}
	conf, err := createWARPAmneziaConf(ctx, opts)
	if err != nil {
		return svc.AWG2StatusView(), err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = warpDefaultName
	}
	return svc.AWG2Import(conf, name)
}

func createWARPAmneziaConf(ctx context.Context, opts WARPCreateOptions) (string, error) {
	priv, pub, err := awg.GenKeypair()
	if err != nil {
		return "", err
	}
	reg, err := warpRegister(ctx, pub)
	if err != nil {
		return "", err
	}
	if len(reg.Config.Peers) == 0 || strings.TrimSpace(reg.Config.Peers[0].PublicKey) == "" {
		return "", fmt.Errorf("Cloudflare не вернул публичный ключ WARP peer")
	}
	addr := warpClientAddress(reg.Config.Interface.Addresses)
	if addr == "" {
		return "", fmt.Errorf("Cloudflare не вернул IPv4 адрес WARP")
	}
	endpoint := normalizeWARPEndpoint(opts.Endpoint)
	if endpoint == "" {
		endpoint = warpDefaultEP
	}
	return renderWARPAmneziaConf(priv, addr, reg.Config.Peers[0].PublicKey, endpoint), nil
}

func warpRegister(ctx context.Context, publicKey string) (*warpRegisterResponse, error) {
	req := warpRegisterRequest{
		Key:    publicKey,
		Locale: "en_US",
		Model:  warpDefaultModel,
		TOS:    time.Now().Format(time.RFC3339Nano),
		Type:   "Android",
	}
	var out warpRegisterResponse
	if err := warpJSON(ctx, http.MethodPost, warpAPIURL+"/"+warpAPIVersion+"/reg", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func warpJSON(ctx context.Context, method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(in); err != nil {
			return err
		}
		body = &b
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.3-1922")
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := warpHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("Cloudflare API %s: %s", resp.Status, msg)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return err
		}
	}
	return nil
}

var warpHTTPClient = &http.Client{
	Timeout: 25 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	},
}

func renderWARPAmneziaConf(privateKey, address, peerPublicKey, endpoint string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s
MTU = %d
S1 = 0
S2 = 0
S3 = 0
S4 = 0
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = %s
I2 = %s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
PersistentKeepalive = 25
`, privateKey, address, warpDefaultDNS, warpDefaultMTU, warpDefaultI1, warpDefaultI2, strings.TrimSpace(peerPublicKey), endpoint)
}

func warpClientAddress(addrs warpAddresses) string {
	v4 := strings.TrimSpace(addrs.V4)
	if v4 == "" {
		return ""
	}
	if strings.Contains(v4, "/") {
		return v4
	}
	return v4 + "/32"
}

func normalizeWARPEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	host, port, ok := splitHostPortDefault(endpoint, 2408)
	if !ok || port <= 0 || port > 65535 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func isWARPConfig(cfg awg.ServerConfig) bool {
	if cfg.Install != "imported" {
		return false
	}
	if strings.TrimSpace(cfg.PublicKey) == warpPeerPublicKey {
		return true
	}
	host, _, ok := splitHostPortDefault(cfg.Endpoint, 2408)
	return ok && warpHostLooksLikeIngress(host)
}

func warpEndpointCandidates(current string) []string {
	current = normalizeWARPEndpoint(current)
	currentHost, currentPort := "", 0
	if current != "" {
		currentHost, currentPort, _ = splitHostPortDefault(current, 2408)
	}
	hosts := warpCandidateHosts(currentHost)
	ports := warpCandidatePorts(currentPort)
	out := make([]string, 0, len(hosts)*len(ports))
	seen := map[string]bool{}
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		for _, port := range ports {
			ep := normalizeWARPEndpoint(net.JoinHostPort(host, strconv.Itoa(port)))
			if ep == "" || seen[ep] {
				continue
			}
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

func (svc *Service) awgPrioritizedWARPEndpointCandidates(current string, ranked []string) []string {
	return prioritizeWARPEndpoints(current, svc.awgKnownWARPEndpoints(), ranked)
}

func (svc *Service) awgKnownWARPEndpoints() []string {
	out := []string{}
	for _, srv := range svc.serverSnapshot() {
		cfg := srv.Manager.Config()
		if !isWARPConfig(cfg) {
			continue
		}
		out = append(out, cfg.Endpoint)
	}
	return out
}

func prioritizeWARPEndpoints(current string, known, ranked []string) []string {
	current = normalizeWARPEndpoint(current)
	out := []string{}
	seen := map[string]bool{}
	add := func(endpoint string) {
		endpoint = normalizeWARPEndpoint(endpoint)
		if endpoint == "" {
			return
		}
		key := strings.ToLower(endpoint)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, endpoint)
	}

	// Non-default ports are usually explicit/manual. Keep them first, then try
	// throughput-proven WARP seeds before RTT-only ranking.
	if current != "" && !strings.HasSuffix(current, ":2408") {
		add(current)
	}
	for _, endpoint := range warpBootstrapEndpoints {
		add(endpoint)
	}
	for _, endpoint := range ranked {
		add(endpoint)
	}
	for _, endpoint := range known {
		add(endpoint)
	}
	add(current)
	return out
}

func warpCandidateHosts(currentHost string) []string {
	hosts := []string{}
	add := func(host string) {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	add(currentHost)
	add("engage.cloudflareclient.com")

	octets := []int{1, 2, 3, 4, 5, 8, 10, 16, 20, 32, 50, 64, 80, 100, 128, 150, 180, 200, 220, 240, 250}
	// Cloudflare's documented WARP ingress is 162.159.193.0/24. Consumer
	// WARP and common AWG-WARP generators also use the adjacent anycast pools
	// below, so keep them in the probe set and let the router measure them.
	for _, prefix := range []string{"162.159.193", "162.159.192", "162.159.195", "188.114.96", "188.114.97"} {
		for _, n := range octets {
			add(prefix + "." + strconv.Itoa(n))
		}
	}
	seen := map[string]bool{}
	out := hosts[:0]
	for _, host := range hosts {
		key := strings.ToLower(host)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, host)
	}
	return out
}

func warpCandidatePorts(currentPort int) []int {
	ports := []int{}
	add := func(port int) {
		if port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	add(currentPort)
	for _, port := range []int{2408, 500, 1701, 4500, 8886} {
		add(port)
	}
	seen := map[int]bool{}
	out := ports[:0]
	for _, port := range ports {
		if seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	return out
}

func warpHostLooksLikeIngress(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "engage.cloudflareclient.com" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{
		"162.159.192.0/24",
		"162.159.193.0/24",
		"162.159.195.0/24",
		"188.114.96.0/24",
		"188.114.97.0/24",
	} {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func splitHostPortDefault(raw string, defaultPort int) (host string, port int, ok bool) {
	if h, p, err := net.SplitHostPort(raw); err == nil {
		n, _ := strconv.Atoi(p)
		return strings.Trim(h, "[]"), n, n > 0 && n <= 65535
	}
	if strings.Count(raw, ":") > 1 {
		return strings.Trim(raw, "[]"), defaultPort, true
	}
	if i := strings.LastIndexByte(raw, ':'); i > 0 {
		n, err := strconv.Atoi(raw[i+1:])
		if err != nil {
			return "", 0, false
		}
		return raw[:i], n, true
	}
	return raw, defaultPort, true
}
