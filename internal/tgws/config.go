package tgws

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
)

// Config holds every knob the proxy understands. It is persisted as tgws.json
// in the app data dir and edited from the "TG WS Proxy" web tab. Web auth and
// self-update are handled by the host service, so those fields are absent.
type Config struct {
	Enabled bool `json:"enabled"`

	Port   int    `json:"port"`
	Secret string `json:"secret"` // 32 hex chars; auto-generated when empty

	DCRedirects map[int]string `json:"dc_redirects"`

	BufferSize    int  `json:"buffer_size"`
	PoolSize      int  `json:"pool_size"`
	ProxyProtocol bool `json:"proxy_protocol"`

	CFProxy             bool   `json:"cfproxy"`
	CFProxyUserDomain   string `json:"cfproxy_user_domain"`
	CFProxyWorkerDomain string `json:"cfproxy_worker_domain"`

	FakeTLSDomain string `json:"fake_tls_domain"`

	// LinkHost is embedded in the tg:// link. Empty = best-effort guess (the
	// request Host header, then the router's outbound IP).
	LinkHost string `json:"link_host"`
}

// Default returns the Keenetic-LAN defaults. The proxy is disabled by default
// so installing an update never opens a new listening port unexpectedly.
func Default() *Config {
	return &Config{
		Enabled:     false,
		Port:        1433,
		DCRedirects: map[int]string{2: "149.154.167.220", 4: "149.154.167.220"},
		BufferSize:  256 * 1024,
		PoolSize:    4,
		CFProxy:     true,
	}
}

// EnsureSecret generates a random 16-byte (32 hex) secret if none is set.
func (c *Config) EnsureSecret() {
	if c.Secret == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		c.Secret = hex.EncodeToString(b)
	}
}

// Normalize fills zero-valued fields with defaults so a partial config from
// the UI or an old file is still usable.
func (c *Config) Normalize() {
	if c.Port == 0 {
		c.Port = 1433
	}
	if c.BufferSize < 4096 {
		c.BufferSize = 256 * 1024
	}
	if c.PoolSize < 0 {
		c.PoolSize = 0
	}
	if c.DCRedirects == nil {
		c.DCRedirects = map[int]string{}
	}
	c.EnsureSecret()
}

func (c *Config) Validate() []string {
	var errs []string
	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Sprintf("порт %d вне диапазона", c.Port))
	}
	if c.Secret != "" {
		if len(c.Secret) != 32 {
			errs = append(errs, "secret должен быть ровно 32 hex-символа")
		} else if _, err := hex.DecodeString(c.Secret); err != nil {
			errs = append(errs, "secret не является корректным hex")
		}
	}
	for dc, ip := range c.DCRedirects {
		if !validDC(dc) {
			errs = append(errs, fmt.Sprintf("неизвестный DC %d", dc))
		}
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("неверный IP для DC%d: %q", dc, ip))
		}
	}
	if c.BufferSize < 4096 {
		errs = append(errs, "buffer_size должен быть >= 4096")
	}
	if c.PoolSize < 0 {
		errs = append(errs, "pool_size должен быть >= 0")
	}
	return errs
}

func validDC(dc int) bool {
	for _, d := range dcIDs {
		if d == dc {
			return true
		}
	}
	return false
}

// TGLink builds a tg://proxy link. host priority: hostOverride (e.g. the
// request Host header) -> cfg.LinkHost -> outbound-IP guess.
func TGLink(c *Config, hostOverride string) string {
	host := hostOverride
	if host == "" {
		host = c.LinkHost
	}
	if host == "" {
		host = localIPGuess()
	}
	if c.FakeTLSDomain != "" {
		domainHex := hex.EncodeToString([]byte(c.FakeTLSDomain))
		return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=ee%s%s", host, c.Port, c.Secret, domainHex)
	}
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=dd%s", host, c.Port, c.Secret)
}

func localIPGuess() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return "127.0.0.1"
}

// --- Cloudflare-proxied fallback default pool ----------------------------
// Encoded so a casual scan of the binary doesn't list fallback infrastructure;
// decoded at load time (see cfproxyDefaultPool).

var cfproxyEncodedDefaults = []string{
	"virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com",
	"twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com",
	"bxaxtxmrw.com", "dmohrsgmohcrwb.com",
}

var cfTLD = string([]byte{46, 99, 111, 46, 117, 107}) // ".co.uk"

func decodeCFProxy(label string) string {
	if len(label) < 4 || label[len(label)-4:] != ".com" {
		return label
	}
	body := label[:len(label)-4]
	n := 0
	for _, ch := range body {
		if isAlpha(ch) {
			n++
		}
	}
	out := make([]rune, 0, len(body))
	for _, ch := range body {
		if isAlpha(ch) {
			var base rune = 'A'
			if ch > '`' {
				base = 'a'
			}
			out = append(out, ((ch-base-rune(n))%26+26)%26+base)
		} else {
			out = append(out, ch)
		}
	}
	return string(out) + cfTLD
}

func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func (c *Config) cfproxyDefaultPool() []string {
	out := make([]string, 0, len(cfproxyEncodedDefaults))
	for _, d := range cfproxyEncodedDefaults {
		out = append(out, decodeCFProxy(d))
	}
	return out
}
