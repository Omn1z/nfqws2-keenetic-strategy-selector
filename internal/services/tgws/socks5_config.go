package tgws

import (
	"fmt"
	"net"
	"net/url"
)

// Socks5Config holds the SOCKS5 Telegram proxy knobs (adapted from TGLock).
// Persisted as socks5.json. The proxy listens on the LAN (all interfaces) and
// tunnels Telegram DC traffic over WSS to web.telegram.org; non-Telegram
// CONNECTs are relayed directly (pass-through). Optional username/password auth
// gates access (empty = no-auth, like TGLock).
type Socks5Config struct {
	Enabled bool `json:"enabled"`

	Port int    `json:"port"`
	User string `json:"user"` // optional SOCKS5 username; empty = no-auth
	Pass string `json:"pass"` // optional SOCKS5 password

	BufferSize  int            `json:"buffer_size"`
	DCRedirects map[int]string `json:"dc_redirects"` // optional DC->IP override; empty = DNS to kws{dc}.web.telegram.org
	LinkHost    string         `json:"link_host"`
}

// Socks5Default returns the LAN defaults. Disabled by default so an update never
// opens a new listening port unexpectedly. Port 1080 is the SOCKS convention and
// avoids the 1433 used by the MTProto proxy.
func Socks5Default() *Socks5Config {
	return &Socks5Config{
		Enabled:     false,
		Port:        1080,
		BufferSize:  64 * 1024,
		DCRedirects: map[int]string{},
	}
}

func (c *Socks5Config) Normalize() {
	if c.Port == 0 {
		c.Port = 1080
	}
	if c.BufferSize < 4096 {
		c.BufferSize = 64 * 1024
	}
	if c.DCRedirects == nil {
		c.DCRedirects = map[int]string{}
	}
}

func (c *Socks5Config) Validate() []string {
	var errs []string
	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Sprintf("порт %d вне диапазона", c.Port))
	}
	if c.BufferSize < 4096 {
		errs = append(errs, "buffer_size должен быть >= 4096")
	}
	if (c.User == "") != (c.Pass == "") {
		errs = append(errs, "укажите и логин, и пароль (или оставьте оба пустыми)")
	}
	for dc, ip := range c.DCRedirects {
		if !validDC(dc) {
			errs = append(errs, fmt.Sprintf("неизвестный DC %d", dc))
		}
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("неверный IP для DC%d", dc))
		}
	}
	return errs
}

// Socks5LinkFor builds a tg://socks link Telegram accepts to auto-add the proxy.
func Socks5LinkFor(c *Socks5Config, hostOverride string) string {
	host := hostOverride
	if host == "" {
		host = c.LinkHost
	}
	if host == "" {
		host = localIPGuess()
	}
	link := fmt.Sprintf("tg://socks?server=%s&port=%d", host, c.Port)
	if c.User != "" {
		link += fmt.Sprintf("&user=%s&pass=%s", url.QueryEscape(c.User), url.QueryEscape(c.Pass))
	}
	return link
}
