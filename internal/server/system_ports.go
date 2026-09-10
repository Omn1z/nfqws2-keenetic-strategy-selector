package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"nfqws2strategy/internal/services/dnsroute"
)

type systemPorts struct {
	PanelPort int    `json:"panel_port"`
	DNSPort   int    `json:"dns_port"`
	PanelURL  string `json:"panel_url,omitempty"`
}

func (s *Server) getSystemPorts(w http.ResponseWriter, r *http.Request) {
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	writeJSON(w, 200, systemPorts{PanelPort: s.app.PanelPort(), DNSPort: s.app.DNSServer().Config().DNSPort})
}

func (s *Server) setSystemPorts(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PanelPort *int `json:"panel_port"`
		DNSPort   *int `json:"dns_port"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	dns := s.app.DNSServer()
	old := dns.Config()
	previousPanelPort := s.app.PanelPort()
	next := systemPorts{PanelPort: previousPanelPort, DNSPort: old.DNSPort}
	if in.PanelPort != nil {
		next.PanelPort = *in.PanelPort
	}
	if in.DNSPort != nil {
		next.DNSPort = *in.DNSPort
	}
	if err := validateSystemPorts(next); err != nil {
		httpErr(w, 400, err)
		return
	}
	dnsChanged := next.DNSPort != old.DNSPort
	if dnsChanged {
		host, err := dnsroute.ResolveLANHost(old.ListenHost, s.app.Cfg.WANIfaces)
		if err == nil {
			err = probeDNSPort(host, next.DNSPort)
		}
		if err != nil {
			httpErr(w, 400, err)
			return
		}
		cfg := old
		cfg.DNSPort = next.DNSPort
		if err := dns.SetConfig(cfg); err != nil {
			httpErr(w, 400, err)
			return
		}
		if st := dns.Status(); old.Enabled && !st.Running {
			err := fmt.Errorf("не удалось запустить DNS на порту %d: %s", next.DNSPort, st.LastError)
			if rollback := dns.SetConfig(old); rollback != nil {
				err = fmt.Errorf("%w; восстановление DNS: %v", err, rollback)
			}
			httpErr(w, 400, err)
			return
		}
	}
	if next.PanelPort != previousPanelPort {
		if err := s.app.SetPanelPort(next.PanelPort); err != nil {
			if dnsChanged {
				if rollback := dns.SetConfig(old); rollback != nil {
					err = fmt.Errorf("%w; восстановление DNS: %v", err, rollback)
				}
			}
			httpErr(w, 400, err)
			return
		}
		next.PanelURL = panelPortURL(r, next.PanelPort)
	}
	writeJSON(w, 200, next)
}

func validateSystemPorts(p systemPorts) error {
	if p.PanelPort < 1 || p.PanelPort > 65535 || p.DNSPort < 1 || p.DNSPort > 65535 {
		return fmt.Errorf("порты должны быть от 1 до 65535")
	}
	if p.PanelPort == p.DNSPort {
		return fmt.Errorf("панели и DNS нужны разные порты")
	}
	return nil
}

// Check both transports even while the DNS service is disabled. The actual
// listener still checks bind errors; this probe never replaces another service.
func probeDNSPort(host string, port int) error {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("порт DNS %d TCP недоступен: %w", port, err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("порт DNS %d UDP недоступен: %w", port, err)
	}
	return udp.Close()
}

func panelPortURL(r *http.Request, port int) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u, err := url.Parse(scheme + "://" + r.Host)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" {
		return ""
	}
	u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	return u.String()
}
