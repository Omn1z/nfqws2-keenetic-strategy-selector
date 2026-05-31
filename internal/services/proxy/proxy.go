// Package proxy wires the two Telegram proxies (MTProto->WS and SOCKS5): config
// persistence, lifecycle (auto-start on boot, start/stop), live status, and tg://
// link generation. The protocol cores live in internal/services/tgws; this is the
// app-facing service object the orchestrator holds.
package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"log"

	"nfqws2strategy/internal/services/tgws"
	"nfqws2strategy/internal/tools/store"
)

const (
	tgwsConfigFile   = "tgws.json"
	socks5ConfigFile = "socks5.json"
)

// TGWSStatus is the combined view the Telegram tab polls.
type TGWSStatus struct {
	Running bool          `json:"running"`
	Config  tgws.Config   `json:"config"`
	Stats   tgws.Snapshot `json:"stats"`
	Link    string        `json:"link"`
}

// Socks5Status is the combined view the SOCKS5 sub-tab polls.
type Socks5Status struct {
	Running bool                `json:"running"`
	Config  tgws.Socks5Config   `json:"config"`
	Stats   tgws.Socks5Snapshot `json:"stats"`
	Link    string              `json:"link"`
}

// Service owns both Telegram proxy managers + their persistence.
type Service struct {
	store  *store.Store
	tgws   *tgws.Manager
	socks5 *tgws.Socks5Manager
}

// New loads the persisted configs (or defaults) and auto-starts each proxy that
// was enabled (a start failure, e.g. a busy port, is logged, not fatal), then
// persists back (so a freshly generated secret is saved).
func New(st *store.Store) *Service {
	s := &Service{store: st}
	s.initTGWS()
	s.initSocks5()
	return s
}

// TGWS / Socks5 expose the underlying managers for service-control (restart).
func (s *Service) TGWS() *tgws.Manager         { return s.tgws }
func (s *Service) Socks5() *tgws.Socks5Manager { return s.socks5 }

// ---- MTProto WS proxy ----

func (s *Service) initTGWS() {
	cfg := tgws.Default()
	if err := s.store.Load(tgwsConfigFile, cfg); err != nil {
		cfg = tgws.Default() // missing/garbage file -> defaults
	}
	cfg.Normalize()
	s.tgws = tgws.NewManager(cfg)
	if cfg.Enabled {
		if err := s.tgws.Start(); err != nil {
			log.Printf("tgws: auto-start failed: %v", err)
		}
	}
	s.tgwsSave()
}

func (s *Service) tgwsSave() {
	c := s.tgws.Config()
	if err := s.store.Save(tgwsConfigFile, &c); err != nil {
		log.Printf("tgws: save config failed: %v", err)
	}
}

// TGWSStatusFor returns the proxy status; host (request Host header) points the
// tg:// link at the address the user reached the UI on.
func (s *Service) TGWSStatusFor(host string) TGWSStatus {
	return TGWSStatus{
		Running: s.tgws.Running(),
		Config:  s.tgws.Config(),
		Stats:   s.tgws.Stats(),
		Link:    s.tgws.Link(host),
	}
}

// TGWSSetConfig applies proxy settings from the form. The enable toggle is handled
// separately (TGWSStart/Stop); an empty secret preserves the current one.
func (s *Service) TGWSSetConfig(in *tgws.Config) error {
	cur := s.tgws.Config()
	if in.Secret == "" {
		in.Secret = cur.Secret
	}
	in.Enabled = cur.Enabled
	if err := s.tgws.SetConfig(in); err != nil {
		return err
	}
	s.tgwsSave()
	return nil
}

func (s *Service) TGWSStart() error {
	cur := s.tgws.Config()
	cur.Enabled = true
	if err := s.tgws.SetConfig(&cur); err != nil {
		return err
	}
	s.tgwsSave()
	return nil
}

func (s *Service) TGWSStop() error {
	cur := s.tgws.Config()
	cur.Enabled = false
	if err := s.tgws.SetConfig(&cur); err != nil {
		return err
	}
	s.tgwsSave()
	return nil
}

// TGWSNewSecret regenerates the MTProto secret, persists it and restarts the proxy
// if it is running.
func (s *Service) TGWSNewSecret() (string, error) {
	cur := s.tgws.Config()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	cur.Secret = hex.EncodeToString(b)
	if err := s.tgws.SetConfig(&cur); err != nil {
		return "", err
	}
	s.tgwsSave()
	return cur.Secret, nil
}

// StopTGWS stops the proxy on shutdown without changing the persisted enabled
// flag, so it auto-starts again next boot.
func (s *Service) StopTGWS() {
	if s.tgws != nil {
		s.tgws.Stop()
	}
}

// ---- SOCKS5 proxy ----

func (s *Service) initSocks5() {
	cfg := tgws.Socks5Default()
	if err := s.store.Load(socks5ConfigFile, cfg); err != nil {
		cfg = tgws.Socks5Default()
	}
	cfg.Normalize()
	s.socks5 = tgws.NewSocks5Manager(cfg)
	if cfg.Enabled {
		if err := s.socks5.Start(); err != nil {
			log.Printf("socks5: auto-start failed: %v", err)
		}
	}
	s.socks5Save()
}

func (s *Service) socks5Save() {
	c := s.socks5.Config()
	if err := s.store.Save(socks5ConfigFile, &c); err != nil {
		log.Printf("socks5: save config failed: %v", err)
	}
}

func (s *Service) Socks5StatusFor(host string) Socks5Status {
	return Socks5Status{
		Running: s.socks5.Running(),
		Config:  s.socks5.Config(),
		Stats:   s.socks5.Stats(),
		Link:    s.socks5.Link(host),
	}
}

// Socks5SetConfig applies settings from the form (the enable toggle is handled by
// Socks5Start/Stop).
func (s *Service) Socks5SetConfig(in *tgws.Socks5Config) error {
	cur := s.socks5.Config()
	in.Enabled = cur.Enabled
	if err := s.socks5.SetConfig(in); err != nil {
		return err
	}
	s.socks5Save()
	return nil
}

func (s *Service) Socks5Start() error {
	cur := s.socks5.Config()
	cur.Enabled = true
	if err := s.socks5.SetConfig(&cur); err != nil {
		return err
	}
	s.socks5Save()
	return nil
}

func (s *Service) Socks5Stop() error {
	cur := s.socks5.Config()
	cur.Enabled = false
	if err := s.socks5.SetConfig(&cur); err != nil {
		return err
	}
	s.socks5Save()
	return nil
}

// StopSocks5 stops the proxy on shutdown without changing the persisted enabled
// flag, so it auto-starts again next boot.
func (s *Service) StopSocks5() {
	if s.socks5 != nil {
		s.socks5.Stop()
	}
}
