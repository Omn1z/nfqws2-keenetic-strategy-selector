package app

import (
	"log"

	"nfqws2strategy/internal/tgws"
)

const socks5ConfigFile = "socks5.json"

// Socks5Status is the combined view the SOCKS5 sub-tab polls.
type Socks5Status struct {
	Running bool                `json:"running"`
	Config  tgws.Socks5Config   `json:"config"`
	Stats   tgws.Socks5Snapshot `json:"stats"`
	Link    string              `json:"link"`
}

// initSocks5 loads the persisted SOCKS5 config (or defaults) and auto-starts the
// proxy if it was enabled. A start failure (e.g. port busy) is logged, not fatal.
func (a *App) initSocks5() {
	cfg := tgws.Socks5Default()
	if err := a.store.Load(socks5ConfigFile, cfg); err != nil {
		cfg = tgws.Socks5Default()
	}
	cfg.Normalize()
	a.socks5 = tgws.NewSocks5Manager(cfg)
	if cfg.Enabled {
		if err := a.socks5.Start(); err != nil {
			log.Printf("socks5: auto-start failed: %v", err)
		}
	}
	a.socks5Save()
}

func (a *App) socks5Save() {
	c := a.socks5.Config()
	if err := a.store.Save(socks5ConfigFile, &c); err != nil {
		log.Printf("socks5: save config failed: %v", err)
	}
}

func (a *App) Socks5StatusFor(host string) Socks5Status {
	return Socks5Status{
		Running: a.socks5.Running(),
		Config:  a.socks5.Config(),
		Stats:   a.socks5.Stats(),
		Link:    a.socks5.Link(host),
	}
}

// Socks5SetConfig applies settings from the form (the enable toggle is handled
// by Socks5Start/Stop).
func (a *App) Socks5SetConfig(in *tgws.Socks5Config) error {
	cur := a.socks5.Config()
	in.Enabled = cur.Enabled
	if err := a.socks5.SetConfig(in); err != nil {
		return err
	}
	a.socks5Save()
	return nil
}

func (a *App) Socks5Start() error {
	cur := a.socks5.Config()
	cur.Enabled = true
	if err := a.socks5.SetConfig(&cur); err != nil {
		return err
	}
	a.socks5Save()
	return nil
}

func (a *App) Socks5Stop() error {
	cur := a.socks5.Config()
	cur.Enabled = false
	if err := a.socks5.SetConfig(&cur); err != nil {
		return err
	}
	a.socks5Save()
	return nil
}

// StopSocks5 stops the proxy on shutdown without changing the persisted enabled
// flag, so it auto-starts again next boot.
func (a *App) StopSocks5() {
	if a.socks5 != nil {
		a.socks5.Stop()
	}
}
