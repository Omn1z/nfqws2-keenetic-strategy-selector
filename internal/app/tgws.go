package app

import (
	"crypto/rand"
	"encoding/hex"
	"log"

	"nfqws2strategy/internal/tgws"
)

const tgwsConfigFile = "tgws.json"

// TGWSStatus is the combined view the web tab polls.
type TGWSStatus struct {
	Running bool          `json:"running"`
	Config  tgws.Config   `json:"config"`
	Stats   tgws.Snapshot `json:"stats"`
	Link    string        `json:"link"`
}

// initTGWS loads the persisted proxy config (or defaults) and auto-starts the
// proxy if it was enabled. A start failure (e.g. port busy) is logged, not
// fatal — the rest of the service must still come up.
func (a *App) initTGWS() {
	cfg := tgws.Default()
	if err := a.store.Load(tgwsConfigFile, cfg); err != nil {
		// missing/garbage file -> defaults
		cfg = tgws.Default()
	}
	cfg.Normalize()
	a.tgws = tgws.NewManager(cfg)
	if cfg.Enabled {
		if err := a.tgws.Start(); err != nil {
			log.Printf("tgws: auto-start failed: %v", err)
		}
	}
	// Persist back so a freshly generated secret is saved.
	a.tgwsSave()
}

func (a *App) tgwsSave() {
	c := a.tgws.Config()
	if err := a.store.Save(tgwsConfigFile, &c); err != nil {
		log.Printf("tgws: save config failed: %v", err)
	}
}

// TGWSStatusFor returns the proxy status; host (request Host header) is used to
// point the tg:// link at the address the user reached the UI on.
func (a *App) TGWSStatusFor(host string) TGWSStatus {
	return TGWSStatus{
		Running: a.tgws.Running(),
		Config:  a.tgws.Config(),
		Stats:   a.tgws.Stats(),
		Link:    a.tgws.Link(host),
	}
}

// TGWSSetConfig applies proxy settings from the form. The enable toggle is
// handled separately (TGWSStart/Stop), and an empty secret preserves the
// current one (the UI may hide it).
func (a *App) TGWSSetConfig(in *tgws.Config) error {
	cur := a.tgws.Config()
	if in.Secret == "" {
		in.Secret = cur.Secret
	}
	in.Enabled = cur.Enabled
	if err := a.tgws.SetConfig(in); err != nil {
		return err
	}
	a.tgwsSave()
	return nil
}

func (a *App) TGWSStart() error {
	cur := a.tgws.Config()
	cur.Enabled = true
	if err := a.tgws.SetConfig(&cur); err != nil {
		return err
	}
	a.tgwsSave()
	return nil
}

func (a *App) TGWSStop() error {
	cur := a.tgws.Config()
	cur.Enabled = false
	if err := a.tgws.SetConfig(&cur); err != nil {
		return err
	}
	a.tgwsSave()
	return nil
}

// TGWSNewSecret regenerates the MTProto secret, persists it and restarts the
// proxy if it is running.
func (a *App) TGWSNewSecret() (string, error) {
	cur := a.tgws.Config()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	cur.Secret = hex.EncodeToString(b)
	if err := a.tgws.SetConfig(&cur); err != nil {
		return "", err
	}
	a.tgwsSave()
	return cur.Secret, nil
}

// StopTGWS stops the proxy on service shutdown without changing the persisted
// enabled flag, so it auto-starts again next boot.
func (a *App) StopTGWS() {
	if a.tgws != nil {
		a.tgws.Stop()
	}
}
