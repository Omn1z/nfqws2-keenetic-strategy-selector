package awgroute

import (
	"context"
	"log"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

const awgConfigFile = "awg.json"

// AWG2Status is the combined view the AWG2 tab polls.
type AWG2Status struct {
	Config       awg.ServerConfig  `json:"config"` // redacted (no secrets)
	HasPassword  bool              `json:"has_password"`
	HasKey       bool              `json:"has_key"`
	HasServerKey bool              `json:"has_server_key"`
	Deployed     bool              `json:"deployed"`
	LastDeploy   *awg.DeployResult `json:"last_deploy"`
	Status       *awg.Status       `json:"status"`
	Endpoint     string            `json:"endpoint"`
	Engine       EngineInfo        `json:"engine"`
	Client       *ClientStatus     `json:"client"`
}

// initAWG loads the persisted AWG2 config (or defaults). It NEVER auto-deploys —
// provisioning a remote VPS is always an explicit user action.
func (svc *Service) initAWG() {
	cfg := awg.Default()
	if err := svc.store.Load(awgConfigFile, cfg); err != nil {
		cfg = awg.Default()
	}
	cfg.Normalize()
	svc.awg = awg.NewManager(cfg)
	// Bring the local client tunnel up on boot if the user enabled it (best-effort).
	if cfg.Client.Enabled {
		go func() {
			if err := svc.awgClientUpOS(); err != nil {
				log.Printf("awg: client autostart: %v", err)
				return
			}
			// Re-apply split-routing if it was committed before (persist across
			// reboot/panel restart). It was user-confirmed previously, so we apply
			// AND commit: the apply still arms the ~90s dead-man's switch, the
			// commit disarms it, so a misapply still auto-rolls-back.
			c := svc.awg.Config()
			if c.Routing.Active && c.Routing.Mode != "off" {
				time.Sleep(4 * time.Second) // let the handshake settle + startup repair finish
				if err := svc.awgApplyRoutingOS(); err != nil {
					log.Printf("awg: routing auto-apply: %v", err)
				} else {
					_ = svc.awgCommitRoutingOS()
					logbuf.Append("awg2", "info", "маршрутизация восстановлена после перезапуска")
				}
			}
		}()
	}
}

func (svc *Service) awgSave() {
	c := svc.awg.Config()
	if err := svc.store.SaveSecret(awgConfigFile, &c); err != nil {
		log.Printf("awg: save config failed: %v", err)
	}
}

// StopAWG is a no-op for the server side (nothing runs locally). It exists for
// Shutdown symmetry; router-client teardown is wired separately.
func (svc *Service) StopAWG() {}

// AWG2StatusView returns the redacted config + presence flags + last deploy/status.
func (svc *Service) AWG2StatusView() AWG2Status {
	full := svc.awg.Config()
	return AWG2Status{
		Config:       svc.awg.Redacted(),
		HasPassword:  strings.TrimSpace(full.Conn.Password) != "",
		HasKey:       strings.TrimSpace(full.Conn.KeyPEM) != "",
		HasServerKey: strings.TrimSpace(full.PrivateKey) != "",
		Deployed:     full.DeployedAt > 0,
		LastDeploy:   svc.awg.LastDeploy(),
		Status:       svc.awg.LastStatus(),
		Endpoint:     full.Endpoint,
		Engine:       svc.AWG2EngineInfo(),
		Client:       svc.awgClientStatus(),
	}
}

// AWG2SetConfig applies editable settings from the form, preserving generated
// keys, peers, routing/client sub-state, and blank-sent secrets.
func (svc *Service) AWG2SetConfig(in *awg.ServerConfig) error {
	cur := svc.awg.Config()
	if strings.TrimSpace(in.Conn.Password) == "" {
		in.Conn.Password = cur.Conn.Password
	}
	if strings.TrimSpace(in.Conn.KeyPEM) == "" {
		in.Conn.KeyPEM = cur.Conn.KeyPEM
	}
	if strings.TrimSpace(in.Conn.KeyPass) == "" {
		in.Conn.KeyPass = cur.Conn.KeyPass
	}
	in.PrivateKey = cur.PrivateKey
	in.PublicKey = cur.PublicKey
	in.DeployedAt = cur.DeployedAt
	in.Peers = cur.Peers
	in.Client = cur.Client
	in.Routing = cur.Routing
	if strings.TrimSpace(in.Conn.Host) == strings.TrimSpace(cur.Conn.Host) {
		in.Conn.KnownKey = cur.Conn.KnownKey
	} else {
		in.Conn.KnownKey = "" // re-pin TOFU for a new host
	}
	if err := svc.awg.SetConfig(in); err != nil {
		return err
	}
	svc.awgSave()
	return nil
}

// AWG2Deploy generates+persists the server keys (once) then provisions over SSH.
func (svc *Service) AWG2Deploy() (awg.DeployResult, error) {
	if changed, err := svc.awg.EnsureKeys(); err != nil {
		return awg.DeployResult{}, err
	} else if changed {
		svc.awgSave() // persist keys BEFORE deploy so a crash never loses them
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	logbuf.Append("awg2", "info", "деплой AWG2-сервера…")
	res, err := svc.awg.Deploy(ctx, func(s awg.Step) {
		lvl := "info"
		if !s.OK {
			lvl = "error"
		}
		msg := "deploy " + s.Name
		if s.Detail != "" {
			msg += ": " + s.Detail
		}
		logbuf.Append("awg2", lvl, msg)
	})
	svc.awgSave() // persist DeployedAt / pinned host key / WAN iface
	if res.OK {
		// populate live status right away so the card doesn't show «нет связи»
		sctx, scancel := context.WithTimeout(context.Background(), 25*time.Second)
		_, _ = svc.awg.Status(sctx)
		scancel()
	}
	if err != nil {
		logbuf.Append("awg2", "error", "деплой: "+err.Error())
	}
	return res, err
}

func (svc *Service) AWG2RefreshStatus() (awg.Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return svc.awg.Status(ctx)
}

func (svc *Service) AWG2AddPeer(in awg.Peer) (awg.Peer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	p, err := svc.awg.AddPeer(ctx, in)
	svc.awgSave()
	p.PrivateKey, p.PSK = "", "" // never return secrets to the client
	return p, err
}

func (svc *Service) AWG2RemovePeer(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	err := svc.awg.RemovePeer(ctx, id)
	svc.awgSave()
	return err
}

func (svc *Service) AWG2ClientConfig(id string) (text, filename string, err error) {
	return svc.awg.ClientConfig(id)
}

// AWG2SetRouting persists the split-routing config (mode/zones/mtu/etc.) and — when
// routing is already active — applies the edit to the live tunnel immediately, so
// editing zones/masks/killswitch in the UI "just works" without a separate
// «Применить». No dead-man's switch is armed for a live refresh: membership/matcher/
// mode changes never affect panel reachability (LAN/private/self/endpoint are always
// excluded from the tunnel). Switching the mode to «off» tears routing down.
func (svc *Service) AWG2SetRouting(rc awg.RoutingConfig) error {
	svc.awg.SetRouting(rc)
	svc.awgSave()
	cfg := svc.awg.Config()
	if !cfg.Routing.Active {
		return nil // not active yet — user activates with «Применить»
	}
	if cfg.Routing.Mode == "off" {
		return svc.AWG2TeardownRouting()
	}
	// Apply to the live tunnel in the BACKGROUND so the HTTP response (and the UI
	// «Сохранить и применить» button) returns instantly and can NEVER freeze on a
	// slow router command — awgRefreshRoutingOS runs several ipset/iptables/ip calls
	// (each capped at 15s) and a transiently-slow one would otherwise hang the request.
	// The config is already persisted above; the refresh re-asserts the live state.
	go func() { _ = svc.awgRefreshRoutingOS() }()
	return nil
}
