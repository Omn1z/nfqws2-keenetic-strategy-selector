package awgroute

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
	storeutil "nfqws2strategy/internal/tools/store"
)

const awgConfigFile = "awg.json"

type awgPersisted struct {
	ActiveID string               `json:"active_id"`
	Servers  []awgPersistedServer `json:"servers"`
}

type awgPersistedServer struct {
	ID     string           `json:"id"`
	Name   string           `json:"name"`
	Config awg.ServerConfig `json:"config"`
}

// AWG2ServerSummary is one configured AWG2 server in the selector. Only the
// active server can own the local router tunnel (awg0), but any server can be
// selected, edited, deployed, or deleted.
type AWG2ServerSummary struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Host         string `json:"host"`
	Endpoint     string `json:"endpoint"`
	Enabled      bool   `json:"enabled"`
	Imported     bool   `json:"imported"`
	Protocol     string `json:"protocol"`
	Active       bool   `json:"active"`
	Deployed     bool   `json:"deployed"`
	Connected    bool   `json:"connected"`
	Reachable    bool   `json:"reachable"`
	HasPassword  bool   `json:"has_password"`
	HasKey       bool   `json:"has_key"`
	HasServerKey bool   `json:"has_server_key"`
	LastError    string `json:"last_error,omitempty"`
}

type AWG2DeployServerResult struct {
	ID     string           `json:"id"`
	Label  string           `json:"label"`
	OK     bool             `json:"ok"`
	Result awg.DeployResult `json:"result"`
	Error  string           `json:"error,omitempty"`
}

// AWG2Status is the combined view the AWG2 tab polls.
type AWG2Status struct {
	Config       awg.ServerConfig    `json:"config"` // redacted (no secrets)
	ActiveID     string              `json:"active_server_id"`
	Servers      []AWG2ServerSummary `json:"servers"`
	HasPassword  bool                `json:"has_password"`
	HasKey       bool                `json:"has_key"`
	HasServerKey bool                `json:"has_server_key"`
	Deployed     bool                `json:"deployed"`
	LastDeploy   *awg.DeployResult   `json:"last_deploy"`
	Status       *awg.Status         `json:"status"`
	Endpoint     string              `json:"endpoint"`
	Engine       EngineInfo          `json:"engine"`
	Client       *ClientStatus       `json:"client"`
}

// initAWG loads the persisted AWG2 config (or defaults). It NEVER auto-deploys —
// provisioning a remote VPS is always an explicit user action.
func (svc *Service) initAWG() {
	state := svc.loadAWGState()
	svc.installAWGState(state)
	if svc.ensureRouterPeersLocal() {
		svc.awgSave()
	}
	// Bring the local client tunnel up on boot if the user enabled it (best-effort).
	cfg := svc.awg.Config()
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
			if awgShouldRestoreRouting(c) {
				time.Sleep(4 * time.Second) // let the handshake settle + startup repair finish
				if err := svc.awgApplyRoutingOS(); err != nil {
					log.Printf("awg: routing auto-apply: %v", err)
				} else {
					_ = svc.awgCommitRoutingOS()
					svc.awg.SetRoutingActive(true)
					svc.awgSave()
					logbuf.Append("awg2", "info", "маршрутизация восстановлена после перезапуска")
				}
			}
		}()
	}
}

func awgShouldRestoreRouting(c awg.ServerConfig) bool {
	return c.Routing.Mode != "off" && (c.Routing.Active || c.Client.Enabled)
}

func (svc *Service) awgSave() {
	state := svc.snapshotAWGState()
	if err := svc.store.SaveSecret(awgConfigFile, &state); err != nil {
		log.Printf("awg: save config failed: %v", err)
	}
}

func (svc *Service) loadAWGState() awgPersisted {
	b, err := os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil {
		return defaultAWGState()
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(b, &shape) == nil {
		if _, ok := shape["servers"]; ok {
			var st awgPersisted
			if json.Unmarshal(b, &st) == nil && len(st.Servers) > 0 {
				return normalizeAWGState(st)
			}
			log.Printf("awg: persisted multi-server config is invalid, using defaults without legacy remap")
			return defaultAWGState()
		}
	}
	var legacy awg.ServerConfig
	if json.Unmarshal(b, &legacy) == nil {
		legacy.Normalize()
		return normalizeAWGState(awgPersisted{
			ActiveID: "awg0",
			Servers:  []awgPersistedServer{{ID: "awg0", Config: legacy}},
		})
	}
	return defaultAWGState()
}

func defaultAWGState() awgPersisted {
	cfg := awg.Default()
	return awgPersisted{
		ActiveID: "awg0",
		Servers:  []awgPersistedServer{{ID: "awg0", Config: *cfg}},
	}
}

func normalizeAWGState(st awgPersisted) awgPersisted {
	if len(st.Servers) == 0 {
		return defaultAWGState()
	}
	seen := map[string]bool{}
	out := make([]awgPersistedServer, 0, len(st.Servers))
	for _, srv := range st.Servers {
		id := strings.TrimSpace(srv.ID)
		if id == "" || seen[id] {
			id = "awg-" + storeutil.NewID()
		}
		seen[id] = true
		srv.ID = id
		srv.Name = strings.TrimSpace(srv.Name)
		srv.Config.Normalize()
		out = append(out, srv)
	}
	st.Servers = out
	if strings.TrimSpace(st.ActiveID) == "" || !seen[st.ActiveID] {
		st.ActiveID = st.Servers[0].ID
	}
	return st
}

func (svc *Service) installAWGState(st awgPersisted) {
	st = normalizeAWGState(st)
	servers := make(map[string]*managedServer, len(st.Servers))
	order := make([]string, 0, len(st.Servers))
	for _, entry := range st.Servers {
		cfg := entry.Config
		cfg.Normalize()
		servers[entry.ID] = &managedServer{
			ID:      entry.ID,
			Name:    strings.TrimSpace(entry.Name),
			Manager: awg.NewManager(&cfg),
		}
		order = append(order, entry.ID)
	}

	svc.mu.Lock()
	svc.servers = servers
	svc.order = order
	svc.activeID = st.ActiveID
	if active := servers[svc.activeID]; active != nil {
		svc.awg = active.Manager
	} else if len(order) > 0 {
		svc.activeID = order[0]
		svc.awg = servers[svc.activeID].Manager
	}
	svc.mu.Unlock()
}

func (svc *Service) snapshotAWGState() awgPersisted {
	svc.mu.RLock()
	activeID := svc.activeID
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	svc.mu.RUnlock()

	st := awgPersisted{ActiveID: activeID, Servers: make([]awgPersistedServer, 0, len(entries))}
	for _, srv := range entries {
		st.Servers = append(st.Servers, awgPersistedServer{
			ID:     srv.ID,
			Name:   srv.Name,
			Config: srv.Manager.Config(),
		})
	}
	if len(st.Servers) == 0 {
		return defaultAWGState()
	}
	return st
}

func (svc *Service) ensureRouterPeersLocal() bool {
	svc.mu.RLock()
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	svc.mu.RUnlock()

	changed := false
	for _, srv := range entries {
		cfg := srv.Manager.Config()
		if cfg.Install == "imported" {
			continue
		}
		if _, ok, err := srv.Manager.EnsureRouterPeerLocal(); err == nil && ok {
			changed = true
		}
	}
	return changed
}

func (svc *Service) activeServerID() string {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return svc.activeID
}

// StopAWG is a no-op for the server side (nothing runs locally). It exists for
// Shutdown symmetry; router-client teardown is wired separately.
func (svc *Service) StopAWG() {}

// AWG2StatusView returns the redacted config + presence flags + last deploy/status.
func (svc *Service) AWG2StatusView() AWG2Status {
	full := svc.awg.Config()
	return AWG2Status{
		Config:       svc.awg.Redacted(),
		ActiveID:     svc.activeServerID(),
		Servers:      svc.awgServerSummaries(),
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

func (svc *Service) awgServerSummaries() []AWG2ServerSummary {
	svc.mu.RLock()
	activeID := svc.activeID
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	svc.mu.RUnlock()

	connected := svc.TunnelUp()
	out := make([]AWG2ServerSummary, 0, len(entries))
	for _, srv := range entries {
		cfg := srv.Manager.Config()
		st := srv.Manager.LastStatus()
		sum := AWG2ServerSummary{
			ID:           srv.ID,
			Label:        awgServerLabel(srv, cfg),
			Host:         strings.TrimSpace(cfg.Conn.Host),
			Endpoint:     strings.TrimSpace(cfg.Endpoint),
			Enabled:      cfg.Enabled,
			Imported:     cfg.Install == "imported",
			Protocol:     cfg.Protocol,
			Active:       srv.ID == activeID,
			Deployed:     cfg.DeployedAt > 0,
			HasPassword:  strings.TrimSpace(cfg.Conn.Password) != "",
			HasKey:       strings.TrimSpace(cfg.Conn.KeyPEM) != "",
			HasServerKey: strings.TrimSpace(cfg.PrivateKey) != "",
		}
		if st != nil {
			sum.Reachable = st.Up || st.Reachable
			sum.LastError = st.Error
		}
		if sum.Active {
			sum.Connected = connected
		}
		out = append(out, sum)
	}
	return out
}

func awgServerLabel(srv *managedServer, cfg awg.ServerConfig) string {
	if strings.TrimSpace(srv.Name) != "" {
		return strings.TrimSpace(srv.Name)
	}
	if strings.TrimSpace(cfg.Endpoint) != "" {
		return strings.TrimSpace(cfg.Endpoint)
	}
	if strings.TrimSpace(cfg.Conn.Host) != "" {
		return strings.TrimSpace(cfg.Conn.Host)
	}
	if srv.ID == "awg0" {
		return "AWG2"
	}
	return "AWG2 " + strings.TrimPrefix(srv.ID, "awg-")
}

func (svc *Service) AWG2AddServer(name string) AWG2Status {
	cfg := awg.Default()
	id := "awg-" + storeutil.NewID()
	srv := &managedServer{ID: id, Name: strings.TrimSpace(name), Manager: awg.NewManager(cfg)}
	_, _, _ = srv.Manager.EnsureRouterPeerLocal()
	old := svc.awg
	if old != nil {
		_ = svc.awgTeardownRoutingOS()
		old.SetClientEnabled(false)
		old.SetRoutingActive(false)
		_ = svc.awgClientDownOS()
	}

	svc.mu.Lock()
	if svc.servers == nil {
		svc.servers = map[string]*managedServer{}
	}
	svc.servers[id] = srv
	svc.order = append(svc.order, id)
	svc.activeID = id
	svc.awg = srv.Manager
	svc.mu.Unlock()

	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return svc.AWG2StatusView()
}

func (svc *Service) AWG2SelectServer(id string) error {
	id = strings.TrimSpace(id)
	svc.mu.RLock()
	srv := svc.servers[id]
	oldID := svc.activeID
	old := svc.awg
	svc.mu.RUnlock()
	if srv == nil {
		return fmt.Errorf("AWG2-сервер не найден")
	}
	if !srv.Manager.Config().Enabled {
		return fmt.Errorf("AWG2-сервер выключен")
	}
	if id == oldID {
		return nil
	}
	if old != nil {
		_ = svc.awgTeardownRoutingOS()
		old.SetClientEnabled(false)
		old.SetRoutingActive(false)
		_ = svc.awgClientDownOS()
	}

	svc.mu.Lock()
	svc.activeID = id
	svc.awg = srv.Manager
	svc.mu.Unlock()
	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return nil
}

func (svc *Service) AWG2SetServerEnabled(id string, enabled bool) error {
	id = strings.TrimSpace(id)
	svc.mu.RLock()
	srv := svc.servers[id]
	active := id != "" && id == svc.activeID
	svc.mu.RUnlock()
	if srv == nil {
		return fmt.Errorf("AWG2-сервер не найден")
	}
	if !enabled && active {
		_ = svc.awgTeardownRoutingOS()
		srv.Manager.SetClientEnabled(false)
		srv.Manager.SetRoutingActive(false)
		_ = svc.awgClientDownOS()
		svc.route.tunnelUpAt.Store(0)
	}
	srv.Manager.SetEnabled(enabled)
	svc.awgSave()
	if enabled && active && srv.Manager.Config().Routing.Mode != "off" {
		go func() {
			if err := svc.awgEnsureClientUpForRouting("включения сервера"); err != nil {
				logbuf.Append("awg2", "warn", "туннель после включения сервера не поднялся: "+err.Error())
				return
			}
			svc.awgRestoreCommittedRouting("включения сервера")
		}()
	}
	return nil
}

func (svc *Service) AWG2DeleteServer(id string) error {
	id = strings.TrimSpace(id)
	svc.mu.RLock()
	srv := svc.servers[id]
	active := id != "" && id == svc.activeID
	old := svc.awg
	svc.mu.RUnlock()
	if srv == nil {
		return fmt.Errorf("AWG2-сервер не найден")
	}
	if active && old != nil {
		_ = svc.awgTeardownRoutingOS()
		old.SetClientEnabled(false)
		old.SetRoutingActive(false)
		_ = svc.awgClientDownOS()
	}

	svc.mu.Lock()
	delete(svc.servers, id)
	nextOrder := svc.order[:0]
	for _, oid := range svc.order {
		if oid != id {
			nextOrder = append(nextOrder, oid)
		}
	}
	svc.order = nextOrder
	if len(svc.order) == 0 {
		cfg := awg.Default()
		def := &managedServer{ID: "awg0", Manager: awg.NewManager(cfg)}
		svc.servers["awg0"] = def
		svc.order = append(svc.order, "awg0")
		svc.activeID = "awg0"
		svc.awg = def.Manager
	} else if active {
		svc.activeID = svc.order[0]
		svc.awg = svc.servers[svc.activeID].Manager
	}
	svc.mu.Unlock()
	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return nil
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
	if !in.Enabled && cur.Enabled {
		in.Enabled = cur.Enabled
	}
	if strings.TrimSpace(in.Protocol) == "" {
		in.Protocol = cur.Protocol
	}
	in.PrivateKey = cur.PrivateKey
	in.PublicKey = cur.PublicKey
	in.DeployedAt = cur.DeployedAt
	in.Peers = cur.Peers
	in.Client = cur.Client
	in.Routing = cur.Routing
	if !sameSSHIdentity(in.Conn, cur.Conn) {
		in.Conn.KnownKey = "" // re-pin TOFU for a new host
	}
	if err := svc.awg.SetConfig(in); err != nil {
		return err
	}
	svc.awgSave()
	return nil
}

func sameSSHIdentity(a, b awg.Credentials) bool {
	return strings.TrimSpace(a.Host) == strings.TrimSpace(b.Host) &&
		a.Port == b.Port &&
		strings.TrimSpace(a.User) == strings.TrimSpace(b.User) &&
		strings.TrimSpace(a.AuthKind) == strings.TrimSpace(b.AuthKind)
}

func (svc *Service) AWG2Deploy() (awg.DeployResult, error) {
	return svc.AWG2DeployServer(svc.activeServerID())
}

func (svc *Service) AWG2DeployServer(id string) (awg.DeployResult, error) {
	id = strings.TrimSpace(id)
	svc.mu.RLock()
	srv := svc.servers[id]
	svc.mu.RUnlock()
	if srv == nil {
		return awg.DeployResult{}, fmt.Errorf("AWG2-сервер не найден")
	}
	return svc.deployServer(srv)
}

func (svc *Service) AWG2DeployServers(ids []string) []AWG2DeployServerResult {
	results := []AWG2DeployServerResult{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		svc.mu.RLock()
		srv := svc.servers[id]
		svc.mu.RUnlock()
		if srv == nil {
			results = append(results, AWG2DeployServerResult{ID: id, OK: false, Error: "AWG2-сервер не найден"})
			continue
		}
		cfg := srv.Manager.Config()
		res, err := svc.deployServer(srv)
		item := AWG2DeployServerResult{ID: srv.ID, Label: awgServerLabel(srv, cfg), OK: err == nil && res.OK, Result: res}
		if err != nil {
			item.Error = err.Error()
		}
		results = append(results, item)
	}
	return results
}

// deployServer generates+persists the server keys (once) then provisions over SSH.
func (svc *Service) deployServer(srv *managedServer) (awg.DeployResult, error) {
	cfg := srv.Manager.Config()
	if !cfg.Enabled {
		return awg.DeployResult{}, fmt.Errorf("сервер выключен")
	}
	if cfg.Install == "imported" {
		return awg.DeployResult{}, fmt.Errorf("это импортированный конфиг — деплой на VPS недоступен, можно только поднимать туннель")
	}
	if _, changed, err := srv.Manager.EnsureRouterPeer(context.Background()); err != nil {
		return awg.DeployResult{}, err
	} else if changed {
		svc.awgSave()
	}
	if changed, err := srv.Manager.EnsureKeys(); err != nil {
		return awg.DeployResult{}, err
	} else if changed {
		svc.awgSave() // persist keys BEFORE deploy so a crash never loses them
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	logbuf.Append("awg2", "info", "деплой AWG2-сервера "+awgServerLabel(srv, cfg)+"…")
	res, err := srv.Manager.Deploy(ctx, func(s awg.Step) {
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
		_, _ = srv.Manager.Status(sctx)
		scancel()
		if srv.ID == svc.activeServerID() && srv.Manager.Config().Client.Enabled {
			go svc.awgReconnectActiveClientAfterDeploy(srv.ID)
		}
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

func (svc *Service) AWG2ClientExport(id, format string) (text, filename, contentType string, err error) {
	return svc.awg.ClientExport(id, format)
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
