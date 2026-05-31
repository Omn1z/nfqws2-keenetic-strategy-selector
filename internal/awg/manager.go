package awg

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialer opens a runner to a host; the production value wraps Dial. Tests swap
// it for a fake transport.
type Dialer func(ctx context.Context, cred Credentials) (runner, string, error)

func defaultDialer(ctx context.Context, cred Credentials) (runner, string, error) {
	c, learned, err := Dial(ctx, cred)
	if err != nil {
		return nil, learned, err
	}
	return c, learned, nil
}

// Manager owns the AWG2 server config + peers and the SSH-driven operations
// against the VPS. Methods are safe for concurrent use.
type Manager struct {
	mu         sync.Mutex
	cfg        *ServerConfig
	lastDep    *DeployResult
	lastStatus *Status
	deploying  bool
	dial       Dialer
}

func NewManager(cfg *ServerConfig) *Manager {
	cfg.Normalize()
	return &Manager{cfg: cfg, dial: defaultDialer}
}

// PeerStatus is a peer's live state parsed from `awg show <iface> dump`.
type PeerStatus struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint"`
	LatestHandshake int64  `json:"latest_handshake"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	Online          bool   `json:"online"`
}

// Status is the live server status.
type Status struct {
	Reachable  bool         `json:"reachable"`
	Up         bool         `json:"up"`
	ListenPort int          `json:"listen_port"`
	Peers      []PeerStatus `json:"peers"`
	Error      string       `json:"error,omitempty"`
}

func (c ServerConfig) clone() ServerConfig {
	cp := c
	cp.Peers = append([]Peer(nil), c.Peers...)
	cp.Routing.Zones = make([]Zone, len(c.Routing.Zones))
	for i, z := range c.Routing.Zones {
		z.Domains = append([]string(nil), z.Domains...)
		z.IPs = append([]string(nil), z.IPs...)
		cp.Routing.Zones[i] = z
	}
	return cp
}

// Config returns a deep copy of the current config (secrets included).
func (m *Manager) Config() ServerConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.clone()
}

// Redacted returns a deep copy with every secret blanked, for API responses.
func (m *Manager) Redacted() ServerConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg.clone()
	c.PrivateKey = ""
	c.Conn.Password = ""
	c.Conn.KeyPEM = ""
	c.Conn.KeyPass = ""
	for i := range c.Peers {
		c.Peers[i].HasPrivate = strings.TrimSpace(c.Peers[i].PrivateKey) != ""
		c.Peers[i].PrivateKey = ""
		c.Peers[i].PSK = ""
	}
	return c
}

// SetConfig validates and replaces the config. The caller (app layer) is
// responsible for preserving blank-sent secrets and the generated server keys.
func (m *Manager) SetConfig(in *ServerConfig) error {
	in.Normalize()
	if errs := in.Validate(); len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	m.mu.Lock()
	m.cfg = in
	m.mu.Unlock()
	return nil
}

// SetRouting updates only the split-routing config (saved independently of the
// server settings, so it can be edited before the server is even configured).
func (m *Manager) SetRouting(rc RoutingConfig) {
	m.mu.Lock()
	m.cfg.Routing = rc
	m.cfg.Normalize()
	m.mu.Unlock()
}

// SetClientEnabled toggles the local-client autostart flag, persisted so the
// router tunnel comes back up after a panel restart.
func (m *Manager) SetClientEnabled(v bool) {
	m.mu.Lock()
	m.cfg.Client.Enabled = v
	m.mu.Unlock()
}

// SetRoutingActive marks split-routing as committed/active, persisted so the
// panel re-applies it automatically after a restart/reboot.
func (m *Manager) SetRoutingActive(v bool) {
	m.mu.Lock()
	m.cfg.Routing.Active = v
	m.mu.Unlock()
}

// EnsureKeys generates the server keypair + randomized 2.0 obfuscation once.
// Returns true if anything changed (so the caller persists before deploying).
func (m *Manager) EnsureKeys() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(m.cfg.PrivateKey) != "" {
		return false, nil
	}
	priv, pub, err := GenKeypair()
	if err != nil {
		return false, err
	}
	m.cfg.PrivateKey, m.cfg.PublicKey = priv, pub
	if err := RandomizeObf(&m.cfg.Obf); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) LastDeploy() *DeployResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastDep
}

// Deploy provisions (or re-provisions) the server over SSH.
func (m *Manager) Deploy(ctx context.Context, progress func(Step)) (DeployResult, error) {
	m.mu.Lock()
	if m.deploying {
		m.mu.Unlock()
		return DeployResult{}, fmt.Errorf("деплой уже выполняется")
	}
	m.deploying = true
	cred := m.cfg.Conn
	cfg := m.cfg.clone()
	dial := m.dial
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.deploying = false
		m.mu.Unlock()
	}()

	r, learned, err := dial(ctx, cred)
	if err != nil {
		res := DeployResult{Steps: []Step{{Name: "connect", OK: false, Detail: redact(err.Error())}}, Error: redact(err.Error())}
		m.mu.Lock()
		m.lastDep = &res
		m.mu.Unlock()
		return res, err
	}
	defer r.Close()

	res := Deploy(ctx, r, &cfg, progress)

	m.mu.Lock()
	if strings.TrimSpace(m.cfg.Conn.KnownKey) == "" && learned != "" {
		m.cfg.Conn.KnownKey = learned
	}
	if cfg.WANIface != "" {
		m.cfg.WANIface = cfg.WANIface
	}
	if res.OK {
		m.cfg.DeployedAt = time.Now().Unix()
		m.cfg.Endpoint = cfg.Endpoint
	}
	m.lastDep = &res
	m.mu.Unlock()
	return res, nil
}

// Status queries the live server over SSH.
func (m *Manager) LastStatus() *Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastStatus
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	var st Status
	defer func() {
		cp := st
		m.mu.Lock()
		m.lastStatus = &cp
		m.mu.Unlock()
	}()
	m.mu.Lock()
	cred := m.cfg.Conn
	iface := m.cfg.Interface
	dial := m.dial
	byPub := map[string]Peer{}
	for _, p := range m.cfg.Peers {
		byPub[p.PublicKey] = p
	}
	m.mu.Unlock()

	r, _, err := dial(ctx, cred)
	if err != nil {
		st.Error = redact(err.Error())
		return st, err
	}
	defer r.Close()
	out, _, _ := r.Run(ctx, fmt.Sprintf("awg show %s dump 2>/dev/null", iface))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		st.Reachable = true
		return st, nil
	}
	st.Reachable, st.Up = true, true
	if f0 := strings.Fields(lines[0]); len(f0) >= 3 {
		st.ListenPort = atoiSafe(f0[2])
	}
	now := time.Now().Unix()
	for _, ln := range lines[1:] {
		f := strings.Split(ln, "\t")
		if len(f) < 7 {
			continue
		}
		ps := PeerStatus{
			PublicKey:       f[0],
			Endpoint:        f[2],
			LatestHandshake: atoi64(f[4]),
			RxBytes:         atoi64(f[5]),
			TxBytes:         atoi64(f[6]),
		}
		ps.Online = ps.LatestHandshake > 0 && now-ps.LatestHandshake < 180
		if p, ok := byPub[ps.PublicKey]; ok {
			ps.ID, ps.Name = p.ID, p.Name
		}
		st.Peers = append(st.Peers, ps)
	}
	return st, nil
}

// AddPeer creates a peer (generating keys/PSK/address as needed) and, if the
// server is already deployed, applies it live via awg syncconf.
func (m *Manager) AddPeer(ctx context.Context, in Peer) (Peer, error) {
	m.mu.Lock()
	if strings.TrimSpace(in.PublicKey) == "" {
		priv, pub, err := GenKeypair()
		if err != nil {
			m.mu.Unlock()
			return Peer{}, err
		}
		in.PrivateKey, in.PublicKey = priv, pub
	}
	if strings.TrimSpace(in.PSK) == "" {
		psk, err := GenPSK()
		if err != nil {
			m.mu.Unlock()
			return Peer{}, err
		}
		in.PSK = psk
	}
	if in.ID == "" {
		in.ID = newID()
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = "peer-" + in.ID[:4]
	}
	if strings.TrimSpace(in.Address) == "" {
		in.Address = m.nextPeerAddrLocked()
	}
	if strings.TrimSpace(in.AllowedIPs) == "" {
		in.AllowedIPs = "0.0.0.0/0, ::/0"
	}
	if in.Keepalive == 0 {
		in.Keepalive = 25
	}
	in.CreatedAt = time.Now().Unix()
	in.HasPrivate = strings.TrimSpace(in.PrivateKey) != ""
	m.cfg.Peers = append(m.cfg.Peers, in)
	cfg := m.cfg.clone()
	cred := m.cfg.Conn
	iface := m.cfg.Interface
	deployed := m.cfg.DeployedAt > 0
	dial := m.dial
	m.mu.Unlock()

	if deployed {
		if err := syncPeers(ctx, dial, cred, &cfg, iface); err != nil {
			return in, fmt.Errorf("пир сохранён, но не применён на сервере: %w", err)
		}
	}
	return in, nil
}

// RemovePeer drops a peer and (if deployed) applies the removal live.
func (m *Manager) RemovePeer(ctx context.Context, id string) error {
	m.mu.Lock()
	idx := -1
	for i := range m.cfg.Peers {
		if m.cfg.Peers[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		m.mu.Unlock()
		return fmt.Errorf("пир не найден")
	}
	m.cfg.Peers = append(m.cfg.Peers[:idx], m.cfg.Peers[idx+1:]...)
	cfg := m.cfg.clone()
	cred := m.cfg.Conn
	iface := m.cfg.Interface
	deployed := m.cfg.DeployedAt > 0
	dial := m.dial
	m.mu.Unlock()

	if deployed {
		if err := syncPeers(ctx, dial, cred, &cfg, iface); err != nil {
			return fmt.Errorf("пир удалён из конфига, но не применён на сервере: %w", err)
		}
	}
	return nil
}

// ClientConfig renders the .conf a peer uses to connect (emits private key).
func (m *Manager) ClientConfig(id string) (text, filename string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.cfg.Peers {
		if p.ID == id {
			if strings.TrimSpace(p.PrivateKey) == "" {
				return "", "", fmt.Errorf("для этого пира нет приватного ключа (добавьте пир заново)")
			}
			return ClientConf(m.cfg, p), safeName(p.Name) + ".conf", nil
		}
	}
	return "", "", fmt.Errorf("пир не найден")
}

// RouterPeer returns the peer flagged as this router, or false.
func (m *Manager) RouterPeer() (Peer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.cfg.Peers {
		if p.IsRouter {
			return p, true
		}
	}
	return Peer{}, false
}

func (m *Manager) nextPeerAddrLocked() string {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(m.cfg.Address))
	if err != nil || ip.To4() == nil {
		return ""
	}
	used := map[string]bool{ipOnly(m.cfg.Address): true}
	for _, p := range m.cfg.Peers {
		used[ipOnly(p.Address)] = true
	}
	b := ipnet.IP.To4()
	for i := 2; i < 255; i++ {
		cand := fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], i)
		if !used[cand] {
			return cand + "/32"
		}
	}
	return ""
}

func syncPeers(ctx context.Context, dial Dialer, cred Credentials, cfg *ServerConfig, iface string) error {
	r, _, err := dial(ctx, cred)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.Put(ctx, "/etc/amnezia/amneziawg/"+iface+".conf", 0o600, []byte(ServerConf(cfg))); err != nil {
		return err
	}
	_, errOut, err := r.Run(ctx, fmt.Sprintf("awg-quick strip %[1]s > /tmp/awg-%[1]s.sync 2>/dev/null && awg syncconf %[1]s /tmp/awg-%[1]s.sync; rm -f /tmp/awg-%[1]s.sync", iface))
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(errOut))
	}
	return nil
}

// ---- small helpers ----

var reKey = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)

func redact(s string) string { return reKey.ReplaceAllString(s, "***") }

func newID() string {
	var b [6]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var reUnsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string {
	s = reUnsafeName.ReplaceAllString(strings.TrimSpace(s), "_")
	s = strings.Trim(s, "._-")
	if s == "" {
		return "peer"
	}
	return s
}

func ipOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
