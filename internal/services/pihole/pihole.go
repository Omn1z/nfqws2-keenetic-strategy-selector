// Package pihole manages the Pi-hole v6 docker container — install/upgrade/
// start/stop, log tailing, and stats fetching via Pi-hole's REST API.
//
// We treat the Pi-hole admin UI as authoritative for blocklist/whitelist/query
// log management (their UI is well-built and a re-skin would be busywork); our
// integration adds the lifecycle controls a router-side panel needs:
//
//   - run inside the platform's docker (Xiaomi's bundled dockerd) with OPA
//     authz constraints in mind (bind mounts must be /mnt/usb-*).
//   - persist the data volumes on the USB stick where docker storage lives.
//   - chain Pi-hole into the AWG2 DNS proxy (our :5354 forwards non-AWG-zone
//     queries to :5353 so blocklists apply to LAN clients).
//   - surface compact stats in our dashboard via the Pi-hole REST API.
package pihole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	ContainerName = "pihole"
	ImageName     = "pihole/pihole:latest"

	// Default ports the container binds (host network mode). They were picked
	// to avoid colliding with dnsmasq:53 and our selector:8090.
	DefaultDNSPort = 5353
	DefaultUIPort  = 8053

	// USB-anchored config root. OPA authz on the bundled dockerd only allows
	// bind mounts from /mnt/usb-*; storing pi-hole data on the same USB volume
	// where docker's image store lives is the obvious "everything-in-one-place"
	// choice.
	DefaultDataRoot = "/mnt/usb-b23e7f6e/mi_docker/pihole"

	// Pi-hole's stats endpoint; we use it for the dashboard summary.
	statsPath = "/api/stats/summary"
	authPath  = "/api/auth"
)

// Config holds the user-tunable pi-hole settings persisted by the selector.
type Config struct {
	Password        string `json:"password"`         // pi-hole admin password — also our REST API auth
	DNSPort         int    `json:"dns_port"`         // FTL DNS port; default 5353
	UIPort          int    `json:"ui_port"`          // web UI port; default 8053
	DataRoot        string `json:"data_root"`        // USB path for /etc/pihole + /etc/dnsmasq.d volumes
	Timezone        string `json:"timezone"`         // TZ env var (Europe/Moscow on this router)
	DNSChainEnabled bool   `json:"dns_chain_enabled"` // when true, AWG2 DNS proxy forwards non-zone queries to pi-hole
}

// Default returns a sensible Config for this router. Users can tweak via API.
func Default() Config {
	return Config{
		Password:        "root",
		DNSPort:         DefaultDNSPort,
		UIPort:          DefaultUIPort,
		DataRoot:        DefaultDataRoot,
		Timezone:        "Europe/Moscow",
		DNSChainEnabled: false,
	}
}

// Status is the live container view shown to the UI.
type Status struct {
	Config

	Installed    bool   `json:"installed"`     // image present locally
	Running      bool   `json:"running"`       // container exists AND state=running
	Healthy      bool   `json:"healthy"`       // docker healthcheck reports healthy
	State        string `json:"state"`         // "running" | "restarting" | "exited" | ""
	ContainerID  string `json:"container_id"`  // short id when running
	UptimeSec    int64  `json:"uptime_sec"`    // seconds since container start
	ImageDigest  string `json:"image_digest"`  // current image sha for upgrade detection
	UpgradeAvail bool   `json:"upgrade_avail"` // remote digest differs from local
	Error        string `json:"error,omitempty"`
}

// Stats summarises what pi-hole knows: totals, blocked, blocklist size.
type Stats struct {
	TotalQueries     int     `json:"total_queries"`
	BlockedQueries   int     `json:"blocked_queries"`
	PercentBlocked   float64 `json:"percent_blocked"`
	DomainsOnList    int     `json:"domains_on_list"`
	UniqueDomains    int     `json:"unique_domains"`
	UniqueClients    int     `json:"unique_clients"`
	ActiveClients    int     `json:"active_clients"`
	BlockingStatus   string  `json:"blocking_status"`
	Error            string  `json:"error,omitempty"`
}

// Service is the per-app singleton; holds the docker CLI path and a cached
// session id for pi-hole REST API (re-issued on demand).
type Service struct {
	dockerBin string
	cfg       Config

	mu      sync.Mutex
	sid     string // pi-hole session id; valid until pi-hole expires it (~5 min idle)
	sidAt   time.Time

	// onChainChange is called when the user toggles DNS chain integration; the
	// awgroute service uses it to re-apply the DNS proxy upstream.
	onChainChange func(enabled bool, piholeUpstream string)
}

// New creates a Service. The dockerBin path is discovered: on the Xiaomi router
// the docker CLI lives at /mnt/usb-*/mi_docker/docker-binaries/docker; we fall
// back to "docker" on PATH for dev machines.
func New(cfg Config) *Service {
	if cfg.DNSPort == 0 {
		cfg.DNSPort = DefaultDNSPort
	}
	if cfg.UIPort == 0 {
		cfg.UIPort = DefaultUIPort
	}
	if cfg.DataRoot == "" {
		cfg.DataRoot = DefaultDataRoot
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "Europe/Moscow"
	}
	if cfg.Password == "" {
		cfg.Password = "root"
	}
	return &Service{dockerBin: discoverDockerBin(), cfg: cfg}
}

// discoverDockerBin finds the docker CLI; the bundled one isn't in PATH.
func discoverDockerBin() string {
	candidates := []string{
		"/mnt/usb-b23e7f6e/mi_docker/docker-binaries/docker",
		"/opt/bin/docker",
		"docker",
	}
	for _, p := range candidates {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return "docker"
}

func (s *Service) SetConfig(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

func (s *Service) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// SetChainChangeHook registers a callback invoked whenever DNSChainEnabled
// flips; the AWG2 routing service uses this to swap the DNS proxy upstream
// between system DNS (127.0.0.1:53) and Pi-hole (127.0.0.1:5353).
func (s *Service) SetChainChangeHook(fn func(enabled bool, upstream string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChainChange = fn
}

// docker runs a docker CLI command with a timeout, returns its combined output.
func (s *Service) docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.dockerBin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

// Status returns the live container snapshot. Best-effort: any docker error
// surfaces as Status.Error; the field defaults still render in the UI.
func (s *Service) Status() Status {
	st := Status{Config: s.Config()}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Image present?
	if out, err := s.docker(ctx, "images", "-q", ImageName); err == nil && out != "" {
		st.Installed = true
	}
	// Container state — use inspect for richer info than docker ps.
	out, err := s.docker(ctx, "inspect", ContainerName, "--format",
		"{{.Id}}|{{.State.Status}}|{{.State.Health.Status}}|{{.State.StartedAt}}|{{.Image}}")
	if err != nil {
		// Container missing — that's fine, just report not-running.
		return st
	}
	fs := strings.SplitN(out, "|", 5)
	if len(fs) >= 4 {
		st.ContainerID = shortID(fs[0])
		st.State = fs[1]
		st.Running = st.State == "running"
		st.Healthy = fs[2] == "healthy"
		if t, err := time.Parse(time.RFC3339Nano, fs[3]); err == nil && !t.IsZero() {
			st.UptimeSec = int64(time.Since(t).Seconds())
			if st.UptimeSec < 0 {
				st.UptimeSec = 0
			}
		}
		if len(fs) >= 5 {
			st.ImageDigest = shortDigest(fs[4])
		}
	}
	return st
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func shortDigest(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Install pulls the image and runs the container with our settings. Idempotent:
// if a container with the same name exists, it's removed first so we don't end
// up with a duplicate. Returns the combined docker output (for the UI log pane).
func (s *Service) Install(ctx context.Context) (string, error) {
	cfg := s.Config()

	// Ensure data dirs exist on the USB volume.
	if err := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("mkdir -p %q %q",
		cfg.DataRoot+"/etc", cfg.DataRoot+"/dnsmasq.d")).Run(); err != nil {
		return "", fmt.Errorf("mkdir dataroot: %w", err)
	}

	var log strings.Builder
	// Skip the pull if the image is already cached locally — `docker pull` needs
	// internet, and on this router DNS/AWG may not be up yet when we run at boot.
	// Idempotent when called from the boot-time recovery path.
	haveImage := false
	if out, err := s.docker(ctx, "images", "-q", ImageName); err == nil && strings.TrimSpace(out) != "" {
		haveImage = true
	}
	if !haveImage {
		pull, err := s.docker(ctx, "pull", ImageName)
		log.WriteString("pull:\n" + pull + "\n")
		if err != nil {
			return log.String(), fmt.Errorf("pull: %w", err)
		}
	} else {
		log.WriteString("pull: skipped (image cached locally)\n")
	}
	// Remove any prior container (ignore error if missing).
	rm, _ := s.docker(ctx, "rm", "-f", ContainerName)
	if rm != "" {
		log.WriteString("rm-prev: " + rm + "\n")
	}

	args := []string{
		"run", "-d",
		"--name", ContainerName,
		"--network", "host",
		"--restart", "unless-stopped",
		"-e", "TZ=" + cfg.Timezone,
		"-e", "FTLCONF_webserver_api_password=" + cfg.Password,
		"-e", fmt.Sprintf("FTLCONF_dns_port=%d", cfg.DNSPort),
		"-e", fmt.Sprintf("FTLCONF_webserver_port=%d", cfg.UIPort),
		// LOCAL listening mode restricts DNS to local subnets — we don't want
		// pi-hole acting as an open resolver on the WAN side.
		"-e", "FTLCONF_dns_listeningMode=LOCAL",
		// USB ext4 may lack file-capability xattr support; without root the FTL
		// caps-setting step fails and the container restart-loops.
		"-e", "DNSMASQ_USER=root",
		"-v", cfg.DataRoot + "/etc:/etc/pihole",
		"-v", cfg.DataRoot + "/dnsmasq.d:/etc/dnsmasq.d",
		ImageName,
	}
	runOut, err := s.docker(ctx, args...)
	log.WriteString("run:\n")
	log.WriteString(runOut + "\n")
	if err != nil {
		return log.String(), fmt.Errorf("run: %w", err)
	}
	// Open the LAN-side firewall hole for the UI port. This is best-effort —
	// if iptables fails, the container still runs.
	openLANPort(ctx, cfg.UIPort)
	log.WriteString(fmt.Sprintf("opened firewall: tcp/%d\n", cfg.UIPort))
	return log.String(), nil
}

// openLANPort allows TCP traffic from br-lan (the LAN bridge) to the pi-hole
// web UI. fw3's zone_lan_input chain is the standard insertion point for LAN
// inbound rules on OpenWrt-derived stacks. Idempotent: check-then-insert.
func openLANPort(ctx context.Context, port int) {
	// -C returns non-zero if the rule doesn't exist; only then do we insert.
	check := exec.CommandContext(ctx, "iptables", "-C", "zone_lan_input",
		"-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if check.Run() == nil {
		return
	}
	add := exec.CommandContext(ctx, "iptables", "-I", "zone_lan_input",
		"-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT",
		"-m", "comment", "--comment", "pi-hole admin")
	_ = add.Run()
}

// Start / Stop / Restart wrap the docker CLI; safe to call when container
// doesn't exist (callers should call Install first). Start re-asserts the LAN
// firewall rule because fw3 wipes it on reboot.
func (s *Service) Start(ctx context.Context) (string, error) {
	out, err := s.docker(ctx, "start", ContainerName)
	if err == nil {
		openLANPort(ctx, s.Config().UIPort)
	}
	return out, err
}

// EnsureFirewall (re-)adds the LAN-input rule for the admin port. Called at
// selector boot from app.initPihole so a router reboot doesn't strand the user
// outside the pi-hole UI. Idempotent and silent.
func (s *Service) EnsureFirewall() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	openLANPort(ctx, s.Config().UIPort)
}

// EnsureRunning is the boot-time recovery hook. If the user had pi-hole
// installed before a reboot, their expectation is that it just comes back —
// not that they have to click "Install" again. So:
//
//   - container running → noop
//   - container exited / stale (the xiaomi-docker bundle leaves a stale
//     containerd shim dir on reboot which makes a plain `docker start` fail
//     with "mkdir … file exists") → docker rm -f + docker run (Install)
//   - container missing AND image absent → noop (user must Install explicitly)
//   - container missing AND image present → docker run (Install)
//
// Run as a goroutine from initPihole because Install can take 1-3 min on the
// (rare) cold-pull path and we don't want to block selector startup.
func (s *Service) EnsureRunning() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		st := s.Status()
		if st.Running && st.Healthy {
			return // nothing to do
		}
		if !st.Installed && st.State == "" {
			return // never installed; respect user's explicit choice
		}
		// Reinstall path: rm stale (if any) + run.
		if _, err := s.Install(ctx); err == nil {
			openLANPort(ctx, s.Config().UIPort)
		}
	}()
}
func (s *Service) Stop(ctx context.Context) (string, error) {
	return s.docker(ctx, "stop", "-t", "10", ContainerName)
}
func (s *Service) Restart(ctx context.Context) (string, error) {
	return s.docker(ctx, "restart", "-t", "10", ContainerName)
}
func (s *Service) Remove(ctx context.Context) (string, error) {
	return s.docker(ctx, "rm", "-f", ContainerName)
}

// Logs returns the last N lines from the container.
func (s *Service) Logs(ctx context.Context, lines int) (string, error) {
	if lines <= 0 || lines > 5000 {
		lines = 200
	}
	return s.docker(ctx, "logs", "--tail", fmt.Sprintf("%d", lines), ContainerName)
}

// Upgrade pulls a fresh image and recreates the container if the digest changed.
// Returns "" + nil when nothing to do (already up-to-date).
func (s *Service) Upgrade(ctx context.Context) (string, error) {
	var log strings.Builder
	pull, err := s.docker(ctx, "pull", ImageName)
	log.WriteString("pull:\n" + pull + "\n")
	if err != nil {
		return log.String(), fmt.Errorf("pull: %w", err)
	}
	// Recreate with the existing config.
	cfg := s.Config()
	_, _ = s.docker(ctx, "rm", "-f", ContainerName)
	runArgs := []string{"run", "-d", "--name", ContainerName, "--network", "host",
		"--restart", "unless-stopped",
		"-e", "TZ=" + cfg.Timezone,
		"-e", "FTLCONF_webserver_api_password=" + cfg.Password,
		"-e", fmt.Sprintf("FTLCONF_dns_port=%d", cfg.DNSPort),
		"-e", fmt.Sprintf("FTLCONF_webserver_port=%d", cfg.UIPort),
		"-e", "FTLCONF_dns_listeningMode=LOCAL",
		"-e", "DNSMASQ_USER=root",
		"-v", cfg.DataRoot + "/etc:/etc/pihole",
		"-v", cfg.DataRoot + "/dnsmasq.d:/etc/dnsmasq.d",
		ImageName}
	runOut, err := s.docker(ctx, runArgs...)
	log.WriteString("run:\n" + runOut + "\n")
	return log.String(), err
}

// ensureSession (re)authenticates against pi-hole's REST API when our cached
// session id is missing or stale. Pi-hole v6 sessions expire ~5 min idle.
func (s *Service) ensureSession(ctx context.Context) error {
	s.mu.Lock()
	if s.sid != "" && time.Since(s.sidAt) < 4*time.Minute {
		s.mu.Unlock()
		return nil
	}
	pwd := s.cfg.Password
	port := s.cfg.UIPort
	s.mu.Unlock()

	body, _ := json.Marshal(map[string]string{"password": pwd})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d%s", port, authPath), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("auth: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Session struct {
			SID string `json:"sid"`
		} `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Session.SID == "" {
		return errors.New("auth: empty sid")
	}
	s.mu.Lock()
	s.sid, s.sidAt = out.Session.SID, time.Now()
	s.mu.Unlock()
	return nil
}

// Stats fetches the live dashboard summary from pi-hole. Best-effort: any
// network/auth error returns a Stats with the Error field set so the UI can
// show "—" gracefully.
func (s *Service) Stats(ctx context.Context) Stats {
	st := Stats{}
	if err := s.ensureSession(ctx); err != nil {
		st.Error = err.Error()
		return st
	}
	s.mu.Lock()
	port, sid := s.cfg.UIPort, s.sid
	s.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d%s", port, statsPath), nil)
	req.Header.Set("X-FTL-SID", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		st.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return st
	}
	// Pi-hole's response shape (trimmed to what we render):
	//   { queries: { total, blocked, percent_blocked, unique_domains,
	//       active_clients, ... }, gravity: { domains_being_blocked } }
	var raw struct {
		Queries struct {
			Total          int     `json:"total"`
			Blocked        int     `json:"blocked"`
			PercentBlocked float64 `json:"percent_blocked"`
			UniqueDomains  int     `json:"unique_domains"`
			ActiveClients  int     `json:"active_clients"`
		} `json:"queries"`
		Gravity struct {
			Domains int `json:"domains_being_blocked"`
		} `json:"gravity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		st.Error = err.Error()
		return st
	}
	st.TotalQueries = raw.Queries.Total
	st.BlockedQueries = raw.Queries.Blocked
	st.PercentBlocked = raw.Queries.PercentBlocked
	st.UniqueDomains = raw.Queries.UniqueDomains
	st.ActiveClients = raw.Queries.ActiveClients
	st.DomainsOnList = raw.Gravity.Domains
	return st
}

// SetDNSChain toggles the chain flag and fires the registered hook so the
// AWG2 DNS proxy can swap its upstream live. Persistence is the caller's job.
func (s *Service) SetDNSChain(enabled bool) {
	s.mu.Lock()
	s.cfg.DNSChainEnabled = enabled
	port := s.cfg.DNSPort
	hook := s.onChainChange
	s.mu.Unlock()
	if hook != nil {
		hook(enabled, fmt.Sprintf("127.0.0.1:%d", port))
	}
}

// PiholeUpstream is the address other services (awgroute) consume when
// DNSChainEnabled is true. Returned even when disabled so callers can pre-bind.
func (s *Service) PiholeUpstream() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("127.0.0.1:%d", s.cfg.DNSPort)
}

// piholeFreshDefaultUpstreams is what FTL ships with — restored when the chain
// is disabled so pi-hole resolves directly without our proxy in the loop.
var piholeFreshDefaultUpstreams = []string{
	"8.8.8.8", "8.8.4.4",
	"2001:4860:4860::8888", "2001:4860:4860::8844",
	"2606:4700:4700::1001", "2606:4700:4700::1111",
	"1.0.0.1", "1.1.1.1",
}

// SetUpstreams rewrites pi-hole's dns.upstreams via the REST API. Used to
// splice the selector proxy in front of pi-hole's recursive path: when chain
// is on, callers pass ["127.0.0.1#<proxy-port>"]; on disable, pass the empty
// slice to restore FTL defaults. Pi-hole reloads atomically — no FTL restart.
func (s *Service) SetUpstreams(ctx context.Context, upstreams []string) error {
	if err := s.ensureSession(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	port, sid := s.cfg.UIPort, s.sid
	s.mu.Unlock()
	addrs := upstreams
	if len(addrs) == 0 {
		addrs = piholeFreshDefaultUpstreams
	}
	body, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"dns": map[string]any{"upstreams": addrs},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch,
		fmt.Sprintf("http://127.0.0.1:%d/api/config", port), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FTL-SID", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("set upstreams: HTTP %d", resp.StatusCode)
	}
	return nil
}
