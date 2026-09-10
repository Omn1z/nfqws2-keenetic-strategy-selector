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
	"os"
	"os/exec"
	"regexp"
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

	// USB-anchored config root: see discoverDataRoot for runtime discovery
	// (/mnt/usb-<id>/mi_docker/pihole). OPA authz on the bundled dockerd only
	// allows bind mounts from /mnt/usb-*.

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
// The USB path is discovered at runtime (/mnt/usb-<id>/mi_docker/pihole), so a
// fresh install on a different router doesn't inherit anyone else's hardcoded id.
func Default() Config {
	return Config{
		Password:        "root",
		DNSPort:         DefaultDNSPort,
		UIPort:          DefaultUIPort,
		DataRoot:        discoverDataRoot(),
		Timezone:        "Europe/Moscow",
		DNSChainEnabled: false,
	}
}

// discoverDataRoot walks /mnt/usb-* and returns the first dir whose
// mi_docker/pihole sibling looks usable. Falls back to a generic placeholder
// so the field is never empty (the UI will show it and the user can fix it).
func discoverDataRoot() string {
	ents, _ := os.ReadDir("/mnt")
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "usb-") {
			continue
		}
		base := "/mnt/" + e.Name() + "/mi_docker"
		if fi, err := os.Stat(base); err == nil && fi.IsDir() {
			return base + "/pihole"
		}
	}
	return "/mnt/usb/mi_docker/pihole"
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

	mu    sync.Mutex
	sid   string // pi-hole session id; valid until pi-hole expires it (~5 min idle)
	sidAt time.Time

	// http is a per-Service client with keep-alive tuned for the FTL local API.
	// http.DefaultClient opens a fresh socket every call + has no timeout, so a
	// hung FTL would hang Dashboard polls indefinitely. Reusing the client lets
	// the kernel keep the TCP socket warm across Stats / SetUpstreams / auth.
	http *http.Client

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
		cfg.DataRoot = discoverDataRoot()
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "Europe/Moscow"
	}
	if cfg.Password == "" {
		cfg.Password = "root"
	}
	return &Service{
		dockerBin: discoverDockerBin(),
		cfg:       cfg,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// Loopback talk only — FTL is 127.0.0.1:8053. Keep a small pool of
				// reusable conns so the typical poll-every-N-sec dashboard doesn't
				// keep TCP-handshaking to the same port.
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
		},
	}
}

// discoverDockerBin finds the docker CLI; the bundled one isn't in PATH and
// lives under /mnt/usb-<id>/mi_docker/docker-binaries/docker — the <id> varies
// per router. Walk /mnt/usb-* first, then fall back to PATH.
func discoverDockerBin() string {
	ents, _ := os.ReadDir("/mnt")
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "usb-") {
			continue
		}
		cand := "/mnt/" + e.Name() + "/mi_docker/docker-binaries/docker"
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	for _, p := range []string{"/opt/bin/docker", "docker"} {
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
	// FTL writes pihole.toml ~10s after first start. Apply the add-subnet
	// patch as soon as it appears so a fresh user gets the EDNS Client Subnet
	// directive without having to restart the selector after Install. Runs
	// async so the UI's "Install" button doesn't block on it.
	s.ApplyPersistentPatchesWhenReady()
	return log.String(), nil
}

// ApplyPersistentPatchesWhenReady polls for pihole.toml (created by FTL on
// first start) for up to 60s, then runs EnsureAddSubnet. Idempotent. Safe to
// call repeatedly — both the wait and the patch no-op when not needed.
func (s *Service) ApplyPersistentPatchesWhenReady() {
	cfg := s.Config()
	if cfg.DataRoot == "" {
		return
	}
	toml := cfg.DataRoot + "/etc/pihole.toml"
	go func() {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(toml); err == nil {
				_ = s.EnsureAddSubnet()
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
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

// EnsureAddSubnet makes pi-hole's bundled dnsmasq copy the original client IP
// into the EDNS0 Client Subnet option of every upstream query. Our :5354
// proxy parses it back out — without this, the trace log shows every query
// as "src=127.0.0.1" because pi-hole hides the real LAN client behind its
// own socket.
//
// Pi-hole v6 ignores /etc/dnsmasq.d/*.conf unless `misc.etc_dnsmasq_d = true`,
// and the recommended escape hatch for arbitrary directives is
// `misc.dnsmasq_lines = ["add-subnet=32,128"]` in /etc/pihole/pihole.toml.
// We patch that array in place (preserves any other lines the user added)
// then trigger a DNS restart so FTL re-reads its config.
//
// Idempotent: a re-run with the directive already present is a no-op.
func (s *Service) EnsureAddSubnet() error {
	const directive = "add-subnet=32,128"
	cfg := s.Config()
	if cfg.DataRoot == "" {
		return fmt.Errorf("DataRoot not set")
	}
	tomlPath := cfg.DataRoot + "/etc/pihole.toml"
	raw, err := os.ReadFile(tomlPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", tomlPath, err)
	}
	if strings.Contains(string(raw), directive) {
		return nil // already applied
	}
	// Find the `dnsmasq_lines = [...]` line and append our directive inside the
	// array. Pi-hole writes the array on a single line so this regex is enough;
	// fall back to a no-op if the layout changed in a future pi-hole release.
	re := regexp.MustCompile(`(?m)^(\s*dnsmasq_lines\s*=\s*\[)([^\]]*)(\])`)
	m := re.FindSubmatchIndex(raw)
	if m == nil {
		return fmt.Errorf("dnsmasq_lines key not found in %s", tomlPath)
	}
	inner := strings.TrimSpace(string(raw[m[4]:m[5]]))
	var patched []byte
	if inner == "" {
		patched = append(patched, raw[:m[4]]...)
		patched = append(patched, []byte(` "`+directive+`" `)...)
		patched = append(patched, raw[m[5]:]...)
	} else {
		patched = append(patched, raw[:m[5]]...)
		patched = append(patched, []byte(`, "`+directive+`"`)...)
		patched = append(patched, raw[m[5]:]...)
	}
	if err := os.WriteFile(tomlPath, patched, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tomlPath, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// `restartdns` re-execs pihole-FTL with the patched config (reloaddns only
	// SIGHUPs and doesn't pick up new dnsmasq_lines). MUST use s.dockerBin —
	// on Xiaomi router docker isn't in PATH (lives under /mnt/usb-*/mi_docker/),
	// so "docker exec" silently ENOENTs and FTL never picks up the patched
	// add-subnet=32,128 → trace log shows 127.0.0.1 as the client of every
	// query until the user reboots.
	if out, err := exec.CommandContext(ctx, s.dockerBin, "exec", ContainerName, "pihole", "restartdns").CombinedOutput(); err != nil {
		return fmt.Errorf("pihole restartdns: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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
		// Reinstall path: rm stale (if any) + run. Install() already kicks off
		// the persistent-patch wait async, so we don't need to repeat it here.
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

// invalidateSession drops the cached SID. Called when FTL replies 401 to a
// request we'd considered valid — otherwise the next 4 minutes of polls would
// keep failing until our 4-min TTL bumps the SID. Cheap reset under the lock.
func (s *Service) invalidateSession() {
	s.mu.Lock()
	s.sid, s.sidAt = "", time.Time{}
	s.mu.Unlock()
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
	resp, err := s.http.Do(req)
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
	resp, err := s.http.Do(req)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			s.invalidateSession()
		}
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
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			s.invalidateSession()
		}
		return fmt.Errorf("set upstreams: HTTP %d", resp.StatusCode)
	}
	return nil
}
