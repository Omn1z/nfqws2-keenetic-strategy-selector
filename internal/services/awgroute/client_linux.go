//go:build linux

package awgroute

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/strs"
)

const (
	awgEngineDir        = "/opt/usr/bin"
	awgClientDir        = "/opt/etc/amnezia/amneziawg"
	awgClientTxQueueLen = 4096
)

var awgIface = "awg0"

func awgArchSupported(a string) bool {
	switch a {
	case "arm64", "arm", "mips", "mipsle":
		return true
	}
	return false
}

func awgGoBin() string { return filepath.Join(awgEngineDir, "amneziawg-go") }

func awgClientIface(cfg awg.ServerConfig) string {
	if iface := strings.TrimSpace(cfg.ClientIface); validAWGClientIfaceName(iface) {
		return iface
	}
	return awgIface
}

func awgClientConfPath(iface string) string {
	return filepath.Join(awgClientDir, iface+".conf")
}

func awgSockPath(iface string) string {
	return "/var/run/amneziawg/" + iface + ".sock"
}

func awgTuneClientKernelBuffers() {
	for _, kv := range []struct {
		path  string
		value string
	}{
		{"/proc/sys/net/core/rmem_max", "8388608"},
		{"/proc/sys/net/core/wmem_max", "8388608"},
		{"/proc/sys/net/core/rmem_default", "8388608"},
		{"/proc/sys/net/core/wmem_default", "8388608"},
		{"/proc/sys/net/core/netdev_max_backlog", "4096"},
		{"/proc/sys/net/ipv4/tcp_mtu_probing", "1"},
	} {
		_ = os.WriteFile(kv.path, []byte(kv.value+"\n"), 0o644)
	}
}

func awgDaemonStartCmd(iface string) string {
	return "GOMEMLIMIT=128MiB GOGC=200 GODEBUG=madvdontneed=1 " + shell.Quote(awgGoBin()) + " " + shell.Quote(iface)
}

func awgDaemonEnvGuardScript(iface string) string {
	qiface := shell.Quote(iface)
	qsock := shell.Quote(awgSockPath(iface))
	return strings.Join([]string{
		"if ip link show " + qiface + " >/dev/null 2>&1; then",
		"  p=$(ps w | awk -v i=" + qiface + " '$0 ~ \"amneziawg-go \" i && $0 !~ /awk/ {print $1; exit}')",
		"  ok=0",
		"  if [ -n \"$p\" ]; then",
		"    envs=$(tr '\\0' '\\n' </proc/$p/environ 2>/dev/null || true)",
		"    echo \"$envs\" | grep -qx 'GOMEMLIMIT=128MiB' && echo \"$envs\" | grep -qx 'GOGC=200' && echo \"$envs\" | grep -qx 'GODEBUG=madvdontneed=1' && ok=1",
		"  fi",
		"  if [ \"$ok\" != 1 ]; then",
		"    ip link del " + qiface + " 2>/dev/null || true",
		"    [ -n \"$p\" ] && kill \"$p\" 2>/dev/null || true",
		"    rm -f " + qsock + " 2>/dev/null || true",
		"    sleep 1",
		"  fi",
		"fi",
	}, "\n")
}

func awgSetActiveIfaceOS(iface string) {
	if validAWGClientIfaceName(iface) {
		awgIface = iface
		return
	}
	awgIface = "awg0"
}

func (svc *Service) awgDisableLegacyExternalWatchdogsOS() {
	const path = "/opt/etc/init.d/S53awg1-watchdog"
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	txt := string(b)
	if !strings.Contains(txt, "awg1-watchdog") || !strings.Contains(txt, "/api/awg2/client/up") {
		return
	}
	_, _ = awgRun(path + " stop 2>/dev/null || true")
	_ = os.Chmod(path, 0o644)
	logbuf.Append("awg2", "info", "disabled legacy awg1 watchdog")
}

func (svc *Service) awgEngineInfoOS() EngineInfo {
	info := inspectEngine(awgGoBin())
	info.Arch, info.Supported = runtime.GOARCH, awgArchSupported(runtime.GOARCH)
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		info.TunOK = true
	}
	return info
}

func (svc *Service) awgInstallEngineOS() (string, error) {
	opCtx := svc.clientOpContext()
	if err := opCtx.Err(); err != nil {
		return "", err
	}
	arch := runtime.GOARCH
	if !awgArchSupported(arch) {
		return "", fmt.Errorf("нет сборки движка AmneziaWG для архитектуры %s", arch)
	}
	if svc.cfg.Repo == "" {
		return "", fmt.Errorf("repo релизов не настроен")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		_ = exec.Command("sh", "-c", "modprobe tun 2>/dev/null; [ -e /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }").Run()
	}
	asset := "awg-engine-linux-" + arch + ".tar.gz"
	base := "https://github.com/" + svc.cfg.Repo + "/releases/latest/download/"
	logbuf.Append("awg2", "info", "скачивание движка "+asset+"…")
	data, err := httpGetBytes(opCtx, base+asset, 90*time.Second)
	if err != nil {
		return "", fmt.Errorf("скачивание движка: %w", err)
	}
	sumTxt, err := httpGetBytes(opCtx, base+asset+".sha256", 20*time.Second)
	if err != nil {
		return "", fmt.Errorf("не удалось получить контрольную сумму движка: %w", err)
	}
	if fields := strings.Fields(string(sumTxt)); len(fields) == 0 || !strings.EqualFold(fields[0], fmt.Sprintf("%x", sha256.Sum256(data))) {
		return "", fmt.Errorf("контрольная сумма движка не совпала")
	}
	if err := opCtx.Err(); err != nil {
		return "", err
	}
	if err := extractEngine(data, awgEngineDir); err != nil {
		return "", err
	}
	// split-routing needs ipset — install it alongside the engine if it's absent
	if _, e1 := os.Stat("/opt/sbin/ipset"); e1 != nil {
		if _, e2 := os.Stat("/opt/bin/ipset"); e2 != nil {
			logbuf.Append("awg2", "info", "установка ipset (нужен для маршрутизации)…")
			ctx, cancel := context.WithTimeout(opCtx, 60*time.Second)
			cmd := exec.CommandContext(ctx, "sh", "-c", opkgBin()+" update >/dev/null 2>&1; "+opkgBin()+" install ipset 2>&1")
			cmd.WaitDelay = time.Second
			_, _ = cmd.CombinedOutput()
			cancel()
		}
	}
	logbuf.Append("awg2", "info", "движок установлен в "+awgEngineDir)
	return "движок установлен: " + svc.awgEngineInfoOS().AwgVersion + "; включённые туннели автоматически переподключатся", nil
}

// extractEngine writes amneziawg-go from the tar.gz to dir (0755).
func extractEngine(data []byte, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("распаковка движка: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	dst := filepath.Join(dir, "amneziawg-go")
	tmp := dst + ".new"
	defer os.Remove(tmp)
	got := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(h.Name) != "amneziawg-go" {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 64<<20 || got != 0 {
			return fmt.Errorf("неверный файл amneziawg-go в архиве")
		}
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, io.LimitReader(tr, 64<<20)); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := validateEngineBinary(tmp, runtime.GOARCH); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		got++
	}
	if got < 1 {
		return fmt.Errorf("в архиве движка нет amneziawg-go")
	}
	// Validate the gzip footer before replacing a working engine.
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return fmt.Errorf("повреждён архив движка: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func (svc *Service) awgClientUpOS() error {
	return svc.awgClientUpManagerOS(svc.awgActive())
}

func (svc *Service) awgClientUpManagerOS(am *awg.Manager) error {
	opCtx := svc.clientOpContext()
	if err := opCtx.Err(); err != nil {
		return err
	}
	if am == nil {
		return fmt.Errorf("AWG2-сервер не выбран")
	}
	cfg := am.RuntimeConfig()
	if !cfg.Enabled {
		return fmt.Errorf("AWG2-сервер выключен")
	}
	if info := svc.awgEngineInfoOS(); !info.Installed {
		return fmt.Errorf("движок AWG2 не установлен — нажмите «Установить движок»")
	} else if !info.TunOK {
		return fmt.Errorf("нет /dev/net/tun — TUN недоступен на этом роутере")
	} else if cfg.RequiresAWG31() && !info.AWG3Supported {
		return fmt.Errorf("для этого профиля нужен движок AmneziaWG 3.1 — обновите движок в панели")
	}
	p, ok := am.RouterPeer()
	if !ok {
		return fmt.Errorf("сначала добавьте этот роутер как пир (вкладка «Клиенты», отметка «роутер»)")
	}
	if strings.TrimSpace(p.PrivateKey) == "" {
		return fmt.Errorf("у роутер-пира нет приватного ключа — добавьте пир заново")
	}
	// Omitted AWG device fields retain their previous UAPI values. A fresh
	// daemon is required for protocol/obfuscation changes and engine upgrades.
	if err := svc.awgClientDownManagerOS(am); err != nil {
		return err
	}
	if err := opCtx.Err(); err != nil {
		return err
	}
	iface := awgClientIface(cfg)
	if err := os.MkdirAll(awgClientDir, 0o755); err != nil {
		return err
	}
	_ = writeFile0600(awgClientConfPath(iface), awg.ClientConf(&cfg, p)) // reference copy

	mtu := awgTunnelMTU(cfg)
	awgTuneClientKernelBuffers()
	// 1) start the userspace daemon (creates the iface + UAPI socket) + bring up.
	script := strings.Join([]string{
		"mkdir -p /var/run/amneziawg",
		awgDaemonEnvGuardScript(iface),
		"ip link show " + iface + " >/dev/null 2>&1 || (rm -f " + shell.Quote(awgSockPath(iface)) + " 2>/dev/null || true; " + awgDaemonStartCmd(iface) + "; sleep 1)",
		"ip addr flush dev " + iface + " 2>/dev/null || true",
		awgAddressScript(iface, p.Address),
		"ip link set " + iface + " mtu " + strconv.Itoa(mtu),
		"ip link set " + iface + " qlen " + strconv.Itoa(awgClientTxQueueLen) + " 2>/dev/null || true",
		"ip link set " + iface + " up",
		"echo iface-up",
	}, "\n")
	ctx, cancel := context.WithTimeout(opCtx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput(); err != nil {
		return fmt.Errorf("поднятие интерфейса: %v: %s", err, strs.LastLines(strings.TrimSpace(string(out)), 4))
	}
	// 2) wait for the UAPI socket, then apply the WG + 2.0-obfuscation config
	for i := 0; i < 20; i++ {
		if _, e := os.Stat(awgSockPath(iface)); e == nil {
			break
		}
		if !waitClientContext(opCtx, 200*time.Millisecond) {
			return opCtx.Err()
		}
	}
	if isWARPConfig(cfg) {
		next, err := svc.awgApplyBestWARPEndpoint(opCtx, am, cfg, p, iface)
		if next.Endpoint != cfg.Endpoint {
			// A handshake can arrive just after the probe timeout. Keep policy
			// endpoint exclusions consistent with the daemon's last UAPI set,
			// including an exhausted scan which will be retried by the supervisor.
			if am.RuntimeConfig().Endpoint != next.Endpoint {
				if saveErr := am.SetConfig(&next); saveErr != nil {
					return saveErr
				}
				svc.awgSave()
			}
			cfg = next
			_ = writeFile0600(awgClientConfPath(iface), awg.ClientConf(&cfg, p))
		}
		if err != nil {
			return err
		}
		logbuf.Append("awg2", "info", "туннель "+iface+" поднят (WARP endpoint auto)")
		return nil
	}
	host, portStr, _ := net.SplitHostPort(strings.TrimSpace(cfg.Endpoint))
	endpointIP := resolveHostIP(host)
	port, _ := strconv.Atoi(portStr)
	if endpointIP == "" || port == 0 {
		return fmt.Errorf("не удалось разрешить адрес сервера (endpoint)")
	}
	svc.rememberPolicyDNS(host, []string{endpointIP})
	if gw, dev := awgDefaultRoute(); dev != "" {
		_, _ = awgRun(awgEndpointRouteCmd(endpointIP, gw, dev))
	}
	setText, err := awg.RenderUAPISet(&cfg, p, endpointIP, port)
	if err != nil {
		return err
	}
	resp, err := uapiRequestIfaceContext(opCtx, iface, setText)
	if err != nil {
		return fmt.Errorf("UAPI: %w", err)
	}
	if !strings.Contains(resp, "errno=0") {
		return fmt.Errorf("UAPI set отклонён: %s", strings.TrimSpace(resp))
	}
	if cfg.PeerKeepaliveValue(p) == "0" {
		if err := svc.awgProbeClientOS(am); err != nil {
			return err
		}
	}
	logbuf.Append("awg2", "info", "туннель "+iface+" поднят (конфиг применён по UAPI)")
	return nil
}

func (svc *Service) awgClientDownOS() error {
	return svc.awgClientDownManagerOS(svc.awgActive())
}

func (svc *Service) awgClientDownManagerOS(am *awg.Manager) error {
	if am == nil {
		return fmt.Errorf("AWG2-server is not selected")
	}
	iface := awgClientIface(am.RuntimeConfig())
	script := strings.Join([]string{
		"ip link set " + iface + " down 2>/dev/null || true",
		"ip link del " + iface + " 2>/dev/null || true",
		"pkill -f '(^|/)amneziawg-go " + iface + "$' 2>/dev/null || true",
		"rm -f " + awgSockPath(iface) + " 2>/dev/null || true",
		"echo down",
	}, "\n")
	ctx, cancel := context.WithTimeout(svc.clientOpContext(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	logbuf.Append("awg2", "info", "туннель "+iface+" опущен: "+strs.LastLines(strings.TrimSpace(string(out)), 2))
	return nil
}

func (svc *Service) awgClientStatusOS() *ClientStatus {
	return svc.awgClientStatusManagerOS(svc.awgActive())
}

func (svc *Service) awgClientStatusManagerOS(am *awg.Manager) *ClientStatus {
	if am == nil {
		return nil
	}
	cfg := am.RuntimeConfig()
	st := awgClientStatusIfaceOS(awgClientIface(cfg))
	if st == nil {
		return nil
	}
	if st.Endpoint != "" {
		svc.rememberPolicyDNS(hostOf(cfg.Endpoint), []string{hostOf(st.Endpoint)})
	}
	if st.MTU == 0 {
		st.MTU = awgTunnelMTU(cfg)
	}
	if st.Address == "" {
		for _, p := range cfg.Peers {
			if p.IsRouter {
				st.Address = p.Address
				break
			}
		}
	}
	svc.clientRecoveryStatus(am, st)
	return st
}

func awgClientStatusIfaceOS(iface string) *ClientStatus {
	return awgClientStatusIfaceContextOS(context.Background(), iface)
}

func awgClientStatusIfaceContextOS(opCtx context.Context, iface string) *ClientStatus {
	st := &ClientStatus{}
	ctx, cancel := context.WithTimeout(opCtx, 2*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, "ip", "link", "show", iface).Run() == nil {
		st.IfacePresent = true
	}
	if _, err := os.Stat(awgSockPath(iface)); err != nil {
		return st
	}
	resp, err := uapiRequestIfaceContext(opCtx, iface, "get=1\n\n")
	if err != nil || !strings.Contains(resp, "public_key=") {
		return st
	}
	u := awg.ParseUAPIGet(resp)
	st.LastHandshake, st.RxBytes, st.TxBytes, st.Endpoint = u.LastHandshake, u.RxBytes, u.TxBytes, u.Endpoint
	st.Running = st.Endpoint != ""
	st.Connected = u.LastHandshake > 0 && time.Now().Unix()-u.LastHandshake < 180
	return st
}

// uapiRequest sends one UAPI request over a short-lived amneziawg-go unix
// socket. Keep the half-close: wireguard-go/amneziawg-go treat EOF on the write
// side as the unambiguous end-of-request on all builds we target.
func uapiRequest(req string) (string, error) {
	return uapiRequestIface(awgIface, req)
}

func uapiRequestIface(iface, req string) (string, error) {
	return uapiRequestIfaceContext(context.Background(), iface, req)
}

func uapiRequestIfaceContext(ctx context.Context, iface, req string) (string, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", awgSockPath(iface))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		return "", err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	data, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ---- helpers ----

func httpGetBytes(parent context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "nfqws2-strategy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d для %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}

func writeFile0600(path, content string) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func portOf(endpoint string) int {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.LastIndex(endpoint, ":"); i >= 0 {
		n, _ := strconv.Atoi(endpoint[i+1:])
		return n
	}
	return 0
}

func awgAddressScript(iface, addresses string) string {
	lines := []string{}
	for _, raw := range strings.Split(addresses, ",") {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}
		lines = append(lines, "ip addr add "+shell.Quote(addr)+" dev "+iface)
	}
	if len(lines) == 0 {
		return "true"
	}
	return strings.Join(lines, "\n")
}

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
