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
	routerpath "nfqws2strategy/internal/tools/path"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/strs"
)

const awgClientTxQueueLen = 4096

// OpenWrt's native filesystem is rooted at /, while Entware keeps the
// router-side userspace engine and profiles below /opt.  Keep the selection in
// one place so an APK install never downloads an engine to a directory that
// the runtime cannot execute.
var (
	awgEngineDir = routerpath.Path(routerpath.AWGEngineDir)
	awgClientDir = routerpath.Path(routerpath.AWGConfigDir)
)

func awgLegacyWatchdogPathOS() string {
	return routerpath.Path(routerpath.AWGLegacyWatchdog)
}

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
	path := awgLegacyWatchdogPathOS()
	if path == "" {
		return
	}
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
	if awgTunReadyOS() {
		info.TunOK = true
	}
	return info
}

func awgTunReadyOS() bool {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return false
	}
	if !routerpath.IsOpenWrt() {
		return true
	}
	return exec.Command("modprobe", "tun").Run() == nil
}

func ensureAWGTunOS(ctx context.Context) error {
	if !routerpath.IsOpenWrt() || awgTunReadyOS() {
		return nil
	}
	if _, err := exec.LookPath("apk"); err != nil {
		return fmt.Errorf("OpenWrt: не найден модуль TUN (/dev/net/tun не готов); установите пакет kmod-tun")
	}
	cmd := exec.CommandContext(ctx, "apk", "add", "kmod-tun")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("OpenWrt: установка kmod-tun: %v: %s", err, strs.LastLines(strings.TrimSpace(string(out)), 4))
	}
	if exec.CommandContext(ctx, "modprobe", "tun").Run() != nil || !awgTunReadyOS() {
		return fmt.Errorf("OpenWrt: пакет kmod-tun установлен, но модуль TUN не загрузился")
	}
	logbuf.Append("awg2", "info", "OpenWrt: загружен модуль kmod-tun")
	return nil
}

func ensureAWGIPSetOS(ctx context.Context) error {
	if exec.CommandContext(ctx, "ipset", "list", "-n").Run() == nil {
		return nil
	}

	var cmd *exec.Cmd
	if routerpath.IsOpenWrt() {
		apk, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("OpenWrt: не найден apk для установки ipset")
		}
		cmd = exec.CommandContext(ctx, apk, "add", "ipset", "kmod-ipt-ipset")
	} else {
		pm := opkgBin()
		cmd = exec.CommandContext(ctx, "sh", "-c", pm+" update >/dev/null 2>&1; "+pm+" install ipset 2>&1")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("установка ipset: %v: %s", err, strs.LastLines(strings.TrimSpace(string(out)), 4))
	}
	// OpenWrt may install the module without loading it into the running kernel.
	if routerpath.IsOpenWrt() {
		_ = exec.CommandContext(ctx, "modprobe", "ip_set").Run()
		_ = exec.CommandContext(ctx, "modprobe", "ip_set_hash_net").Run()
		_ = exec.CommandContext(ctx, "modprobe", "xt_set").Run()
	}
	if err := exec.CommandContext(ctx, "ipset", "list", "-n").Run(); err != nil {
		return fmt.Errorf("ipset установлен, но утилита не может открыть netfilter sets")
	}
	logbuf.Append("awg2", "info", "ipset готов для маршрутизации")
	return nil
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
	if err := ensureAWGTunOS(opCtx); err != nil {
		return "", err
	}
	if !routerpath.IsOpenWrt() {
		_ = exec.Command("sh", "-c", "modprobe tun 2>/dev/null; [ -e /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }").Run()
	}
	asset := "awg-engine-linux-" + arch + ".tar.gz"
	base := "https://github.com/" + svc.cfg.Repo + "/releases/latest/download/"
	logbuf.Append("awg2", "info", "скачивание движка "+asset+"…")
	if err := installAWGEngineFromRelease(opCtx, base+asset, awgEngineDir, !routerpath.IsOpenWrt(), awgWgetCandidates()); err != nil {
		return "", err
	}
	// Split-routing needs ipset. Installation is best-effort here because the
	// engine itself can still be used without routing; applying routing returns
	// a hard error when the package cannot be prepared.
	ctx, cancel := context.WithTimeout(opCtx, 60*time.Second)
	if err := ensureAWGIPSetOS(ctx); err != nil {
		logbuf.Append("awg2", "warn", err.Error())
	}
	cancel()
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
	if err := ensureAWGTunOS(opCtx); err != nil {
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

const (
	awgArchiveMaxBytes  = 32 << 20
	awgChecksumMaxBytes = 4 << 10
)

type awgWgetCommand struct {
	path string
	args []string
}

// Only a verified archive reaches extractEngine, which atomically replaces
// the existing executable after validating the complete gzip stream.
func installAWGEngineFromRelease(ctx context.Context, archiveURL, dir string, preferWget bool, wget []awgWgetCommand) error {
	data, err := downloadAWGAsset(ctx, archiveURL, awgArchiveMaxBytes, preferWget, wget)
	if err != nil {
		return fmt.Errorf("скачивание движка: %w", err)
	}
	sumTxt, err := downloadAWGAsset(ctx, archiveURL+".sha256", awgChecksumMaxBytes, preferWget, wget)
	if err != nil {
		return fmt.Errorf("не удалось получить контрольную сумму движка: %w", err)
	}
	if fields := strings.Fields(string(sumTxt)); len(fields) == 0 || !strings.EqualFold(fields[0], fmt.Sprintf("%x", sha256.Sum256(data))) {
		return fmt.Errorf("контрольная сумма движка не совпала")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return extractEngine(data, dir)
}

func awgWgetCandidates() []awgWgetCommand {
	var commands []awgWgetCommand
	if info, err := os.Stat("/opt/bin/wget"); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
		commands = append(commands, awgWgetCommand{path: "/opt/bin/wget"})
	}
	if info, err := os.Stat("/bin/busybox"); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
		commands = append(commands, awgWgetCommand{path: "/bin/busybox", args: []string{"wget"}})
	}
	if path, err := exec.LookPath("wget"); err == nil && path != "/opt/bin/wget" {
		commands = append(commands, awgWgetCommand{path: path})
	}
	return commands
}

// On some Entware routers wget works where Go's HTTPS fetch stalls.
// OpenWrt keeps the Go client first and uses wget only after a failure.
func downloadAWGAsset(parent context.Context, url string, maxBytes int64, preferWget bool, wget []awgWgetCommand) ([]byte, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	var errors []string
	tryHTTP := func() ([]byte, error) {
		data, err := httpGetBytes(parent, url, 90*time.Second, maxBytes)
		if err != nil {
			errors = append(errors, "Go HTTP: "+err.Error())
		}
		return data, err
	}
	tryWget := func() ([]byte, error) {
		if len(wget) == 0 {
			errors = append(errors, "wget не найден")
			return nil, fmt.Errorf("wget не найден")
		}
		data, err := wgetGetBytes(parent, url, maxBytes, wget)
		if err != nil {
			errors = append(errors, "wget: "+err.Error())
		}
		return data, err
	}
	first, second := tryHTTP, tryWget
	firstName, secondName := "Go HTTP", "wget"
	if preferWget {
		first, second = tryWget, tryHTTP
		firstName, secondName = secondName, firstName
	}
	if data, err := first(); err == nil {
		return data, nil
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	logbuf.Append("awg2", "warn", "загрузка AWG2 через "+firstName+" не удалась; пробуем "+secondName)
	if data, err := second(); err == nil {
		return data, nil
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s", strings.Join(errors, "; "))
}

func wgetGetBytes(parent context.Context, url string, maxBytes int64, commands []awgWgetCommand) ([]byte, error) {
	timeout := 2 * time.Minute
	if maxBytes > awgChecksumMaxBytes {
		timeout = 8 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var errors []string
	for _, candidate := range commands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		args := append(append([]string{}, candidate.args...), "-q", "-O", "-", url)
		cmd := exec.CommandContext(ctx, candidate.path, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			errors = append(errors, candidate.path+": "+err.Error())
			continue
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			_ = stdout.Close()
			errors = append(errors, candidate.path+": "+err.Error())
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(stdout, maxBytes+1))
		if int64(len(data)) > maxBytes {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("файл больше лимита %d байт", maxBytes)
		}
		waitErr := cmd.Wait()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if readErr == nil && waitErr == nil && len(data) > 0 {
			return data, nil
		}
		if readErr == nil && waitErr == nil {
			errors = append(errors, candidate.path+": пустой ответ")
		} else if readErr != nil {
			errors = append(errors, candidate.path+": "+readErr.Error())
		} else {
			errors = append(errors, fmt.Sprintf("%s: %v %s", candidate.path, waitErr, strings.TrimSpace(stderr.String())))
		}
	}
	return nil, fmt.Errorf("%s", strings.Join(errors, "; "))
}

func httpGetBytes(parent context.Context, url string, timeout time.Duration, maxBytes int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nfqws2-strategy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d для %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("файл больше лимита %d байт", maxBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("пустой ответ для %s", url)
	}
	return data, nil
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
