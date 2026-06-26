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
	info := EngineInfo{Arch: runtime.GOARCH, Supported: awgArchSupported(runtime.GOARCH)}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		info.TunOK = true
	}
	if _, err := os.Stat(awgGoBin()); err == nil {
		info.Installed = true
	}
	return info
}

func (svc *Service) awgInstallEngineOS() (string, error) {
	arch := runtime.GOARCH
	if !awgArchSupported(arch) {
		return "", fmt.Errorf("нет сборки движка AWG2 для архитектуры %s", arch)
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
	data, err := httpGetBytes(base+asset, 90*time.Second)
	if err != nil {
		return "", fmt.Errorf("скачивание движка: %w", err)
	}
	if sumTxt, e := httpGetBytes(base+asset+".sha256", 20*time.Second); e == nil {
		if fields := strings.Fields(string(sumTxt)); len(fields) > 0 {
			if got := fmt.Sprintf("%x", sha256.Sum256(data)); fields[0] != got {
				return "", fmt.Errorf("контрольная сумма движка не совпала")
			}
		}
	}
	if err := extractEngine(data, awgEngineDir); err != nil {
		return "", err
	}
	// split-routing needs ipset — install it alongside the engine if it's absent
	if _, e1 := os.Stat("/opt/sbin/ipset"); e1 != nil {
		if _, e2 := os.Stat("/opt/bin/ipset"); e2 != nil {
			logbuf.Append("awg2", "info", "установка ipset (нужен для маршрутизации)…")
			_, _ = exec.Command("sh", "-c", opkgBin()+" update >/dev/null 2>&1; "+opkgBin()+" install ipset 2>&1").CombinedOutput()
		}
	}
	logbuf.Append("awg2", "info", "движок установлен в "+awgEngineDir)
	return "движок установлен: " + asset, nil
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
		dst := filepath.Join(dir, "amneziawg-go")
		tmp := dst + ".new"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, io.LimitReader(tr, 64<<20)); err != nil {
			f.Close()
			return err
		}
		f.Close()
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		_ = os.Chmod(dst, 0o755)
		got++
	}
	if got < 1 {
		return fmt.Errorf("в архиве движка нет amneziawg-go")
	}
	return nil
}

func (svc *Service) awgClientUpOS() error {
	return svc.awgClientUpManagerOS(svc.awgActive())
}

func (svc *Service) awgClientUpManagerOS(am *awg.Manager) error {
	if info := svc.awgEngineInfoOS(); !info.Installed {
		return fmt.Errorf("движок AWG2 не установлен — нажмите «Установить движок»")
	} else if !info.TunOK {
		return fmt.Errorf("нет /dev/net/tun — TUN недоступен на этом роутере")
	}
	if am == nil {
		return fmt.Errorf("AWG2-сервер не выбран")
	}
	p, ok := am.RouterPeer()
	if !ok {
		return fmt.Errorf("сначала добавьте этот роутер как пир (вкладка «Клиенты», отметка «роутер»)")
	}
	if strings.TrimSpace(p.PrivateKey) == "" {
		return fmt.Errorf("у роутер-пира нет приватного ключа — добавьте пир заново")
	}
	cfg := am.Config()
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
	ctx, cancel := contextTimeout(30 * time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput(); err != nil {
		return fmt.Errorf("поднятие интерфейса: %v: %s", err, strs.LastLines(strings.TrimSpace(string(out)), 4))
	}
	// 2) wait for the UAPI socket, then apply the WG + 2.0-obfuscation config
	for i := 0; i < 20; i++ {
		if _, e := os.Stat(awgSockPath(iface)); e == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if isWARPConfig(cfg) {
		next, err := svc.awgApplyBestWARPEndpoint(am, cfg, p, iface)
		if err != nil {
			return err
		}
		if next.Endpoint != cfg.Endpoint {
			cfg = next
			_ = writeFile0600(awgClientConfPath(iface), awg.ClientConf(&cfg, p))
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
	if gw, dev := awgDefaultRoute(); dev != "" {
		_, _ = awgRun(awgEndpointRouteCmd(endpointIP, gw, dev))
	}
	setText, err := awg.RenderUAPISet(&cfg, p, endpointIP, port)
	if err != nil {
		return err
	}
	resp, err := uapiRequestIface(iface, setText)
	if err != nil {
		return fmt.Errorf("UAPI: %w", err)
	}
	if !strings.Contains(resp, "errno=0") {
		return fmt.Errorf("UAPI set отклонён: %s", strings.TrimSpace(resp))
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
	iface := awgClientIface(am.Config())
	script := strings.Join([]string{
		"ip link set " + iface + " down 2>/dev/null || true",
		"ip link del " + iface + " 2>/dev/null || true",
		"pkill -f '" + awgGoBin() + " " + iface + "' 2>/dev/null || true",
		"rm -f " + awgSockPath(iface) + " 2>/dev/null || true",
		"echo down",
	}, "\n")
	ctx, cancel := contextTimeout(15 * time.Second)
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
	cfg := am.Config()
	st := awgClientStatusIfaceOS(awgClientIface(cfg))
	if st == nil {
		return nil
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
	return st
}

func awgClientStatusIfaceOS(iface string) *ClientStatus {
	st := &ClientStatus{}
	if exec.Command("ip", "link", "show", iface).Run() == nil {
		st.IfacePresent = true
	}
	if _, err := os.Stat(awgSockPath(iface)); err != nil {
		return st
	}
	resp, err := uapiRequestIface(iface, "get=1\n\n")
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
	conn, err := net.DialTimeout("unix", awgSockPath(iface), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
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

func httpGetBytes(url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := contextTimeout(timeout)
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
