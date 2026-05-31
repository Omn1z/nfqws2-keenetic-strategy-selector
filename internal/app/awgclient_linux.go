//go:build linux

package app

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
)

const (
	awgEngineDir  = "/opt/usr/bin"
	awgClientDir  = "/opt/etc/amnezia/amneziawg"
	awgClientConf = awgClientDir + "/awg0.conf"
	awgIface      = "awg0"
	awgSock       = "/var/run/amneziawg/awg0.sock"
)

func awgArchSupported(a string) bool {
	switch a {
	case "arm64", "arm", "mips", "mipsle":
		return true
	}
	return false
}

func awgGoBin() string { return filepath.Join(awgEngineDir, "amneziawg-go") }

func (a *App) awgEngineInfoOS() EngineInfo {
	info := EngineInfo{Arch: runtime.GOARCH, Supported: awgArchSupported(runtime.GOARCH)}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		info.TunOK = true
	}
	if _, err := os.Stat(awgGoBin()); err == nil {
		info.Installed = true
	}
	return info
}

func (a *App) awgInstallEngineOS() (string, error) {
	arch := runtime.GOARCH
	if !awgArchSupported(arch) {
		return "", fmt.Errorf("нет сборки движка AWG2 для архитектуры %s", arch)
	}
	if a.Cfg.Repo == "" {
		return "", fmt.Errorf("repo релизов не настроен")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		_ = exec.Command("sh", "-c", "modprobe tun 2>/dev/null; [ -e /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }").Run()
	}
	asset := "awg-engine-linux-" + arch + ".tar.gz"
	base := "https://github.com/" + a.Cfg.Repo + "/releases/latest/download/"
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

func (a *App) awgClientUpOS() error {
	if info := a.awgEngineInfoOS(); !info.Installed {
		return fmt.Errorf("движок AWG2 не установлен — нажмите «Установить движок»")
	} else if !info.TunOK {
		return fmt.Errorf("нет /dev/net/tun — TUN недоступен на этом роутере")
	}
	p, ok := a.awg.RouterPeer()
	if !ok {
		return fmt.Errorf("сначала добавьте этот роутер как пир (вкладка «Клиенты», отметка «роутер»)")
	}
	if strings.TrimSpace(p.PrivateKey) == "" {
		return fmt.Errorf("у роутер-пира нет приватного ключа — добавьте пир заново")
	}
	cfg := a.awg.Config()
	endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
	port := portOf(cfg.Endpoint)
	if endpointIP == "" || port == 0 {
		return fmt.Errorf("не удалось разрешить адрес сервера (endpoint)")
	}
	setText, err := awg.RenderUAPISet(&cfg, p, endpointIP, port)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(awgClientDir, 0o755); err != nil {
		return err
	}
	_ = writeFile0600(awgClientConf, awg.ClientConf(&cfg, p)) // reference copy

	mtu := cfg.Routing.MTU
	if mtu == 0 {
		mtu = 1280
	}
	// 1) start the userspace daemon (creates the iface + UAPI socket) + bring up
	script := strings.Join([]string{
		"mkdir -p /var/run/amneziawg",
		"ip link show " + awgIface + " >/dev/null 2>&1 || (" + awgGoBin() + " " + awgIface + "; sleep 1)",
		"ip addr flush dev " + awgIface + " 2>/dev/null || true",
		"ip addr add " + p.Address + " dev " + awgIface,
		"ip link set " + awgIface + " mtu " + strconv.Itoa(mtu),
		"ip link set " + awgIface + " up",
		"echo iface-up",
	}, "\n")
	ctx, cancel := contextTimeout(30 * time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput(); err != nil {
		return fmt.Errorf("поднятие интерфейса: %v: %s", err, lastLines(strings.TrimSpace(string(out)), 4))
	}
	// 2) wait for the UAPI socket, then apply the WG + 2.0-obfuscation config
	for i := 0; i < 20; i++ {
		if _, e := os.Stat(awgSock); e == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	resp, err := uapiRequest(setText)
	if err != nil {
		return fmt.Errorf("UAPI: %w", err)
	}
	if !strings.Contains(resp, "errno=0") {
		return fmt.Errorf("UAPI set отклонён: %s", strings.TrimSpace(resp))
	}
	logbuf.Append("awg2", "info", "туннель awg0 поднят (конфиг применён по UAPI)")
	return nil
}

func (a *App) awgClientDownOS() error {
	script := strings.Join([]string{
		"ip link set " + awgIface + " down 2>/dev/null || true",
		"ip link del " + awgIface + " 2>/dev/null || true",
		"pkill -f '" + awgGoBin() + " " + awgIface + "' 2>/dev/null || true",
		"rm -f " + awgSock + " 2>/dev/null || true",
		"echo down",
	}, "\n")
	ctx, cancel := contextTimeout(15 * time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	logbuf.Append("awg2", "info", "туннель awg0 опущен: "+lastLines(strings.TrimSpace(string(out)), 2))
	return nil
}

func (a *App) awgClientStatusOS() *ClientStatus {
	st := &ClientStatus{}
	if exec.Command("ip", "link", "show", awgIface).Run() == nil {
		st.IfacePresent = true
	}
	if _, err := os.Stat(awgSock); err != nil {
		return st
	}
	resp, err := uapiRequest("get=1\n\n")
	if err != nil || !strings.Contains(resp, "public_key=") {
		return st
	}
	st.Running = true
	u := awg.ParseUAPIGet(resp)
	st.LastHandshake, st.RxBytes, st.TxBytes, st.Endpoint = u.LastHandshake, u.RxBytes, u.TxBytes, u.Endpoint
	st.Connected = u.LastHandshake > 0 && time.Now().Unix()-u.LastHandshake < 180
	return st
}

// uapiRequest sends a UAPI request over the amneziawg-go unix socket and returns
// the response. It half-closes the write side so the daemon sees end-of-request.
func uapiRequest(req string) (string, error) {
	conn, err := net.DialTimeout("unix", awgSock, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	data, err := io.ReadAll(conn)
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

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
