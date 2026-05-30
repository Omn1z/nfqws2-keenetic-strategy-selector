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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/awg"
	"nfqws2strategy/internal/logbuf"
)

const (
	awgEngineDir  = "/opt/usr/bin"
	awgClientDir  = "/opt/etc/amnezia/amneziawg"
	awgClientConf = awgClientDir + "/awg0.conf"
	awgSetConf    = awgClientDir + "/awg0.setconf"
	awgIface      = "awg0"
)

func awgArchSupported(a string) bool {
	switch a {
	case "arm64", "arm", "mips", "mipsle":
		return true
	}
	return false
}

func awgGoBin() string  { return filepath.Join(awgEngineDir, "amneziawg-go") }
func awgToolBin() string { return filepath.Join(awgEngineDir, "awg") }

func (a *App) awgEngineInfoOS() EngineInfo {
	info := EngineInfo{Arch: runtime.GOARCH, Supported: awgArchSupported(runtime.GOARCH)}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		info.TunOK = true
	}
	_, e1 := os.Stat(awgGoBin())
	_, e2 := os.Stat(awgToolBin())
	info.Installed = e1 == nil && e2 == nil
	if info.Installed {
		ctx, cancel := contextTimeout(4 * time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, awgToolBin(), "--version").CombinedOutput(); err == nil {
			info.AwgVersion = strings.TrimSpace(string(out))
		}
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
	// ensure /dev/net/tun exists (load the module if needed)
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
			got := fmt.Sprintf("%x", sha256.Sum256(data))
			if fields[0] != got {
				return "", fmt.Errorf("контрольная сумма движка не совпала")
			}
		}
	}
	if err := extractEngine(data, awgEngineDir); err != nil {
		return "", err
	}
	logbuf.Append("awg2", "info", "движок установлен в "+awgEngineDir)
	return "движок установлен: " + asset, nil
}

// extractEngine writes amneziawg-go + awg from the tar.gz to dir (0755).
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
	want := map[string]bool{"amneziawg-go": true, "awg": true}
	got := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Base(h.Name)
		if !want[name] {
			continue
		}
		dst := filepath.Join(dir, name)
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
	if got < 2 {
		return fmt.Errorf("в архиве движка нет ожидаемых бинарников")
	}
	return nil
}

func (a *App) awgClientUpOS() error {
	info := a.awgEngineInfoOS()
	if !info.Installed {
		return fmt.Errorf("движок AWG2 не установлен — нажмите «Установить движок»")
	}
	if !info.TunOK {
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
	if err := os.MkdirAll(awgClientDir, 0o755); err != nil {
		return err
	}
	if err := writeFile0600(awgSetConf, awg.SetConfText(&cfg, p)); err != nil {
		return err
	}
	_ = writeFile0600(awgClientConf, awg.ClientConf(&cfg, p))
	mtu := cfg.Routing.MTU
	if mtu == 0 {
		mtu = 1376
	}
	script := strings.Join([]string{
		"set -e",
		"mkdir -p /var/run/amneziawg",
		"ip link show " + awgIface + " >/dev/null 2>&1 || " + awgGoBin() + " " + awgIface,
		"sleep 1",
		"ip addr flush dev " + awgIface + " 2>/dev/null || true",
		"ip addr add " + p.Address + " dev " + awgIface,
		awgToolBin() + " setconf " + awgIface + " " + awgSetConf,
		"ip link set " + awgIface + " mtu " + strconv.Itoa(mtu),
		"ip link set " + awgIface + " up",
		"echo client-up-done",
	}, "\n")
	ctx, cancel := contextTimeout(30 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	detail := lastLines(strings.TrimSpace(string(out)), 4)
	logbuf.Append("awg2", "info", "client up: "+detail)
	if err != nil {
		return fmt.Errorf("поднятие туннеля: %v: %s", err, detail)
	}
	return nil
}

func (a *App) awgClientDownOS() error {
	script := strings.Join([]string{
		"ip link set " + awgIface + " down 2>/dev/null || true",
		"ip link del " + awgIface + " 2>/dev/null || true",
		"pkill -f '" + awgGoBin() + " " + awgIface + "' 2>/dev/null || true",
		"rm -f /var/run/amneziawg/" + awgIface + ".sock 2>/dev/null || true",
		"echo client-down-done",
	}, "\n")
	ctx, cancel := contextTimeout(15 * time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	logbuf.Append("awg2", "info", "client down: "+lastLines(strings.TrimSpace(string(out)), 3))
	return nil
}

func (a *App) awgClientStatusOS() *ClientStatus {
	st := &ClientStatus{}
	if exec.Command("ip", "link", "show", awgIface).Run() == nil {
		st.IfacePresent = true
	}
	if _, err := os.Stat(awgToolBin()); err != nil {
		return st
	}
	ctx, cancel := contextTimeout(6 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, awgToolBin(), "show", awgIface, "dump").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return st
	}
	st.Running = true
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) >= 2 {
		f := strings.Split(lines[1], "\t")
		if len(f) >= 7 {
			st.Endpoint = f[2]
			st.LastHandshake = parseInt64(f[4])
			st.RxBytes = parseInt64(f[5])
			st.TxBytes = parseInt64(f[6])
			st.Connected = st.LastHandshake > 0 && time.Now().Unix()-st.LastHandshake < 180
		}
	}
	return st
}

// ---- small helpers ----

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

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
