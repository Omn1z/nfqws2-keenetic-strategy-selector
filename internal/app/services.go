package app

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
)

// ServiceResult is the outcome of restarting one service (Dashboard restart button).
type ServiceResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// RestartServices restarts the requested services sequentially and returns a
// per-service result. Supported names: "nfqws2" (the live DPI-bypass service)
// and "tgws" (the integrated Telegram proxy). It NEVER reboots the router — it
// only restarts the named services.
func (a *App) RestartServices(names []string) []ServiceResult {
	out := make([]ServiceResult, 0, len(names))
	for _, n := range names {
		switch n {
		case "nfqws2":
			out = append(out, a.restartNfqws2())
		case "tgws":
			out = append(out, a.restartTGWS())
		case "socks5":
			out = append(out, a.restartSocks5())
		default:
			out = append(out, ServiceResult{Name: n, OK: false, Detail: "неизвестный сервис"})
		}
	}
	return out
}

// restartNfqws2 robustly restarts the main nfqws2 service.
//
// Background: the upstream init's is_running() uses `pgrep -nf /opt/usr/bin/nfqws2`,
// which substring-matched OUR old binary path /opt/usr/bin/nfqws2-strategy and, when
// our PID was the newest, made the init mis-detect nfqws2 as "not running" — it then
// skipped the kill on stop and orphaned nfqws2 holding NFQUEUE 300 (the post-reboot
// "nfqws2 не поднимается" + nfqws-keenetic-web "stopped" symptoms). v0.10.2 renamed our
// binary to /opt/usr/bin/n2s to remove that collision at the source. We still mirror the
// proven manual recovery here as defense-in-depth (a not-yet-migrated install, or any
// other stale nfqws2): stop (drops the firewall), `killall nfqws2` (exact process-name
// match — never this binary), then start fresh.
func (a *App) restartNfqws2() ServiceResult {
	init := a.Cfg.Nfqws2Init
	script := init + " stop 2>&1 || true\n" +
		"killall nfqws2 2>/dev/null\n" +
		"killall nfqws2-keenetic 2>/dev/null\n" +
		"sleep 2\n" +
		init + " start 2>&1"
	logbuf.Append("system", "info", "restart nfqws2 (recovery)…")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	detail := lastLines(strings.TrimSpace(string(b)), 6)
	if err != nil {
		logbuf.Append("system", "error", "restart nfqws2: "+err.Error())
		return ServiceResult{Name: "nfqws2", OK: false, Detail: fmt.Sprintf("%s (%v)", detail, err)}
	}
	logbuf.Append("system", "info", "restart nfqws2: ок")
	return ServiceResult{Name: "nfqws2", OK: true, Detail: detail}
}

func (a *App) restartSocks5() ServiceResult {
	if a.socks5 == nil {
		return ServiceResult{Name: "socks5", OK: false, Detail: "менеджер не инициализирован"}
	}
	if !a.socks5.Config().Enabled {
		return ServiceResult{Name: "socks5", OK: false, Detail: "прокси выключен — нечего перезапускать"}
	}
	logbuf.Append("system", "info", "restart socks5…")
	if err := a.socks5.Restart(); err != nil {
		logbuf.Append("system", "error", "restart socks5: "+err.Error())
		return ServiceResult{Name: "socks5", OK: false, Detail: err.Error()}
	}
	return ServiceResult{Name: "socks5", OK: true, Detail: "перезапущен"}
}

// Nfqws2Start ensures the live nfqws2 engine is running: it first reaps any
// orphaned nfqws2 (the upstream S51 pgrep-collision can leave one holding the
// queue) then starts. Nfqws2Stop stops and reaps. These back the dashboard
// NFQWS2 Start/Stop controls; the router is never rebooted.
func (a *App) Nfqws2Start() ServiceResult {
	init := a.Cfg.Nfqws2Init
	script := "killall nfqws2 2>/dev/null\nkillall nfqws2-keenetic 2>/dev/null\nsleep 1\n" + init + " start 2>&1"
	return a.nfqws2Ctl("start", script)
}

func (a *App) Nfqws2Stop() ServiceResult {
	init := a.Cfg.Nfqws2Init
	script := init + " stop 2>&1 || true\nkillall nfqws2 2>/dev/null\nkillall nfqws2-keenetic 2>/dev/null\necho 'nfqws2 stopped'"
	return a.nfqws2Ctl("stop", script)
}

func (a *App) nfqws2Ctl(action, script string) ServiceResult {
	logbuf.Append("system", "info", "nfqws2 "+action+"…")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	detail := lastLines(strings.TrimSpace(string(b)), 6)
	if err != nil {
		logbuf.Append("system", "error", "nfqws2 "+action+": "+err.Error())
		return ServiceResult{Name: "nfqws2", OK: false, Detail: fmt.Sprintf("%s (%v)", detail, err)}
	}
	logbuf.Append("system", "info", "nfqws2 "+action+": ок")
	return ServiceResult{Name: "nfqws2", OK: true, Detail: detail}
}

func (a *App) restartTGWS() ServiceResult {
	if a.tgws == nil {
		return ServiceResult{Name: "tgws", OK: false, Detail: "менеджер не инициализирован"}
	}
	if !a.tgws.Config().Enabled {
		return ServiceResult{Name: "tgws", OK: false, Detail: "прокси выключен — нечего перезапускать"}
	}
	logbuf.Append("system", "info", "restart tgws…")
	if err := a.tgws.Restart(); err != nil {
		logbuf.Append("system", "error", "restart tgws: "+err.Error())
		return ServiceResult{Name: "tgws", OK: false, Detail: err.Error()}
	}
	return ServiceResult{Name: "tgws", OK: true, Detail: "перезапущен"}
}

// lastLines keeps at most the final n lines, for compact UI display.
func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
