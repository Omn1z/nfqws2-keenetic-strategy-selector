package app

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"nfqws2strategy/internal/logbuf"
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
		default:
			out = append(out, ServiceResult{Name: n, OK: false, Detail: "неизвестный сервис"})
		}
	}
	return out
}

// restartNfqws2 robustly restarts the main nfqws2 service.
//
// Why not a plain `S51nfqws2 restart`: the upstream init's is_running() uses
// `pgrep -nf /opt/usr/bin/nfqws2`, which also matches OUR
// /opt/usr/bin/nfqws2-strategy process (substring) and picks it as the newest —
// so the init mis-detects nfqws2 as "not running", skips the kill on stop, and
// orphans nfqws2 holding NFQUEUE 300, so a fresh start can't bind the queue
// (this is the post-reboot "nfqws2 не поднимается" symptom). We therefore mirror
// the proven manual recovery: stop (drops the firewall), `killall nfqws2`
// (matches by exact process name — never this nfqws2-strategy), then start fresh.
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
