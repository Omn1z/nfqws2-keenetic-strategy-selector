package app

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	routerpath "nfqws2strategy/internal/tools/path"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/strs"
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
func (a *App) restartNfqws2Raw() ServiceResult {
	if err := a.nfqws2.PrepareServiceStrategies(); err != nil {
		return ServiceResult{Name: "nfqws2", OK: false, Detail: err.Error()}
	}
	if _, err := a.nfqws2.PrepareWANInterfaces(); err != nil {
		return ServiceResult{Name: "nfqws2", OK: false, Detail: err.Error()}
	}
	serviceRevision := ""
	if state, err := a.nfqws2.ServiceStrategies(); err == nil {
		serviceRevision = state.Revision
	}
	init := shell.Quote(a.Cfg.Nfqws2Init)
	script := init + " stop 2>&1 || true\n" +
		"killall nfqws2 2>/dev/null\n" +
		"killall nfqws2.real 2>/dev/null\n" +
		"killall nfqws2-keenetic 2>/dev/null\n" +
		"sleep 2\n" +
		"rm -f " + shell.Quote(a.Cfg.Nfqws2Conf+".run") + "\n" +
		init + " start 2>&1\nsleep 1\n" + nfqws2StartedCheck
	logbuf.Append("system", "info", "restart nfqws2 (recovery)…")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	detail := strs.LastLines(strings.TrimSpace(string(b)), 6)
	if err != nil {
		logbuf.Append("system", "error", "restart nfqws2: "+err.Error())
		return ServiceResult{Name: "nfqws2", OK: false, Detail: fmt.Sprintf("%s (%v)", detail, err)}
	}
	logbuf.Append("system", "info", "restart nfqws2: ок")
	if err := a.nfqws2.ServiceStrategiesApplied(serviceRevision); err != nil {
		return ServiceResult{Name: "nfqws2", OK: false, Detail: "NFQWS2 запущен; статус сервисных стратегий не сохранён: " + err.Error()}
	}
	return ServiceResult{Name: "nfqws2", OK: true, Detail: detail}
}

func (a *App) restartSocks5() ServiceResult {
	if a.proxy.Socks5() == nil {
		return ServiceResult{Name: "socks5", OK: false, Detail: "менеджер не инициализирован"}
	}
	if !a.proxy.Socks5().Config().Enabled {
		return ServiceResult{Name: "socks5", OK: false, Detail: "прокси выключен — нечего перезапускать"}
	}
	logbuf.Append("system", "info", "restart socks5…")
	if err := a.proxy.Socks5().Restart(); err != nil {
		logbuf.Append("system", "error", "restart socks5: "+err.Error())
		return ServiceResult{Name: "socks5", OK: false, Detail: err.Error()}
	}
	return ServiceResult{Name: "socks5", OK: true, Detail: "перезапущен"}
}

// Nfqws2Start ensures the live nfqws2 engine is running: it first reaps any
// orphaned nfqws2 (the upstream S51 pgrep-collision can leave one holding the
// queue) then starts. Nfqws2Stop stops and reaps. These back the dashboard
// NFQWS2 Start/Stop controls; the router is never rebooted.
func (a *App) nfqws2StartRaw() ServiceResult {
	if err := a.nfqws2.PrepareServiceStrategies(); err != nil {
		return ServiceResult{Name: "nfqws2", OK: false, Detail: err.Error()}
	}
	if _, err := a.nfqws2.PrepareWANInterfaces(); err != nil {
		return ServiceResult{Name: "nfqws2", OK: false, Detail: err.Error()}
	}
	serviceRevision := ""
	if state, err := a.nfqws2.ServiceStrategies(); err == nil {
		serviceRevision = state.Revision
	}
	init := shell.Quote(a.Cfg.Nfqws2Init)
	script := "for n in nfqws2 nfqws2.real nfqws2-keenetic; do killall \"$n\" 2>/dev/null; done\nsleep 1\nrm -f " + shell.Quote(a.Cfg.Nfqws2Conf+".run") + "\n" + init + " start 2>&1\nsleep 1\n" + nfqws2StartedCheck
	result := a.nfqws2Ctl("start", script)
	if result.OK {
		if err := a.nfqws2.ServiceStrategiesApplied(serviceRevision); err != nil {
			result.OK = false
			result.Detail = "NFQWS2 запущен; статус сервисных стратегий не сохранён: " + err.Error()
		}
	}
	return result
}

const nfqws2StartedCheck = "if ! pidof nfqws2 nfqws2.real nfqws2-keenetic >/dev/null 2>&1; then echo 'NFQWS2 не запущен: проверьте параметры стратегий и журнал движка'; exit 1; fi\n"

// The upstream S51 init's stop is fragile on installations where the actual
// binary is "nfqws2.real" (an Entware wrapper) and/or where the pidfile got
// wiped: is_running()'s pidfile check fails, stop() bails with "not running",
// the .real daemon survives, the queue stays bound. So we do the cleanup
// by calling init stop while its pidfile is still valid, then force-cleaning
// known orphan process names and verifying the queue rules were removed.
func (a *App) nfqws2StopRaw() ServiceResult {
	init := shell.Quote(a.Cfg.Nfqws2Init)
	script := init + " stop 2>&1 || true\n" +
		"for n in nfqws2 nfqws2.real nfqws2-keenetic; do killall \"$n\" 2>/dev/null; done\n" +
		"sleep 1\n" +
		"for n in nfqws2 nfqws2.real nfqws2-keenetic; do for pid in $(pidof \"$n\" 2>/dev/null); do kill -9 \"$pid\" 2>/dev/null; done; done\n" +
		"for attempt in 1 2 3; do pidof nfqws2 nfqws2.real nfqws2-keenetic >/dev/null 2>&1 || break; sleep 1; done\n" +
		init + " firewall_stop 2>&1 || true\n" +
		"if pidof nfqws2 nfqws2.real nfqws2-keenetic >/dev/null 2>&1; then echo 'NFQWS2 не остановлен: процесс движка ещё работает'; exit 1; fi\n" +
		nfqws2StoppedFirewallCheck(a.Cfg.MainQueue) +
		"rm -f " + shell.Quote(a.Cfg.Nfqws2Conf+".run") + " " + shell.Quote(nfqws2ServicePIDPath(a.Cfg.Nfqws2Conf)) + " || { echo 'NFQWS2: не удалось удалить устаревшие runtime-файлы'; exit 1; }\n" +
		"echo 'nfqws2 stopped'"
	return a.nfqws2Ctl("stop", script)
}

func nfqws2StoppedFirewallCheck(queue int) string {
	return "command -v awk >/dev/null 2>&1 || { echo 'NFQWS2: awk недоступен для проверки firewall'; exit 1; }\n" +
		"for cmd in iptables ip6tables; do\n" +
		"  command -v \"$cmd\" >/dev/null 2>&1 || continue\n" +
		"  inspect_status=0; rules=$(\"$cmd\" -w 2 -t mangle -S 2>/dev/null) || inspect_status=$?\n" +
		// iptables1.4 accepts only bare '-w', which waits without a bound.
		// On its argument-error status retry without waiting; keep real read
		// failures visible rather than declaring the firewall clean.
		"  if [ \"$inspect_status\" -eq 2 ]; then inspect_status=0; rules=$(\"$cmd\" -t mangle -S 2>/dev/null) || inspect_status=$?; fi\n" +
		"  if [ \"$inspect_status\" -ne 0 ]; then if [ \"$cmd\" = ip6tables ] && ! grep -qx mangle /proc/net/ip6_tables_names 2>/dev/null; then continue; fi; echo \"NFQWS2: не удалось проверить $cmd после остановки\"; exit 1; fi\n" +
		"  if printf '%s\\n' \"$rules\" | awk -v queue=" + fmt.Sprint(queue) + " 'BEGIN { found=0 } { target=0; owned=0; for(i=1;i<=NF;i++) { if($i==\"-j\" && $(i+1)==\"NFQUEUE\") target=1; if($i==\"--queue-num\" && $(i+1)==queue) owned=1 } if(target && owned) found=1 } END { exit !found }'; then echo \"NFQWS2: остались правила NFQUEUE в $cmd\"; exit 1; fi\n" +
		"done\n"
}

func nfqws2ServicePIDPath(conf string) string {
	if filepath.Clean(conf) == filepath.Clean(routerpath.Path(routerpath.Nfqws2Conf)) {
		return routerpath.Path(routerpath.Nfqws2PID)
	}
	// Isolated/custom config roots keep cleanup local, including test fixtures.
	return filepath.Join(filepath.Dir(conf), "nfqws2.pid")
}

func (a *App) nfqws2Ctl(action, script string) ServiceResult {
	logbuf.Append("system", "info", "nfqws2 "+action+"…")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	detail := strs.LastLines(strings.TrimSpace(string(b)), 6)
	if err != nil {
		logbuf.Append("system", "error", "nfqws2 "+action+": "+err.Error())
		return ServiceResult{Name: "nfqws2", OK: false, Detail: fmt.Sprintf("%s (%v)", detail, err)}
	}
	logbuf.Append("system", "info", "nfqws2 "+action+": ок")
	return ServiceResult{Name: "nfqws2", OK: true, Detail: detail}
}

func (a *App) restartTGWS() ServiceResult {
	if a.proxy.TGWS() == nil {
		return ServiceResult{Name: "tgws", OK: false, Detail: "менеджер не инициализирован"}
	}
	if !a.proxy.TGWS().Config().Enabled {
		return ServiceResult{Name: "tgws", OK: false, Detail: "прокси выключен — нечего перезапускать"}
	}
	logbuf.Append("system", "info", "restart tgws…")
	if err := a.proxy.TGWS().Restart(); err != nil {
		logbuf.Append("system", "error", "restart tgws: "+err.Error())
		return ServiceResult{Name: "tgws", OK: false, Detail: err.Error()}
	}
	return ServiceResult{Name: "tgws", OK: true, Detail: "перезапущен"}
}
