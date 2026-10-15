package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/logbuf"
)

type Nfqws2ServiceState struct {
	Running   bool `json:"running"`
	ManualOff bool `json:"manual_off"`
}

// Operations are fixed at initialization. Tests supply in-memory operations
// so service-control races and persistence failures never touch the router.
type nfqws2ServiceOperations struct {
	running func() bool
	start   func() ServiceResult
	stop    func() ServiceResult
	restart func() ServiceResult
}

func (a *App) nfqws2ManuallyOff() bool {
	if a.automation == nil {
		return false
	}
	a.automation.mu.Lock()
	defer a.automation.mu.Unlock()
	return a.automation.state.Nfqws2ManualOff
}

func (a *App) nfqws2ServiceRunning() bool {
	if a.automation != nil && a.automation.serviceOps != nil && a.automation.serviceOps.running != nil {
		return a.automation.serviceOps.running()
	}
	if a.nfqws2Running() {
		return true
	}
	return nfqws2MainDaemonRunning(nfqws2ServicePIDPath(a.Cfg.Nfqws2Conf), "/proc", nfqws2ServiceMainQueue(a.Cfg.Nfqws2Conf, a.Cfg.MainQueue))
}

// A strategy test runs the same executable as the main service. A process-name
// probe would report those workers as the live service and make the OFF
// watchdog stop them. Only the main pidfile can identify a fallback process;
// its argv must also agree with the main queue or own that exact daemon pidfile.
// The latter detects a partially started/custom-queue Entware daemon before it
// binds its queue. OpenWrt procd runs it in the foreground, without --pidfile.
func nfqws2MainDaemonRunning(pidFile, procRoot string, mainQueue int) bool {
	pidWire, err := readNfqws2IdentityFile(pidFile, 64)
	if err != nil {
		return false
	}
	pidText := strings.TrimSpace(string(pidWire))
	pid, err := strconv.ParseUint(pidText, 10, 32)
	if err != nil || pid <= 1 || strconv.FormatUint(pid, 10) != pidText {
		return false
	}
	wire, err := readNfqws2IdentityFile(filepath.Join(procRoot, pidText, "cmdline"), 256*1024)
	if err != nil {
		return false
	}
	argv := strings.Split(strings.TrimSuffix(string(wire), "\x00"), "\x00")
	switch filepath.Base(argv[0]) {
	case "nfqws2", "nfqws2.real", "nfqws2-keenetic":
	default:
		return false
	}
	queue, seenQueue := -1, false
	daemon, ownPIDFile := false, false
	for i := 1; i < len(argv); i++ {
		key, value, hasValue := strings.Cut(argv[i], "=")
		switch key {
		case "--daemon", "-D":
			daemon = !hasValue
		case "--qnum", "--pidfile", "--writable":
			if !hasValue {
				i++
				if i >= len(argv) {
					return false
				}
				value = argv[i]
			}
			switch key {
			case "--qnum":
				q, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return false
				}
				queue, seenQueue = int(q), true
			case "--pidfile":
				if filepath.Clean(value) != filepath.Clean(pidFile) {
					return false
				}
				ownPIDFile = true
			case "--writable":
				if strings.Contains(filepath.ToSlash(value), "/tmp/nfqws2-strategy/") {
					return false
				}
			}
		}
	}
	return seenQueue && (queue == mainQueue || daemon && ownPIDFile)
}

func readNfqws2IdentityFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	wire, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(wire)) > limit {
		err = fmt.Errorf("NFQWS2: слишком большой файл идентификации процесса")
	}
	return wire, err
}

func nfqws2ServiceMainQueue(conf string, fallback int) int {
	queue := fallback
	for _, path := range []string{conf, conf + ".run"} {
		wire, err := readNfqws2IdentityFile(path, 2*1024*1024)
		if err != nil {
			continue
		}
		value, present, err := config.LiteralShellConfigValue(string(wire), "NFQUEUE_NUM")
		if err != nil || !present {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err == nil {
			queue = int(parsed)
		}
	}
	return queue
}

func (a *App) Nfqws2ServiceStatus() Nfqws2ServiceState {
	return Nfqws2ServiceState{Running: a.nfqws2ServiceRunning(), ManualOff: a.nfqws2ManuallyOff()}
}

func (a *App) runNfqws2ServiceOperation(action string) ServiceResult {
	var operation func() ServiceResult
	if a.automation != nil && a.automation.serviceOps != nil {
		switch action {
		case "start":
			operation = a.automation.serviceOps.start
		case "stop":
			operation = a.automation.serviceOps.stop
		case "restart":
			operation = a.automation.serviceOps.restart
		}
	}
	if operation != nil {
		return operation()
	}
	switch action {
	case "start":
		return a.nfqws2StartRaw()
	case "stop":
		return a.nfqws2StopRaw()
	case "restart":
		return a.restartNfqws2Raw()
	default:
		return ServiceResult{Name: "nfqws2", Detail: "неизвестная команда сервиса"}
	}
}

// Save under the automation state mutex so config posts and pick-history writes
// retain the manual override. The service mutex must be held by the caller.
func (a *App) persistNfqws2ManualOff(off bool) error {
	if a.automation == nil || a.store == nil {
		return fmt.Errorf("хранилище управления NFQWS2 не инициализировано")
	}
	rt := a.automation
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state.Nfqws2ManualOff == off {
		return nil
	}
	next := rt.state
	next.Nfqws2ManualOff = off
	if err := a.store.Save(automationFile, &next); err != nil {
		return fmt.Errorf("сохранение состояния NFQWS2: %w", err)
	}
	rt.state = next
	return nil
}

// Nfqws2Stop persists OFF before touching the service. A failed stop is reported
// accurately, and the watchdog retries it instead of restarting the engine.
func (a *App) Nfqws2Stop() ServiceResult {
	if a.automation == nil {
		return a.runNfqws2ServiceOperation("stop")
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	if err := a.persistNfqws2ManualOff(true); err != nil {
		return ServiceResult{Name: "nfqws2", Detail: err.Error()}
	}
	result := a.runNfqws2ServiceOperation("stop")
	a.automation.serviceNeedsStop = !result.OK
	return result
}

// Only this explicit start clears a saved OFF. Restart/apply/watchdog actions
// remain unable to turn a deliberately disabled engine back on.
func (a *App) Nfqws2Start() ServiceResult {
	if a.automation == nil {
		return a.runNfqws2ServiceOperation("start")
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	wasOff := a.nfqws2ManuallyOff()
	result := ServiceResult{Name: "nfqws2", OK: true, Detail: "NFQWS2 уже запущен"}
	if !a.nfqws2ServiceRunning() {
		result = a.runNfqws2ServiceOperation("start")
	}
	if !result.OK {
		if wasOff {
			cleanup := a.runNfqws2ServiceOperation("stop")
			a.automation.serviceNeedsStop = !cleanup.OK
			if !cleanup.OK {
				result.Detail += "; остановка после неудачного запуска: " + cleanup.Detail
			}
		}
		return result
	}
	if !wasOff {
		return result
	}
	if err := a.persistNfqws2ManualOff(false); err != nil {
		// Do not leave an active engine contradicting the retained OFF after a
		// failed preference write. The next watchdog tick retries cleanup too.
		cleanup := a.runNfqws2ServiceOperation("stop")
		a.automation.serviceNeedsStop = !cleanup.OK
		result.OK = false
		result.Detail = err.Error()
		if !cleanup.OK {
			result.Detail += "; остановка после ошибки сохранения: " + cleanup.Detail
		}
	}
	if result.OK {
		a.automation.serviceNeedsStop = false
	}
	return result
}

func (a *App) restartNfqws2() ServiceResult {
	if a.automation == nil {
		return a.runNfqws2ServiceOperation("restart")
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	if a.nfqws2ManuallyOff() {
		return ServiceResult{Name: "nfqws2", Detail: "NFQWS2 выключен вручную; сначала включите сервис"}
	}
	return a.runNfqws2ServiceOperation("restart")
}

func (a *App) startNfqws2Automatically() ServiceResult {
	if a.automation == nil {
		return ServiceResult{Name: "nfqws2", Detail: "автоматика не инициализирована"}
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	if a.nfqws2ManuallyOff() {
		return ServiceResult{Name: "nfqws2", Detail: "NFQWS2 выключен вручную"}
	}
	return a.runNfqws2ServiceOperation("start")
}

func (a *App) enforceNfqws2Automation(mode string, fallback bool, handshakeAge int64) {
	if a.automation == nil {
		return
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	// A queued watchdog step must not execute a mode captured before a user
	// changed its preference while another service operation held this lock.
	mode = a.AutomationConfig().Mode
	if a.nfqws2ManuallyOff() {
		if a.automation.serviceNeedsStop || a.nfqws2ServiceRunning() {
			logbuf.Append("automation", "info", "восстановление ручного выключения NFQWS2")
			a.automation.serviceNeedsStop = !a.runNfqws2ServiceOperation("stop").OK
		}
		return
	}
	if (mode == "on" || mode == "auto" && fallback) && !a.nfqws2ServiceRunning() {
		logbuf.Append("automation", "info", fmt.Sprintf("start nfqws2: mode=%s, AWG handshake age=%ds", mode, handshakeAge))
		a.runNfqws2ServiceOperation("start")
	}
}

func (a *App) restoreNfqws2ManualOff() {
	if a.automation == nil {
		return
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	if a.nfqws2ManuallyOff() {
		a.automation.serviceNeedsStop = !a.runNfqws2ServiceOperation("stop").OK
	}
}

func (a *App) withNfqws2FirewallApply(background bool, apply func() error) error {
	if a.automation == nil {
		return apply()
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	if a.nfqws2ManuallyOff() {
		if background {
			return nil
		}
		return fmt.Errorf("список сохранён; NFQWS2 выключен вручную — включите сервис перед применением NFQUEUE bypass")
	}
	return apply()
}

func (a *App) withNfqws2PackageUpdate(update func() (string, error)) (string, error) {
	if a.automation == nil {
		return update()
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	wasOff := a.nfqws2ManuallyOff()
	output, err := update()
	if wasOff {
		// Package post-install hooks may launch the engine even when an
		// install ultimately fails. Restore OFF on both success and failure.
		cleanup := a.runNfqws2ServiceOperation("stop")
		a.automation.serviceNeedsStop = !cleanup.OK
		if !cleanup.OK {
			err = errors.Join(err, fmt.Errorf("NFQWS2: остановка после обновления: %s", cleanup.Detail))
		}
	}
	return output, err
}
