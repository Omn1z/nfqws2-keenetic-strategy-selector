//go:build linux

package arpblock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"syscall"
	"time"

	routerpath "nfqws2strategy/internal/tools/path"
)

var terminalEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
var nativeError = regexp.MustCompile(`(?im)^\s*(?:[a-z][a-z0-9_]*(?:::[a-z][a-z0-9_]*)+\s+error\s*\[|%?error\s*:|command\s+not\s+found)`)

func nativeBackend() (string, string, commandFunc) {
	if routerpath.IsOpenWrt() {
		return "openwrt", "На OpenWrt настройте изолированную гостевую сеть и AP isolation в LuCI. Управление изоляцией из этой панели пока доступно только для Keenetic.", nil
	}
	binary, err := exec.LookPath("ndmc")
	if err != nil {
		return "unknown", "Штатный контроллер Keenetic ndmc не найден", nil
	}
	return "keenetic", "", func(ctx context.Context, command string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-c", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.WaitDelay = time.Second
		cmd.Cancel = func() error {
			if cmd.Process == nil {
				return os.ErrProcessDone
			}
			err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		out := &boundedOutput{}
		cmd.Stdout, cmd.Stderr = out, out
		err := cmd.Run()
		if errors.Is(err, exec.ErrWaitDelay) && cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		// Never echo native output: running-config includes Wi-Fi passwords.
		if err != nil {
			return "", fmt.Errorf("Keenetic: команда не завершилась (%w)", err)
		}
		if out.truncated {
			return "", fmt.Errorf("Keenetic: ответ превышает допустимый размер")
		}
		text := terminalEscape.ReplaceAllString(string(out.data), "")
		if nativeError.MatchString(text) {
			return "", fmt.Errorf("Keenetic отклонил команду; проверьте поддержку изоляции в прошивке")
		}
		return text, nil
	}
}

type boundedOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := (2 << 20) - len(w.data)
	if len(p) > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	w.data = append(w.data, p...)
	return n, nil
}
