//go:build linux

package dnsroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func shadowRenewalPlatform() bool {
	if _, err := os.Stat("/etc/openwrt_release"); !os.IsNotExist(err) {
		return false
	}
	_, err := exec.LookPath("ndmc")
	return err == nil
}

func (a *Adapter) refreshShadowForRenew(ctx context.Context) ([]string, error) {
	if err := lockShadowContext(ctx, &a.shadow.discoveryMu); err != nil {
		return nil, err
	}
	a.shadow.discoveryUntil = time.Time{}
	a.shadow.discoveryMu.Unlock()
	return a.shadowServersOS(ctx)
}

func (a *Adapter) shadowRenewTarget(ctx context.Context) (shadowNativeState, error) {
	if err := lockShadowContext(ctx, &a.shadow.discoveryMu); err != nil {
		return shadowNativeState{}, err
	}
	defer a.shadow.discoveryMu.Unlock()
	s := a.shadow.native
	if s.reader == nil || s.reader.snapshot().closed || !validKeeneticInterface(s.iface) || !validShadowWAN(s.device) {
		return shadowNativeState{}, fmt.Errorf("нет активного наблюдения DHCP на подтверждённом WAN; обновление не выполнялось")
	}
	s.client = append(net.IP(nil), s.client...)
	return s, nil
}

// Validate the live physical WAN again immediately before the explicit action.
// A remembered native alias or a process name alone is insufficient authority.
func (a *Adapter) verifyShadowRenewTarget(ctx context.Context, target shadowNativeState, ndmc string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	devices := map[string]string{}
	var ips []net.IP
	identity := ""
	for _, nic := range interfaces {
		configured := false
		for _, name := range a.cfg.WANIfaces {
			configured = configured || name == nic.Name
		}
		if !configured || nic.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := nic.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip != nil {
				ips = append(ips, ip)
				devices[ip.String()] = nic.Name
			}
		}
		if nic.Name == target.device {
			identity = fmt.Sprintf("%d/%s", nic.Index, nic.HardwareAddr)
		}
	}
	if identity != target.identity || devices[target.client.String()] != target.device {
		return fmt.Errorf("адрес или интерфейс WAN изменился; обновление не выполнялось")
	}
	routes, err := command(ctx, "ip", "-4", "route", "show", "table", "main", "default")
	if err != nil {
		return fmt.Errorf("не удалось проверить текущий маршрут WAN: %w", err)
	}
	if shadowWANKey(routes, a.cfg.WANIfaces, ips) != target.key {
		return fmt.Errorf("маршрут WAN изменился; обновление не выполнялось")
	}
	out, err := command(ctx, ndmc, "-c", "show interface")
	if err = shadowNativeCommandError(ctx, "show interface", out, err); err != nil {
		return err
	}
	matched := false
	for _, wan := range parseShadowBroadcastWANs(out, routes, a.cfg.WANIfaces, devices) {
		matched = matched || wan.native == target.iface && wan.device == target.device && wan.client.Equal(target.client)
	}
	if !matched {
		return fmt.Errorf("штатный интерфейс не совпадает с активным WAN; обновление не выполнялось")
	}
	operation := "show ip dhcp client " + target.iface
	out, err = command(ctx, ndmc, "-c", operation)
	if err = shadowNativeCommandError(ctx, operation, out, err); err != nil {
		return err
	}
	if !shadowNativeDHCPRunning(out, target.iface) {
		return fmt.Errorf("штатный DHCP-клиент выбранного WAN не запущен; обновление не выполнялось")
	}
	return nil
}

func shadowNativeDHCPRunning(output, iface string) bool {
	id, service := "", ""
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch key {
		case "id":
			if id != "" {
				return false
			}
			id = strings.TrimSpace(value)
		case "service":
			if service != "" {
				return false
			}
			service = strings.TrimSpace(value)
		}
	}
	return id == iface && service == "running"
}

func (a *Adapter) renewShadowDNSOS(ctx context.Context) (result ShadowRenewalResult, resultErr error) {
	a.mu.Lock()
	running, lifetime := a.started, a.runCtx
	a.mu.Unlock()
	if !running || lifetime == nil || lifetime.Err() != nil {
		return result, fmt.Errorf("сначала включите DNS Server")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(lifetime, cancel)
	defer stop()
	ctx, finish := a.shadow.diagnostics.begin(ctx)
	defer func() {
		shadowDiagnosticEvent(ctx, "native.renew.result", result.Status+": "+result.Message, 0)
		finish(result.Servers, resultErr, time.Time{})
	}()
	shadowDiagnosticEvent(ctx, "native.renew.preflight", "Пользователь подтвердил однократное штатное обновление DHCP; проверка WAN и захвата", 0)
	if servers, _ := a.refreshShadowForRenew(ctx); len(servers) > 0 {
		return ShadowRenewalResult{Status: "resolved", Servers: servers, Message: "DNS провайдера уже определены автоматически; обновлять аренду не потребовалось."}, nil
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	target, err := a.shadowRenewTarget(ctx)
	if err != nil {
		return result, err
	}
	result.Interface, result.Device = target.iface, target.device
	ndmc, err := exec.LookPath("ndmc")
	if err != nil {
		return result, err
	}
	if err := lockShadowContext(ctx, &a.opMu); err != nil {
		return result, err
	}
	if err := lockShadowContext(ctx, &a.shadow.discoveryMu); err != nil {
		a.opMu.Unlock()
		return result, err
	}
	// Close/Prepare cannot change the run between this check and the command.
	err = func() error {
		a.mu.Lock()
		current := a.started && a.runCtx == lifetime
		a.mu.Unlock()
		if !current || ctx.Err() != nil {
			return fmt.Errorf("DNS Server остановлен; обновление не выполнялось")
		}
		// Re-read the live route after lock acquisition, not before a possible
		// wait behind Close or another route operation.
		preflight, finishPreflight := context.WithTimeout(ctx, 3*time.Second)
		err := a.verifyShadowRenewTarget(preflight, target, ndmc)
		finishPreflight()
		if err != nil {
			return err
		}
		live := a.shadow.native
		if ctx.Err() != nil || live.reader != target.reader || live.key != target.key || target.reader.snapshot().closed {
			return fmt.Errorf("наблюдение WAN изменилось; обновление не выполнялось")
		}
		return nil
	}()
	if err != nil {
		a.shadow.discoveryMu.Unlock()
		a.opMu.Unlock()
		return result, err
	}
	baseline := target.reader.snapshot().sequence
	a.shadowRenewal.sent()
	shadowDiagnosticEvent(ctx, "native.renew.command", target.iface+" / "+target.device+": штатная команда DHCP renew отправляется один раз", 0)
	operation := "interface " + target.iface + " ip dhcp client renew"
	commandCtx, finishCommand := context.WithTimeout(ctx, 3*time.Second)
	out, commandErr := command(commandCtx, ndmc, "-c", operation)
	err = shadowNativeCommandError(commandCtx, operation, out, commandErr)
	finishCommand()
	a.shadow.discoveryMu.Unlock()
	a.opMu.Unlock()
	if err != nil {
		return result, fmt.Errorf("команда DHCP renew: %w; автоматического повтора не будет", err)
	}
	waitLimit := 8 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		waitLimit = max(0, min(waitLimit, time.Until(deadline)-2500*time.Millisecond))
	}
	snapshot, err := waitShadowRenewal(ctx, target.reader, baseline, waitLimit)
	if err != nil {
		return result, err
	}
	servers, discoveryErr := a.refreshShadowForRenew(ctx)
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(servers) > 0 {
		result.Status, result.Servers, result.Message = "resolved", servers, "DNS провайдера получены автоматически."
		return result, nil
	}
	result.Status, result.Message = "waiting", "Команда DHCP renew отправлена. Новый DNS пока не получен; наблюдение продолжится без повторной команды."
	// A NAK explains why this originally verified WAN may already be gone.
	if snapshot.sequence > baseline && snapshot.observation.Kind == "nak" {
		result.Status, result.Message = "nak", "Провайдер отклонил прежнюю DHCP-аренду. Штатный клиент Keenetic восстанавливает подключение."
	}
	live, liveErr := a.shadowRenewTarget(ctx)
	if liveErr == nil && live.reader == target.reader && live.key == target.key && snapshot.sequence > baseline {
		switch snapshot.observation.Kind {
		case "ack_no_dns":
			result.Status, result.Message = "no_dns", "Провайдер подтвердил DHCP-аренду, но не передал пригодные DNS-серверы (option 6)."
		}
	}
	if discoveryErr != nil {
		shadowDiagnosticEvent(ctx, "native.renew.discovery", discoveryErr.Error(), 0)
	}
	return result, nil
}

func waitShadowRenewal(ctx context.Context, reader shadowNativeReader, baseline uint64, limit time.Duration) (shadowNativeSnapshot, error) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := reader.snapshot()
		if snapshot.closed || snapshot.sequence > baseline {
			return snapshot, nil
		}
		select {
		case <-ctx.Done():
			return snapshot, ctx.Err()
		case <-timer.C:
			return snapshot, nil
		case <-ticker.C:
		}
	}
}
