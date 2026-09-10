//go:build linux

package awgroute

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func clientSupervisorSupported() bool { return true }

var clientEnginePIDs sync.Map // iface -> pid; executable and argv rechecked on use

func awgClientCurrentEngineOS(cfg awg.ServerConfig) bool {
	installed, err := os.Stat(awgGoBin())
	if err != nil {
		return false
	}
	iface := awgClientIfaceName(cfg)
	check := func(pid string) bool {
		cmd, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			return false
		}
		args := strings.Split(string(cmd), "\x00")
		if len(args) < 2 || filepath.Base(args[0]) != "amneziawg-go" || args[1] != iface {
			return false
		}
		live, err := os.Stat(filepath.Join("/proc", pid, "exe"))
		return err == nil && os.SameFile(installed, live)
	}
	if cached, ok := clientEnginePIDs.Load(iface); ok && check(cached.(string)) {
		return true
	}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if check(e.Name()) {
			clientEnginePIDs.Store(iface, e.Name())
			return true
		}
	}
	clientEnginePIDs.Delete(iface)
	return false
}

// Only the peer's keepalive setting is touched. Sending the same nonzero value
// does not trigger SendKeepalive in amneziawg-go; its 0 -> nonzero transition
// does. Restore it even if shutdown/down cancels the probe between requests.
func (svc *Service) awgProbeClientOS(am *awg.Manager) error {
	cfg := am.RuntimeConfig()
	p, ok := am.RouterPeer()
	if !ok {
		return fmt.Errorf("пир роутера отсутствует")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.PublicKey))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("некорректный публичный ключ сервера")
	}
	prefix := "set=1\npublic_key=" + hex.EncodeToString(key) + "\npersistent_keepalive_interval="
	iface := awgClientIfaceName(cfg)
	resp, err := uapiRequestIfaceContext(svc.clientOpContext(), iface, prefix+"0\n\n")
	if err != nil || !strings.Contains(resp, "errno=0") {
		return fmt.Errorf("keepalive probe: %v %s", err, strings.TrimSpace(resp))
	}
	interval := cfg.PeerKeepaliveValue(p)
	restoreInterval := interval
	if interval == "0" || interval == "" {
		interval = "25"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err = uapiRequestIfaceContext(ctx, iface, prefix+interval+"\n\n")
	if err != nil || !strings.Contains(resp, "errno=0") {
		return fmt.Errorf("keepalive restore: %v %s", err, strings.TrimSpace(resp))
	}
	if restoreInterval == "0" {
		resp, err = uapiRequestIfaceContext(ctx, iface, prefix+"0\n\n")
		if err != nil || !strings.Contains(resp, "errno=0") {
			return fmt.Errorf("keepalive disable restore: %v %s", err, strings.TrimSpace(resp))
		}
	}
	return nil
}

func (svc *Service) awgRecoverClientOS(am *awg.Manager) error {
	ctx := svc.clientOpContext()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !awgShouldAutostartClient(am.RuntimeConfig()) {
		return fmt.Errorf("туннель выключен")
	}
	if _, _, err := am.EnsureRouterPeer(ctx); err != nil {
		return err
	}
	if err := svc.awgClientUpManagerOS(am); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return svc.awgRestoreClientRoutesOS(am)
}

// Recovering one interface does not stop DNS, flush learned ipsets, change the
// selected profile, or toggle committed routing. Re-pin endpoints and restore
// device routes lost by ip link del, then re-render the existing hook in place.
func (svc *Service) awgRestoreClientRoutesOS(am *awg.Manager) error {
	if am == nil || !awgShouldRestoreRouting(am.RuntimeConfig()) {
		return nil
	}
	if err := svc.clientOpContext().Err(); err != nil {
		return err
	}
	rules, tunnels := svc.awgBuildMultiPolicyCached()
	if len(rules) == 0 || len(tunnels) == 0 {
		if am == svc.awgActive() && am.RuntimeConfig().Routing.Mode == "full" {
			return svc.awgRestoreLegacyClientRoutesOS(am)
		}
		return nil
	}
	_, missing := os.Stat(awgMultiHookPath)
	if missing != nil {
		// Boot (or externally removed hook): initialize once. Never clear an
		// already-running proxy during ordinary tunnel recovery.
		if err := awgWriteMultiSets(rules); err != nil {
			return err
		}
	}
	if err := svc.awgInstallMultiRoutes(tunnels); err != nil {
		return err
	}
	svc.route.mu.Lock()
	dnsOn := svc.route.dnsProxy != nil
	svc.route.mu.Unlock()
	if !dnsOn {
		dnsOn = svc.awgEnsureMultiDNSProxy(rules)
	}
	if err := awgWriteMultiHook(tunnels, rules, dnsOn, svc.dnsChainEnabled()); err != nil {
		return err
	}
	awgSetAccel(false)
	svc.route.mu.Lock()
	refreshing := svc.route.multiStopRefresh != nil
	svc.route.mu.Unlock()
	if !refreshing {
		svc.awgStartMultiPolicyRefresh()
	}
	return nil
}

// The legacy full-tunnel mode has no zones and therefore no multi-policy
// rules. Preserve its committed datapath without resetting DNS/learned sets.
func (svc *Service) awgRestoreLegacyClientRoutesOS(am *awg.Manager) error {
	cfg := am.RuntimeConfig()
	endpointIP := svc.cachedPolicyHostIP(hostOf(cfg.Endpoint))
	gw, dev := awgDefaultRoute()
	if endpointIP == "" || dev == "" {
		return fmt.Errorf("не удалось определить WAN-маршрут до endpoint")
	}
	if _, err := os.Stat(awgHookPath); err != nil {
		// Full mode needs only empty set definitions; packet routing is in
		// the blanket firewall rule, not a bulk resolution of old zones.
		if err := svc.awgBuildRecoveryFullSets(); err != nil {
			return err
		}
		if awgUsesDNSProxy(&cfg) {
			awgRestoreSets()
		}
	}
	if err := awgRunCheck(awgEndpointRouteCmd(endpointIP, gw, dev)); err != nil {
		return err
	}
	iface := awgClientIfaceName(cfg)
	if err := awgRunCheck("ip route replace default dev " + iface + " table " + awgTable); err != nil {
		return err
	}
	_, _ = awgRun("while ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null; do :; done")
	if err := awgRunCheck("ip rule add fwmark " + awgMarkRule + " table " + awgTable); err != nil {
		return err
	}
	_, _ = awgRun("ip -6 route replace default dev " + iface + " table " + awgTable)
	_, _ = awgRun("ip -6 rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip -6 rule add fwmark " + awgMarkRule + " table " + awgTable)
	awgApplyKillswitch(cfg.Routing.Killswitch)
	svc.route.mu.Lock()
	dnsOn := svc.route.dnsProxy != nil
	refreshing := svc.route.stopRefresh != nil
	svc.route.active = true
	svc.route.mu.Unlock()
	if !dnsOn {
		dnsOn = svc.awgEnsureDNSProxy(&cfg)
	}
	if err := awgWriteHook(awgEffectiveMode(cfg.Routing), endpointIP, dev, awgTunnelMTU(cfg), dnsOn, svc.dnsChainEnabled(), awgTunnelV6Reaches(), cfg.Routing.Zones); err != nil {
		return err
	}
	awgSetAccel(false)
	if !refreshing {
		svc.awgStartRefresh()
	}
	return nil
}

func (svc *Service) awgBuildRecoveryFullSets() error {
	var b strings.Builder
	for _, set := range []string{awgSetInc, awgSetExc} {
		b.WriteString("create " + set + " hash:net family inet -exist\n")
		b.WriteString("create " + set + "_6 hash:net family inet6 -exist\n")
	}
	_, err := awgRunStdin("ipset restore -exist", b.String())
	return err
}
