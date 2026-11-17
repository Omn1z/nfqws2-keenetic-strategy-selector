package nfqws2

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/shell"
)

const transportEndpointsFile = "nfqws-transport-endpoints"

// SetTransportEndpointProvider supplies the router's VPN transport addresses.
// The provider must only take snapshots: it runs while bypassMu is held.
func (m *Manager) SetTransportEndpointProvider(provider func() []string) {
	m.bypassMu.Lock()
	defer m.bypassMu.Unlock()
	m.transportEndpoints = provider
}

func transportEndpointManifest(endpoints []string) string {
	seen := make(map[string]bool)
	var lines []string
	for _, endpoint := range endpoints {
		address, err := netip.ParseAddrPort(strings.TrimSpace(endpoint))
		if err != nil || address.Port() == 0 || address.Addr().Zone() != "" {
			continue
		}
		ip := address.Addr().Unmap()
		if !ip.IsGlobalUnicast() {
			continue
		}
		line := fmt.Sprintf("%s %d\n", ip, address.Port())
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "")
}

// syncTransportEndpoints keeps a separate cache, preserving the user's lists.
// Call with bypassMu held. A missing NFQWS installation remains untouched.
func (m *Manager) syncTransportEndpoints() (string, bool, error) {
	if m.transportEndpoints == nil || strings.TrimSpace(m.cfg.Nfqws2Conf) == "" {
		return "", false, nil
	}
	dir := filepath.Dir(m.cfg.Nfqws2Conf)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	manifest := transportEndpointManifest(m.transportEndpoints())
	name := filepath.Join(dir, transportEndpointsFile)
	old, err := os.ReadFile(name)
	if err == nil && string(old) == manifest {
		return manifest, true, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	f, err := os.CreateTemp(dir, ".nfqws-transport-*")
	if err != nil {
		return "", false, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(manifest); err != nil {
		_ = f.Close()
		return "", false, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", false, err
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}
	if err := os.Rename(f.Name(), name); err != nil {
		return "", false, err
	}
	return manifest, true, nil
}

// RefreshTransportBypass runs before a VPN peer starts using an endpoint. It
// only updates the dedicated bypass chain, never starts NFQWS or resolves user
// domains. Locally generated VPN UDP is exempted by address AND port, so other
// protocols at the same address retain their configured NFQUEUE processing.
func (m *Manager) RefreshTransportBypass() error {
	m.bypassMu.Lock()
	defer m.bypassMu.Unlock()
	_, installed, err := m.syncTransportEndpoints()
	if err != nil || !installed {
		return err
	}
	dir := filepath.Dir(m.cfg.Nfqws2Conf)
	helper := filepath.Join(dir, "nfqws-strategy-bypass.sh")
	if err := ensureBypassScript(helper); err != nil {
		return err
	}
	if err := ensureBypassPersistence(dir, m.cfg.Nfqws2Init, helper); err != nil {
		return err
	}
	if err := ensureBypassInitHook(m.cfg.Nfqws2Init, helper); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", transportBypassRefreshCommand(helper)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("VPN transport NFQUEUE bypass: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func transportBypassRefreshCommand(helper string) string {
	// Only two absent parents mean NFQWS is off for that family. A partial
	// rebuild can still queue VPN packets, so fail before UAPI in that state.
	var commands []string
	for _, family := range []string{"iptables", "ip6tables"} {
		commands = append(commands, fmt.Sprintf(`if command -v %[1]s >/dev/null 2>&1; then
  inspect_status=0; snapshot=$(%[1]s -w 2 -t mangle -S 2>/dev/null) || inspect_status=$?
  if [ "$inspect_status" -eq 2 ]; then
    inspect_status=0; snapshot=$(%[1]s -t mangle -S 2>/dev/null) || inspect_status=$?
  fi
  if [ "$inspect_status" -ne 0 ]; then
    [ "$inspect_status" -ne 4 ] || exit 4
    if [ %[1]s = ip6tables ] && ! grep -qx mangle /proc/net/ip6_tables_names 2>/dev/null; then snapshot=;
    else echo 'VPN transport NFQUEUE bypass: cannot inspect %[1]s' >&2; exit 1; fi
  fi
  post=0; pre=0
  case "
$snapshot
" in *'
-N nfqws_post
'*) post=1 ;; esac
  case "
$snapshot
" in *'
-N nfqws_pre
'*) pre=1 ;; esac
  case "$post:$pre" in
    0:0) : ;;
    1:1) %[2]s %[1]s || exit $? ;;
    *) echo 'VPN transport NFQUEUE bypass: incomplete %[1]s parent chains' >&2; exit 1 ;;
  esac
fi`, family, shell.Quote(helper)))
	}
	return strings.Join(commands, "\n")
}
