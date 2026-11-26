//go:build linux

package arpspoof

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	routerpath "nfqws2strategy/internal/tools/path"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/strs"
)

const (
	hookPath = ""
)

var legacyHookPath = routerpath.Path(routerpath.ARPSpoofHook)

func (s *Service) applyConfig(cfg Config) error {
	return s.applyConfigLinux(cfg, true)
}

func (s *Service) refreshConfig(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	return s.applyConfigLinux(cfg, false)
}

func (s *Service) applyConfigLinux(cfg Config, logAnnounce bool) error {
	_ = os.Remove(legacyHookPath)
	ndmc := lookupTool("ndmc")
	ops := macOperations{
		targets: func(c Config) ([]string, error) {
			wan := append([]string(nil), s.cfg.WANIfaces...)
			wan = append(wan, resolveApplyTargets(s.cfg.WANIfaces)...)
			ifaces := c.Ifaces
			if len(ifaces) == 0 {
				ifaces = suggestedInterfaceNames(interfaceCandidates(wan))
			}
			targets := resolveApplyTargets(ifaces)
			for _, name := range targets {
				for _, excluded := range wan {
					if name == excluded {
						return nil, fmt.Errorf("refusing to change WAN interface %s", name)
					}
				}
			}
			return targets, nil
		},
		read: func(name string) (macState, error) {
			kernel, err := interfaceMAC(name)
			if err != nil {
				return macState{}, err
			}
			if ndmc == "" {
				return macState{MAC: kernel}, nil
			}
			native, err := keeneticMAC(ndmc, name)
			// An old ip-link-only installation can report the new MAC here
			// while NDM's packet generators still use the old one. A native
			// command is therefore mandatory once on start/explicit apply.
			return macState{MAC: native, Inconsistent: native != kernel || logAnnounce}, err
		},
		write: func(name, mac string) error {
			if ndmc != "" {
				return setKeeneticMAC(ndmc, name, mac)
			}
			if lookupTool("ip") == "" {
				return fmt.Errorf("ip tool not found")
			}
			if out, err := runShell("ip link set dev " + shell.Quote(name) + " address " + shell.Quote(mac)); err != nil {
				return fmt.Errorf("%v: %s", err, strs.LastLines(out, 4))
			}
			actual, err := interfaceMAC(name)
			if err != nil || actual != mac {
				return fmt.Errorf("kernel MAC verification failed: got %q, want %q (%v)", actual, mac, err)
			}
			logbuf.Append("arp-spoofing", "info", "interface "+name+" MAC -> "+mac)
			return nil
		},
		announce: announceARP,
	}
	return s.applyMACConfig(cfg, logAnnounce, ops)
}

func interfaceMAC(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		if _, statErr := os.Stat(filepath.Join("/sys/class/net", name)); os.IsNotExist(statErr) {
			return "", os.ErrNotExist
		}
		return "", err
	}
	mac, err := normalizeMAC(iface.HardwareAddr.String())
	if err != nil || mac == "" {
		return "", fmt.Errorf("interface %s has no valid Ethernet MAC", name)
	}
	return mac, nil
}

func resolveApplyTargets(ifaces []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range cleanIfaces(ifaces) {
		target, ok := applyTarget(name)
		if !ok || seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

func applyTarget(name string) (string, bool) {
	if master, err := os.Readlink(filepath.Join("/sys/class/net", name, "master")); err == nil {
		base := filepath.Base(master)
		if base != "." && base != "" {
			return base, true
		}
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "ra") || strings.HasPrefix(lower, "apcli") || strings.HasPrefix(lower, "wifi") || strings.HasPrefix(lower, "wlan") || strings.HasPrefix(lower, "wl") {
		return "", false
	}
	return name, true
}

func announceARP(iface string, logAnnounce bool) {
	if lookupTool("arping") == "" {
		return
	}
	ips := ifaceIPv4Addrs(iface)
	for _, ip := range ips {
		if out, err := runShell("arping -q -U -c 2 -I " + shell.Quote(iface) + " -s " + shell.Quote(ip) + " " + shell.Quote(ip)); err != nil {
			logbuf.Append("arp-spoofing", "warn", "ARP announcement on "+iface+": "+strs.LastLines(out, 3))
			return
		}
	}
	if logAnnounce && len(ips) > 0 {
		logbuf.Append("arp-spoofing", "info", "gratuitous ARP sent on "+iface+" for "+strings.Join(ips, ", "))
	}
}

func ifaceIPv4Addrs(iface string) []string {
	out, err := runShell("ip -o -4 addr show dev " + shell.Quote(iface) + " | awk '{print $4}' | cut -d/ -f1")
	if err != nil || out == "" {
		return nil
	}
	var ips []string
	for _, ip := range strings.Fields(out) {
		if net.ParseIP(ip).To4() != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func runShell(cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
