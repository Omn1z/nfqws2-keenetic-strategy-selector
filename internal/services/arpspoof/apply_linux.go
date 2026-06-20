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
)

const (
	hookPath       = ""
	legacyHookPath = "/opt/etc/ndm/netfilter.d/92-n2s-arp-spoof.sh"
)

func (s *Service) applyConfig(cfg Config) error {
	_ = os.Remove(legacyHookPath)
	if !cfg.Enabled {
		return s.restoreOriginalMACs()
	}
	if lookupTool("ip") == "" {
		return fmt.Errorf("ip tool not found")
	}
	ifaces := cfg.Ifaces
	if len(ifaces) == 0 {
		ifaces = suggestedInterfaceNames(interfaceCandidates(s.cfg.WANIfaces))
	}
	targets := resolveApplyTargets(ifaces)
	if len(targets) == 0 {
		return fmt.Errorf("AUTO did not find a LAN bridge, select br0 via API if needed")
	}
	for _, name := range targets {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		current := strings.ToUpper(iface.HardwareAddr.String())
		if current == "" {
			return fmt.Errorf("interface %s has no Ethernet MAC", name)
		}
		if _, ok := s.origMACs[name]; !ok && current != cfg.MAC {
			s.origMACs[name] = current
		}
		if current == cfg.MAC {
			announceARP(name)
			continue
		}
		if out, err := runShell("ip link set dev " + shellQuote(name) + " address " + shellQuote(cfg.MAC)); err != nil {
			msg := lastLines(out, 4)
			logbuf.Append("arp-spoofing", "warn", "set "+name+": "+msg)
			return fmt.Errorf("set %s MAC: %v: %s", name, err, msg)
		}
		logbuf.Append("arp-spoofing", "info", "interface "+name+" MAC -> "+cfg.MAC)
		announceARP(name)
	}
	return nil
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

func announceARP(iface string) {
	if lookupTool("arping") == "" {
		return
	}
	ips := ifaceIPv4Addrs(iface)
	for _, ip := range ips {
		_, _ = runShell("arping -q -U -c 3 -I " + shellQuote(iface) + " -s " + shellQuote(ip) + " " + shellQuote(ip))
		_, _ = runShell("arping -q -A -c 2 -I " + shellQuote(iface) + " -s " + shellQuote(ip) + " " + shellQuote(ip))
	}
	if len(ips) > 0 {
		logbuf.Append("arp-spoofing", "info", "gratuitous ARP sent on "+iface+" for "+strings.Join(ips, ", "))
	}
}

func ifaceIPv4Addrs(iface string) []string {
	out, err := runShell("ip -o -4 addr show dev " + shellQuote(iface) + " | awk '{print $4}' | cut -d/ -f1")
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

func (s *Service) restoreOriginalMACs() error {
	if len(s.origMACs) == 0 {
		return nil
	}
	if lookupTool("ip") == "" {
		return fmt.Errorf("ip tool not found")
	}
	var firstErr error
	for name, mac := range s.origMACs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			delete(s.origMACs, name)
			continue
		}
		current := strings.ToUpper(iface.HardwareAddr.String())
		if current != mac {
			if out, err := runShell("ip link set dev " + shellQuote(name) + " address " + shellQuote(mac)); err != nil {
				msg := lastLines(out, 4)
				logbuf.Append("arp-spoofing", "warn", "restore "+name+": "+msg)
				if firstErr == nil {
					firstErr = fmt.Errorf("restore %s MAC: %v: %s", name, err, msg)
				}
				continue
			}
			logbuf.Append("arp-spoofing", "info", "interface "+name+" MAC restored -> "+mac)
		}
		delete(s.origMACs, name)
	}
	return firstErr
}

func runShell(cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
