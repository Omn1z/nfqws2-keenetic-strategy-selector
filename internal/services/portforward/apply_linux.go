//go:build linux

package portforward

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/strs"
)

const (
	hookPath    = "/opt/etc/ndm/netfilter.d/91-n2s-port-forward.sh"
	natChain    = "N2S_PFWD"
	filterChain = "N2S_PFWD_FWD"
)

var reIface = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

func (s *Service) applyRules(rules []Rule) error {
	enabled := enabledRules(rules)
	if len(enabled) == 0 {
		_ = os.Remove(hookPath)
		return cleanupRules()
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(hookPath, []byte(s.firewallHook(enabled)), 0o755); err != nil {
		return err
	}
	out, err := runShell("sh " + shell.Quote(hookPath))
	if err != nil {
		msg := strs.LastLines(out, 3)
		logbuf.Append("port-forwarding", "warn", "firewall hook: "+msg)
		return fmt.Errorf("apply port forwarding: %v: %s", err, msg)
	}
	return nil
}

func enabledRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func (s *Service) firewallHook(rules []Rule) string {
	var b strings.Builder
	ifaces := safeWANIfaces(s.cfg.WANIfaces)
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Port Forwarding hook managed by nfqws2-strategy. DO NOT EDIT.\n")
	b.WriteString("[ \"$type\" = \"ip6tables\" ] && exit 0\n")
	b.WriteString("iptables -t nat -N " + natChain + " 2>/dev/null || true\n")
	b.WriteString("iptables -t nat -F " + natChain + "\n")
	b.WriteString("iptables -N " + filterChain + " 2>/dev/null || true\n")
	b.WriteString("iptables -F " + filterChain + "\n")
	b.WriteString("while iptables -t nat -D PREROUTING -j " + natChain + " 2>/dev/null; do :; done\n")
	b.WriteString("iptables -t nat -A PREROUTING -j " + natChain + "\n")
	b.WriteString("while iptables -D FORWARD -j " + filterChain + " 2>/dev/null; do :; done\n")
	b.WriteString("iptables -I FORWARD 1 -j " + filterChain + "\n")
	for _, r := range rules {
		b.WriteString("# " + shellComment(r.Name) + " -> " + r.DeviceIP + "\n")
		writeProtoRules(&b, ifaces, r.DeviceIP, "tcp", r.TCP)
		writeProtoRules(&b, ifaces, r.DeviceIP, "udp", r.UDP)
	}
	return b.String()
}

func writeProtoRules(b *strings.Builder, ifaces []string, ip, proto string, ranges []Range) {
	for _, pr := range ranges {
		spec := portSpec(pr)
		for _, iface := range ifaces {
			iarg := ifaceArg(iface)
			b.WriteString("iptables -t nat -A " + natChain + " " + iarg + "-p " + proto + " --dport " + spec + " -j DNAT --to-destination " + ip + "\n")
			b.WriteString("iptables -A " + filterChain + " " + iarg + "-p " + proto + " -d " + ip + " --dport " + spec + " -j ACCEPT\n")
		}
	}
}

func cleanupRules() error {
	script := strings.Join([]string{
		"while iptables -t nat -D PREROUTING -j " + natChain + " 2>/dev/null; do :; done",
		"iptables -t nat -F " + natChain + " 2>/dev/null || true",
		"iptables -t nat -X " + natChain + " 2>/dev/null || true",
		"while iptables -D FORWARD -j " + filterChain + " 2>/dev/null; do :; done",
		"iptables -F " + filterChain + " 2>/dev/null || true",
		"iptables -X " + filterChain + " 2>/dev/null || true",
		"exit 0",
	}, "\n")
	out, err := runShell(script)
	if err != nil {
		msg := strs.LastLines(out, 3)
		logbuf.Append("port-forwarding", "warn", "cleanup: "+msg)
		return fmt.Errorf("cleanup port forwarding: %v: %s", err, msg)
	}
	return nil
}

func safeWANIfaces(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, iface := range in {
		iface = strings.TrimSpace(iface)
		if iface == "" || seen[iface] || !reIface.MatchString(iface) {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func ifaceArg(iface string) string {
	if iface == "" {
		return ""
	}
	return "-i " + shell.Quote(iface) + " "
}

func portSpec(r Range) string {
	if r.End == r.Start {
		return strconv.Itoa(r.Start)
	}
	return strconv.Itoa(r.Start) + ":" + strconv.Itoa(r.End)
}


func shellComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func runShell(cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

