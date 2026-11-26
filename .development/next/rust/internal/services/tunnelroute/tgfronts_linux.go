//go:build linux

package tunnelroute

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/tgfronts"
)

func validIface(iface string) bool {
	if iface == "" || len(iface) > 32 {
		return false
	}
	for i := 0; i < len(iface); i++ {
		c := iface[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func run(cmd string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "sh", "-c", cmd).Run()
}

// SetTGFrontRoutes points the Telegram web-front host routes at iface.
func SetTGFrontRoutes(iface string) {
	if !validIface(iface) {
		return
	}
	dev := shell.Quote(iface)
	for _, ip := range tgfronts.IPs() {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			run("ip route replace " + ip + "/32 dev " + dev)
		}
	}
}

// DelTGFrontRoutes removes Telegram web-front host routes owned by iface.
func DelTGFrontRoutes(iface string) {
	if !validIface(iface) {
		return
	}
	dev := shell.Quote(iface)
	for _, ip := range tgfronts.IPs() {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			run("ip route del " + ip + "/32 dev " + dev + " 2>/dev/null")
		}
	}
}
