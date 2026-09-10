// Package tcpdump centralizes the on-demand tcpdump plumbing shared by the device
// packet capture (services/monitor) and the ClientHello blob capture
// (services/blobs): locating the binary, picking the capture interface for a LAN
// device, the "needs install" sentinel, and the whitelisted opkg install. Keeping
// it here lets both services reuse it without depending on each other.
package tcpdump

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/netmon"
)

// ErrNeedInstall signals that a packet capture needs tcpdump installed; callers
// turn it into a {need_install} response so the UI can offer to install it.
var ErrNeedInstall = errors.New("tcpdump not installed")

// Path returns the tcpdump binary path, or "" when it is not installed.
func Path() string {
	if p, err := exec.LookPath("tcpdump"); err == nil {
		return p
	}
	for _, p := range []string{"/opt/sbin/tcpdump", "/opt/bin/tcpdump", "/usr/sbin/tcpdump"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DeviceIface returns the bridge a LAN device is on (br0/br2), where its packets
// carry the device's real IP in both directions (pre-NAT). Defaults to br0.
func DeviceIface(ip string) string {
	arp, _ := netmon.ARP()
	for _, e := range arp {
		if e.IP.String() == ip && e.Device != "" {
			return e.Device
		}
	}
	return "br0"
}

// allowedPackages is the strict whitelist of opkg packages the UI may install —
// never run opkg with an arbitrary, caller-supplied name.
var allowedPackages = map[string]bool{"tcpdump": true}

// Install installs a whitelisted opkg package (currently only tcpdump). Always
// user-initiated via the UI install prompt.
func Install(pkg string) (string, error) {
	if !allowedPackages[pkg] {
		return "", fmt.Errorf("пакет %q не разрешён к установке", pkg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	logbuf.Append("system", "info", "opkg install "+pkg+" …")
	out, err := exec.CommandContext(ctx, "opkg", "install", pkg).CombinedOutput()
	if err != nil {
		// stale package lists → refresh and retry once
		upd, _ := exec.CommandContext(ctx, "opkg", "update").CombinedOutput()
		out2, err2 := exec.CommandContext(ctx, "opkg", "install", pkg).CombinedOutput()
		out = append(append(upd, out...), out2...)
		err = err2
	}
	res := strings.TrimSpace(string(out))
	if err != nil {
		logbuf.Append("system", "error", fmt.Sprintf("opkg install %s: %v", pkg, err))
		return res, fmt.Errorf("opkg: %v", err)
	}
	logbuf.Append("system", "info", "opkg install "+pkg+": ок")
	return res, nil
}
