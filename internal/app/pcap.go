package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/netmon"
	"nfqws2strategy/internal/tools/store"
)

const maxStoredPcaps = 5

// ErrNeedTcpdump signals that the per-packet capture needs tcpdump installed;
// the server turns it into a {need_install} response so the UI can prompt.
var ErrNeedTcpdump = errors.New("tcpdump not installed")

// Pcap is one per-packet capture of a device's traffic (tcpdump → .pcap file).
type Pcap struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Iface     string `json:"iface"`
	Seconds   int    `json:"seconds"`
	Status    string `json:"status"` // running | done | error
	Error     string `json:"error,omitempty"`
	StartedAt int64  `json:"started_at"`
	ElapsedMs int64  `json:"elapsed_ms"`
	Packets   int    `json:"packets"`
	Dropped   int    `json:"dropped"`
	SizeBytes int64  `json:"size_bytes"`
	file      string // server-side path, not serialized
}

// allowedPackages is the strict whitelist of opkg packages the UI may install —
// never run opkg with an arbitrary, caller-supplied name.
var allowedPackages = map[string]bool{"tcpdump": true}

func tcpdumpPath() string {
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

// deviceIface returns the bridge a LAN device is on (br0/br2), where its packets
// carry the device's real IP in both directions (pre-NAT). Defaults to br0.
func deviceIface(ip string) string {
	arp, _ := netmon.ARP()
	for _, e := range arp {
		if e.IP.String() == ip && e.Device != "" {
			return e.Device
		}
	}
	return "br0"
}

// InstallPackage installs a whitelisted opkg package (currently only tcpdump).
// Always user-initiated via the UI install prompt.
func (a *App) InstallPackage(pkg string) (string, error) {
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

// StartPcap launches a time-bounded tcpdump capture of one device's traffic and
// returns the initial snapshot. Returns ErrNeedTcpdump if tcpdump is missing.
func (a *App) StartPcap(ip string, seconds int) (*Pcap, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("неверный IP")
	}
	if tcpdumpPath() == "" {
		return nil, ErrNeedTcpdump
	}
	if seconds <= 0 || seconds > 120 {
		seconds = 30
	}
	dir := "/tmp/nfqws2-strategy"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	id := store.NewID()
	p := &Pcap{ID: id, IP: ip, Iface: deviceIface(ip), Seconds: seconds, Status: "running", StartedAt: time.Now().Unix(), file: filepath.Join(dir, "pcap-"+id+".pcap")}
	a.pcapMu.Lock()
	a.pcaps[id] = p
	a.pcapOrder = append(a.pcapOrder, id)
	for len(a.pcapOrder) > maxStoredPcaps {
		old := a.pcapOrder[0]
		if op := a.pcaps[old]; op != nil {
			_ = os.Remove(op.file)
		}
		delete(a.pcaps, old)
		a.pcapOrder = a.pcapOrder[1:]
	}
	a.pcapMu.Unlock()
	go a.runPcap(p)
	return a.snapshotPcap(id), nil
}

var (
	rePktCaptured = regexp.MustCompile(`(\d+) packets? captured`)
	rePktDropped  = regexp.MustCompile(`(\d+) packets? dropped by kernel`)
)

func (a *App) runPcap(p *Pcap) {
	bin := tcpdumpPath()
	logbuf.Append("pcap", "info", fmt.Sprintf("pcap %s: захват %s на %s, %dс", short(p.ID), p.IP, p.Iface, p.Seconds))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.Seconds+3)*time.Second)
	defer cancel()
	// -G N -W 1 autostops after N seconds and writes a single file.
	cmd := exec.CommandContext(ctx, bin, "-i", p.Iface, "-n", "-w", p.file, "-G", strconv.Itoa(p.Seconds), "-W", "1", "host", p.IP)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		a.setPcap(func() { p.Status = "error"; p.Error = err.Error() })
		logbuf.Append("pcap", "error", "pcap: "+err.Error())
		return
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			a.setPcap(func() {
				if m := rePktCaptured.FindStringSubmatch(stderr.String()); m != nil {
					p.Packets, _ = strconv.Atoi(m[1])
				}
				if m := rePktDropped.FindStringSubmatch(stderr.String()); m != nil {
					p.Dropped, _ = strconv.Atoi(m[1])
				}
				if fi, e := os.Stat(p.file); e == nil {
					p.SizeBytes = fi.Size()
				}
				p.ElapsedMs = time.Since(start).Milliseconds()
				p.Status = "done"
			})
			logbuf.Append("pcap", "info", fmt.Sprintf("pcap %s: готово — %d пакетов, %d отброшено, %d Б", short(p.ID), p.Packets, p.Dropped, p.SizeBytes))
			return
		case <-tick.C:
			if fi, e := os.Stat(p.file); e == nil {
				a.setPcap(func() { p.SizeBytes = fi.Size(); p.ElapsedMs = time.Since(start).Milliseconds() })
			}
		}
	}
}

func (a *App) setPcap(mut func()) {
	a.pcapMu.Lock()
	mut()
	a.pcapMu.Unlock()
}

func (a *App) GetPcap(id string) (*Pcap, bool) {
	p := a.snapshotPcap(id)
	return p, p != nil
}

func (a *App) snapshotPcap(id string) *Pcap {
	a.pcapMu.Lock()
	defer a.pcapMu.Unlock()
	p, ok := a.pcaps[id]
	if !ok {
		return nil
	}
	cp := *p
	return &cp
}

// PcapFile returns the finished capture's path + a download filename.
func (a *App) PcapFile(id string) (path, name string, ok bool) {
	a.pcapMu.Lock()
	defer a.pcapMu.Unlock()
	p, found := a.pcaps[id]
	if !found || p.Status != "done" {
		return "", "", false
	}
	return p.file, fmt.Sprintf("pcap-%s-%s.pcap", p.IP, short(p.ID)), true
}
