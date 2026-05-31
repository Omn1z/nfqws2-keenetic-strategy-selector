package monitor

import (
	"context"
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
	"nfqws2strategy/internal/tools/store"
	"nfqws2strategy/internal/tools/tcpdump"
)

const maxStoredPcaps = 5

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

// StartPcap launches a time-bounded tcpdump capture of one device's traffic and
// returns the initial snapshot. Returns tcpdump.ErrNeedInstall if tcpdump is missing.
func (s *Service) StartPcap(ip string, seconds int) (*Pcap, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("неверный IP")
	}
	if tcpdump.Path() == "" {
		return nil, tcpdump.ErrNeedInstall
	}
	if seconds <= 0 || seconds > 120 {
		seconds = 30
	}
	dir := "/tmp/nfqws2-strategy"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	id := store.NewID()
	p := &Pcap{ID: id, IP: ip, Iface: tcpdump.DeviceIface(ip), Seconds: seconds, Status: "running", StartedAt: time.Now().Unix(), file: filepath.Join(dir, "pcap-"+id+".pcap")}
	s.pcapMu.Lock()
	s.pcaps[id] = p
	s.pcapOrder = append(s.pcapOrder, id)
	for len(s.pcapOrder) > maxStoredPcaps {
		old := s.pcapOrder[0]
		if op := s.pcaps[old]; op != nil {
			_ = os.Remove(op.file)
		}
		delete(s.pcaps, old)
		s.pcapOrder = s.pcapOrder[1:]
	}
	s.pcapMu.Unlock()
	go s.runPcap(p)
	return s.snapshotPcap(id), nil
}

var (
	rePktCaptured = regexp.MustCompile(`(\d+) packets? captured`)
	rePktDropped  = regexp.MustCompile(`(\d+) packets? dropped by kernel`)
)

func (s *Service) runPcap(p *Pcap) {
	bin := tcpdump.Path()
	logbuf.Append("pcap", "info", fmt.Sprintf("pcap %s: захват %s на %s, %dс", short(p.ID), p.IP, p.Iface, p.Seconds))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.Seconds+3)*time.Second)
	defer cancel()
	// -G N -W 1 autostops after N seconds and writes a single file.
	cmd := exec.CommandContext(ctx, bin, "-i", p.Iface, "-n", "-w", p.file, "-G", strconv.Itoa(p.Seconds), "-W", "1", "host", p.IP)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		s.setPcap(func() { p.Status = "error"; p.Error = err.Error() })
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
			s.setPcap(func() {
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
				s.setPcap(func() { p.SizeBytes = fi.Size(); p.ElapsedMs = time.Since(start).Milliseconds() })
			}
		}
	}
}

func (s *Service) setPcap(mut func()) {
	s.pcapMu.Lock()
	mut()
	s.pcapMu.Unlock()
}

func (s *Service) GetPcap(id string) (*Pcap, bool) {
	p := s.snapshotPcap(id)
	return p, p != nil
}

func (s *Service) snapshotPcap(id string) *Pcap {
	s.pcapMu.Lock()
	defer s.pcapMu.Unlock()
	p, ok := s.pcaps[id]
	if !ok {
		return nil
	}
	cp := *p
	return &cp
}

// PcapFile returns the finished capture's path + a download filename.
func (s *Service) PcapFile(id string) (path, name string, ok bool) {
	s.pcapMu.Lock()
	defer s.pcapMu.Unlock()
	p, found := s.pcaps[id]
	if !found || p.Status != "done" {
		return "", "", false
	}
	return p.file, fmt.Sprintf("pcap-%s-%s.pcap", p.IP, short(p.ID)), true
}
