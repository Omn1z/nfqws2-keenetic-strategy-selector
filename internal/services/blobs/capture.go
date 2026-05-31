package blobs

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/store"
	"nfqws2strategy/internal/tools/tcpdump"
	"nfqws2strategy/internal/tools/tlsblob"
)

const maxStoredBlobCaps = 5

// BlobCapture is a short tcpdump capture of a device's TLS traffic, parsed into
// the ClientHello(s) it sent — candidates the user can save as a fake-payload
// blob. Reuses the shared tcpdump plumbing (tcpdump.Path / tcpdump.ErrNeedInstall).
type BlobCapture struct {
	ID         string              `json:"id"`
	IP         string              `json:"ip"`
	Iface      string              `json:"iface"`
	Seconds    int                 `json:"seconds"`
	Status     string              `json:"status"` // running | done | error
	Error      string              `json:"error,omitempty"`
	StartedAt  int64               `json:"started_at"`
	ElapsedMs  int64               `json:"elapsed_ms"`
	Candidates []tlsblob.Candidate `json:"candidates"` // Candidate.Bytes is json:"-" (held server-side)
	file       string
}

// StartBlobCapture sniffs a device's TLS (:443) traffic for `seconds` and
// extracts every ClientHello it sends. Returns tcpdump.ErrNeedInstall when
// tcpdump is missing so the UI can offer to install it (same flow as pcap capture).
func (s *Service) StartBlobCapture(ip string, seconds int) (*BlobCapture, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("неверный IP")
	}
	if tcpdump.Path() == "" {
		return nil, tcpdump.ErrNeedInstall
	}
	if seconds <= 0 || seconds > 120 {
		seconds = 20
	}
	dir := "/tmp/nfqws2-strategy"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	id := store.NewID()
	c := &BlobCapture{ID: id, IP: ip, Iface: tcpdump.DeviceIface(ip), Seconds: seconds, Status: "running", StartedAt: time.Now().Unix(), Candidates: []tlsblob.Candidate{}, file: filepath.Join(dir, "blobcap-"+id+".pcap")}
	s.capMu.Lock()
	s.caps[id] = c
	s.capOrder = append(s.capOrder, id)
	for len(s.capOrder) > maxStoredBlobCaps {
		old := s.capOrder[0]
		if oc := s.caps[old]; oc != nil {
			_ = os.Remove(oc.file)
		}
		delete(s.caps, old)
		s.capOrder = s.capOrder[1:]
	}
	s.capMu.Unlock()
	go s.runBlobCapture(c)
	return s.snapshotBlobCap(id), nil
}

func (s *Service) runBlobCapture(c *BlobCapture) {
	bin := tcpdump.Path()
	logbuf.Append("blobcap", "info", fmt.Sprintf("blobcap %s: захват ClientHello %s на %s, %dс", short(c.ID), c.IP, c.Iface, c.Seconds))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Seconds+3)*time.Second)
	defer cancel()
	// -G N -W 1 autostops after N seconds and writes a single file.
	cmd := exec.CommandContext(ctx, bin, "-i", c.Iface, "-n", "-w", c.file, "-G", strconv.Itoa(c.Seconds), "-W", "1", "host", c.IP, "and", "tcp", "port", "443")
	start := time.Now()
	out, _ := cmd.CombinedOutput() // rely on the written file, not the exit code
	if s := strings.TrimSpace(string(out)); s != "" {
		logbuf.Append("blobcap", "info", "blobcap tcpdump: "+s)
	}

	// A missing or <24-byte file means tcpdump matched no packets (no TLS from the
	// device in the window) — that's a clean "0 caught", not an error.
	data, _ := os.ReadFile(c.file)
	if len(data) < 24 {
		s.setBlobCap(func() {
			c.Candidates = []tlsblob.Candidate{}
			c.ElapsedMs = time.Since(start).Milliseconds()
			c.Status = "done"
		})
		logbuf.Append("blobcap", "info", fmt.Sprintf("blobcap %s: готово — 0 ClientHello (нет трафика)", short(c.ID)))
		return
	}
	cands, perr := tlsblob.ParsePcapClientHellos(data)
	if perr != nil {
		s.setBlobCap(func() { c.Status = "error"; c.Error = perr.Error() })
		return
	}
	s.setBlobCap(func() {
		c.Candidates = cands
		c.ElapsedMs = time.Since(start).Milliseconds()
		c.Status = "done"
	})
	logbuf.Append("blobcap", "info", fmt.Sprintf("blobcap %s: готово — %d ClientHello", short(c.ID), len(cands)))
}

func (s *Service) setBlobCap(mut func()) {
	s.capMu.Lock()
	mut()
	s.capMu.Unlock()
}

func (s *Service) GetBlobCapture(id string) (*BlobCapture, bool) {
	c := s.snapshotBlobCap(id)
	return c, c != nil
}

func (s *Service) snapshotBlobCap(id string) *BlobCapture {
	s.capMu.Lock()
	defer s.capMu.Unlock()
	c, ok := s.caps[id]
	if !ok {
		return nil
	}
	cp := *c
	// make (not []T(nil)) so an empty list marshals as [] not null — a null here
	// crashes the frontend's cap.candidates access (see the v0.7.0 trace bug).
	cp.Candidates = append(make([]tlsblob.Candidate, 0, len(c.Candidates)), c.Candidates...)
	return &cp
}

// SaveCapturedBlob stores the chosen captured ClientHello as a custom blob.
func (s *Service) SaveCapturedBlob(id string, index int, name string) (string, error) {
	s.capMu.Lock()
	c, ok := s.caps[id]
	if !ok || index < 0 || index >= len(c.Candidates) {
		s.capMu.Unlock()
		return "", fmt.Errorf("ClientHello не найден")
	}
	data := append([]byte(nil), c.Candidates[index].Bytes...)
	s.capMu.Unlock()
	if len(data) == 0 {
		return "", fmt.Errorf("пустой ClientHello")
	}
	return s.SaveBlob(name, data)
}

// ValidateBlob reads a blob (custom or system) and reports whether it is a
// structurally valid TLS ClientHello usable as a fake payload.
func (s *Service) ValidateBlob(name string) (bool, string, error) {
	_, path, ok := s.ResolveBlob(name)
	if !ok {
		return false, "", fmt.Errorf("блоб не найден")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, "", err
	}
	valid, detail := tlsblob.ValidateClientHello(b)
	return valid, detail, nil
}

// GenerateBlob builds a TLS ClientHello for the chosen domain and saves it as a
// custom blob. alpn/minVer are optional knobs (see tlsblob.GenerateClientHello).
func (s *Service) GenerateBlob(sni string, alpn []string, minVer uint16, name string) (string, error) {
	data, err := tlsblob.GenerateClientHello(sni, alpn, minVer)
	if err != nil {
		return "", err
	}
	return s.SaveBlob(name, data)
}

// short truncates an id for log lines.
func short(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}
