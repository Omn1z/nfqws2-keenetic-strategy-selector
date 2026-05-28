package app

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

	"nfqws2strategy/internal/logbuf"
	"nfqws2strategy/internal/store"
	"nfqws2strategy/internal/tlsblob"
)

const maxStoredBlobCaps = 5

// BlobCapture is a short tcpdump capture of a device's TLS traffic, parsed into
// the ClientHello(s) it sent — candidates the user can save as a fake-payload
// blob. Reuses the v0.8.0 tcpdump plumbing (tcpdumpPath / ErrNeedTcpdump).
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
// extracts every ClientHello it sends. Returns ErrNeedTcpdump when tcpdump is
// missing so the UI can offer to install it (same flow as pcap capture).
func (a *App) StartBlobCapture(ip string, seconds int) (*BlobCapture, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("неверный IP")
	}
	if tcpdumpPath() == "" {
		return nil, ErrNeedTcpdump
	}
	if seconds <= 0 || seconds > 120 {
		seconds = 20
	}
	dir := "/tmp/nfqws2-strategy"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	id := store.NewID()
	c := &BlobCapture{ID: id, IP: ip, Iface: deviceIface(ip), Seconds: seconds, Status: "running", StartedAt: time.Now().Unix(), Candidates: []tlsblob.Candidate{}, file: filepath.Join(dir, "blobcap-"+id+".pcap")}
	a.blobCapMu.Lock()
	a.blobCaps[id] = c
	a.blobCapOrder = append(a.blobCapOrder, id)
	for len(a.blobCapOrder) > maxStoredBlobCaps {
		old := a.blobCapOrder[0]
		if oc := a.blobCaps[old]; oc != nil {
			_ = os.Remove(oc.file)
		}
		delete(a.blobCaps, old)
		a.blobCapOrder = a.blobCapOrder[1:]
	}
	a.blobCapMu.Unlock()
	go a.runBlobCapture(c)
	return a.snapshotBlobCap(id), nil
}

func (a *App) runBlobCapture(c *BlobCapture) {
	bin := tcpdumpPath()
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
		a.setBlobCap(func() {
			c.Candidates = []tlsblob.Candidate{}
			c.ElapsedMs = time.Since(start).Milliseconds()
			c.Status = "done"
		})
		logbuf.Append("blobcap", "info", fmt.Sprintf("blobcap %s: готово — 0 ClientHello (нет трафика)", short(c.ID)))
		return
	}
	cands, perr := tlsblob.ParsePcapClientHellos(data)
	if perr != nil {
		a.setBlobCap(func() { c.Status = "error"; c.Error = perr.Error() })
		return
	}
	a.setBlobCap(func() {
		c.Candidates = cands
		c.ElapsedMs = time.Since(start).Milliseconds()
		c.Status = "done"
	})
	logbuf.Append("blobcap", "info", fmt.Sprintf("blobcap %s: готово — %d ClientHello", short(c.ID), len(cands)))
}

func (a *App) setBlobCap(mut func()) {
	a.blobCapMu.Lock()
	mut()
	a.blobCapMu.Unlock()
}

func (a *App) GetBlobCapture(id string) (*BlobCapture, bool) {
	c := a.snapshotBlobCap(id)
	return c, c != nil
}

func (a *App) snapshotBlobCap(id string) *BlobCapture {
	a.blobCapMu.Lock()
	defer a.blobCapMu.Unlock()
	c, ok := a.blobCaps[id]
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
func (a *App) SaveCapturedBlob(id string, index int, name string) (string, error) {
	a.blobCapMu.Lock()
	c, ok := a.blobCaps[id]
	if !ok || index < 0 || index >= len(c.Candidates) {
		a.blobCapMu.Unlock()
		return "", fmt.Errorf("ClientHello не найден")
	}
	data := append([]byte(nil), c.Candidates[index].Bytes...)
	a.blobCapMu.Unlock()
	if len(data) == 0 {
		return "", fmt.Errorf("пустой ClientHello")
	}
	return a.SaveBlob(name, data)
}

// ValidateBlob reads a blob (custom or system) and reports whether it is a
// structurally valid TLS ClientHello usable as a fake payload.
func (a *App) ValidateBlob(name string) (bool, string, error) {
	_, path, ok := a.resolveBlob(name)
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
func (a *App) GenerateBlob(sni string, alpn []string, minVer uint16, name string) (string, error) {
	data, err := tlsblob.GenerateClientHello(sni, alpn, minVer)
	if err != nil {
		return "", err
	}
	return a.SaveBlob(name, data)
}
