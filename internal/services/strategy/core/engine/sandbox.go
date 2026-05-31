// Package engine runs candidate strategies in isolated sandboxes and measures
// them. Each sandbox owns a dedicated NFQUEUE number, a source-port range, and
// temporary iptables chains scoped so the main nfqws2 service is unaffected.
package engine

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nfqws2strategy/internal/tools/config"
)

const (
	procMark = "0x40000000/0x40000000" // nfqws marks its own generated packets
	exclMark = "0x20000000/0x20000000" // main nfqws chains RETURN on this connmark
)

// Sandbox is one isolated test slot (one worker).
type Sandbox struct {
	cfg    *config.Config
	Worker int
	QNum   int
	PortLo int
	PortHi int
	wrDir  string

	mu  sync.Mutex
	cmd *exec.Cmd
	log strings.Builder
}

func NewSandbox(cfg *config.Config, worker int) *Sandbox {
	lo := cfg.PortBase + worker*cfg.PortsPerWorker
	return &Sandbox{
		cfg:    cfg,
		Worker: worker,
		QNum:   cfg.FirstQueue + worker,
		PortLo: lo,
		PortHi: lo + cfg.PortsPerWorker - 1,
		wrDir:  fmt.Sprintf("/tmp/nfqws2-strategy/w%d", worker),
	}
}

func (s *Sandbox) postChain() string { return fmt.Sprintf("STRAT_POST_%d", s.Worker) }
func (s *Sandbox) preChain() string  { return fmt.Sprintf("STRAT_PRE_%d", s.Worker) }

func ipt(args ...string) error {
	out, err := exec.Command("iptables", append([]string{"-w"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func iptQuiet(args ...string) {
	_ = exec.Command("iptables", append([]string{"-w"}, args...)...).Run()
}

// RulesUp installs the sandbox's iptables chains and jumps so the test
// connection is excluded from the main nfqws service and queued to this
// sandbox's nfqws. Idempotent-ish: it flushes existing chains first.
func (s *Sandbox) RulesUp() error { return s.rulesUp(true) }

// RulesUpExcludeOnly installs chains that only mark the test connection as
// excluded from the main nfqws service WITHOUT queuing it anywhere, i.e. the
// connection gets no desync at all. This yields a true baseline ("is the host
// blocked with no bypass?") even while the main nfqws service is running.
func (s *Sandbox) RulesUpExcludeOnly() error { return s.rulesUp(false) }

func (s *Sandbox) rulesUp(queue bool) error {
	pc, prc := s.postChain(), s.preChain()
	sport := fmt.Sprintf("%d:%d", s.PortLo, s.PortHi)
	q := strconv.Itoa(s.QNum)

	s.RulesDown() // clean any leftovers

	iptQuiet("-t", "mangle", "-N", pc)
	if err := ipt("-t", "mangle", "-F", pc); err != nil {
		return err
	}
	iptQuiet("-t", "mangle", "-N", prc)
	if err := ipt("-t", "mangle", "-F", prc); err != nil {
		return err
	}

	// Skip nfqws-generated packets so we never re-queue our own fakes.
	if err := ipt("-t", "mangle", "-A", pc, "-m", "mark", "--mark", procMark, "-j", "RETURN"); err != nil {
		return err
	}
	for _, ifc := range s.cfg.WANIfaces {
		// Mark test connections excluded from the main nfqws service.
		if err := ipt("-t", "mangle", "-A", pc, "-o", ifc, "-p", "tcp", "--dport", "443", "--sport", sport,
			"-j", "CONNMARK", "--set-xmark", exclMark); err != nil {
			return err
		}
		if !queue {
			continue
		}
		// Queue first outgoing packets of the test connection to our nfqws.
		if err := ipt("-t", "mangle", "-A", pc, "-o", ifc, "-p", "tcp", "--dport", "443", "--sport", sport,
			"-m", "connbytes", "--connbytes", "1:16", "--connbytes-mode", "packets", "--connbytes-dir", "original",
			"-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"); err != nil {
			return err
		}
		// Queue first reply packets.
		if err := ipt("-t", "mangle", "-A", prc, "-i", ifc, "-p", "tcp", "--sport", "443", "--dport", sport,
			"-m", "connbytes", "--connbytes", "1:16", "--connbytes-mode", "packets", "--connbytes-dir", "reply",
			"-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"); err != nil {
			return err
		}
	}
	// Jump in at the top so we run before the main nfqws chains.
	if err := ipt("-t", "mangle", "-I", "POSTROUTING", "1", "-j", pc); err != nil {
		return err
	}
	if err := ipt("-t", "mangle", "-I", "PREROUTING", "1", "-j", prc); err != nil {
		return err
	}
	return nil
}

// RulesDown removes the sandbox's chains and jumps. Safe to call repeatedly.
func (s *Sandbox) RulesDown() {
	pc, prc := s.postChain(), s.preChain()
	iptQuiet("-t", "mangle", "-D", "POSTROUTING", "-j", pc)
	iptQuiet("-t", "mangle", "-D", "PREROUTING", "-j", prc)
	iptQuiet("-t", "mangle", "-F", pc)
	iptQuiet("-t", "mangle", "-X", pc)
	iptQuiet("-t", "mangle", "-F", prc)
	iptQuiet("-t", "mangle", "-X", prc)
}

// StartNfqws launches a dedicated nfqws2 child bound to this sandbox's queue,
// loaded with the shared base args, any extra args (e.g. run-selected blobs),
// then the strategy args. It returns once the queue is bound or after a timeout.
func (s *Sandbox) StartNfqws(extraArgs, strategyArgs []string) error {
	s.StopNfqws()
	if err := os.MkdirAll(s.wrDir, 0o755); err != nil {
		return err
	}
	args := []string{fmt.Sprintf("--qnum=%d", s.QNum), "--writeable=" + s.wrDir}
	args = append(args, s.cfg.BaseArgs...)
	args = append(args, extraArgs...)
	args = append(args, strategyArgs...)

	cmd := exec.Command(s.cfg.NfqwsBin, args...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		return err
	}
	pw.Close() // parent's copy; child keeps its dup

	s.mu.Lock()
	s.cmd = cmd
	s.log.Reset()
	s.mu.Unlock()

	var once sync.Once
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			s.mu.Lock()
			s.log.WriteString(line)
			s.log.WriteByte('\n')
			s.mu.Unlock()
			if strings.Contains(line, "setting copy_packet mode") {
				once.Do(func() { close(ready) })
			}
		}
		pr.Close()
	}()

	select {
	case <-ready:
		return nil
	case <-time.After(10 * time.Second):
		s.StopNfqws()
		return fmt.Errorf("nfqws start timeout; log:\n%s", s.Log())
	}
}

// StopNfqws terminates the sandbox's nfqws2 child.
func (s *Sandbox) StopNfqws() {
	s.mu.Lock()
	cmd := s.cmd
	s.cmd = nil
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
	}
}

// Log returns the captured nfqws2 output so far.
func (s *Sandbox) Log() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log.String()
}
