// Package engine runs candidate strategies in isolated sandboxes and measures
// them. Each sandbox owns a dedicated NFQUEUE number, a source-port range, and
// temporary iptables chains scoped so the main nfqws2 service is unaffected.
package engine

import (
	"context"
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
	noExit   = -2                      // s.lastExit sentinel: process has not exited yet
)

// Sandbox is one isolated test slot (one worker).
type Sandbox struct {
	cfg    *config.Config
	Worker int
	QNum   int
	PortLo int
	PortHi int
	wrDir  string

	mu       sync.Mutex
	cmd      *exec.Cmd
	done     chan struct{} // closed when cmd exits; owned by the single Wait goroutine
	logPath  string        // file the engine's stdout/stderr is captured to (race-free vs a pipe)
	lastArgs []string      // full argv (binary + args) of the most recent launch, for diagnostics
	lastExit int           // exit code of the most recent launch; noExit while running, -1 if signalled
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
// then the strategy args. It returns once the queue is actually bound in the
// kernel, or after a timeout.
//
// Readiness is detected by watching /proc/net/netfilter/nfnetlink_queue for our
// queue number rather than by parsing the child's log: the engine's startup
// output varies by version and may be block-buffered down the pipe (so nothing
// flushes for seconds), which previously produced spurious "nfqws start timeout"
// with an empty log even though the engine was running. The child's output is
// still captured for diagnostics, and an early exit (e.g. bad args) is reported
// immediately instead of waiting out the full timeout.
func (s *Sandbox) StartNfqws(extraArgs, strategyArgs []string) error {
	s.StopNfqws()
	if err := os.MkdirAll(s.wrDir, 0o755); err != nil {
		return err
	}
	args := []string{fmt.Sprintf("--qnum=%d", s.QNum), "--writable=" + s.wrDir}
	args = append(args, s.cfg.BaseArgs...)
	args = append(args, extraArgs...)
	args = append(args, strategyArgs...)
	// The sandbox engine must run in the foreground so we own its lifetime and can
	// read its output; a --daemon in the base args would fork and the launched PID
	// would exit immediately (false "exited before binding").
	args = stripDaemon(args)

	// Capture stdout/stderr to a file rather than a pipe: a fast-exiting child
	// (e.g. an arg error) can leave its message unread in a pipe when we look,
	// whereas the file holds it regardless of timing.
	logPath := s.wrDir + "/launch.log"
	lf, err := os.Create(logPath)
	if err != nil {
		return err
	}

	cmd := exec.Command(s.cfg.NfqwsBin, args...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return err
	}
	lf.Close() // the child inherited its own fd

	done := make(chan struct{})
	s.mu.Lock()
	s.cmd = cmd
	s.done = done
	s.logPath = logPath
	s.lastArgs = append([]string{s.cfg.NfqwsBin}, args...)
	s.lastExit = noExit
	s.mu.Unlock()

	// Single owner of cmd.Wait: records the exit code and signals both the
	// readiness loop and Stop.
	go func() {
		st, _ := cmd.Process.Wait()
		s.mu.Lock()
		if st != nil {
			s.lastExit = st.ExitCode()
		}
		s.mu.Unlock()
		close(done)
	}()

	deadline := time.Now().Add(10 * time.Second)
	exited := false
	doneCh := done
	for {
		if s.queueBound() {
			return nil
		}
		select {
		case <-doneCh:
			// The process is gone. If it exited cleanly the engine may have
			// double-forked despite stripDaemon, so keep polling for the queue
			// until the deadline; a non-zero exit is a real failure, report it now.
			if s.queueBound() {
				return nil
			}
			if code := s.exitCode(); code != 0 {
				return fmt.Errorf("nfqws exited (code %d) before binding queue %d", code, s.QNum)
			}
			exited = true
			doneCh = nil
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			s.StopNfqws()
			if exited {
				return fmt.Errorf("nfqws exited before binding queue %d", s.QNum)
			}
			return fmt.Errorf("nfqws start timeout (queue %d not bound)", s.QNum)
		}
	}
}

// stripDaemon removes daemonize flags so the sandbox engine stays in the
// foreground under our control.
func stripDaemon(args []string) []string {
	out := args[:0:0]
	for _, a := range args {
		if a == "--daemon" || a == "-D" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// exitCode returns the recorded exit code of the most recent launch (noExit if
// it is still running, -1 if it was terminated by a signal).
func (s *Sandbox) exitCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastExit
}

// queueBound reports whether this sandbox's NFQUEUE number is currently bound by
// a listener in the kernel (i.e. the child nfqws2 has created and configured it).
func (s *Sandbox) queueBound() bool {
	b, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return false
	}
	want := strconv.Itoa(s.QNum)
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == want {
			return true
		}
	}
	return false
}

// StopNfqws terminates the sandbox's nfqws2 child.
func (s *Sandbox) StopNfqws() {
	s.mu.Lock()
	cmd := s.cmd
	done := s.done
	s.cmd = nil
	s.done = nil
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	if done == nil { // no Wait goroutine (shouldn't happen); reap directly
		_, _ = cmd.Process.Wait()
		return
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

// Log returns the engine's captured stdout/stderr from the most recent launch.
func (s *Sandbox) Log() string {
	s.mu.Lock()
	p := s.logPath
	s.mu.Unlock()
	if p == "" {
		return ""
	}
	b, _ := os.ReadFile(p)
	return string(b)
}

// Diagnostics returns a human-readable report of the most recent launch for the
// UI: the exact command line, the exit code, the engine's own stdout/stderr (if
// any -- nfqws2 usually logs to syslog instead), and a tail of the system log
// filtered for nfqws. It is meant to be called right after StartNfqws fails.
func (s *Sandbox) Diagnostics() string {
	s.mu.Lock()
	args := s.lastArgs
	exit := s.lastExit
	s.mu.Unlock()
	out := s.Log()

	var b strings.Builder
	if len(args) > 0 {
		fmt.Fprintf(&b, "$ %s\n", strings.Join(args, " "))
	}
	switch exit {
	case noExit:
		b.WriteString("статус: процесс ещё жив (очередь не привязалась)\n")
	case -1:
		b.WriteString("статус: завершён сигналом\n")
	default:
		fmt.Fprintf(&b, "код выхода: %d\n", exit)
	}
	if strings.TrimSpace(out) != "" {
		b.WriteString("\nstdout/stderr движка:\n")
		b.WriteString(out)
		if !strings.HasSuffix(out, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("stdout/stderr движка: пусто (nfqws2 пишет в syslog)\n")
	}
	if sl := syslogTail("nfqws", 30); sl != "" {
		b.WriteString("\nsyslog (последние строки про nfqws):\n")
		b.WriteString(sl)
	} else {
		b.WriteString("\nsyslog: строк про nfqws не найдено (logread недоступен?)\n")
	}
	return b.String()
}

// syslogTail returns up to n recent system-log lines matching filter. It tries
// busybox `logread` (Keenetic/Entware) first, then common message files. Best
// effort: any failure yields "".
func syslogTail(filter string, n int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tail := strconv.Itoa(n)
	cmds := []string{
		"logread 2>/dev/null | grep -iE '" + filter + "' | tail -n " + tail,
		"dmesg 2>/dev/null | grep -iE '" + filter + "' | tail -n " + tail,
		"grep -iE '" + filter + "' /var/log/messages 2>/dev/null | tail -n " + tail,
		"grep -iE '" + filter + "' /opt/var/log/messages 2>/dev/null | tail -n " + tail,
		"grep -iE '" + filter + "' /opt/var/log/nfqws2.log 2>/dev/null | tail -n " + tail,
	}
	for _, c := range cmds {
		out, err := exec.CommandContext(ctx, "sh", "-c", c).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return string(out)
		}
	}
	return ""
}
