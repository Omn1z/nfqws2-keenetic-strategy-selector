// Package engine runs candidate strategies in isolated sandboxes and measures
// them. Each sandbox owns a dedicated NFQUEUE number, a source-port range, and
// temporary iptables chains scoped so the main nfqws2 service is unaffected.
package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nfqws2strategy/internal/tools/config"
	routerpath "nfqws2strategy/internal/tools/path"
)

const (
	procMark = "0x40000000/0x40000000" // nfqws marks its own generated packets
	exclMark = "0x20000000/0x20000000" // our temporary guards exclude test connections
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

	// ruleExec permits a command-level firewall fake in tests. Production uses
	// iptables directly; no shell or process-wide mutable command hook is used.
	ruleExec      func(...string) ([]byte, error)
	expectedRules [][]string
	guardChains   []string
	queueRead     func() ([]byte, error)
	localAddrs    func() ([]net.Addr, error)
	localIPs      []string

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
func (s *Sandbox) outChain() string  { return fmt.Sprintf("STRAT_OUT_%d", s.Worker) }

func (s *Sandbox) iptOutput(args ...string) ([]byte, error) {
	if s.ruleExec != nil {
		return s.ruleExec(args...)
	}
	return exec.Command("iptables", append([]string{"-w"}, args...)...).CombinedOutput()
}

func (s *Sandbox) ipt(args ...string) error {
	out, err := s.iptOutput(args...)
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Sandbox) iptQuiet(args ...string) {
	_, _ = s.iptOutput(args...)
}

// addRule records the exact rule for later validation. Position is only used
// when installing a jump/guard; iptables -C checks its match and target.
func (s *Sandbox) addRule(chain string, first bool, args ...string) error {
	op := []string{"-t", "mangle", "-A", chain}
	if first {
		op = []string{"-t", "mangle", "-I", chain, "1"}
	}
	if err := s.ipt(append(op, args...)...); err != nil {
		return err
	}
	s.expectedRules = append(s.expectedRules, append([]string{"-t", "mangle", "-C", chain}, args...))
	return nil
}

func (s *Sandbox) mainGuard(chain, originalSource string) []string {
	sport := fmt.Sprintf("%d:%d", s.PortLo, s.PortHi)
	args := []string{"-p", "tcp"}
	if chain == "nfqws_post" {
		args = append(args, "--sport", sport, "--dport", "443")
	} else {
		args = append(args, "--sport", "443", "--dport", sport)
	}
	args = append(args, "-m", "connmark", "--mark", exclMark)
	if originalSource != "" {
		args = append(args, "-m", "conntrack", "--ctorigsrc", originalSource)
	}
	return append(args, "-j", "RETURN")
}

// Main service chains can be absent when it is stopped. Inspect the whole
// table, so a permission/extension/iptables error is never mistaken for absence.
func (s *Sandbox) mainChains() ([]string, error) {
	out, err := s.iptOutput("-t", "mangle", "-S")
	if err != nil {
		return nil, fmt.Errorf("inspect main NFQWS2 firewall: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var chains []string
	for _, name := range []string{"nfqws_post", "nfqws_pre"} {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(line) == "-N "+name {
				chains = append(chains, name)
				break
			}
		}
	}
	return chains, nil
}

// CheckRules detects an external firewall/service restart during a run. A
// result obtained after losing the sandbox or its main-service guards must not
// be accepted as a successful isolated probe. Call before and after probing.
func (s *Sandbox) CheckRules() error {
	if len(s.expectedRules) == 0 {
		return fmt.Errorf("sandbox firewall is not installed")
	}
	localIPs, err := s.localIPv4()
	if err != nil {
		return err
	}
	if strings.Join(localIPs, ",") != strings.Join(s.localIPs, ",") {
		return fmt.Errorf("local IPv4 addresses changed during the test; repeat the test")
	}
	chains, err := s.mainChains()
	if err != nil {
		return err
	}
	if strings.Join(chains, ",") != strings.Join(s.guardChains, ",") {
		return fmt.Errorf("main NFQWS2 firewall changed during the test; repeat the test")
	}
	for _, rule := range s.expectedRules {
		if err := s.ipt(rule...); err != nil {
			return fmt.Errorf("sandbox isolation was lost; repeat the test: %w", err)
		}
	}
	return nil
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

func (s *Sandbox) rulesUp(queue bool) (setupErr error) {
	pc, prc, oc := s.postChain(), s.preChain(), s.outChain()
	sport := fmt.Sprintf("%d:%d", s.PortLo, s.PortHi)
	q := strconv.Itoa(s.QNum)

	s.RulesDown() // clean any leftovers
	defer func() {
		if setupErr != nil {
			s.RulesDown()
		}
	}()
	if len(s.cfg.WANIfaces) == 0 || s.PortLo < 1 || s.PortHi > 65535 || s.PortHi < s.PortLo {
		return fmt.Errorf("invalid sandbox WAN interfaces or source-port range")
	}
	localIPs, err := s.localIPv4()
	if err != nil {
		return err
	}
	s.localIPs = localIPs

	for _, chain := range []string{pc, prc, oc} {
		s.iptQuiet("-t", "mangle", "-N", chain)
		if err := s.ipt("-t", "mangle", "-F", chain); err != nil {
			return err
		}
	}

	// Skip nfqws-generated packets so we never re-queue our own fakes.
	for _, chain := range []string{oc, pc} {
		if err := s.addRule(chain, false, "-m", "mark", "--mark", procMark, "-j", "RETURN"); err != nil {
			return err
		}
	}
	// Only router-local test sockets are marked. Doing this in POSTROUTING also
	// captured forwarded LAN clients that happened to use the same source port.
	if err := s.addRule(oc, false, "-p", "tcp", "--dport", "443", "--sport", sport,
		"-j", "CONNMARK", "--set-xmark", exclMark); err != nil {
		return err
	}
	for _, ifc := range s.cfg.WANIfaces {
		if !queue {
			continue
		}
		for _, source := range localIPs {
			// MARK_EXCLUDE is shared with vendor policy rules. The original
			// conntrack source must also be a router address, even on replies
			// that are still addressed to its WAN IP before reverse NAT.
			if err := s.addRule(pc, false, "-o", ifc, "-p", "tcp", "--dport", "443", "--sport", sport,
				"-m", "connmark", "--mark", exclMark, "-m", "conntrack", "--ctorigsrc", source,
				"-m", "connbytes", "--connbytes", "1:16", "--connbytes-mode", "packets", "--connbytes-dir", "original",
				"-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"); err != nil {
				return err
			}
			if err := s.addRule(prc, false, "-i", ifc, "-p", "tcp", "--sport", "443", "--dport", sport,
				"-m", "connmark", "--mark", exclMark, "-m", "conntrack", "--ctorigsrc", source,
				"-m", "connbytes", "--connbytes", "1:16", "--connbytes-mode", "packets", "--connbytes-dir", "reply",
				"-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"); err != nil {
				return err
			}
		}
	}
	// A connmark alone does not exclude anything: the vendor's chains do not
	// necessarily test MARK_EXCLUDE. Return only from those chains, preserving
	// unrelated mangle/routing rules after their jumps in the built-in chains.
	chains, err := s.mainChains()
	if err != nil {
		return err
	}
	s.guardChains = chains
	for _, chain := range chains {
		for _, source := range localIPs {
			if err := s.addRule(chain, true, s.mainGuard(chain, source)...); err != nil {
				return err
			}
		}
	}
	// Jump in at the top so we run before the main nfqws chains.
	if err := s.addRule("POSTROUTING", true, "-j", pc); err != nil {
		return err
	}
	if err := s.addRule("PREROUTING", true, "-j", prc); err != nil {
		return err
	}
	// Install marking last, after every exclusion/queue path is ready.
	if err := s.addRule("OUTPUT", true, "-j", oc); err != nil {
		return err
	}
	return nil
}

// RulesDown removes the sandbox's chains and jumps. Safe to call repeatedly.
func (s *Sandbox) RulesDown() {
	pc, prc, oc := s.postChain(), s.preChain(), s.outChain()
	s.iptQuiet("-t", "mangle", "-D", "OUTPUT", "-j", oc)
	s.iptQuiet("-t", "mangle", "-D", "POSTROUTING", "-j", pc)
	s.iptQuiet("-t", "mangle", "-D", "PREROUTING", "-j", prc)
	s.removeMainGuards()
	for _, chain := range []string{pc, prc, oc} {
		s.iptQuiet("-t", "mangle", "-F", chain)
		s.iptQuiet("-t", "mangle", "-X", chain)
	}
	s.expectedRules = nil
	s.guardChains = nil
	s.localIPs = nil
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
	if err := s.CheckRules(); err != nil {
		return err
	}
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
	_, err := s.QueuePackets()
	return err == nil
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
	logDir := routerpath.Path(routerpath.StrategyLogDir)
	cmds := []string{
		"logread 2>/dev/null | grep -iE '" + filter + "' | tail -n " + tail,
		"dmesg 2>/dev/null | grep -iE '" + filter + "' | tail -n " + tail,
	}
	if logDir != "" {
		cmds = append(cmds,
			"grep -iE '"+filter+"' "+routerpath.Path(routerpath.StrategyLogDir, "messages")+" 2>/dev/null | tail -n "+tail,
			"grep -iE '"+filter+"' "+routerpath.Path(routerpath.StrategyLogDir, "nfqws2.log")+" 2>/dev/null | tail -n "+tail,
		)
	}
	for _, c := range cmds {
		out, err := exec.CommandContext(ctx, "sh", "-c", c).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return string(out)
		}
	}
	return ""
}
