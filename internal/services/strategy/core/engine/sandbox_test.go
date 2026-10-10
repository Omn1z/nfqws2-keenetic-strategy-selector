package engine

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

// The command fake executes only the small iptables subset used here. Packet
// traversal is independent of the generated rule layout: RETURN resumes the
// caller, whereas NFQUEUE finishes this mangle hook (NF_ACCEPT resumes at the
// next netfilter hook, not the next rule of this iptables table).
type sandboxFirewall struct {
	chains map[string][][]string
	fail   string
}

func newSandboxFirewall(main bool) *sandboxFirewall {
	f := &sandboxFirewall{chains: map[string][][]string{
		"OUTPUT": nil, "POSTROUTING": nil, "PREROUTING": nil,
	}}
	if main {
		f.addMain()
	}
	return f
}

func (f *sandboxFirewall) addMain() {
	f.chains["nfqws_post"] = [][]string{{"-p", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "300"}}
	f.chains["nfqws_pre"] = [][]string{{"-p", "tcp", "--sport", "443", "-j", "NFQUEUE", "--queue-num", "300"}}
	f.chains["POSTROUTING"] = append(f.chains["POSTROUTING"], []string{"-j", "nfqws_post"})
	f.chains["PREROUTING"] = append(f.chains["PREROUTING"], []string{"-j", "nfqws_pre"})
	// Unrelated rules after the vendor chains must still execute for baseline
	// packets; a broad ACCEPT added to the sandbox would break this assertion.
	for _, chain := range []string{"POSTROUTING", "PREROUTING"} {
		f.chains[chain] = append(f.chains[chain], []string{"-j", "MARK", "--set-xmark", "0x100/0x100"})
	}
}

func (f *sandboxFirewall) exec(args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	if f.fail != "" && line == f.fail {
		f.fail = ""
		return []byte("injected firewall failure"), errors.New("exit status 1")
	}
	if len(args) < 3 || args[0] != "-t" || args[1] != "mangle" {
		return nil, fmt.Errorf("unsupported command: %s", line)
	}
	op := args[2]
	if op == "-S" && len(args) == 3 {
		var lines []string
		for chain := range f.chains {
			if chain != "OUTPUT" && chain != "POSTROUTING" && chain != "PREROUTING" {
				lines = append(lines, "-N "+chain)
			}
		}
		sort.Strings(lines)
		return []byte(strings.Join(lines, "\n")), nil
	}
	if len(args) < 4 {
		return nil, fmt.Errorf("missing chain: %s", line)
	}
	chain := args[3]
	rules, exists := f.chains[chain]
	if op == "-N" {
		if exists {
			return nil, errors.New("chain already exists")
		}
		f.chains[chain] = nil
		return nil, nil
	}
	if !exists {
		return nil, errors.New("chain missing")
	}
	switch op {
	case "-S":
		lines := []string{"-N " + chain}
		for _, rule := range rules {
			lines = append(lines, "-A "+chain+" "+strings.Join(rule, " "))
		}
		return []byte(strings.Join(lines, "\n")), nil
	case "-F":
		f.chains[chain] = nil
	case "-X":
		for _, rs := range f.chains {
			for _, r := range rs {
				if ruleValue(r, "-j") == chain {
					return nil, errors.New("chain still referenced")
				}
			}
		}
		if len(rules) != 0 {
			return nil, errors.New("chain not empty")
		}
		delete(f.chains, chain)
	case "-A":
		f.chains[chain] = append(rules, append([]string(nil), args[4:]...))
	case "-I":
		if len(args) < 5 || args[4] != "1" {
			return nil, errors.New("unsupported insertion position")
		}
		f.chains[chain] = append([][]string{append([]string(nil), args[5:]...)}, rules...)
	case "-D", "-C":
		for i, r := range rules {
			if reflect.DeepEqual(r, args[4:]) {
				if op == "-D" {
					f.chains[chain] = append(rules[:i], rules[i+1:]...)
				}
				return nil, nil
			}
		}
		return nil, errors.New("rule missing")
	default:
		return nil, fmt.Errorf("unsupported operation: %s", line)
	}
	return nil, nil
}

func ruleValue(rule []string, key string) string {
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] == key {
			return rule[i+1]
		}
	}
	return ""
}

type sandboxPacket struct {
	in, out        string
	originalSource string // conntrack original tuple, preserved through NAT
	sport, dport   int
	count          int
	mark, connmark uint32
	queues         []int
}

func portInRange(port int, value string) bool {
	parts := strings.Split(value, ":")
	lo, _ := strconv.Atoi(parts[0])
	hi := lo
	if len(parts) > 1 {
		hi, _ = strconv.Atoi(parts[1])
	}
	return port >= lo && port <= hi
}

func parseMark(value string) (uint32, uint32) {
	parts := strings.Split(value, "/")
	v, _ := strconv.ParseUint(parts[0], 0, 32)
	mask := uint64(0xffffffff)
	if len(parts) > 1 {
		mask, _ = strconv.ParseUint(parts[1], 0, 32)
	}
	return uint32(v), uint32(mask)
}

func (f *sandboxFirewall) traverse(chain string, p *sandboxPacket) bool {
rules:
	for _, r := range f.chains[chain] {
		module := ""
		for i := 0; i+1 < len(r); i++ {
			key, value := r[i], r[i+1]
			switch key {
			case "-m":
				module = value
			case "-i":
				if value != p.in {
					continue rules
				}
			case "-o":
				if value != p.out {
					continue rules
				}
			case "--sport":
				if !portInRange(p.sport, value) {
					continue rules
				}
			case "--dport":
				if !portInRange(p.dport, value) {
					continue rules
				}
			case "--connbytes":
				if !portInRange(p.count, value) {
					continue rules
				}
			case "--ctorigsrc":
				originalSource := p.originalSource
				if originalSource == "" {
					originalSource = "10.0.0.2"
				}
				if value != originalSource {
					continue rules
				}
			case "--mark":
				mark := p.mark
				if module == "connmark" {
					mark = p.connmark
				}
				v, mask := parseMark(value)
				if mark&mask != v {
					continue rules
				}
			}
		}
		switch target := ruleValue(r, "-j"); target {
		case "RETURN":
			return false
		case "ACCEPT":
			return true
		case "CONNMARK":
			v, mask := parseMark(ruleValue(r, "--set-xmark"))
			p.connmark = (p.connmark &^ mask) ^ v
		case "MARK":
			v, mask := parseMark(ruleValue(r, "--set-xmark"))
			p.mark = (p.mark &^ mask) ^ v
		case "NFQUEUE":
			q, _ := strconv.Atoi(ruleValue(r, "--queue-num"))
			p.queues = append(p.queues, q)
			return true
		default:
			if f.traverse(target, p) {
				return true
			}
		}
	}
	return false
}

func testSandbox(f *sandboxFirewall, worker int) *Sandbox {
	s := NewSandbox(&config.Config{WANIfaces: []string{"eth3", "eth2.4"}, FirstQueue: 200, PortBase: 50000, PortsPerWorker: 200}, worker)
	s.ruleExec = f.exec
	s.localAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("192.168.3.1"), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	return s
}

func TestSandboxBaselineSkipsMainWithoutSkippingOtherMangleRules(t *testing.T) {
	f := newSandboxFirewall(true)
	s := testSandbox(f, 0)
	if err := s.RulesUpExcludeOnly(); err != nil {
		t.Fatal(err)
	}
	defer s.RulesDown()
	for _, ifc := range []string{"eth3", "eth2.4"} {
		p := sandboxPacket{out: ifc, sport: s.PortLo + 1, dport: 443, count: 1, connmark: 0x1234}
		f.traverse("OUTPUT", &p)
		f.traverse("POSTROUTING", &p)
		if len(p.queues) != 0 || p.mark != 0x100 || p.connmark != 0x20001234 {
			t.Fatalf("baseline went through main or skipped routing rules on %s: %+v", ifc, p)
		}
		reply := sandboxPacket{in: ifc, sport: 443, dport: p.sport, count: 1, connmark: p.connmark}
		f.traverse("PREROUTING", &reply)
		if len(reply.queues) != 0 || reply.mark != 0x100 {
			t.Fatalf("baseline reply went through main or skipped routing rules: %+v", reply)
		}
	}
	if err := s.CheckRules(); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxCandidateDoesNotCaptureForwardedLANClients(t *testing.T) {
	f := newSandboxFirewall(true)
	s := testSandbox(f, 0)
	if err := s.RulesUp(); err != nil {
		t.Fatal(err)
	}
	defer s.RulesDown()
	for _, ifc := range []string{"eth3", "eth2.4"} {
		p := sandboxPacket{out: ifc, sport: s.PortLo + 1, dport: 443, count: 1, originalSource: "192.168.3.42"}
		// Forwarded LAN packets never traverse OUTPUT.
		f.traverse("POSTROUTING", &p)
		if p.connmark != 0 || !reflect.DeepEqual(p.queues, []int{300}) {
			t.Fatalf("forwarded connection captured on %s: %+v", ifc, p)
		}
		reply := sandboxPacket{in: ifc, sport: 443, dport: p.sport, count: 1, originalSource: "192.168.3.42"}
		f.traverse("PREROUTING", &reply)
		if !reflect.DeepEqual(reply.queues, []int{300}) {
			t.Fatalf("forwarded reply captured: %+v", reply)
		}
		p = sandboxPacket{out: ifc, sport: s.PortLo + 2, dport: 443, count: 1}
		f.traverse("OUTPUT", &p)
		f.traverse("POSTROUTING", &p)
		if !reflect.DeepEqual(p.queues, []int{200}) {
			t.Fatalf("local candidate missed its queue: %+v", p)
		}
		reply = sandboxPacket{in: ifc, sport: 443, dport: p.sport, count: 1, connmark: p.connmark}
		f.traverse("PREROUTING", &reply)
		if !reflect.DeepEqual(reply.queues, []int{200}) {
			t.Fatalf("local candidate reply missed its queue: %+v", reply)
		}
		p.queues, p.count = nil, 17
		f.traverse("POSTROUTING", &p)
		if len(p.queues) != 0 || p.mark != 0x100 {
			t.Fatalf("later candidate packet leaked into main or skipped mangle: %+v", p)
		}
	}
}

func TestSandboxWorkersCleanupAndIdempotence(t *testing.T) {
	f := newSandboxFirewall(true)
	original := fmt.Sprint(f.chains)
	a, b := testSandbox(f, 0), testSandbox(f, 1)
	for i := 0; i < 2; i++ {
		if err := a.RulesUp(); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.RulesUp(); err != nil {
		t.Fatal(err)
	}
	a.RulesDown()
	if err := b.CheckRules(); err != nil {
		t.Fatalf("worker cleanup affected another worker: %v", err)
	}
	p := sandboxPacket{out: "eth3", sport: b.PortLo + 1, dport: 443, count: 1}
	f.traverse("OUTPUT", &p)
	f.traverse("POSTROUTING", &p)
	if !reflect.DeepEqual(p.queues, []int{201}) {
		t.Fatalf("wrong worker: %+v", p)
	}
	// A new Sandbox object also repairs stale rules after an unclean exit.
	testSandbox(f, 1).RulesDown()
	b.RulesDown()
	if got := fmt.Sprint(f.chains); got != original {
		t.Fatalf("cleanup changed vendor rules:\ngot %s\nwant %s", got, original)
	}
}

func TestSandboxLeavesOtherLocalSocketsAndGeneratedPacketsAlone(t *testing.T) {
	f := newSandboxFirewall(true)
	s := testSandbox(f, 0)
	if err := s.RulesUp(); err != nil {
		t.Fatal(err)
	}
	defer s.RulesDown()
	for _, port := range []int{s.PortLo - 1, s.PortHi + 1} {
		p := sandboxPacket{out: "eth3", sport: port, dport: 443, count: 1, connmark: 0x1234}
		f.traverse("OUTPUT", &p)
		f.traverse("POSTROUTING", &p)
		if p.connmark != 0x1234 || !reflect.DeepEqual(p.queues, []int{300}) {
			t.Fatalf("unrelated local socket changed: %+v", p)
		}
	}
	p := sandboxPacket{out: "eth3", sport: s.PortLo + 1, dport: 443, count: 1, mark: 0x40000000, connmark: 0x1234}
	f.traverse("OUTPUT", &p)
	f.traverse(s.postChain(), &p)
	if p.connmark != 0x1234 || len(p.queues) != 0 {
		t.Fatalf("nfqws-generated fake was remarked/requeued: %+v", p)
	}
}

func TestSandboxSetupRollsBackPartialFirewall(t *testing.T) {
	for _, command := range []string{
		"-t mangle -A STRAT_OUT_0 -p tcp --dport 443 --sport 50000:50199 -j CONNMARK --set-xmark " + exclMark,
		"-t mangle -A STRAT_POST_0 -o eth3 -p tcp --dport 443 --sport 50000:50199 -m connmark --mark " + exclMark + " -m conntrack --ctorigsrc 10.0.0.2 -m connbytes --connbytes 1:16 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 200 --queue-bypass",
		"-t mangle -S",
		"-t mangle -I nfqws_pre 1 -p tcp --sport 443 --dport 50000:50199 -m connmark --mark " + exclMark + " -m conntrack --ctorigsrc 10.0.0.2 -j RETURN",
		"-t mangle -I PREROUTING 1 -j STRAT_PRE_0",
		"-t mangle -I OUTPUT 1 -j STRAT_OUT_0",
	} {
		t.Run(command, func(t *testing.T) {
			f := newSandboxFirewall(true)
			original := fmt.Sprint(f.chains)
			f.fail = command
			s := testSandbox(f, 0)
			if err := s.RulesUp(); err == nil {
				t.Fatal("setup succeeded despite injected failure")
			}
			if got := fmt.Sprint(f.chains); got != original {
				t.Fatalf("partial rules left behind:\ngot %s\nwant %s", got, original)
			}
			if s.CheckRules() == nil {
				t.Fatal("failed setup still reports valid isolation")
			}
		})
	}
}

func TestSandboxDetectsLostIsolationAndServiceChanges(t *testing.T) {
	for _, change := range []string{"guard", "output_jump", "queue", "new_main", "removed_main"} {
		t.Run(change, func(t *testing.T) {
			f := newSandboxFirewall(change != "new_main")
			s := testSandbox(f, 0)
			if err := s.RulesUp(); err != nil {
				t.Fatal(err)
			}
			if err := s.CheckRules(); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "guard":
				f.chains["nfqws_post"] = f.chains["nfqws_post"][1:]
			case "output_jump":
				f.chains["OUTPUT"] = nil
			case "queue":
				f.chains[s.postChain()] = nil
			case "new_main":
				f.addMain()
			case "removed_main":
				delete(f.chains, "nfqws_pre")
			}
			if s.CheckRules() == nil {
				t.Fatal("external firewall change was not detected")
			}
		})
	}
}

func TestSandboxDoesNotStartEngineWithLostIsolation(t *testing.T) {
	f := newSandboxFirewall(true)
	s := testSandbox(f, 0)
	if err := s.RulesUp(); err != nil {
		t.Fatal(err)
	}
	f.chains["nfqws_post"] = f.chains["nfqws_post"][1:]
	if err := s.StartNfqws(nil, nil); err == nil || !strings.Contains(err.Error(), "isolation was lost") {
		t.Fatalf("engine start did not reject missing guard: %v", err)
	}
}
