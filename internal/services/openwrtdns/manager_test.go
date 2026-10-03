package openwrtdns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type fakeUCI struct {
	configs    map[string][]section
	durable    map[string][]section
	deltas     map[string][]string
	calls      []string
	generation int
	fail       func(string) bool
	afterWrite func()
}

func scalar(value string) option   { return option{Kind: "option", Values: []string{value}} }
func list(values ...string) option { return option{Kind: "list", Values: values} }
func cloneSections(in []section) []section {
	out := make([]section, len(in))
	for i, s := range in {
		out[i] = s
		out[i].Options = map[string]option{}
		for k, v := range s.Options {
			v.Values = append([]string(nil), v.Values...)
			out[i].Options[k] = v
		}
	}
	return out
}
func newFixture(t *testing.T) (*Manager, *fakeUCI) {
	t.Helper()
	f := &fakeUCI{configs: map[string][]section{
		"network": {
			{ID: "loopback", Type: "interface", Options: map[string]option{"proto": scalar("static")}},
			{ID: "lan", Type: "interface", Options: map[string]option{"proto": scalar("static"), "device": scalar("br-lan"), "ipaddr": scalar("192.168.1.1")}},
			{ID: "wan", Type: "interface", Options: map[string]option{"proto": scalar("dhcp"), "device": scalar("eth1"), "dns": list("9.9.9.9", "149.112.112.112")}},
		},
		"dhcp": {
			{ID: "@dnsmasq[0]", Type: "dnsmasq", Options: map[string]option{"domainneeded": scalar("1"), "server": list("8.8.8.8", "/corp.example/192.168.4.1", "/lan/", "/#/9.9.9.9"), "interface": list("lan", "guest"), "cachesize": scalar("1000")}},
			{ID: "lan", Type: "dhcp", Options: map[string]option{"interface": scalar("lan"), "start": scalar("100"), "limit": scalar("150")}},
		},
	}, durable: map[string][]section{}, deltas: map[string][]string{}, generation: 1}
	for pkg, s := range f.configs {
		f.durable[pkg] = cloneSections(s)
	}
	m := &Manager{filename: filepath.Join(t.TempDir(), snapshotName), supported: true, run: f.run}
	return m, f
}
func (f *fakeUCI) actualID(id string) string {
	if strings.HasPrefix(id, "@dnsmasq[") {
		return fmt.Sprintf("cfg%02d%s", f.generation, strings.TrimSuffix(strings.TrimPrefix(id, "@dnsmasq["), "]"))
	}
	return id
}
func (f *fakeUCI) find(pkg, id string) *section {
	for i := range f.configs[pkg] {
		s := &f.configs[pkg][i]
		if s.ID == id || f.actualID(s.ID) == id {
			return s
		}
	}
	return nil
}
func (f *fakeUCI) export(pkg string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "package %s\n", pkg)
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	for _, s := range f.configs[pkg] {
		fmt.Fprintf(&out, "\nconfig %s", s.Type)
		if !strings.HasPrefix(s.ID, "@") {
			fmt.Fprintf(&out, " %s", quote(s.ID))
		}
		out.WriteByte('\n')
		keys := []string{}
		for key := range s.Options {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			v := s.Options[key]
			for _, value := range v.Values {
				fmt.Fprintf(&out, "\t%s %s %s\n", v.Kind, key, quote(value))
			}
		}
	}
	return out.String()
}
func (f *fakeUCI) run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.fail != nil && f.fail(call) {
		return "", errors.New("injected failure")
	}
	if name == "ubus" {
		if strings.Join(args, " ") == "call network.interface dump" {
			return `{"interface":[{"interface":"wan","up":true,"l3_device":"eth1","route":[{"target":"0.0.0.0","mask":0}]}]}`, nil
		}
		if strings.Join(args, " ") == "call network reload" {
			return "{}", nil
		}
	}
	if name == "/etc/init.d/dnsmasq" {
		if len(args) != 2 || args[0] != "reload" || f.find("dhcp", args[1]) == nil {
			return "", fmt.Errorf("invalid reload instance %v", args)
		}
		return "", nil
	}
	if name != "uci" {
		return "", fmt.Errorf("unexpected command %s", call)
	}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	if len(args) != i+2 {
		return "", fmt.Errorf("unexpected uci args %v", args)
	}
	op, target := args[i], args[i+1]
	switch op {
	case "export":
		return f.export(target), nil
	case "changes":
		return strings.Join(f.deltas[target], "\n"), nil
	case "commit":
		f.durable[target] = cloneSections(f.configs[target])
		f.deltas[target] = nil
		if target == "dhcp" {
			f.generation++
		}
		return "", nil
	case "show":
		parts := strings.Split(target, ".")
		if len(parts) != 2 {
			return "", fmt.Errorf("bad show")
		}
		s := f.find(parts[0], parts[1])
		if s == nil {
			return "", fmt.Errorf("section missing")
		}
		return parts[0] + "." + f.actualID(s.ID) + "=" + s.Type + "\n", nil
	case "delete", "set", "add_list":
		key, value, _ := strings.Cut(target, "=")
		parts := strings.Split(key, ".")
		if len(parts) != 3 {
			return "", fmt.Errorf("bad key %s", key)
		}
		s := f.find(parts[0], parts[1])
		if s == nil {
			return "", fmt.Errorf("missing section %s", parts[1])
		}
		deltaKey := parts[0] + "." + f.actualID(s.ID) + "." + parts[2]
		switch op {
		case "delete":
			if _, ok := s.Options[parts[2]]; !ok {
				return "", fmt.Errorf("missing option")
			}
			delete(s.Options, parts[2])
			f.deltas[parts[0]] = append(f.deltas[parts[0]], "-"+deltaKey)
		case "set":
			s.Options[parts[2]] = scalar(value)
			f.deltas[parts[0]] = append(f.deltas[parts[0]], deltaKey+"='"+value+"'")
		case "add_list":
			v := s.Options[parts[2]]
			v.Kind = "list"
			v.Values = append(v.Values, value)
			s.Options[parts[2]] = v
			f.deltas[parts[0]] = append(f.deltas[parts[0]], deltaKey+"+='"+value+"'")
		}
		if f.afterWrite != nil {
			f.afterWrite()
		}
		return "", nil
	}
	return "", fmt.Errorf("unexpected command %s", call)
}
func (f *fakeUCI) writes() int {
	n := 0
	for _, c := range f.calls {
		for _, x := range []string{"uci -q delete ", "uci -q set ", "uci -q add_list ", "uci -q commit ", "ubus call network reload", "/etc/init.d/dnsmasq reload"} {
			if strings.HasPrefix(c, x) {
				n++
			}
		}
	}
	return n
}
func revision(t *testing.T, m *Manager) string {
	t.Helper()
	s, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s.Revision
}
func applyFixture(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Apply(context.Background(), "wan", "@dnsmasq[0]", Endpoint{"192.168.1.1", 5356}, revision(t, m)); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRestoreAnonymousInstanceAndExactOptions(t *testing.T) {
	m, f := newFixture(t)
	originalNetwork, originalDHCP := cloneSections(f.configs["network"]), cloneSections(f.configs["dhcp"])
	s, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Interfaces[0].ID != "wan" || !s.Interfaces[0].Default || s.Instances[0].ID != "@dnsmasq[0]" || len(s.Instances[0].Networks) != 2 {
		t.Fatalf("bad choices %+v", s)
	}
	applyFixture(t, m)
	wantServer := list("192.168.1.1#5356", "/corp.example/192.168.4.1", "/lan/")
	if got := f.find("dhcp", "@dnsmasq[0]").Options["server"]; !reflect.DeepEqual(got, wantServer) {
		t.Fatalf("server=%+v", got)
	}
	if got := f.find("network", "wan").Options["dns"]; !reflect.DeepEqual(got, list("192.168.1.1")) {
		t.Fatalf("dns=%+v", got)
	}
	if f.find("network", "wan").scalar("peerdns") != "0" || f.find("dhcp", "@dnsmasq[0]").scalar("noresolv") != "1" {
		t.Fatal("loop prevention missing")
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "/etc/init.d/dnsmasq reload cfg020") {
		t.Fatalf("reload did not use new anonymous ID: %v", f.calls)
	}
	b, err := m.CurrentBinding()
	if err != nil || b == nil || b.Endpoint.Port != 5356 {
		t.Fatalf("binding %+v %v", b, err)
	}
	if err = m.Restore(context.Background(), revision(t, m)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.configs["network"], originalNetwork) || !reflect.DeepEqual(f.configs["dhcp"], originalDHCP) {
		t.Fatalf("original UCI types/options not restored: %+v", f.configs)
	}
	if !reflect.DeepEqual(f.configs, f.durable) {
		t.Fatal("rollback not committed")
	}
	if _, err = os.Stat(m.filename); !os.IsNotExist(err) {
		t.Fatalf("snapshot remains: %v", err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "ifdown") || strings.Contains(call, "ifup") || strings.Contains(call, " restart") {
			t.Fatalf("WAN restart: %s", call)
		}
	}
}

func TestReapplyPreservesOriginalAndNoopDoesNotReload(t *testing.T) {
	m, f := newFixture(t)
	original := cloneSections(f.configs["dhcp"])
	applyFixture(t, m)
	n := f.writes()
	applyFixture(t, m)
	if f.writes() != n {
		t.Fatal("unchanged binding reloaded")
	}
	if err := m.Apply(context.Background(), "wan", "@dnsmasq[0]", Endpoint{"192.168.1.2", 5300}, revision(t, m)); err != nil {
		t.Fatal(err)
	}
	if got := f.find("dhcp", "@dnsmasq[0]").Options["server"].Values[0]; got != "192.168.1.2#5300" {
		t.Fatal(got)
	}
	if err := m.Restore(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.configs["dhcp"], original) {
		t.Fatal("reapply replaced original snapshot")
	}
}

func TestApplyRefusesUnsafeStateBeforeWrites(t *testing.T) {
	for _, test := range []string{"revision", "pending", "endpoint53", "wildcard", "loopback", "badID", "missing", "disabled", "ambiguous", "oversized"} {
		t.Run(test, func(t *testing.T) {
			m, f := newFixture(t)
			rev := revision(t, m)
			iface, instance, e := "wan", "@dnsmasq[0]", Endpoint{"192.168.1.1", 5356}
			switch test {
			case "revision":
				rev = "old"
			case "pending":
				f.deltas["network"] = []string{"network.wan.metric='10'"}
			case "endpoint53":
				e.Port = 53
			case "wildcard":
				e.Host = "0.0.0.0"
			case "loopback":
				e.Host = "127.0.0.1"
			case "badID":
				instance = "@dnsmasq[0];reboot"
			case "missing":
				iface = "absent"
			case "disabled":
				f.find("dhcp", instance).Options["port"] = scalar("0")
				rev = revision(t, m)
			case "ambiguous":
				s := cloneSections(f.configs["dhcp"][:1])[0]
				s.ID = "@dnsmasq[1]"
				f.configs["dhcp"] = append(f.configs["dhcp"], s)
				rev = revision(t, m)
			case "oversized":
				values := make([]string, 257)
				for i := range values {
					values[i] = fmt.Sprintf("/d%d.test/8.8.8.8", i)
				}
				f.find("dhcp", instance).Options["server"] = list(values...)
				rev = revision(t, m)
			}
			if err := m.Apply(context.Background(), iface, instance, e, rev); err == nil {
				t.Fatal("accepted unsafe state")
			}
			if f.writes() != 0 {
				t.Fatalf("mutated UCI: %v", f.calls)
			}
			if _, err := os.Stat(m.filename); !os.IsNotExist(err) {
				t.Fatal("invalid snapshot saved")
			}
		})
	}
}

func TestApplyFailuresRollbackEveryMutationPhase(t *testing.T) {
	for _, failAt := range []string{"uci -q set dhcp.", "uci -q delete dhcp.", "uci -q add_list dhcp.@dnsmasq[0].server=/corp.example/192.168.4.1", "uci -q set network.wan.peerdns=0", "uci -q commit network", "uci -q commit dhcp", "ubus call network reload", "/etc/init.d/dnsmasq reload"} {
		t.Run(failAt, func(t *testing.T) {
			m, f := newFixture(t)
			before := map[string][]section{"network": cloneSections(f.configs["network"]), "dhcp": cloneSections(f.configs["dhcp"])}
			failed := false
			f.fail = func(call string) bool {
				if !failed && strings.HasPrefix(call, failAt) {
					failed = true
					return true
				}
				return false
			}
			if err := m.Apply(context.Background(), "wan", "@dnsmasq[0]", Endpoint{"192.168.1.1", 5356}, revision(t, m)); err == nil {
				t.Fatal("failure hidden")
			}
			if !failed {
				t.Fatal("failure point not visited")
			}
			if !reflect.DeepEqual(f.configs, before) || !reflect.DeepEqual(f.durable, before) {
				t.Fatalf("rollback failed: %+v", f.configs)
			}
			if b, err := m.CurrentBinding(); b != nil || err != nil {
				t.Fatalf("snapshot remained %+v %v", b, err)
			}
		})
	}
}

func TestRestoreFailureRetainsManagedState(t *testing.T) {
	m, f := newFixture(t)
	applyFixture(t, m)
	applied := cloneSections(f.configs["dhcp"])
	failed := false
	f.fail = func(c string) bool {
		if !failed && c == "ubus call network reload" {
			failed = true
			return true
		}
		return false
	}
	if err := m.Restore(context.Background(), ""); err == nil {
		t.Fatal("failure hidden")
	}
	if !reflect.DeepEqual(applied, f.configs["dhcp"]) {
		t.Fatal("failed restore changed active binding")
	}
	s, err := m.readSnapshot()
	if err != nil || s == nil || s.Pending {
		t.Fatalf("backup %+v %v", s, err)
	}
}

func TestPendingOwnPartialListCanRecoverAfterRestart(t *testing.T) {
	m, f := newFixture(t)
	original := cloneSections(f.configs["dhcp"])
	// Fail after the first new list entry, then prevent rollback's read. This
	// models the process disappearing with its own staged UCI changes present.
	failed := false
	f.fail = func(c string) bool {
		if strings.HasPrefix(c, "uci -q add_list dhcp.@dnsmasq[0].server=/corp.example/") {
			failed = true
			return true
		}
		return failed && c == "uci -q -N export network"
	}
	if err := m.Apply(context.Background(), "wan", "@dnsmasq[0]", Endpoint{"192.168.1.1", 5356}, revision(t, m)); err == nil {
		t.Fatal("failure hidden")
	}
	f.fail = nil
	s, err := m.readSnapshot()
	if err != nil || s == nil || !s.Pending {
		t.Fatalf("missing recovery snapshot %+v %v", s, err)
	}
	state, err := m.Status(context.Background())
	if err != nil || !state.Pending || state.Conflict != "" {
		t.Fatalf("recovery action hidden %+v %v", state, err)
	}
	if err = m.Restore(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.configs["dhcp"], original) {
		t.Fatal("interrupted partial list not restored")
	}
}

func TestPostCommitReadbackDetectsConcurrentOwnedEdit(t *testing.T) {
	m, f := newFixture(t)
	base := m.run
	changed := false
	m.run = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := base(ctx, name, args...)
		if !changed && name == "/etc/init.d/dnsmasq" {
			changed = true
			f.find("network", "wan").Options["dns"] = list("4.4.4.4")
		}
		return out, err
	}
	if err := m.Apply(context.Background(), "wan", "@dnsmasq[0]", Endpoint{"192.168.1.1", 5356}, revision(t, m)); err == nil {
		t.Fatal("false success after concurrent owned edit")
	}
	if f.find("network", "wan").Options["dns"].Values[0] != "4.4.4.4" {
		t.Fatal("rollback overwrote concurrent edit")
	}
	s, err := m.readSnapshot()
	if err != nil || s == nil || !s.Pending {
		t.Fatalf("recovery backup %+v %v", s, err)
	}
}

func TestForeignChangeDuringTransactionIsNeverCommitted(t *testing.T) {
	m, f := newFixture(t)
	injected := false
	f.afterWrite = func() {
		if injected {
			return
		}
		injected = true
		f.find("network", "wan").Options["metric"] = scalar("42")
		f.deltas["network"] = append(f.deltas["network"], "network.wan.metric='42'")
	}
	if err := m.Apply(context.Background(), "wan", "@dnsmasq[0]", Endpoint{"192.168.1.1", 5356}, revision(t, m)); err == nil {
		t.Fatal("foreign edit accepted")
	}
	for _, c := range f.calls {
		if strings.Contains(c, " commit ") {
			t.Fatalf("committed foreign edit: %s", c)
		}
	}
	if err := m.Restore(context.Background(), ""); err == nil {
		t.Fatal("restore committed foreign pending edit")
	}
	if f.find("network", "wan").scalar("metric") != "42" {
		t.Fatal("foreign edit overwritten")
	}
}

func TestRestoreConflictPreservesUserChanges(t *testing.T) {
	for _, change := range []string{"owned", "anonymousIdentity", "unrelated"} {
		t.Run(change, func(t *testing.T) {
			m, f := newFixture(t)
			applyFixture(t, m)
			f.calls = nil
			switch change {
			case "owned":
				f.find("network", "wan").Options["dns"] = list("4.4.4.4")
			case "anonymousIdentity":
				f.find("dhcp", "@dnsmasq[0]").Options["interface"] = list("private")
			case "unrelated":
				f.find("network", "wan").Options["metric"] = scalar("10")
			}
			err := m.Restore(context.Background(), "")
			if change == "unrelated" {
				if err != nil {
					t.Fatal(err)
				}
				if f.find("network", "wan").scalar("metric") != "10" {
					t.Fatal("unrelated setting lost")
				}
			} else {
				if err == nil || f.writes() != 0 {
					t.Fatalf("conflict overwritten: %v", err)
				}
			}
		})
	}
}

func TestUnmanagedAndUnsupportedNeverInvokeUCI(t *testing.T) {
	m, f := newFixture(t)
	if err := m.Restore(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal("unmanaged restore accessed UCI")
	}
	m.supported = false
	if err := os.WriteFile(m.filename, []byte("broken foreign backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := m.CurrentBinding(); b != nil || err != nil {
		t.Fatalf("unsupported read %+v %v", b, err)
	}
	s, err := m.Status(context.Background())
	if err != nil || s.Supported {
		t.Fatalf("unsupported status %+v %v", s, err)
	}
	if len(f.calls) != 0 {
		t.Fatal("unsupported invoked tools")
	}
}

func TestMalformedSnapshotCannotWriteArbitraryUCI(t *testing.T) {
	m, f := newFixture(t)
	applyFixture(t, m)
	s, err := m.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	delete(s.Original, "network.wan.dns")
	s.Original["system.system.hostname"] = scalar("bad")
	if err = m.writeSnapshot(s); err == nil {
		t.Fatal("saved unrelated snapshot option")
	}
	f.calls = nil
	if err = os.WriteFile(m.filename, []byte(`{"version":1,"binding":{"interface":"wan","instance":"@dnsmasq[0]","endpoint":{"host":"192.168.1.1","port":53}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = m.Restore(context.Background(), ""); err == nil {
		t.Fatal("accepted malformed snapshot")
	}
	if len(f.calls) != 0 {
		t.Fatal("read UCI before validating snapshot")
	}
}
