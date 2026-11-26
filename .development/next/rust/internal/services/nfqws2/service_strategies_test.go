package nfqws2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

const serviceTestConf = "# original settings\nISP_INTERFACE=\"eth4,eth3\"\nTCP_PORTS=\"80,443\"\nUDP_PORTS=\"443\"\nNFQWS_ARGS=\"--filter-tcp=443 --lua-desync=multisplit:pos=1\"\nNFQWS_ARGS_CUSTOM=\"--filter-tcp=8080 --lua-desync=fake\"\n"

func serviceManagerFixture(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	m := New(&config.Config{Nfqws2Conf: filepath.ToSlash(filepath.Join(root, "nfqws2", "nfqws2.conf")), DataDir: filepath.Join(root, "data")})
	if err := os.MkdirAll(filepath.Dir(m.cfg.Nfqws2Conf), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.cfg.Nfqws2Conf, []byte(serviceTestConf), 0644); err != nil {
		t.Fatal(err)
	}
	return m
}

func testService() []ServiceStrategy {
	return []ServiceStrategy{{ID: "facepunch", Name: "FacePunch", Enabled: true, Groups: []ServiceStrategyGroup{
		{ID: "web", Name: "Web", Kind: "domains", Entries: []string{"facepunch.com"}, Strategy: "--filter-tcp=8443 --lua-desync=multisplit:pos=1 --new --filter-udp=443 --lua-desync=fake:blob=quic_initial"},
		{ID: "game", Name: "Game", Kind: "ips", Entries: []string{"192.0.2.0/24"}, Strategy: "--filter-udp=27015-27050 --lua-desync=fake:blob=0x00000000"},
	}}}
}

func TestServiceStrategiesSaveDisableRestoresGlobalConfig(t *testing.T) {
	m := serviceManagerFixture(t)
	initial, err := m.ServiceStrategies()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := m.PreviewServiceStrategies(testService())
	if err != nil {
		t.Fatal(err)
	}
	if preview.TCPPorts != "80,443,8443" || preview.UDPPorts != "443,27015:27050" || preview.Profiles != 3 {
		t.Fatalf("preview: %+v", preview)
	}
	before, _ := os.ReadFile(m.cfg.Nfqws2Conf)
	if string(before) != serviceTestConf {
		t.Fatal("preview wrote configuration")
	}
	state, err := m.SaveServiceStrategies(testService(), initial.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !state.RestartRequired {
		t.Fatal("save did not require restart")
	}
	saved, _ := os.ReadFile(m.cfg.Nfqws2Conf)
	if !strings.HasPrefix(string(saved), serviceTestConf) || strings.Count(string(saved), "# BEGIN N2S SERVICE STRATEGIES") != 1 {
		t.Fatalf("lost global config: %s", saved)
	}
	if err := m.ServiceStrategiesApplied(state.Revision); err != nil {
		t.Fatal(err)
	}
	state, err = m.ServiceStrategies()
	if err != nil {
		t.Fatal(err)
	}
	if state.RestartRequired {
		t.Fatal("restart status not cleared")
	}
	state.Services[0].Enabled = false
	state, err = m.SaveServiceStrategies(state.Services, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ = os.ReadFile(m.cfg.Nfqws2Conf)
	if string(saved) != serviceTestConf || state.TCPPorts != "80,443" || state.UDPPorts != "443" || state.Profiles != 0 || !state.RestartRequired {
		t.Fatalf("disable did not restore global configuration: %+v\n%s", state, saved)
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(m.cfg.Nfqws2Conf), "lists", "*.list"))
	if len(files) != 2 {
		t.Fatal("lists still used by running process were removed")
	}
}

func TestServiceStrategiesConflictAndInvalidSaveAreReadOnly(t *testing.T) {
	m := serviceManagerFixture(t)
	state, _ := m.ServiceStrategies()
	if _, err := m.SaveServiceStrategies(testService(), ""); !errors.Is(err, ErrServiceStrategiesChanged) {
		t.Fatalf("missing revision: %v", err)
	}
	invalid := testService()
	invalid[0].Groups[0].Entries = nil
	if _, err := m.SaveServiceStrategies(invalid, state.Revision); err == nil {
		t.Fatal("empty active domain group accepted")
	}
	data, _ := os.ReadFile(m.cfg.Nfqws2Conf)
	if string(data) != serviceTestConf {
		t.Fatal("invalid save changed conf")
	}
	if _, err := os.Stat(filepath.Join(m.cfg.DataDir, "nfqws2-service-strategies.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid save wrote state")
	}
	if err := os.WriteFile(m.cfg.Nfqws2Conf, append(data, []byte("# another editor\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveServiceStrategies(testService(), state.Revision); !errors.Is(err, ErrServiceStrategiesChanged) {
		t.Fatalf("stale revision: %v", err)
	}
}

func TestServiceStrategiesImmutableListsAndConcurrentRestart(t *testing.T) {
	m := serviceManagerFixture(t)
	state, _ := m.ServiceStrategies()
	state, err := m.SaveServiceStrategies(testService(), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	oldRevision := state.Revision
	oldFiles, _ := filepath.Glob(filepath.Join(filepath.Dir(m.cfg.Nfqws2Conf), "lists", "*.list"))
	state.Services[0].Groups[0].Entries = []string{"example.org"}
	state, err = m.SaveServiceStrategies(state.Services, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ServiceStrategiesApplied(oldRevision); err != nil {
		t.Fatal(err)
	}
	state, _ = m.ServiceStrategies()
	if !state.RestartRequired {
		t.Fatal("concurrent save incorrectly marked applied")
	}
	for _, name := range oldFiles {
		data, err := os.ReadFile(name)
		if err != nil || strings.Contains(string(data), "example.org") {
			t.Fatal("old live list was replaced")
		}
	}
	for _, name := range oldFiles {
		base := filepath.Base(name)
		if err := m.Save("list", base, ""); !errors.Is(err, errManagedServiceList) {
			t.Fatalf("managed list overwritten: %v", err)
		}
		if err := m.Delete("list", base); err == nil {
			t.Fatal("managed list removed")
		}
		if err := m.SaveAsset("lists/"+base, []byte("example.net\n"), true); !errors.Is(err, errManagedServiceList) {
			t.Fatalf("managed asset overwritten: %v", err)
		}
		if err := m.DeleteAsset("lists/" + base); !errors.Is(err, errManagedServiceList) {
			t.Fatalf("managed asset removed: %v", err)
		}
	}
}

func TestServiceStrategiesRefreshPortsAfterBaseConfigEdit(t *testing.T) {
	m := serviceManagerFixture(t)
	state, _ := m.ServiceStrategies()
	state, err := m.SaveServiceStrategies(testService(), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ServiceStrategiesApplied(state.Revision); err != nil {
		t.Fatal(err)
	}
	source, _ := os.ReadFile(m.cfg.Nfqws2Conf)
	source = []byte(strings.Replace(string(source), `TCP_PORTS="80,443"`, `TCP_PORTS="443,9443"`, 1))
	if err := m.Save("conf", "nfqws2.conf", string(source)); err != nil {
		t.Fatal(err)
	}
	state, err = m.ServiceStrategies()
	if err != nil {
		t.Fatal(err)
	}
	if !state.RestartRequired || state.TCPPorts != "443,8443,9443" {
		t.Fatalf("base port edit missed: %+v", state)
	}
	if err := m.PrepareServiceStrategies(); err != nil {
		t.Fatal(err)
	}
	source, _ = os.ReadFile(m.cfg.Nfqws2Conf)
	if !strings.Contains(string(source), "TCP_PORTS='443,8443,9443'") {
		t.Fatalf("stale generated override: %s", source)
	}
}

func TestServiceStrategiesShellPreservesCustomProfiles(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		shell = "C:/Program Files/Git/bin/bash.exe"
		if _, err = os.Stat(shell); err != nil {
			t.Skip("POSIX shell unavailable")
		}
	}
	for _, custom := range []string{"", "--filter-tcp=8080 --lua-desync=fake"} {
		source := strings.Replace(serviceTestConf, `NFQWS_ARGS_CUSTOM="--filter-tcp=8080 --lua-desync=fake"`, `NFQWS_ARGS_CUSTOM="`+custom+`"`, 1)
		_, output, _, _, err := compileServiceConfig(source, testService(), "/opt/etc/nfqws2/lists")
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(t.TempDir(), "test.conf")
		if err := os.WriteFile(name, []byte(output), 0600); err != nil {
			t.Fatal(err)
		}
		data, err := exec.Command(shell, "-c", `. "$1"; printf '%s\n%s\n%s' "$TCP_PORTS" "$UDP_PORTS" "$NFQWS_ARGS_CUSTOM"`, "service-test", filepath.ToSlash(name)).CombinedOutput()
		if err != nil {
			t.Fatalf("source generated config: %v: %s", err, data)
		}
		value := string(data)
		if !strings.HasPrefix(value, "80,443,8443\n443,27015:27050\n--hostlist=") || strings.Contains(value, "--new --new") || strings.HasSuffix(value, "--new") {
			t.Fatalf("incorrect shell profiles: %s", data)
		}
		if custom != "" && !strings.HasSuffix(value, " --new "+custom) {
			t.Fatal("existing custom profiles not preserved")
		}
	}
}
