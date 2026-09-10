package app

import (
	"os"
	"path/filepath"
	"testing"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

func TestResolvePanelListenAddrSavedPortSurvivesInitArgument(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, panelPortsFile), []byte(`{"panel_port":8095}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, want string }{
		{":8090", ":8095"},
		{"192.168.3.1:8090", "192.168.3.1:8095"},
		{"[::1]:8090", "[::1]:8095"},
	} {
		got, err := ResolvePanelListenAddr(dir, tc.input)
		if err != nil || got != tc.want {
			t.Errorf("ResolvePanelListenAddr(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
}

func TestResolvePanelListenAddrMissingAndInvalid(t *testing.T) {
	dir := t.TempDir()
	if got, err := ResolvePanelListenAddr(dir, ":8090"); err != nil || got != ":8090" {
		t.Fatalf("missing config: %q %v", got, err)
	}
	for _, data := range []string{`{`, `{"panel_port":0}`, `{"panel_port":65536}`} {
		if err := os.WriteFile(filepath.Join(dir, panelPortsFile), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolvePanelListenAddr(dir, ":8090"); err == nil {
			t.Errorf("accepted invalid port config %s", data)
		}
	}
}

type testPanelListener struct{ port string }

func (l *testPanelListener) Address() string                                 { return ":" + l.port }
func (l *testPanelListener) ChangePort(port int, persist func() error) error { return persist() }

func TestPanelPortSettingsUseIndependentFile(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: config.Default(), store: st}
	a.SetPanelListener(&testPanelListener{port: "8090"})
	if err := a.SetPanelPort(8095); err != nil {
		t.Fatal(err)
	}
	if err := a.saveSettings(); err != nil {
		t.Fatal(err)
	}
	var saved panelPortsConfig
	if err := st.Load(panelPortsFile, &saved); err != nil || saved.PanelPort != 8095 {
		t.Fatalf("panel port not persisted separately: %+v %v", saved, err)
	}
	for _, p := range []int{0, -1, 65536} {
		if err := a.SetPanelPort(p); err == nil {
			t.Errorf("accepted invalid panel port %d", p)
		}
	}
}
