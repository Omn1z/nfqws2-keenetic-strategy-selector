package path

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestEntwareLayout(t *testing.T) {
	root := t.TempDir()
	r := NewAt(root)
	if r.Platform() != PlatformEntware {
		t.Fatalf("platform = %v, want Entware", r.Platform())
	}
	checks := map[Key]string{
		DataDir:         filepath.Join(root, "opt", "etc", "nfqws2-strategy"),
		Nfqws2Conf:      filepath.Join(root, "opt", "etc", "nfqws2", "nfqws2.conf"),
		Nfqws2Bin:       filepath.Join(root, "opt", "usr", "bin", "nfqws2"),
		Nfqws2Init:      filepath.Join(root, "opt", "etc", "init.d", "S51nfqws2"),
		StrategyBin:     filepath.Join(root, "opt", "usr", "bin", "n2s"),
		StrategyInit:    filepath.Join(root, "opt", "etc", "init.d", "S52nfqws2-strategy"),
		AWGEngineDir:    filepath.Join(root, "opt", "usr", "bin"),
		AWGConfigDir:    filepath.Join(root, "opt", "etc", "amnezia", "amneziawg"),
		AWGHook:         filepath.Join(root, "opt", "etc", "ndm", "netfilter.d", "90-awg2.sh"),
		PortForwardHook: filepath.Join(root, "opt", "etc", "ndm", "netfilter.d", "91-n2s-port-forward.sh"),
	}
	for key, want := range checks {
		if got := r.Path(key); got != want {
			t.Errorf("Path(%q) = %q, want %q", key, got, want)
		}
	}
	if got := r.Path(Nfqws2ListsDir, "user.list"); got != filepath.Join(root, "opt", "etc", "nfqws2", "lists", "user.list") {
		t.Fatalf("joined list path = %q", got)
	}
}

func TestOpenWrtNativeLayout(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "etc"))
	mustWrite(t, filepath.Join(root, "etc", "openwrt_release"))
	r := NewAt(root)
	if !r.IsOpenWrt() {
		t.Fatal("OpenWrt marker was not detected")
	}
	if got := r.Path(Nfqws2Conf); got != filepath.Join(root, "etc", "nfqws2", "nfqws2.conf") {
		t.Fatalf("conf path = %q", got)
	}
	if got := r.Path(AWGHook); got != filepath.Join(root, "etc", "nfqws2-strategy", "90-awg2.sh") {
		t.Fatalf("AWG hook = %q", got)
	}
	if got := r.Path(AWGLegacyWatchdog); got != "" {
		t.Fatalf("OpenWrt legacy watchdog = %q, want empty", got)
	}
	if got := r.Path(NFQWSBypassFW4); got != filepath.Join(root, "etc", "nfqws2", "nfqws-bypass-fw4.sh") {
		t.Fatalf("bypass fw4 path = %q", got)
	}
}

func TestOpenWrtKeepsExistingOptAWGAssets(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "etc"))
	mustWrite(t, filepath.Join(root, "etc", "rc.common"))
	mustWrite(t, filepath.Join(root, "opt", "usr", "bin", "amneziawg-go"))
	mustMkdir(t, filepath.Join(root, "opt", "etc", "amnezia", "amneziawg"))
	r := NewAt(root)
	if got := r.Path(AWGEngineDir); got != filepath.Join(root, "opt", "usr", "bin") {
		t.Fatalf("legacy AWG engine dir = %q", got)
	}
	if got := r.Path(AWGConfigDir); got != filepath.Join(root, "opt", "etc", "amnezia", "amneziawg") {
		t.Fatalf("legacy AWG config dir = %q", got)
	}
}

func TestResolverIsCachedAndUnknownIsEmpty(t *testing.T) {
	root := t.TempDir()
	r := NewAt(root)
	first := r.Path(DataDir)
	if first == "" || r.Path(Key("does_not_exist")) != "" {
		t.Fatalf("unexpected resolver values: %q / %q", first, r.Path(Key("does_not_exist")))
	}
	// NewAt performs the filesystem probes once. Creating an OpenWrt marker after
	// construction must not mutate the already-selected platform or paths.
	mustMkdir(t, filepath.Join(root, "etc"))
	if err := os.WriteFile(filepath.Join(root, "etc", "openwrt_release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if r.Path(DataDir) != first {
		t.Fatal("resolver changed after construction")
	}
}

func TestResolverConcurrentLookup(t *testing.T) {
	r := NewAt(t.TempDir())
	want := r.Path(Nfqws2ListsDir, "domains.list")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if got := r.Path(Nfqws2ListsDir, "domains.list"); got != want {
					t.Errorf("concurrent lookup = %q, want %q", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, file string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(file))
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
