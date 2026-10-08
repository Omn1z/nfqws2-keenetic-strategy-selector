package nfqws2

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/tools/shell"
)

const keeneticUltraWANConfig = `# Keenetic Ultra with three WAN interfaces.
ISP_INTERFACE="eth4,eth3,eth2.4"
IPV6_ENABLED=1
TCP_PORTS=80,443
NFQWS_ARGS="
--filter-tcp=80,443
--filter-udp=443,50000-50100
"
`

func normalizedKeeneticUltraWANConfig() string {
	return strings.Replace(keeneticUltraWANConfig, "eth4,eth3,eth2.4", "eth4 eth3 eth2.4", 1)
}

func writeWANConfig(t *testing.T, m *Manager, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m.cfg.Nfqws2Conf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.cfg.Nfqws2Conf, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareWANInterfacesPreservesConfigAndPermissions(t *testing.T) {
	m := archiveTestManager(t)
	writeWANConfig(t, m, keeneticUltraWANConfig)
	before, err := os.Stat(m.cfg.Nfqws2Conf)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := m.PrepareWANInterfaces()
	if err != nil || !changed {
		t.Fatalf("prepare comma-separated WAN interfaces: changed=%v, err=%v", changed, err)
	}
	if got := string(readTestAsset(t, m, "nfqws2.conf")); got != normalizedKeeneticUltraWANConfig() {
		t.Fatalf("WAN normalization changed unrelated port lists or multiline arguments:\n%s", got)
	}
	after, err := os.Stat(m.cfg.Nfqws2Conf)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("config permissions changed: %o -> %o", before.Mode().Perm(), after.Mode().Perm())
	}

	// A repeat preparation must not replace an already normalized live config.
	stamp := time.Unix(1234567890, 0)
	if err := os.Chtimes(m.cfg.Nfqws2Conf, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	changed, err = m.PrepareWANInterfaces()
	if err != nil || changed {
		t.Fatalf("prepare already normalized config: changed=%v, err=%v", changed, err)
	}
	after, err = os.Stat(m.cfg.Nfqws2Conf)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(stamp) {
		t.Fatal("already normalized config was rewritten")
	}
}

func TestPrepareWANInterfacesMissingConfigIsNoop(t *testing.T) {
	m := archiveTestManager(t)
	changed, err := m.PrepareWANInterfaces()
	if err != nil || changed {
		t.Fatalf("missing config: changed=%v, err=%v", changed, err)
	}
	if _, err := os.Stat(m.cfg.Nfqws2Conf); !os.IsNotExist(err) {
		t.Fatalf("preparation created missing config: %v", err)
	}
}

func TestPrepareWANInterfacesRejectsInvalidConfigWithoutWriting(t *testing.T) {
	m := archiveTestManager(t)
	invalid := strings.Replace(keeneticUltraWANConfig, "eth4,eth3,eth2.4", "eth4,"+strings.Repeat("x", 16), 1)
	writeWANConfig(t, m, invalid)
	stamp := time.Unix(1234567890, 0)
	if err := os.Chtimes(m.cfg.Nfqws2Conf, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	changed, err := m.PrepareWANInterfaces()
	if err == nil || changed {
		t.Fatalf("invalid interface accepted: changed=%v, err=%v", changed, err)
	}
	if got := string(readTestAsset(t, m, "nfqws2.conf")); got != invalid {
		t.Fatalf("invalid config was partially normalized: %q", got)
	}
	info, err := os.Stat(m.cfg.Nfqws2Conf)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stamp) {
		t.Fatal("invalid config was rewritten")
	}
}

func TestWANInterfacesNormalizedOnConfigWrites(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(*testing.T, *Manager, []byte) error
	}{
		{"editor", func(_ *testing.T, m *Manager, data []byte) error {
			return m.Save("conf", "nfqws2.conf", string(data))
		}},
		{"asset", func(_ *testing.T, m *Manager, data []byte) error {
			return m.SaveAsset("nfqws2.conf", data, true)
		}},
		{"upload", func(_ *testing.T, m *Manager, data []byte) error {
			return m.Upload("conf", "nfqws2.conf", data)
		}},
		{"gzip upload", func(t *testing.T, m *Manager, data []byte) error {
			var compressed bytes.Buffer
			writer := gzip.NewWriter(&compressed)
			if _, err := writer.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			return m.Upload("conf", "nfqws2.conf.gz", compressed.Bytes())
		}},
		{"archive", func(t *testing.T, m *Manager, data []byte) error {
			archive := testZIP(t, map[string][]byte{"nfqws2.conf": data})
			preview, err := m.StrategyPreview(archive, "")
			if err != nil {
				return err
			}
			_, err = m.StrategyImport(archive, "", ArchiveImportOptions{Digest: preview.Digest, Overwrite: true, Lists: "replace"})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := archiveTestManager(t)
			if err := tc.write(t, m, []byte(keeneticUltraWANConfig)); err != nil {
				t.Fatal(err)
			}
			want := normalizedKeeneticUltraWANConfig()
			if got := string(readTestAsset(t, m, "nfqws2.conf")); got != want {
				t.Fatalf("saved config was not normalized or unrelated port lists changed:\n%s", got)
			}
			invalid := []byte("ISP_INTERFACE=\"eth4," + strings.Repeat("x", 16) + "\"\n")
			if err := tc.write(t, m, invalid); err == nil {
				t.Fatal("accepted an overlong interface name")
			}
			if got := string(readTestAsset(t, m, "nfqws2.conf")); got != want {
				t.Fatalf("invalid input replaced the previous config: %q", got)
			}
		})
	}
}

func TestPreparedWANInterfacesApplyBypassForBothFamilies(t *testing.T) {
	m := archiveTestManager(t)
	writeWANConfig(t, m, keeneticUltraWANConfig)
	dir := filepath.Dir(m.cfg.Nfqws2Conf)
	initPath := filepath.Join(dir, "mock-init.sh")
	bypassPath := filepath.Join(dir, "mock-bypass.sh")
	// These mocks never invoke iptables or any other firewall utility. The init
	// reproduces the vendor's whitespace-only loop and rejects a comma token.
	initScript := `#!/bin/sh
set -eu
. "$WAN_TEST_CONFIG"
for iface in $ISP_INTERFACE; do
  case "$iface" in *,*) printf 'invalid interface: %s\n' "$iface" >&2; exit 2 ;; esac
  [ "${#iface}" -lt 16 ] || exit 2
  printf '%s %s\n' "$1" "$iface"
done
`
	bypassScript := "#!/bin/sh\nprintf 'bypass %s\\n' \"$1\"\n"
	for name, content := range map[string]string{initPath: initScript, bypassPath: bypassScript} {
		if err := os.WriteFile(name, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	command := nfqws2BypassApplyCommand(filepath.ToSlash(initPath), filepath.ToSlash(bypassPath))
	sh := bypassTestShell(t)
	run := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, sh, "-c", "WAN_TEST_CONFIG="+shell.Quote(filepath.ToSlash(m.cfg.Nfqws2Conf))+"; export WAN_TEST_CONFIG; "+command)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(); err == nil || !strings.Contains(out, "invalid interface: eth4,eth3,eth2.4") || strings.Contains(out, "bypass ") {
		t.Fatalf("mock did not reproduce comma-interface failure: err=%v, output=%q", err, out)
	}
	if changed, err := m.PrepareWANInterfaces(); err != nil || !changed {
		t.Fatalf("prepare WAN interfaces: changed=%v, err=%v", changed, err)
	}
	want := "firewall_iptables eth4\nfirewall_iptables eth3\nfirewall_iptables eth2.4\n" +
		"firewall_ip6tables eth4\nfirewall_ip6tables eth3\nfirewall_ip6tables eth2.4\n" +
		"bypass iptables\nbypass ip6tables\n"
	if out, err := run(); err != nil || out != want {
		t.Fatalf("bypass did not initialize three WAN interfaces in both families: err=%v, output=%q", err, out)
	}
}

func TestRestoreBypassRepairsWANInterfacesBeforeReusingFreshCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable shell shim")
	}
	m := archiveTestManager(t)
	writeWANConfig(t, m, keeneticUltraWANConfig)
	dir := filepath.Dir(m.cfg.Nfqws2Conf)
	binDir := filepath.Join(dir, "bin")
	listDir := filepath.Join(dir, "lists")
	for _, path := range []string{binDir, listDir} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m.cfg.Nfqws2Init = filepath.Join(dir, "mock-init.sh")
	helper := filepath.Join(dir, "nfqws-strategy-bypass.sh")
	fixture := filepath.Join(dir, "mock-helper.sh")
	calls := filepath.Join(dir, "calls")
	// Keep the post-start anchor inside an unused function so installing the
	// restart hook does not also apply it during a firewall_* invocation.
	const initScript = `#!/bin/sh
set -eu
start_service() {
  system_config
}
case "$1" in firewall_iptables|firewall_ip6tables) ;; *) exit 97 ;; esac
. "$WAN_TEST_CONFIG"
for iface in $ISP_INTERFACE; do
  case "$iface" in *,*) exit 2 ;; esac
  printf '%s %s\n' "$1" "$iface" >> "$WAN_TEST_CALLS"
done
`
	// RestoreBypass regenerates its helper before invoking sh. Replace it at
	// that process boundary, retaining the owned marker so the next restore
	// exercises regeneration again. Only the command ordering is under test;
	// the real generated firewall transaction has its own isolated mock tests.
	const shellShim = `#!/bin/sh
set -eu
case "$2" in
  *"$WAN_TEST_HELPER"*)
    cmp "$WAN_TEST_GENERATED" "$WAN_TEST_HELPER" || exit 98
    cat "$WAN_TEST_FIXTURE" > "$WAN_TEST_HELPER"
    ;;
esac
exec /bin/sh "$@"
`
	const helperFixture = "#!/bin/sh\n# Generated by nfqws2-strategy. Test fixture.\nprintf 'bypass %s\\n' \"$1\" >> \"$WAN_TEST_CALLS\"\n"
	generated := filepath.Join(dir, "expected-generated.sh")
	files := map[string]string{
		m.cfg.Nfqws2Init:             initScript,
		filepath.Join(binDir, "sh"):  shellShim,
		fixture:                      helperFixture,
		generated:                    generatedBypassScript,
		filepath.Join(binDir, "uci"): "#!/bin/sh\nexit 0\n",
	}
	// Even if fixture substitution regresses, no kernel firewall utility may
	// escape to the host. An OpenWrt host's uci is also replaced above.
	for _, name := range []string{"iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "ipset", "nft"} {
		files[filepath.Join(binDir, name)] = "#!/bin/sh\nprintf 'unexpected firewall command\\n' >> \"$WAN_TEST_CALLS\"\nexit 99\n"
	}
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	domains := filepath.Join(listDir, "nfqueue_bypass_domains.list")
	cache := filepath.Join(listDir, "nfqueue_bypass_resolved.list")
	const cachedIPs = "198.51.100.20\n2001:db8::20\n"
	for name, content := range map[string]string{domains: "cached.example.invalid\n", cache: cachedIPs} {
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Unix(1234567890, 0)
	if err := os.Chtimes(domains, stamp.Add(-time.Hour), stamp.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cache, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WAN_TEST_CONFIG", m.cfg.Nfqws2Conf)
	t.Setenv("WAN_TEST_CALLS", calls)
	t.Setenv("WAN_TEST_HELPER", helper)
	t.Setenv("WAN_TEST_FIXTURE", fixture)
	t.Setenv("WAN_TEST_GENERATED", generated)
	wantFirst := "firewall_iptables eth4\nfirewall_iptables eth3\nfirewall_iptables eth2.4\n" +
		"firewall_ip6tables eth4\nfirewall_ip6tables eth3\nfirewall_ip6tables eth2.4\n" +
		"bypass iptables\nbypass ip6tables\n"
	for attempt, want := range []string{wantFirst, "bypass iptables\nbypass ip6tables\n"} {
		if err := os.WriteFile(calls, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := m.RestoreBypass(); err != nil {
			t.Fatalf("restore %d: %v", attempt+1, err)
		}
		got, err := os.ReadFile(calls)
		if err != nil || string(got) != want {
			t.Fatalf("restore %d calls: got %q, want %q, err=%v", attempt+1, got, want, err)
		}
		if got := string(readTestAsset(t, m, "nfqws2.conf")); got != normalizedKeeneticUltraWANConfig() {
			t.Fatalf("restore %d left invalid WAN interfaces: %q", attempt+1, got)
		}
		info, err := os.Stat(cache)
		if err != nil || !info.ModTime().Equal(stamp) {
			t.Fatalf("restore %d rewrote fresh DNS cache: %v", attempt+1, err)
		}
		if got, err := os.ReadFile(cache); err != nil || string(got) != cachedIPs {
			t.Fatalf("restore %d changed cached addresses: %q, %v", attempt+1, got, err)
		}
	}
}
