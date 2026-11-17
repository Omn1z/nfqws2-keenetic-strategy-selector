package nfqws2

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

func TestTransportEndpointManifestNormalizesAndScopesUDP(t *testing.T) {
	got := transportEndpointManifest([]string{
		"[2001:db8::1]:443", "192.0.2.1:51820", "[::ffff:192.0.2.1]:51820",
		"192.0.2.1:443", "vpn.example:443", "192.0.2.1:0", "0.0.0.0:443",
		"[fe80::1%eth0]:443", "192.0.2.1:443\n-j DROP", "[ff02::1]:443",
	})
	if want := "192.0.2.1 443\n192.0.2.1 51820\n2001:db8::1 443\n"; got != want {
		t.Fatalf("manifest = %q; want %q", got, want)
	}
}

func TestTransportRefreshDefersOnlyWhenBothNFQUEUEParentsAreAbsent(t *testing.T) {
	const mock = `
iptables() {
  case "$MODE" in
    read-failure) return 1 ;;
    neither) : ;;
    post-only) printf '%s\n' '-N nfqws_post' ;;
    pre-only) printf '%s\n' '-N nfqws_pre' ;;
    both|helper-failure|disabled-v6|v6-read-failure|v6-lock-absent) printf '%s\n' '-N nfqws_post' '-N nfqws_pre' ;;
  esac
}

ip6tables() { case "$MODE" in disabled-v6|v6-read-failure) return 1 ;; v6-lock-absent) return 4 ;; esac; }
grep() { case "$MODE" in disabled-v6|v6-lock-absent) return 1 ;; esac; }
transport_helper() { printf 'helper called\n'; [ "$MODE" != helper-failure ]; }
`
	for _, mode := range []string{"neither", "post-only", "pre-only", "read-failure", "both", "helper-failure", "disabled-v6", "v6-read-failure", "v6-lock-absent"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(bypassTestShell(t), "-c", mock+transportBypassRefreshCommand("transport_helper"))
			cmd.Env = append(os.Environ(), "MODE="+mode)
			out, err := cmd.CombinedOutput()
			wantSuccess := mode == "neither" || mode == "both" || mode == "disabled-v6"
			if (err == nil) != wantSuccess {
				t.Fatalf("success=%v, output=%s", err == nil, out)
			}
			wantCall := mode == "both" || mode == "helper-failure" || mode == "disabled-v6" || mode == "v6-read-failure" || mode == "v6-lock-absent"
			if strings.Contains(string(out), "helper called") != wantCall {
				t.Fatalf("unexpected helper invocation: %s", out)
			}
		})
	}
}

func TestTransportManifestUpdatesAndClearsWithoutChangingUserLists(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "lists"), 0o755); err != nil {
		t.Fatal(err)
	}
	userList := filepath.Join(dir, "lists", "nfqueue_bypass_ips.list")
	const userContent = "198.51.100.0/24 # user's list\n"
	if err := os.WriteFile(userList, []byte(userContent), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoints := []string{"192.0.2.1:443"}
	m := New(&config.Config{Nfqws2Conf: filepath.Join(dir, "nfqws2.conf")})
	m.SetTransportEndpointProvider(func() []string { return endpoints })
	for _, want := range []string{"192.0.2.1 443\n", "192.0.2.2 443\n", ""} {
		if want == "192.0.2.2 443\n" {
			endpoints = []string{"192.0.2.2:443"}
		} else if want == "" {
			endpoints = nil
		}
		m.bypassMu.Lock()
		_, installed, err := m.syncTransportEndpoints()
		m.bypassMu.Unlock()
		if err != nil || !installed {
			t.Fatalf("sync = %v, %v", installed, err)
		}
		got, err := os.ReadFile(filepath.Join(dir, transportEndpointsFile))
		if err != nil || string(got) != want {
			t.Fatalf("manifest = %q, %v; want %q", got, err, want)
		}
		got, err = os.ReadFile(userList)
		if err != nil || string(got) != userContent {
			t.Fatalf("user list changed = %q, %v", got, err)
		}
	}
}

func TestTransportManifestDoesNotCreateNFQWSInstallation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent-nfqws")
	m := New(&config.Config{Nfqws2Conf: filepath.Join(dir, "nfqws2.conf")})
	m.SetTransportEndpointProvider(func() []string { return []string{"192.0.2.1:443"} })
	if err := m.RefreshTransportBypass(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("missing NFQWS directory was created: %v", err)
	}
}
