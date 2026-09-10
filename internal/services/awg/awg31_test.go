package awg

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testAWG31(t *testing.T) (*ServerConfig, Peer) {
	t.Helper()
	c := Default()
	c.Conn.Host = "192.0.2.1"
	m := NewManager(c)
	if _, err := m.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	p, _, err := m.EnsureRouterPeerLocal()
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.Config()
	return &cfg, p
}

func TestAWG31DefaultIdentityAndSecretPreservation(t *testing.T) {
	c, _ := testAWG31(t)
	if !c.RequiresAWG31() || c.Obf.HeaderProtectionKey == "" || c.Obf.H1 != "1" || c.Obf.S1 != 12 || c.Obf.S4 != 12 {
		t.Fatal("missing safe AWG3.1 preset")
	}
	if errs := c.Validate(); len(errs) != 0 {
		t.Fatal(errs)
	}
	m := NewManager(c)
	if changed, err := m.EnsureKeys(); changed || err != nil {
		t.Fatalf("identity changed: %v %v", changed, err)
	}
	redacted := m.Redacted()
	if redacted.Obf.HeaderProtectionKey != "" || !redacted.Obf.HasHeaderProtectionKey {
		t.Fatal("header protection secret exposed or unmarked")
	}
	redacted.PrivateKey = c.PrivateKey
	redacted.Peers = c.Peers
	if err := m.SetConfig(&redacted); err != nil {
		t.Fatal(err)
	}
	if got := m.Config().Obf.HeaderProtectionKey; got != c.Obf.HeaderProtectionKey {
		t.Fatal("redacted save lost header protection key")
	}
	copy := m.Config()
	*copy.TrafficObfuscation = false
	if !m.Config().UseObfuscation() {
		t.Fatal("config clone shared toggle pointer")
	}
}

func TestAWG31ConfUAPIAndVPNRoundtrip(t *testing.T) {
	c, p := testAWG31(t)
	c.Obf.ContentPaddingAddition = "10-100"
	conf := ClientConf(c, p)
	for _, line := range []string{"HeaderProtectionKey = " + c.Obf.HeaderProtectionKey, "S3 = 12", "S4 = 12", "RekeyTimeout = 3-7", "ContentPaddingAddition = 10-100", "RandomTrailers = on", "DisableCookies = on", "PersistentKeepalive = 25-35"} {
		if !strings.Contains(conf, line+"\n") {
			t.Fatalf("missing %q", line)
		}
		if !strings.HasPrefix(line, "Persistent") && !strings.Contains(ServerConf(c), line+"\n") {
			t.Fatalf("server/client disagreement for %q", line)
		}
	}
	uapi, err := RenderUAPISet(c, p, "192.0.2.1", c.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := keyHex(c.Obf.HeaderProtectionKey)
	for _, line := range []string{"header_protection_key=" + key, "content_padding_addition=10-100", "rekey_after_time=100-120", "random_trailers=true", "disable_cookies=true", "persistent_keepalive_interval=25-35"} {
		if !strings.Contains(uapi, line+"\n") {
			t.Fatalf("missing UAPI %q", line)
		}
	}
	if strings.Index(uapi, "header_protection_key=") > strings.Index(uapi, "public_key=") {
		t.Fatal("device properties after peer")
	}
	uri, err := ClientVPNURI(c, p)
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"conf": conf, "vpn": uri} {
		t.Run(name, func(t *testing.T) {
			got, err := ImportClientConf(source)
			if err != nil {
				t.Fatal(err)
			}
			if !got.RequiresAWG31() || got.EffectiveProtocolVersion() != "3.1" || got.Obf != c.Obf || got.Peers[0].KeepaliveValue() != "25-35" {
				t.Fatal("AWG3.1 source parameters changed during import")
			}
		})
	}
	var raw map[string]any
	data, _ := clientAmneziaJSON(c, p)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	proto := raw["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)
	if proto["protocol_version"] != "3.1" {
		t.Fatal("missing Amnezia protocol version")
	}
}

func TestAWG31ToggleOffProducesPlainWireGuard(t *testing.T) {
	c, p := testAWG31(t)
	key := c.Obf.HeaderProtectionKey
	if err := c.ConfigureTrafficObfuscation(false); err != nil {
		t.Fatal(err)
	}
	if c.UseObfuscation() || c.RequiresAWG31() || c.Obf.HeaderProtectionKey != key {
		t.Fatal("off must retain stored parameters and disable wire obfuscation")
	}
	uapi, err := RenderUAPISet(c, p, "192.0.2.1", c.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"client": ClientConf(c, p), "server": ServerConf(c), "setconf": SetConfText(c, p), "uapi": uapi} {
		for _, forbidden := range []string{"HeaderProtection", "header_protection", "RandomTrailers", "random_trailers", "Jc =", "jc=", "25-35"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains disabled feature %s", name, forbidden)
			}
		}
	}
	uri, _ := ClientVPNURI(c, p)
	got, err := ImportClientConf(uri)
	if err != nil || got.Protocol != "wireguard" {
		t.Fatalf("plain WG VPN import: %v", err)
	}
	if err := c.ConfigureTrafficObfuscation(true); err != nil {
		t.Fatal(err)
	}
	if c.Obf.HeaderProtectionKey != key {
		t.Fatal("toggle regenerated shared header key")
	}
}

func TestAWG31Validation(t *testing.T) {
	c, _ := testAWG31(t)
	tests := []struct {
		name   string
		mutate func(*Obfuscation)
	}{
		{"key length", func(o *Obfuscation) { o.HeaderProtectionKey = "AAAA" }},
		{"nonce length", func(o *Obfuscation) { o.S3 = 11 }},
		{"uint16 overflow", func(o *Obfuscation) { o.RekeyTimeout = "1-65536" }},
		{"reversed", func(o *Obfuscation) { o.KeepaliveTimeout = "20-10" }},
		{"overlap", func(o *Obfuscation) { o.H1, o.H2 = "10-20", "20-30" }},
		{"injection", func(o *Obfuscation) { o.RekeyAfterTime = "10\nprivate_key=bad" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := c.Obf
			tt.mutate(&o)
			if len(o.Validate()) == 0 {
				t.Fatal("accepted invalid 3.1 parameters")
			}
		})
	}
}

func TestLegacyProfilesDoNotUpgradeOrEnableJunkOnNormalize(t *testing.T) {
	c := &ServerConfig{Protocol: "awg", Install: "imported", Obf: Obfuscation{H1: "1", H2: "2", H3: "3", H4: "4", S4: 12}}
	c.Normalize()
	if c.ProtocolVersion != "" || c.TrafficObfuscation != nil || c.RequiresAWG31() || c.Obf.Jc != 0 || c.EffectiveProtocolVersion() != "2" {
		t.Fatal("legacy wire parameters changed")
	}
	c.Protocol = "wireguard"
	if c.RequiresAWG31() || c.UseObfuscation() {
		t.Fatal("plain WG migrated")
	}
}

type failingAWGRunner struct {
	fakeRunner
	fail string
}

func (r *failingAWGRunner) Run(ctx context.Context, cmd string) (string, string, error) {
	if strings.Contains(cmd, r.fail) {
		r.cmds = append(r.cmds, cmd)
		return "", "simulated command failure", errors.New("failed")
	}
	return r.fakeRunner.Run(ctx, cmd)
}

func TestAWG31DeployFailsBeforeConfigWriteOnInstallError(t *testing.T) {
	c, _ := testAWG31(t)
	r := &failingAWGRunner{fail: "git clone"}
	res := Deploy(context.Background(), r, c, nil)
	if res.OK || len(r.puts) != 0 || res.Method != "userspace" {
		t.Fatalf("failed install continued: %+v", res)
	}
}

func TestAWG31DeployStopsOnApplyErrorEvenIfOldPortListens(t *testing.T) {
	c, _ := testAWG31(t)
	r := &failingAWGRunner{fakeRunner: fakeRunner{responses: []kv{{"awg show awg0 2>&1", "0.0.0.0:51820"}}}, fail: "systemctl start awg-quick@"}
	res := Deploy(context.Background(), r, c, nil)
	if res.OK || res.Error == "" {
		t.Fatal("old listening port hid failed apply")
	}
	for _, cmd := range r.cmds {
		if strings.Contains(cmd, "modinfo amneziawg") {
			t.Fatal("AWG3.1 relied on an unverified kernel module")
		}
	}
}

func TestAWG31ProvisionShellSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		bash = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		if _, err := os.Stat(bash); err != nil {
			t.Skip("bash unavailable for syntax validation")
		}
	}
	c, _ := testAWG31(t)
	for name, script := range map[string]string{"install": userspaceInstallScript(), "service": userspaceServiceScript(c.Interface), "bringup": bringUpScript(c)} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".sh")
			if err := os.WriteFile(path, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			// Parse only: installing packages or accessing any server is forbidden
			// in this test and no generated command is executed.
			if out, err := exec.Command(bash, "-n", filepath.ToSlash(path)).CombinedOutput(); err != nil {
				t.Fatalf("shell syntax: %v: %s", err, out)
			}
		})
	}
}

func TestAWG31SecretRedaction(t *testing.T) {
	c, _ := testAWG31(t)
	key := c.Obf.HeaderProtectionKey
	hexKey, _ := keyHex(key)
	if got := redact("HeaderProtectionKey = " + key + " header_protection_key=" + hexKey); strings.Contains(got, key) || strings.Contains(got, hexKey) {
		t.Fatal("secret leaked to deploy logs")
	}
}

func TestAWG31ExplicitVersionSurvivesVPNImport(t *testing.T) {
	c, p := testAWG31(t)
	c.Obf = DefaultObf() // 3.1 can explicitly use only legacy-compatible fields
	p.KeepaliveRange = ""
	uri, err := ClientVPNURI(c, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ImportClientConf(uri)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProtocolVersion != "3.1" || !got.RequiresAWG31() {
		t.Fatal("lost explicit Amnezia version")
	}
}

func TestAWG31UserspaceQuickCreationOverride(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		bash = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		if _, err := os.Stat(bash); err != nil {
			t.Skip("bash unavailable")
		}
	}
	work := t.TempDir()
	source, target := filepath.Join(work, "quick-source.sh"), filepath.Join(work, "quick-result.sh")
	if err := os.WriteFile(source, []byte("#!/bin/bash\nadd_if() {\n  if ! cmd ip link add \"$INTERFACE\" type amneziawg; then\n    echo fallback\n  fi\n}\nother() {\n  echo preserved\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	install := userspaceInstallScript()
	start, end := strings.Index(install, "awk '\n"), strings.Index(install, "grep -Fq 'cmd /usr/bin/amneziawg-go'")
	if start < 0 || end < start {
		t.Fatal("userspace override missing")
	}
	quote := func(p string) string { return "'" + strings.ReplaceAll(filepath.ToSlash(p), "'", "'\\''") + "'" }
	script := strings.ReplaceAll(install[start:end], "/usr/bin/awg-quick", quote(source))
	script = strings.ReplaceAll(script, "\"$work/awg-quick-userspace\"", quote(target))
	cmd := exec.Command(bash)
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("override transformation: %v %s", err, out)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	result := string(raw)
	if !strings.Contains(result, "cmd /usr/bin/amneziawg-go \"$INTERFACE\"") || strings.Contains(result, "type amneziawg") || !strings.Contains(result, "echo preserved") {
		t.Fatal("userspace wrapper failed to isolate interface creation")
	}
}

func TestPendingDeploymentKeepsRuntimeAndExportUntilSuccess(t *testing.T) {
	c, p := testAWG31(t)
	c.DeployedAt = 1
	c.ProtocolVersion = "2"
	c.TrafficObfuscation = nil
	c.Obf = DefaultObf()
	c.Peers[0].KeepaliveRange = ""
	c.Client.Enabled = true
	m := NewManager(c)
	applied := m.Config()
	m.SetAppliedConfig(&applied)
	desired := m.Config()
	desired.ProtocolVersion = "3.1"
	if err := desired.ConfigureTrafficObfuscation(true); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(&desired); err != nil {
		t.Fatal(err)
	}
	if !m.PendingApply() || m.RuntimeConfig().RequiresAWG31() || !m.Config().RequiresAWG31() {
		t.Fatal("pending wire config became active early")
	}
	if _, changed, err := m.EnsureRouterPeerLocal(); err != nil || changed {
		t.Fatalf("existing applied router unavailable: %v %v", changed, err)
	}
	if _, err := m.AddPeer(context.Background(), Peer{}); err == nil {
		t.Fatal("peer addition could sync pending wire format")
	}
	if err := m.RemovePeer(context.Background(), p.ID); err == nil {
		t.Fatal("peer deletion could sync pending wire format")
	}
	m.SetClientEnabled(false)
	m.SetEnabled(false)
	m.SetRouting(RoutingConfig{Mode: "full", MTU: 1420, DomainSource: "resolve"})
	if cfg := m.RuntimeConfig(); cfg.Client.Enabled || cfg.Enabled || cfg.Routing.Mode != "full" {
		t.Fatal("runtime snapshot hid local controls")
	}
	copy := m.AppliedConfig()
	copy.Obf.H1 = "99"
	if m.AppliedConfig().Obf.H1 == "99" {
		t.Fatal("applied snapshot accessor aliases private state")
	}
	fail := &failingAWGRunner{fail: "systemctl start awg-quick@"}
	m.dial = func(context.Context, Credentials) (runner, string, error) { return fail, "", nil }
	res, err := m.Deploy(context.Background(), nil)
	if err != nil || res.OK || !m.PendingApply() {
		t.Fatalf("failed deployment lost snapshot: %v %+v", err, res)
	}
	text, _, _, err := m.ClientExport(p.ID, "conf")
	if err != nil || strings.Contains(text, "HeaderProtectionKey") {
		t.Fatal("failed deployment exported unapplied format")
	}
	ok := &fakeRunner{responses: []kv{{"awg show awg0 2>&1", "interface: awg0\n0.0.0.0:51820"}}}
	m.dial = func(context.Context, Credentials) (runner, string, error) { return ok, "", nil }
	res, err = m.Deploy(context.Background(), nil)
	if err != nil || !res.OK || m.PendingApply() || !m.RuntimeConfig().RequiresAWG31() {
		t.Fatalf("successful deployment not activated: %v %+v", err, res)
	}
	text, _, _, err = m.ClientExport(p.ID, "conf")
	if err != nil || !strings.Contains(text, "HeaderProtectionKey") {
		t.Fatal("successful deployment still exports old format")
	}
}
