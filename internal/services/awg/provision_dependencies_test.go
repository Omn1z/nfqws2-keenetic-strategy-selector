package awg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserspaceProvisionCarriesReviewedDependencyLock(t *testing.T) {
	script := userspaceInstallScript()
	for _, want := range []string{
		"go1.26.8.linux-$arch.tar.gz",
		"d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b",
		"211ffced9dcb9633a55eac6364816ec0ddd951389a740e88fa8b3337971bdda0",
		`-modfile="$work/engine-deps.mod" -mod=readonly`,
		`GOTOOLCHAIN=local CGO_ENABLED=0`,
		`engine_current "$work/amneziawg-go"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("provisioning is missing %q", want)
		}
	}
	if strings.Contains(script, "go1.25.7") || strings.Contains(script, "@latest") {
		t.Fatal("provisioning uses an obsolete compiler or unlocked dependency update")
	}
	if strings.Index(script, `engine_current "$work/amneziawg-go"`) > strings.Index(script, `install -m755 "$work/amneziawg-go"`) {
		t.Fatal("engine must be validated before replacing the installed binary")
	}

	// Execute only the two embedded-lock heredocs in a fresh directory: this
	// proves shell quoting preserves the exact bytes without network or install.
	start := strings.Index(script, `  cat > "$work/engine-deps.mod"`)
	end := strings.Index(script, `  (cd "$work/engine"`)
	if start < 0 || end <= start {
		t.Fatal("embedded dependency lock staging is missing")
	}
	dir := t.TempDir()
	quote := "'" + strings.ReplaceAll(filepath.ToSlash(dir), "'", "'\\''") + "'"
	cmd := exec.Command(rollbackBash(t))
	cmd.Stdin = strings.NewReader("set -eu\nwork=" + quote + "\n" + script[start:end])
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("staging dependency locks: %v: %s", err, out)
	}
	for name, expected := range map[string]string{"engine-deps.mod": engineDependencyLock, "engine-deps.sum": engineDependencySums} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, []byte(expected)) {
			t.Fatalf("staged %s differs from embedded release lock: %v", name, err)
		}
	}
}

func TestUserspaceProvisionRebuildsEngineWithOldDependencies(t *testing.T) {
	current := fmt.Sprintf(`/usr/bin/amneziawg-go: go%s
	path	github.com/amnezia-vpn/amneziawg-go/v3
	dep	golang.org/x/crypto	%s	h1:checksum
	dep	golang.org/x/net	%s	h1:checksum
	dep	golang.org/x/sys	%s	h1:checksum
	build	vcs.revision=%s
`, engineDependencyVersion("go"), engineDependencyVersion("golang.org/x/crypto"),
		engineDependencyVersion("golang.org/x/net"), engineDependencyVersion("golang.org/x/sys"), AWGGoRevision)
	tests := []struct {
		name     string
		metadata string
		accepted bool
	}{
		{"current verified build", current, true},
		{"same source old compiler", strings.ReplaceAll(current, "go1.26.8", "go1.25.7"), false},
		{"same source unpatched next compiler", strings.ReplaceAll(current, "go1.26.8", "go1.27.0"), false},
		{"same source old crypto", strings.ReplaceAll(current, "\tv0.57.0\t", "\tv0.42.0\t"), false},
		{"same source old net", strings.ReplaceAll(current, "\tv0.59.0\t", "\tv0.44.0\t"), false},
		{"same source old sys", strings.ReplaceAll(current, "\tv0.48.0\t", "\tv0.36.0\t"), false},
		{"old replacement", strings.ReplaceAll(current, "\tv0.57.0\th1:checksum", "\tv0.57.0\n\t=>\tgolang.org/x/crypto\tv0.42.0\th1:checksum"), false},
		{"local replacement", strings.ReplaceAll(current, "\tv0.57.0\th1:checksum", "\tv0.57.0\n\t=>\t../crypto\t(devel)"), false},
		{"wrong source", strings.ReplaceAll(current, AWGGoRevision, "other-revision"), false},
		{"wrong executable", strings.ReplaceAll(current, "github.com/amnezia-vpn/amneziawg-go/v3", "example.com/other"), false},
		{"missing metadata", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quote := "'" + strings.ReplaceAll(tt.metadata, "'", "'\\''") + "'"
			cmd := exec.Command(rollbackBash(t))
			cmd.Stdin = strings.NewReader("metadata=" + quote + "\n" + userspaceEngineMetadataCheckScript())
			out, err := cmd.CombinedOutput()
			if (err == nil) != tt.accepted {
				t.Fatalf("accepted=%v, want %v: %v: %s", err == nil, tt.accepted, err, out)
			}
		})
	}
}
