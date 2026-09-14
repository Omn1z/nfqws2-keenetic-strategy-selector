package awgroute

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestEngineBuildInfoDetectsWireCapability(t *testing.T) {
	for _, tc := range []struct {
		name, path, version, revision string
		want31                        bool
		wantVersion                   string
	}{
		{"legacy WARP fork", "github.com/amnezia-vpn/amneziawg-go", "v0.2.19+dirty", "1cc94272ca8e9e223a5fe76382f5880f09d3c12d", false, "v0.2.19+dirty"},
		{"3.0 is insufficient", "github.com/amnezia-vpn/amneziawg-go/v3", "v3.0.20260801", "", false, "v3.0.20260801"},
		{"official 3.1", "github.com/amnezia-vpn/amneziawg-go/v3", AWGEngineVersion, awgEngineRevision, true, AWGEngineVersion},
		{"exact source build", "github.com/amnezia-vpn/amneziawg-go/v3", "(devel)", awgEngineRevision, true, AWGEngineVersion},
		{"unknown source build", "github.com/amnezia-vpn/amneziawg-go/v3", "(devel)", "", false, "github.com/amnezia-vpn/amneziawg-go/v3"},
		{"unrelated executable", "example.org/tool", AWGEngineVersion, "", false, AWGEngineVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bi := &debug.BuildInfo{Main: debug.Module{Path: tc.path, Version: tc.version}, Settings: []debug.BuildSetting{{Key: "GOARCH", Value: "arm64"}, {Key: "vcs.revision", Value: tc.revision}}}
			bi.GoVersion, bi.Deps = "go1.26.8", patchedEngineDeps()
			got := engineBuildInfo(bi)
			if got.AWG3Supported != tc.want31 || got.UpdateAvailable == tc.want31 || got.AwgVersion != tc.wantVersion || got.Arch != "arm64" || !got.Installed || got.TargetVersion != AWGEngineVersion {
				t.Fatalf("unexpected engine info: %+v", got)
			}
		})
	}
}

func patchedEngineDeps() []*debug.Module {
	return []*debug.Module{
		{Path: "golang.org/x/crypto", Version: "v0.57.0"},
		{Path: "golang.org/x/net", Version: "v0.59.0"},
		{Path: "golang.org/x/sys", Version: "v0.48.0"},
	}
}

func TestEngineBuildInfoOffersSecurityRebuild(t *testing.T) {
	for _, tc := range []struct {
		name       string
		edit       func(*debug.BuildInfo)
		wantUpdate bool
	}{
		{"patched build", func(*debug.BuildInfo) {}, false},
		{"old compiler", func(b *debug.BuildInfo) { b.GoVersion = "go1.25.7" }, true},
		{"unpatched 1.26", func(b *debug.BuildInfo) { b.GoVersion = "go1.26.7" }, true},
		{"unpatched 1.27", func(b *debug.BuildInfo) { b.GoVersion = "go1.27.0" }, true},
		{"patched 1.27", func(b *debug.BuildInfo) { b.GoVersion = "go1.27.1" }, false},
		{"unknown compiler", func(b *debug.BuildInfo) { b.GoVersion = "" }, true},
		{"old crypto", func(b *debug.BuildInfo) { b.Deps[0].Version = "v0.56.0" }, true},
		{"old net", func(b *debug.BuildInfo) { b.Deps[1].Version = "v0.58.0" }, true},
		{"old sys", func(b *debug.BuildInfo) { b.Deps[2].Version = "v0.47.0" }, true},
		{"missing metadata", func(b *debug.BuildInfo) { b.Deps = nil }, true},
		{"newer dependency", func(b *debug.BuildInfo) { b.Deps[0].Version = "v0.58.0" }, false},
		{"old replacement", func(b *debug.BuildInfo) {
			b.Deps[0].Replace = &debug.Module{Path: "golang.org/x/crypto", Version: "v0.42.0"}
		}, true},
		{"unknown replacement", func(b *debug.BuildInfo) { b.Deps[0].Replace = &debug.Module{Path: "../crypto"} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bi := &debug.BuildInfo{GoVersion: "go1.26.8", Main: debug.Module{Path: "github.com/amnezia-vpn/amneziawg-go/v3", Version: AWGEngineVersion}, Deps: patchedEngineDeps()}
			tc.edit(bi)
			info := engineBuildInfo(bi)
			if !info.AWG3Supported || info.UpdateAvailable != tc.wantUpdate {
				t.Fatalf("security update must be independent of protocol support: %+v", info)
			}
		})
	}
}

func TestInspectEngineMissingAndInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "amneziawg-go")
	if info := inspectEngine(path); info.Installed || info.AWG3Supported || info.TargetVersion != AWGEngineVersion {
		t.Fatalf("missing engine: %+v", info)
	}
	if err := os.WriteFile(path, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if info := inspectEngine(path); !info.Installed || info.AWG3Supported || !info.UpdateAvailable || info.Error == "" {
		t.Fatalf("unrecognized engine must require an update: %+v", info)
	}
	if err := validateEngineBinary(path, "arm64"); err == nil {
		t.Fatal("accepted an invalid binary")
	}
}
