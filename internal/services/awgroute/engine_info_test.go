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
			got := engineBuildInfo(bi)
			if got.AWG3Supported != tc.want31 || got.UpdateAvailable == tc.want31 || got.AwgVersion != tc.wantVersion || got.Arch != "arm64" || !got.Installed || got.TargetVersion != AWGEngineVersion {
				t.Fatalf("unexpected engine info: %+v", got)
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
