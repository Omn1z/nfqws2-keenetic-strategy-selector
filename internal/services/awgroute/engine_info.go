package awgroute

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --version in upstream still prints 0.0.20250522 even in AWG 3.1.
// Use the Go module/version embedded in the executable instead.
const AWGEngineVersion = "v3.1.20260828"
const awgEngineRevision = "b5928efb6ca19f0153958460c3d141f04abc5c2e"

var engineInfoCache struct {
	sync.Mutex
	path  string
	size  int64
	mtime time.Time
	info  EngineInfo
}

func inspectEngine(path string) EngineInfo {
	st, err := os.Stat(path)
	if err != nil {
		return EngineInfo{TargetVersion: AWGEngineVersion}
	}
	engineInfoCache.Lock()
	defer engineInfoCache.Unlock()
	if engineInfoCache.path == path && engineInfoCache.size == st.Size() && engineInfoCache.mtime.Equal(st.ModTime()) {
		return engineInfoCache.info
	}
	info := EngineInfo{Installed: true, TargetVersion: AWGEngineVersion, UpdateAvailable: true}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		info.Error = "не удалось определить версию движка: " + err.Error()
	} else {
		info = engineBuildInfo(bi)
	}
	engineInfoCache.path, engineInfoCache.size, engineInfoCache.mtime = path, st.Size(), st.ModTime()
	engineInfoCache.info = info
	return info
}

func engineBuildInfo(bi *debug.BuildInfo) EngineInfo {
	info := EngineInfo{Installed: true, TargetVersion: AWGEngineVersion}
	version := bi.Main.Version
	rev := ""
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			rev = s.Value
		}
		if s.Key == "GOARCH" {
			info.Arch = s.Value
		}
	}
	if rev == awgEngineRevision && (version == "" || version == "(devel)") {
		version = AWGEngineVersion
	}
	info.AwgVersion = version
	if version == "" || version == "(devel)" {
		info.AwgVersion = bi.Main.Path
		if len(rev) >= 12 {
			info.AwgVersion += " @" + rev[:12]
		}
	}
	info.AWG3Supported = bi.Main.Path == "github.com/amnezia-vpn/amneziawg-go/v3" && (versionAtLeast31(version) || rev == awgEngineRevision)
	info.UpdateAvailable = !info.AWG3Supported
	return info
}

func versionAtLeast31(v string) bool {
	p := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(p) < 2 {
		return false
	}
	major, e1 := strconv.Atoi(p[0])
	minor, e2 := strconv.Atoi(p[1])
	return e1 == nil && e2 == nil && major == 3 && minor >= 1
}

func validateEngineBinary(path, arch string) error {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("неверный бинарник движка: %w", err)
	}
	info := engineBuildInfo(bi)
	if !info.AWG3Supported {
		return fmt.Errorf("архив содержит старый движок %s; требуется AmneziaWG 3.1 (%s)", info.AwgVersion, AWGEngineVersion)
	}
	if info.Arch != arch {
		return fmt.Errorf("архитектура движка %s, требуется %s", info.Arch, arch)
	}
	for _, s := range bi.Settings {
		if s.Key == "GOOS" && s.Value == "linux" {
			return nil
		}
	}
	return fmt.Errorf("движок собран не для Linux")
}
