//go:build linux

package awgroute

import (
	"path/filepath"

	routerpath "nfqws2strategy/internal/tools/path"
)

var (
	awgSetDir         = awgSetDirOS()
	awgRecentFile     = filepath.Join(awgSetDir, "awg2_recent.json")
	awgFMWMarker      = filepath.Join(awgSetDir, ".awg2_fmw_v1")
	awgHostRoutesFile = filepath.Join(awgSetDir, "awg2_hostroutes.json")
	awgHookPath       = awgHookPathOS("90-awg2.sh")
	awgMultiHookPath  = awgHookPathOS("91-awg2-multi.sh")
	awgFW4HookPath    = awgFW4HookPathOS()
	awgNfqwsListsDir  = awgNfqwsListsDirOS()
)

func awgSetDirOS() string {
	return routerpath.Path(routerpath.AWGSetDir)
}

func awgHookPathOS(name string) string {
	if routerpath.IsOpenWrt() {
		return filepath.Join(awgSetDir, name)
	}
	return filepath.Join(filepath.Dir(routerpath.Path(routerpath.AWGHook)), name)
}

func awgNfqwsListsDirOS() string {
	return routerpath.Path(routerpath.AWGListsDir)
}

func awgFW4HookPathOS() string {
	return routerpath.Path(routerpath.AWGFW4Hook)
}
