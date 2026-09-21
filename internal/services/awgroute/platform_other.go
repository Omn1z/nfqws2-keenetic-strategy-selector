//go:build !linux

package awgroute

import routerpath "nfqws2strategy/internal/tools/path"

var (
	awgSetDir         = routerpath.Path(routerpath.AWGSetDir)
	awgRecentFile     = awgSetDir + "/awg2_recent.json"
	awgFMWMarker      = awgSetDir + "/.awg2_fmw_v1"
	awgHostRoutesFile = awgSetDir + "/awg2_hostroutes.json"
	awgHookPath       = routerpath.Path(routerpath.AWGHook)
	awgMultiHookPath  = routerpath.Path(routerpath.AWGMultiHook)
	awgFW4HookPath    = routerpath.Path(routerpath.AWGFW4Hook)
	awgNfqwsListsDir  = routerpath.Path(routerpath.AWGListsDir)
)
