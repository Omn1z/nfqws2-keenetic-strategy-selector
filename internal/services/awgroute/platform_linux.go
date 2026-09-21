//go:build linux

package awgroute

import "path/filepath"

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
	if openWrtOS() {
		return "/etc/nfqws2-strategy"
	}
	return "/opt/etc/nfqws2-strategy"
}

func awgHookPathOS(name string) string {
	if openWrtOS() {
		return filepath.Join(awgSetDir, name)
	}
	return filepath.Join("/opt/etc/ndm/netfilter.d", name)
}

func awgNfqwsListsDirOS() string {
	if openWrtOS() {
		return "/etc/nfqws2/lists"
	}
	return "/opt/etc/nfqws2/lists"
}

func awgFW4HookPathOS() string {
	if openWrtOS() {
		return filepath.Join(awgSetDir, "92-awg2-fw4.sh")
	}
	return filepath.Join("/opt/etc/ndm/netfilter.d", "92-awg2-fw4.sh")
}
