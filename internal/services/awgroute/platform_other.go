//go:build !linux

package awgroute

var (
	awgSetDir         = "/opt/etc/nfqws2-strategy"
	awgRecentFile     = awgSetDir + "/awg2_recent.json"
	awgFMWMarker      = awgSetDir + "/.awg2_fmw_v1"
	awgHostRoutesFile = awgSetDir + "/awg2_hostroutes.json"
	awgHookPath       = "/opt/etc/ndm/netfilter.d/90-awg2.sh"
	awgMultiHookPath  = "/opt/etc/ndm/netfilter.d/91-awg2-multi.sh"
	awgFW4HookPath    = "/opt/etc/ndm/netfilter.d/92-awg2-fw4.sh"
	awgNfqwsListsDir  = "/opt/etc/nfqws2/lists"
)
