//go:build linux

package awgroute

import (
	"net"
	"os"
)

func awgDNSRunningOS(iface string) bool {
	if !validAWGClientIfaceName(iface) {
		return false
	}
	i, err := net.InterfaceByName(iface)
	if err != nil || i.Flags&net.FlagUp == 0 {
		return false
	}
	s, err := os.Stat(awgSockPath(iface))
	return err == nil && s.Mode()&os.ModeSocket != 0
}
