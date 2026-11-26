//go:build !linux

package tunnelroute

func SetTGFrontRoutes(iface string) {}
func DelTGFrontRoutes(iface string) {}
