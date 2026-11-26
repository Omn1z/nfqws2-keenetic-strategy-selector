package app

import "nfqws2strategy/internal/services/awgroute"

// DNSServerPublicConnections exposes configured public identities only: no
// handshake/status probe and no private VPN credentials are needed for import.
func (a *App) DNSServerPublicConnections() []awgroute.AWG2ConnectionRef {
	return a.awgroute.AWG2PublicConnections()
}

func (a *App) WithDNSServerPublicConnections(fn func([]awgroute.AWG2ConnectionRef) error) error {
	return a.awgroute.WithAWG2PublicConnections(fn)
}
