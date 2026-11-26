package app

import "nfqws2strategy/internal/services/dnsserver"

func (a *App) DNSServer() *dnsserver.Service { return a.dnsServer }
