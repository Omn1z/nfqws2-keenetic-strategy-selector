package app

import (
	"nfqws2strategy/internal/services/proxy"
	"nfqws2strategy/internal/services/tgws"
)

// The two Telegram proxies (MTProto WS + SOCKS5) now live in internal/services/
// proxy. These type aliases + thin delegators keep the App surface the HTTP
// handlers (internal/server) and the dashboard call unchanged.

type (
	TGWSStatus   = proxy.TGWSStatus
	Socks5Status = proxy.Socks5Status
)

func (a *App) TGWSStatusFor(host string) TGWSStatus        { return a.proxy.TGWSStatusFor(host) }
func (a *App) TGWSSetConfig(in *tgws.Config) error         { return a.proxy.TGWSSetConfig(in) }
func (a *App) TGWSStart() error                            { return a.proxy.TGWSStart() }
func (a *App) TGWSStop() error                             { return a.proxy.TGWSStop() }
func (a *App) TGWSNewSecret() (string, error)              { return a.proxy.TGWSNewSecret() }
func (a *App) StopTGWS()                                   { a.proxy.StopTGWS() }
func (a *App) Socks5StatusFor(host string) Socks5Status    { return a.proxy.Socks5StatusFor(host) }
func (a *App) Socks5SetConfig(in *tgws.Socks5Config) error { return a.proxy.Socks5SetConfig(in) }
func (a *App) Socks5Start() error                          { return a.proxy.Socks5Start() }
func (a *App) Socks5Stop() error                           { return a.proxy.Socks5Stop() }
func (a *App) StopSocks5()                                 { a.proxy.StopSocks5() }
