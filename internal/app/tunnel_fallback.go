package app

import (
	"strings"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/services/tunnelroute"
)

func (a *App) proxyTunnelFallbackUp(sel string) bool {
	sel = normalizeTunnelFallbackSel(sel)
	switch {
	case sel == "" || sel == "off":
		return false
	case sel == "auto":
		return a.awgroute.FallbackUp("auto")
	case strings.HasPrefix(sel, "awg:"):
		return a.awgroute.FallbackUp(strings.TrimPrefix(sel, "awg:"))
	default:
		return a.awgroute.FallbackUp(sel)
	}
}

func (a *App) syncProxyTunnelRoutes(sel string) {
	sel = normalizeTunnelFallbackSel(sel)
	for _, iface := range a.awgroute.ClientIfaces() {
		tunnelroute.DelTGFrontRoutes(iface)
	}
	if sel == "" || sel == "off" {
		return
	}
	awgSel := sel
	if strings.HasPrefix(awgSel, "awg:") {
		awgSel = strings.TrimPrefix(awgSel, "awg:")
	}
	if iface := a.awgroute.FallbackIface(awgSel); iface != "" {
		tunnelroute.SetTGFrontRoutes(iface)
	}
}

type ProxyTunnelFallback struct {
	Value   string                `json:"value"`   // "off" | "auto" | "<awg-server-id>" | "awg:<id>"
	Servers []awgroute.ServerInfo `json:"servers"` // selectable AWG2 servers ([] not null)
}

func (a *App) ProxyTunnelFallbackView() ProxyTunnelFallback {
	return ProxyTunnelFallback{Value: normalizeTunnelFallbackSel(a.proxy.AWGFallback()), Servers: a.awgroute.Servers()}
}

func normalizeTunnelFallbackSel(sel string) string {
	sel = strings.TrimSpace(sel)
	if sel == "warp" {
		return "auto"
	}
	return sel
}
