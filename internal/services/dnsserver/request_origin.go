package dnsserver

import (
	"context"
	"net"
)

type requestOriginContextKey struct{}

// ClientIP is the actual socket peer, not a claimed original device behind a
// forwarding resolver. In particular, local means router/loopback traffic;
// the DNS packet cannot identify which process or downstream device sent it.
type requestOrigin struct {
	ClientIP  string
	Source    string
	Transport string
}

func requestOriginFromContext(ctx context.Context) requestOrigin {
	if origin, ok := ctx.Value(requestOriginContextKey{}).(requestOrigin); ok {
		return origin
	}
	origin := requestOrigin{Source: "internal"}
	if ip := ContextClientIP(ctx); ip != nil {
		origin.ClientIP, origin.Source = ip.String(), "client"
		if ip.IsLoopback() {
			origin.Source = "local"
		}
	}
	return origin
}

func withRequestOrigin(ctx context.Context, origin requestOrigin) context.Context {
	return context.WithValue(ctx, requestOriginContextKey{}, origin)
}

func withListenerOrigin(ctx context.Context, remote, bindHost, transport string) context.Context {
	host, _, _ := net.SplitHostPort(remote)
	ip := net.ParseIP(host)
	origin := requestOrigin{Source: "client", Transport: transport}
	if ip != nil {
		origin.ClientIP = ip.String()
		if ip.IsLoopback() || ip.Equal(net.ParseIP(bindHost)) {
			origin.Source = "local"
		}
	}
	ctx = context.WithValue(ctx, clientIPContextKey{}, ip)
	return withRequestOrigin(ctx, origin)
}
