//go:build !linux

package dnsroute

import (
	"context"
	"fmt"
	"net"
)

func (a *Adapter) prepareOS(context.Context, ListenOptions) error {
	return fmt.Errorf("NFQWS DNS routing is available only on Linux routers")
}
func (a *Adapter) routesOS() []Route {
	return []Route{{ID: "nfqws", Name: "NFQWS", Error: "маршрутизация доступна только на Linux"}}
}
func (a *Adapter) dialOS(context.Context, string, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("NFQWS DNS routing is available only on Linux routers")
}
func (a *Adapter) closeOS() error { return nil }
