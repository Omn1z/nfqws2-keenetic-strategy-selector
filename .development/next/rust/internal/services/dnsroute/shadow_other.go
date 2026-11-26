//go:build !linux

package dnsroute

import (
	"context"
	"fmt"
	"net"
)

func (a *Adapter) shadowServersOS(context.Context) ([]string, error) {
	return nil, fmt.Errorf("обнаружение DNS провайдера доступно только на Linux-роутере")
}
func (a *Adapter) dialShadowOS(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("Shadow DNS доступен только на Linux-роутере")
}
