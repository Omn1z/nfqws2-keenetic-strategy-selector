//go:build !linux

package dnsroute

import (
	"context"
	"fmt"
)

func shadowRenewalPlatform() bool { return false }
func (a *Adapter) renewShadowDNSOS(context.Context) (ShadowRenewalResult, error) {
	return ShadowRenewalResult{}, fmt.Errorf("обновление DHCP доступно только на Keenetic")
}
