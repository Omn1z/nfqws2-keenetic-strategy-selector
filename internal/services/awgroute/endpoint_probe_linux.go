//go:build linux

package awgroute

import (
	"context"
	"net"
	"os/exec"
	"time"

	"nfqws2strategy/internal/services/awg"
)

// ICMP only orders recovery attempts. Firewalls may drop it while AWG works,
// and a ping reply authenticates neither the server nor the VPN handshake.
func (svc *Service) awgEndpointHintsOS(am *awg.Manager, pool []string) map[string]bool {
	ctx, cancel := context.WithTimeout(svc.clientOpContext(), 2*time.Second)
	defer cancel()
	_ = awgPinEndpointIPs(svc.awgClientEndpointIPs(am), "", func(command string) (string, error) { return awgRunShell(ctx, command, "") })
	return parallelEndpointHints(ctx, pool, svc.cachedPolicyEndpointIP, func(ctx context.Context, rawIP string) bool {
		ip := net.ParseIP(rawIP)
		name := "ping"
		args := []string{"-c", "1", "-W", "1", ip.String()}
		if ip.To4() == nil {
			if path, err := exec.LookPath("ping6"); err == nil {
				name = path
			} else {
				args = append([]string{"-6"}, args...)
			}
		}
		return exec.CommandContext(ctx, name, args...).Run() == nil
	})
}
