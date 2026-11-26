//go:build !linux

package openwrtdns

import "context"

// Mutations are unsupported outside Linux. This stub also permits isolated
// command-runner tests on the developer's host.
func lockTransaction(ctx context.Context, _ string) (func(), error) {
	return func() {}, ctx.Err()
}
