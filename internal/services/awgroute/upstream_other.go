//go:build !linux

package awgroute

// Non-linux stub so dev-machine builds (macOS / Windows) compile. The DNS proxy
// itself doesn't run off-Linux either, so this is purely shape-preserving.

// DNSProxyUpstreamAddr — stub matching the linux export.
func DNSProxyUpstreamAddr() string { return "127.0.0.1#5354" }

// SetDNSChainEnabled — non-linux stub.
func (svc *Service) SetDNSChainEnabled(enabled bool) { _ = enabled }
