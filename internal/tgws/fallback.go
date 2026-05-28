package tgws

import (
	"context"
	"io"
	"log"
	"net"
	"time"
)

type fallbackConfig struct {
	cfproxyEnabled      bool
	cfproxyWorkerDomain string
}

// attemptFallback tries each enabled fallback in order: CF worker, CF proxy
// pool, then direct TCP to the DC default IP. Returns true if one took over
// the connection.
func attemptFallback(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	relayInit []byte, dc int, isMedia bool, reenc *reencryptionContext, stats *Stats,
	cfg fallbackConfig, bal *domainBalancer, splitter *messageSplitter) bool {

	targetIP := dcDefaultIPs[dc]

	if cfg.cfproxyWorkerDomain != "" && targetIP != "" {
		if cfWorker(ctx, client, clientWriter, closeClient, relayInit, dc, isMedia, targetIP, reenc, stats, cfg, splitter) {
			return true
		}
	}
	if cfg.cfproxyEnabled {
		if cfProxy(ctx, client, clientWriter, closeClient, relayInit, dc, reenc, stats, bal, splitter) {
			return true
		}
	}
	if targetIP != "" {
		log.Printf("tgws: DC%d -> TCP fallback %s:443", dc, targetIP)
		if tcpFallback(ctx, client, clientWriter, closeClient, targetIP, relayInit, reenc, stats) {
			return true
		}
	}
	return false
}

func cfWorker(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	relayInit []byte, dc int, isMedia bool, targetIP string, reenc *reencryptionContext, stats *Stats,
	cfg fallbackConfig, splitter *messageSplitter) bool {

	domain := cfg.cfproxyWorkerDomain
	media := "0"
	if isMedia {
		media = "1"
	}
	path := "/apiws?dst=" + targetIP + "&dc=" + itoa(dc) + "&media=" + media
	log.Printf("tgws: DC%d -> CF worker %s", dc, domain)
	ws, err := connectWS(ctx, domain, domain, 10*time.Second, path, 0)
	if err != nil {
		log.Printf("tgws: DC%d CF worker failed: %v", dc, err)
		return false
	}
	stats.connectionsCFProxy.Add(1)
	if err := ws.send(relayInit); err != nil {
		_ = ws.close()
		return false
	}
	bridgeWS(client, clientWriter, closeClient, ws, reenc, stats, splitter)
	return true
}

func cfProxy(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	relayInit []byte, dc int, reenc *reencryptionContext, stats *Stats,
	bal *domainBalancer, splitter *messageSplitter) bool {

	var ws *rawWebSocket
	chosen := ""
	for _, base := range bal.candidatesFor(dc) {
		domain := "kws" + itoa(dc) + "." + base
		w, err := connectWS(ctx, domain, domain, 10*time.Second, "/apiws", 0)
		if err == nil {
			ws = w
			chosen = base
			break
		}
		log.Printf("tgws: DC%d CF %s failed: %v", dc, base, err)
	}
	if ws == nil {
		return false
	}
	if chosen != "" && bal.promote(dc, chosen) {
		log.Printf("tgws: active CF domain for DC%d -> %s", dc, chosen)
	}
	stats.connectionsCFProxy.Add(1)
	if err := ws.send(relayInit); err != nil {
		_ = ws.close()
		return false
	}
	bridgeWS(client, clientWriter, closeClient, ws, reenc, stats, splitter)
	return true
}

func tcpFallback(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	dst string, relayInit []byte, reenc *reencryptionContext, stats *Stats) bool {

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	remote, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(dst, "443"))
	if err != nil {
		log.Printf("tgws: TCP fallback %s:443 failed: %v", dst, err)
		return false
	}
	stats.connectionsTCPFallback.Add(1)
	if _, err := remote.Write(relayInit); err != nil {
		_ = remote.Close()
		return false
	}
	bridgeTCP(client, clientWriter, remote, closeClient, reenc, stats)
	return true
}
