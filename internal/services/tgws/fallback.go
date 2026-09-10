package tgws

import (
	"context"
	"io"
	"log"
	"net"
	"time"
)

type fallbackConfig struct {
	cfproxyEnabled       bool
	cfproxyWorkerDomains []string
	workerPool           *cfWorkerPool
}

// attemptFallback tries each enabled fallback in order: CF worker, CF proxy
// pool, then direct TCP to the DC default IP. Returns true if one took over
// the connection.
func attemptFallback(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	relayInit []byte, dc int, isTest, isMedia bool, reenc *reencryptionContext, stats *Stats,
	cfg fallbackConfig, bal *domainBalancer, splitter *messageSplitter) bool {

	targetIP := fallbackIP(dc, isTest)

	if len(cfg.cfproxyWorkerDomains) > 0 && targetIP != "" {
		if cfWorker(ctx, client, clientWriter, closeClient, relayInit, dc, isTest, targetIP, reenc, stats, cfg) {
			return true
		}
	}
	if cfg.cfproxyEnabled && !isTest {
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
	relayInit []byte, dc int, isTest bool, targetIP string, reenc *reencryptionContext, stats *Stats,
	cfg fallbackConfig) bool {

	var ws *rawWebSocket
	var domain string
	if cfg.workerPool != nil && !isTest {
		ws, domain = cfg.workerPool.acquire(dc, targetIP, cfg.cfproxyWorkerDomains)
	}
	if ws != nil {
		log.Printf("tgws: DC%d -> CF worker pool hit via %s", dc, censorDomains(domain))
	} else {
		domains := cfg.cfproxyWorkerDomains
		if cfg.workerPool != nil {
			domains = cfg.workerPool.availableDomains(domains)
		}
		for _, candidate := range domains {
			if ctx.Err() != nil {
				return false
			}
			log.Printf("tgws: DC%d -> CF worker %s", dc, censorDomains(candidate))
			w, err := connectWS(ctx, candidate, candidate, 10*time.Second, cfWorkerPath(dc, targetIP), 0)
			if err == nil {
				ws = w
				break
			}
			if cfg.workerPool != nil {
				cfg.workerPool.reportFailure(candidate, err)
			}
			log.Printf("tgws: DC%d CF worker %s failed: %s", dc, censorDomains(candidate), censorDomains(err.Error()))
		}
		if ws == nil {
			return false
		}
	}
	stats.connectionsCFProxy.Add(1)
	if err := ws.send(relayInit); err != nil {
		_ = ws.close()
		return false
	}
	// Workers relay an ordinary TCP byte stream and do not need native
	// Telegram WS packet boundaries. In particular, do not buffer a partial
	// MTProto transport packet while waiting to fill the splitter.
	bridgeWS(client, clientWriter, closeClient, ws, reenc, stats, nil, "DC"+itoa(dc)+" CF worker")
	return true
}

func cfProxy(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	relayInit []byte, dc int, reenc *reencryptionContext, stats *Stats,
	bal *domainBalancer, splitter *messageSplitter) bool {

	var ws *rawWebSocket
	chosen := ""
	for _, base := range bal.candidatesFor(dc) {
		if ctx.Err() != nil {
			return false
		}
		domain := "kws" + itoa(dc) + "." + base
		w, err := connectWS(ctx, domain, domain, 10*time.Second, "/apiws", 0)
		if err == nil {
			ws = w
			chosen = base
			break
		}
		log.Printf("tgws: DC%d CF %s failed: %s", dc, censorDomains(base), censorDomains(err.Error()))
	}
	if ws == nil {
		return false
	}
	if chosen != "" && bal.promote(dc, chosen) {
		log.Printf("tgws: active CF domain for DC%d -> %s", dc, censorDomains(chosen))
	}
	stats.connectionsCFProxy.Add(1)
	if err := ws.send(relayInit); err != nil {
		_ = ws.close()
		return false
	}
	bridgeWS(client, clientWriter, closeClient, ws, reenc, stats, splitter, "DC"+itoa(dc)+" CF")
	return true
}

func tcpFallback(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	dst string, relayInit []byte, reenc *reencryptionContext, stats *Stats) bool {

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	remote, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(dst, "443"))
	if err != nil {
		log.Printf("tgws: TCP fallback %s:443 failed: %s", dst, censorDomains(err.Error()))
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

func fallbackIP(dc int, isTest bool) string {
	if isTest {
		return dcTestIPs[dc]
	}
	return dcDefaultIPs[dc]
}
