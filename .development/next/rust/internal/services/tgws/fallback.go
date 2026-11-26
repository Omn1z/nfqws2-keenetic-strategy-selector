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
	tcpBackoff           *tcpFallbackBackoff
	disableSecure        bool
	h2Pool               *cfH2Pool
}

// attemptFallback tries each enabled fallback in order: CF Worker, CF media
// HTTP/2, CF WebSocket, then direct TCP to the DC default IP. Returns true if one took over
// the connection.
func attemptFallback(ctx context.Context, client io.Reader, clientWriter io.Writer, closeClient func(),
	relayInit []byte, dc int, isTest, isMedia bool, reenc *reencryptionContext, stats *Stats,
	cfg fallbackConfig, bal *domainBalancer, splitter *messageSplitter, protocols ...uint32) bool {

	targetIP := fallbackIP(dc, isTest)

	if len(cfg.cfproxyWorkerDomains) > 0 && targetIP != "" {
		if cfWorker(ctx, client, clientWriter, closeClient, relayInit, dc, isTest, targetIP, reenc, stats, cfg) {
			return true
		}
	}
	if cfg.cfproxyEnabled && !isTest {
		if isMedia && !cfg.disableSecure && cfg.h2Pool != nil && len(protocols) > 0 {
			channel, err := cfg.h2Pool.open(ctx, dc, "DC"+itoa(dc)+" media")
			if ctx.Err() != nil {
				if channel != nil {
					channel.close()
				}
				return false
			}
			if err != nil {
				log.Printf("tgws: DC%d HTTP/2 unavailable: %s", dc, censorDomains(err.Error()))
			} else if channel != nil {
				stats.connectionsH2.Add(1)
				stats.connectionsCFProxy.Add(1)
				bridgeH2(ctx, client, clientWriter, closeClient, channel, reenc, stats, protocols[0], "DC"+itoa(dc)+" CF H2")
				return true
			}
		}
		if cfProxy(ctx, client, clientWriter, closeClient, relayInit, dc, reenc, stats, bal, splitter, cfg.disableSecure) {
			return true
		}
	}
	if targetIP != "" {
		if tcpFallback(ctx, client, clientWriter, closeClient, targetIP, relayInit, reenc, stats, cfg.tcpBackoff) {
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
			w, err := connectWS(ctx, candidate, candidate, 10*time.Second, cfWorkerPath(dc, targetIP), 0, !cfg.disableSecure)
			if err == nil {
				ws = w
				break
			}
			if isWSHandshakeQueueError(err) {
				return false
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
	bal *domainBalancer, splitter *messageSplitter, disableSecure bool) bool {

	var ws *rawWebSocket
	chosen := ""
	for _, base := range bal.candidatesFor(dc) {
		if ctx.Err() != nil {
			return false
		}
		domain := "kws" + itoa(dc) + "." + base
		w, err := connectWS(ctx, domain, domain, 10*time.Second, "/apiws", 0, !disableSecure)
		if err == nil {
			ws = w
			chosen = base
			break
		}
		if isWSHandshakeQueueError(err) {
			return false
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
	dst string, relayInit []byte, reenc *reencryptionContext, stats *Stats, backoffs ...*tcpFallbackBackoff) bool {

	var backoff *tcpFallbackBackoff
	if len(backoffs) > 0 {
		backoff = backoffs[0]
	}
	remote, err := prepareTCPFallback(ctx, net.JoinHostPort(dst, "443"), relayInit, backoff)
	if err != nil {
		return false
	}
	defer remote.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = remote.Close() })
	defer stopClose()
	stats.connectionsTCPFallback.Add(1)
	bridgeTCP(client, clientWriter, remote, closeClient, reenc, stats)
	return true
}

func fallbackIP(dc int, isTest bool) string {
	if isTest {
		return dcTestIPs[dc]
	}
	return dcDefaultIPs[dc]
}
