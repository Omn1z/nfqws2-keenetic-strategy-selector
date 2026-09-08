# TG WS Proxy upstream

The in-process Go MTProto proxy is synchronized with
[Flowseal/tg-ws-proxy v1.10.2](https://github.com/Flowseal/tg-ws-proxy/tree/v1.10.2),
commit `f200e33fd283143a9f101d62aaf9d8c1468a23fe` (2026-09-07).

The upstream network implementation is ported into Go, rather than launched as
a separate Python process. Its MIT license is included in `LICENSE.upstream`.

Synchronized behavior:

- MTProto obfuscated transport, Fake TLS, message splitting and AES stream relay.
- WebSocket fragmentation, frame/message limits, batched writes and ping/pong.
- Expiring connection pools, bounded retry backoff, SNI fronting and a separate
  CF Worker pool with domain failover.
- Per-IP timeout cooldown, per-DC retry cooldown and redirect fallback.
- Multiple CF proxy/Worker domains, updated bundled domains and hourly refresh
  of the upstream domain list. Invalid responses preserve the current pool.
- Automatic test-DC detection and optional forced test mode, including separate
  test endpoints and the `/apiws_test` path.
- Listener recovery, session diagnostics and masking of fallback domains in logs.

Keenetic adaptations retained: LAN listener and port defaults, disabled service
on first install, existing secrets/links, JSON persistence and web controls,
shared AWG fallback routes, and the SOCKS5 frontend using the shared WS transport.
The host starts the proxies after route/firewall initialization; background
native pool dials are limited to four simultaneous attempts to avoid connection
bursts on a router. Pool capacity remains configurable independently.
SNI fronting is opt-in (`sni_fronting`, off by default): live tests on Keenetic
showed that a fronted HTTP 101 can succeed while MTProto receives no response.
The upstream mechanism remains available in the UI for networks that need it.
Before borrowing an idle socket, a bounded, non-consuming read checks for EOF
and queued WS CLOSE frames. This replaces asyncio's idle transport close
notification, which a synchronous Go TLS connection does not provide by itself.
Legacy singular CF-domain fields remain readable; explicit new empty arrays
clear them. Existing DC redirects are preserved during upgrades.

Upstream desktop tray, desktop autostart, application updater, Windows packaging,
macOS UI and Python AES dependency selection are not part of the router service.
Their equivalents are managed by the panel, Entware init service and Go runtime.

For another sync, compare `proxy/` and its upstream tests at the new tag, port
network behavior into this package, and run `go test ./internal/services/tgws`
plus the project checks. Keep this revision and `UpstreamVersion`/
`UpstreamCommit` in `constants.go` together.
