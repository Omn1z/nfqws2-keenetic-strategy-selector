# TG WS Proxy upstream

The in-process Go MTProto proxy is synchronized with
[Flowseal/tg-ws-proxy v1.11.2](https://github.com/Flowseal/tg-ws-proxy/tree/v1.11.2),
commit `307a384ab7f522e34bb1a045884d0bd90f40bee5` (2026-10-11).

The upstream network implementation is ported into Go, rather than launched as
a separate Python process. Its MIT license is included in `LICENSE.upstream`.

Synchronized behavior:

- MTProto obfuscated transport, Fake TLS, message splitting and AES stream relay.
- WebSocket fragmentation, frame/message limits, batched writes and ping/pong.
- Expiring connection pools, bounded retry backoff, SNI fronting and a separate
  CF Worker pool with domain failover.
- Native WebSocket routing uses ready pooled sockets only. Empty pools refill
  in the background while the current client uses fallback routes. Pool size
  zero disables native WS; test and production DC pools remain separate.
- TCP fallback has per-endpoint exponential backoff from 30 seconds to one hour
  and one concurrent recovery probe. Successful setup resets the delay; caller
  cancellation does not classify the endpoint as unavailable.
- CF HTTP/2 media multiplexing after the Worker route and before CF WebSocket.
  Ordinary sessions, test DCs, plain-WS mode and SOCKS5 retain their WS/TCP paths.
  MTProto packet framing, bounded replay and independent response delivery let
  multiple media streams share a TLS connection without waiting for each other.
- HTTP 404 and other MTProto transport errors reach the affected native client
  without disabling the CF origin or unrelated channels.
- The last timed-out request retires a silent HTTP/2 TCP connection so future
  channels can reconnect. Other active streams and already buffered replies
  remain intact. New response identities replenish the bounded replay budget
  without discarding the retry delay or allowing duplicate replies to loop.
- Padded intermediate HTTP/2 requests accept up to 256 bytes of padding for
  unencrypted MTProto messages, while encrypted messages retain the 15-byte limit.
- CF Worker shutdown cancels and joins pending refills before returning, including
  sockets that complete concurrently with a reset or stop.
- Multiple CF proxy/Worker domains, updated bundled domains and hourly refresh
  of the upstream domain list. Invalid responses preserve the current pool.
- Verified TLS for ordinary CF/Telegram endpoints and an opt-in plain HTTP
  WebSocket mode (`disable_secure`) for fronts that only expose port 80.
- Automatic test-DC detection and optional forced test mode, including separate
  test endpoints and the `/apiws_test` path.
- Listener recovery, session diagnostics and masking of fallback domains in logs.
- Relay handshakes exclude the HTTP `OPTI` marker as well as existing reserved
  protocol prefixes.

Keenetic adaptations retained: LAN listener and port defaults, disabled service
on first install, existing secrets/links, JSON persistence and web controls,
shared AWG fallback routes, and the SOCKS5 frontend using the shared WS transport.
The host starts the proxies after route/firewall initialization. All native,
CF and Worker WebSocket setups and HTTP/2 TLS handshakes share a limit of four simultaneous attempts;
established streams release their slot. Waiting is bounded and does not mark an
endpoint as unreachable. Pool capacity remains configurable independently.
CF HTTP/2 uses the Go HTTP/2 transport without a separate runtime dependency.
Request, response and replay buffers are bounded per channel and origin, and
replay pauses when native writes are backpressured. The `cfproxy_h2_media`
switch defaults to true, including saved configurations predating the field;
explicitly disabling it preserves the previous CF WebSocket path.
Bounded TLS session caches reduce repeated key exchanges during pool rotation;
verified and opt-in domain-fronted connections use separate caches. Native trust
is supplemented with Entware's CA files once, preserving explicit SSL_CERT_FILE
and SSL_CERT_DIR overrides and ordinary certificate/hostname verification.
The upload splitter reads plaintext already produced by the bridge, avoiding a
third AES pass while preserving MTProto frame boundaries and ciphertext.
The legacy ciphertext-only splitter constructs its decryptor lazily; live
connections do not expand that unused AES key. Go's WebSocket masking and HTTP/2
transport supply the native equivalents of Python's masking tables and batched
flow-control writes.
SNI fronting is opt-in (`sni_fronting`, off by default): live tests on Keenetic
showed that a fronted HTTP 101 can succeed while MTProto receives no response.
The upstream mechanism remains available in the UI for networks that need it.
Before borrowing an idle socket, a bounded, non-consuming read checks for EOF
and queued WS CLOSE frames. This replaces asyncio's idle transport close
notification, which a synchronous Go TLS connection does not provide by itself.
Legacy singular CF-domain fields remain readable; explicit new empty arrays
clear them. Existing DC redirects are preserved during upgrades.

Upstream desktop tray, desktop autostart, application updater (including Linux
auto-update and manual checks), Windows packaging, macOS UI, the Python Windows
event-loop workaround and Python AES dependency selection are not part of the router service.
Their equivalents are managed by the panel, Entware init service and Go runtime.

For another sync, compare `proxy/` and its upstream tests at the new tag, port
network behavior into this package, and run `go test ./internal/services/tgws`
plus the project checks. Keep this revision and `UpstreamVersion`/
`UpstreamCommit` in `constants.go` together.
