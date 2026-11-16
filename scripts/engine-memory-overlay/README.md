The router engine uses a Go build overlay over the pinned upstream checkout.
Release and audit binaries must use the same `overlay.json`. The generator
refuses unexpected upstream constants and never edits the checkout.
Both builds record the `n2s_router_memory_v1` build tag. The panel reads that
marker from Go build information to offer this profile to users whose older
engine has the same upstream version and security dependencies.

The batch is 64 packets, which is the minimum supported by the current Linux
UDP GRO split path (64 segments). Two UDP readers and the TUN reader therefore
hold about 12 MiB of full-size message buffers instead of 24 MiB. The staged
queue retains at most eight batches while a peer has no session key, reducing
its theoretical message-buffer payload from 1 GiB to 32 MiB per peer. Encryption
and decryption queues use 32 batches, and the handshake queue uses 128 packets.
Smaller queues retain less burst traffic and may drop packets sooner if crypto
or the peer cannot keep up. These values are intended for embedded router RAM;
they do not establish a measured throughput improvement.

Message buffers remain 65535 bytes because Linux GSO/GRO handles full-size
coalesced datagrams. The shared WaitPool is deliberately not capped: blocking
allocation while a staged queue owns all buffers can deadlock before that queue
gets an opportunity to evict its oldest batch. These changes reduce allocation
and backlog; they are not a hard process RSS ceiling.

Run the generator tests with `go test ./scripts/engine-memory-overlay`. After
building, run upstream tests with
`go test -overlay=<absolute overlay.json> -modfile=<absolute engine-deps.mod> -mod=readonly -skip '^TestAWGDevicePing$' ./device ./conn ./ipc ./ratelimiter ./replay`
from `.engine-build/amneziawg-go`. The overlay manifest is generated at
`.engine-build/router-memory/overlay.json`.
The overlay includes isolated tests for staged-batch eviction, splitting a full
64-segment GRO datagram, and the three readers' resident batch-buffer payload.

Installing the resulting engine only affects newly started processes. Do not
restart a working tunnel to apply this profile during an uninterrupted session.
