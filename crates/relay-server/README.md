# minip2p-relay-server

`minip2p-relay-server` is the deterministic `no_std + alloc` policy layer for
hosting a Circuit Relay v2 server. The relay wire crate owns one HOP or STOP
handshake; this crate owns the whole service: reservations, exact-connection
identity, admission, token buckets, control deadlines, circuits, forwarding,
accepted-byte accounting, and typed lifecycle events. Sockets, system clocks,
blocking waits, Endpoint composition, ACLs, discovery, metrics, and proxy-aware
IP policy stay in adapters.

The host supplies a `Now`, feeds Swarm events, drains tokenized actions, and
echoes every open/send/close/reset result. Drain a claimed input and all of its
synchronous results to quiescence before delivering another transport event.
Call `handle_tick(now)` before events sampled at the same time; deadlines win at
equality. The service assumes Swarm's single live connection per peer but keeps
exact connection and stream identities so stale superseded inputs cannot mutate
replacement state.

## Compatibility contract

| Area | Behavior | Classification |
| --- | --- | --- |
| Reservation cardinality/renewal | One committed reservation per peer; only the exact stored connection renews it. This relies on Swarm's single-live-connection-per-peer invariant for exact STOP targeting. | Deliberate minip2p deviation from rust-libp2p's connection cardinality. |
| Reservation admission | Availability, peer rate, IP rate, then exact capacity. Renewals consume rate tokens while replacing their slot, including at capacity. | Deliberate minip2p deviation: rate-first and corrected exact capacity. |
| Circuit admission | Limits apply to both endpoints, counting a self-circuit once. | Deliberate minip2p deviation from rust-libp2p's source-only peer cap. |
| Limiters | Four fixed optional full-starting token buckets, each configured as capacity plus one-token refill interval. | rust-libp2p parity in defaults/algorithm; fixed public shape is a minip2p extension. |
| Static HOP, NAT, pause | Relay enablement advertises HOP statically; NAT is outbound-HOP-only. Pause denies new work but preserves HOP and existing lifecycles. Circuit HOP negotiates then returns `PERMISSION_DENIED`. | Deliberate minip2p deviations from dynamic upstream HOP plus a minip2p control extension. |
| Address selection | Explicit trusted override, AutoNAT-confirmed direct addresses, then concrete listeners; first non-empty source, filtering, first-wins deduplication, deterministic truncation. | minip2p extension/deviation from rust-libp2p's confirmed-address source. |
| Identify updates | Selection changes affect future Identify exchanges only; no Identify Push or forced re-identification. | Deliberate minip2p behavior. |
| Frames and malformed input | 8 KiB control frames; deterministic specified status/reset handling. | minip2p extension; rust-libp2p uses 4 KiB and drops some malformed HOP input. |
| Byte accounting | Per-direction transport-accepted totals include pipelined payload. Equality remains open; a crossing chunk is delivered and counted in full. | Circuit Relay v2 parity in directionality; minip2p extension versus rust-libp2p aggregate/excluded pipelining. |
| Duration and zero limits | Duration starts at committed HOP success, including pipelined work. Zero duration/bytes are unlimited and advertised as zero. | Circuit Relay v2 parity; deliberate deviation from rust-libp2p's zero/immediate and later start. |
| Lifecycles | Exactly-once typed reservation/circuit events, terminal reasons, and directional totals commit only after transport acceptance. Unix expiry is optional; monotonic time governs lifetime. | minip2p extension. |
| Control caps and timing | Separate post-negotiation HOP/STOP caps and end-to-end deadlines; no Swarm-wide pre-negotiation cap. | rust-libp2p-shaped workers with deliberate end-to-end minip2p timing. |
| Forwarding/backpressure | Tokenized actions account only accepted writes; transport queues own backpressure. | minip2p extension. |
| Reservation voucher | `voucher: None`. | rust-libp2p parity, while deliberately omitting the protocol recommendation. |

These choices deliberately correct or differ from rust-libp2p 0.22 where the
canonical minip2p relay-server specification says so.

## Explicit non-goals

The service does not provide reservation vouchers, relay discovery/autorelay,
ACLs, metrics, proxy-aware IP limiting, a portable/smoltcp Endpoint driver,
Swarm-wide pre-negotiation stream caps, or replacement of existing test relay
fixtures. These omissions are not claimed as Circuit Relay v2 or rust-libp2p
parity. Low-level portable hosts may drive this crate directly; only the
application-facing Endpoint adapter is std-only.
