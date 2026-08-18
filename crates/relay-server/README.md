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

| Area | minip2p relay-server behavior |
| --- | --- |
| Reservation cardinality | One committed reservation per peer; an exact-connection request renews it. |
| Reservation admission | Availability, peer rate, IP rate, then exact capacity. Renewals consume rate tokens while replacing their existing global slot. |
| Circuit admission | Limits apply to both endpoints, counting a self-circuit once. |
| Static HOP and pause | HOP remains advertised. Pause returns stable denial statuses, and HOP over a relayed connection returns `PERMISSION_DENIED`. |
| Address trust and precedence | Explicit override, AutoNAT-confirmed direct addresses, then concrete listeners; the first non-empty source is normalized and first-wins deduplicated. |
| Address framing | The longest stable source-order prefix fitting the 8 KiB frame is sent; `voucher` is always `None`. |
| Identify updates | Address and protocol changes affect future Identify exchanges only. |
| Malformed control input | The relay wire machines deterministically choose the specified status or reset boundary. The 8 KiB frame limit deliberately differs from rust-libp2p's 4 KiB limit. |
| Byte accounting | Independent directional totals count transport-accepted payload, including pipelined bytes. Equality remains open; the first crossing chunk is delivered and counted in full. |
| Duration and zero limits | Duration starts at committed HOP success. Zero duration and zero bytes are unlimited and advertised as zero. |
| Lifecycles | Reservations and circuits commit only after transport acceptance and terminate exactly once with typed reasons and directional totals. |
| Control caps and timing | HOP and STOP have separate post-negotiation caps and control deadlines. No Swarm-wide pre-negotiation cap is added. |
| Forwarding and backpressure | Forwarding is tokenized and action-based; transport queues own payload backpressure. |
| Wall time | Unix expiry is optional, saturating metadata. Monotonic time alone governs lifetime. |

These choices deliberately correct or differ from rust-libp2p 0.22 where the
canonical minip2p relay-server specification says so.
