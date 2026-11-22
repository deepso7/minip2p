# Automatic RTT scaling for swarm deadlines

Swarm negotiation, Identify, and ping deadlines stay fixed and configurable (`SwarmTimeouts`), rather than scaling automatically from per-connection RTT or exchange-latency estimates. Hosts on slow or loaded links raise `SwarmTimeouts`, `connect_deadline`, and transport handshake timeouts explicitly (`crates/minip2p/README.md`).

## Why this is out of scope

- **It cannot help the hardest exchanges.** A connection's first Identify starts at swarm registration, before any swarm exchange sample exists, so it always falls back to the configured deadline (30 s by default, covering its negotiation, #496). Direct transport handshakes (including TCP's Noise + Yamux upgrade) precede registration.
- **Loaded delay comes from queueing, not steady RTT.** On slow links under bulk traffic, delay is set by flow-control windows parked in the bottleneck queue (QUIC's 1.25 MB stream window and native TCP's 1,664 KiB Yamux window, ADR 0120). Only successful exchanges produce samples, so a quiet connection's low sample goes stale and misses a sudden bulk spike, while a slow or adversarial peer can inflate its own deadlines by replying slowly.
- **There is no uniform RTT source.** `Transport` offers no common RTT accessor: `QuicTransport` exposes its estimate externally only through the `diagnostics` API, TCP has no RTT estimate (Yamux keepalive does not probe on busy connections), and libp2p ping only runs when the host asks.
- **Explicit tuning is preferred over an adaptive estimator.** Raising the fixed deadlines in the v0.11.2 netem retests resolved the 1 Mbit/s second-connection failures; since then, first Identify gained a 30 s default covering negotiation (#496/#503), TCP gained a shallow ciphertext queue (#477/#511) and keepalive fixes under fair sharing (#497/#512), and slow-link deadline and QUIC receive-window tuning are documented (`crates/minip2p/README.md`, `QuicLimits`, `TcpConfig`). We accept explicit tuning rather than adding a per-connection latency estimator, variance tracker, and dual-timeout plumbing across the swarm and ping protocol, without re-running the full #469 netem matrix.

## When to revisit

Revisit if real deployments on long-lived connections hit changing-RTT failures where static `SwarmTimeouts` cannot balance success rate against acceptable failure time. Measure the failing profile with current defaults and explicit receive-window sizing (`QuicLimits::stream_receive_window`, `TcpConfig::default()`) first; if scaling is still needed, test a per-connection exchange-latency estimator (`srtt + 4 × rttvar`, timed from `StreamOpened`, bounded by a measured ceiling) on negotiation and ping before touching Identify.

## Prior requests

- #483: "swarm: scale negotiation and liveness deadlines automatically with measured RTT"
