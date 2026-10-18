# Drop transport memory budgets

Supersedes the memory-budget and default-sizing decisions of ADRs 0019 and 0021. Those ADRs gave each transport (QUIC, TCP, and the circuit transport) a memory budget, with a memory reservation for every connection and stream, and sized the default windows against it. Nothing has needed those bounds yet, and they took a lot of machinery: a shared ledger, `*_within` variants through secure-mux and Yamux, settled-stream reporting, NAT circuit claims, and the relay binary's budget arithmetic. Making the windows grow with the path (#379) would have added more: quinn has no live per-stream window setter, and growing only the connection window loses the margin that keeps a stalled stream from starving the rest. The 2,432 KiB Yamux default from ADR 0021 also slowed relayed traffic (`endpoint_ping_load/relay` p50 went from about 300 µs to about 1,000 µs; Fargate QUIC p99 from 971 µs to 30.7 ms, #379). We decided (#403):

- **No memory budgets.** `MemoryLedger`, every `memory_budget_bytes` field, the `*_reservation_bytes` helpers, the Yamux and secure-mux `*_within` variants with their settled-stream reporting, circuit claims (`hold_circuit_claims`, `BridgeAdoption::claimed`, `AdoptError::BudgetExhausted`) and the relay binary's budget sizing are gone. Memory is bounded by counts, windows and queues, as before ADR 0019.
- **Static windows that hosts set by hand.** `QuicLimits` keeps `stream_receive_window`, `connection_receive_window` and `send_window`, now defaulting to quinn's own: a 1,250,000-byte stream window, an unlimited connection window (`VarInt::MAX`; any value past what QUIC can express is unlimited), and a 10,000,000-byte send window. `YamuxConfig::receive_window` goes back to the specification's 256 KiB. No window grows with the path.
- **What stays from ADR 0019.** `max_connections` counts across all of a transport's sockets; Retry is unchanged (on for every inbound connection by default); the windows are `QuicLimits` fields; the send-queue caps (`max_pending_connection_bytes` and the per-stream caps), the control reserve and round-robin admission; the Apple fast-path `unsafe` exception. An inbound connection is refused only at `max_connections`, silently and before Retry, so there is no `CONNECTION_REFUSED` path any more.
- **What stays from ADR 0021.** Yamux's `max_streams`, the 4 MiB send cap and `max_pending_control`; the decoder limits (`MAX_INPUT_BATCH`, the one-Noise-message cap on `unsent_prefix`, inbound frames limited to the receive window while `max_frame_len` caps only outbound frames); `TooManyStreams` as `ResourceExhausted { resource: "Yamux streams" }`; `TcpConfig::validate` and `CircuitLimits::validate` returning `InvalidLimit` when the Yamux invariants fail; the `tcp_config` and `circuit_limits` builder options; NAT's `max_circuits` slots.
- **ADR 0012 is unchanged.** Unsettled streams and connections keep their slots; that and the windows are the receive bound.

## Trade-off

With the connection window unlimited, one stalled stream cannot spend credit the connection's other streams need. In exchange, nothing bounds a connection's received data in aggregate. The worst case per connection is about the stream limit times (delivered but unacknowledged bytes + what the engine buffers behind the gate), each up to one window. For QUIC's defaults that is 128 × (1.25 MB + 1.25 MB), about 320 MB. For Yamux it is 256 × 256 KiB of delivered data, 64 MiB, plus the send caps. Transport-wide it is that times `max_connections`. Hosts that need a tighter bound lower the windows, the stream limit or the connection limit.

## Rejected alternatives

- **Keeping the budgets with growing windows (#379).** It needs per-stream window changes quinn does not offer, and growing the connection window alone brings back the starvation the static margin prevented.
- **Keeping the budgets with static windows.** It is machinery nothing has needed yet; it can come back, in ADR 0019's terms, when a deployment has to bound memory in aggregate.
- **A bounded default connection window.** Any bound small enough to matter lets a few stalled streams starve the others, the problem ADR 0019's sizing only worked around.

## Consequences

- Yamux goodput on long, fat paths drops back to what a 256 KiB window allows. That is intended; hosts that need more raise `receive_window`. On `endpoint_rtt` (100 Mbit/s, 100 ms) TCP falls from 10.97 MB/s (92% of the link) to 1.53 MB/s (13%), and QUIC on quinn's windows from 11.06 MB/s (93%) to 10.25 MB/s (86%).
- Relayed latency returns to its pre-#385 level, since circuit sessions no longer advertise multi-megabyte windows to the relay: `endpoint_ping_load/relay` p50 goes from 974 to 356–423 µs over TCP and from 940 to 209–246 µs over QUIC (on mito, against the commit before this change).
- Loopback throughput over Yamux gives back what #385's window gained: `endpoint_throughput/tcp` from 815 to about 405 MB/s and `relayed` from 401 to about 271 MB/s on mito. QUIC loopback is unchanged (740 → 716–732 MB/s).
- An embedded host sizes memory from its counts, windows and queues (`docs/md/rust/embedded-devices.mdx`).
- Exposing the windows and the connection and stream limits through FFI and the SDKs is #382.
