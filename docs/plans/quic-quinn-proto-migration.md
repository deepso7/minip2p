# Plan: run `minip2p-quic` on quinn-proto

> **Status:** Proposed. Approved after three review rounds with gpt-6.1-sol (high): round 1 rejected it pending changes, round 2 approved with changes, round 3 approved. Research and measurements: [quinn-proto migration research](../research/quinn-proto-migration.md). Spike: [`docs/research/quinn-proto-spike/`](../research/quinn-proto-spike/).

## Goal

Replace quiche/BoringSSL under `transports/quic` with quinn-proto + rustls (ring), and later quinn-udp. The public surface stays as it is:

- types: `QuicEndpoint`, `QuicTransport`, `DualQuicTransport`, `QuicNodeConfig`, `QuicLimits`, `STREAM_RECEIVE_WINDOW`, and the `diagnostics` items;
- the `Transport` / `BlockingTransport` contract, with its ADR 0012 backpressure semantics.

Non-goals:

- **No async.** The `quinn` crate is not used.
- **No `no_std` QUIC.**
- **No change to the TCP stack.**
- **No change to how std transports wait.** Owned sockets and the readiness wait stay as they are; ADR 0013 / #248 change waiting separately.

## Outcome

- `boring`, `boring-sys`, `quiche`, the `[patch.crates-io]` fork, the BoringSSL bindgen workarounds, and the CMake/libclang steps in CI, Docker and bench images are all gone.
- On std UDP, QUIC throughput is no worse than today's `endpoint_throughput/quic`, measured on the same host before and after. With quinn-udp it is several times higher. Spike numbers are exploratory and promise nothing.
- Every existing QUIC contract and e2e test passes, rewritten only where it reached into quiche.
- Interop holds against rust-libp2p 0.57 and against the last quiche-based minip2p release.

## Decisions

1. **Engine: quinn-proto `0.11.x`** with `default-features = false, features = ["rustls-ring"]`, pinned to a minor version.
2. **TLS: rustls `0.23`** with the `ring` provider, TLS 1.3 only, ALPN `libp2p`. aws-lc-rs is not used (heavier build, no current need for FIPS).
3. **Socket I/O.** PR 1 keeps today's std `UdpSocket` `send_to`/`recv_from`, so behaviour parity is measured without changing I/O. PR 2 adds quinn-udp (GSO, GRO, ECN, pktinfo).
4. **Clocks.**
   - quinn's connection timers take `now: Instant`. Each `poll` samples `Instant::now()` once and passes it everywhere, and calls made between polls sample their own.
   - Deadlines are mapped onto the host's timeline the same way as today: anchor to the poll's `Now`, round non-zero delays up to a whole millisecond.
   - The host's millisecond `Now` is never handed to quinn as time; on loopback that halved throughput in the spike.
   - Retry token issue and expiry use `ServerConfig::time_source`. Production keeps quinn's system-time default, which is parity with today's `unix_time_secs()` for Retry. Tests inject a `TimeSource` to make expiry deterministic.
5. **Peer authentication happens inside the handshake.** Custom rustls `ServerCertVerifier` and `ClientCertVerifier` (the spike's `tls.rs`) do three things:
   - require exactly one certificate;
   - run `minip2p_tls::verify_libp2p_certificate` against host time, through a rustls `TimeProvider` that reads an `Arc<AtomicU64>` the transport updates on each `poll` from `Now::unix_seconds`, falling back to the system clock (the host-clock semantics are unchanged);
   - check CertificateVerify with `rustls::crypto::verify_tls13_signature_with_raw_key` against the certificate's SPKI.

   A dialer builds a per-dial rustls `ClientConfig` whose verifier carries the expected `PeerId`. It shares one `Arc<CertifiedKey>` and the provider, so the per-dial cost is a few `Arc` clones. A wrong identity aborts the handshake with a TLS alert. The local caller gets `TransportEvent::Error { message }`, which carries the rustls error text, then `Closed`, and never `Connected`.

   **Behaviour change:** the peer sees a TLS alert instead of today's application close codes `0x01`–`0x04`. After `Connected`, the verified `PeerId` is read once from `crypto_session().peer_identity()`.

6. **Connection token = TLS exporter.** `export_keying_material(32 bytes, label "minip2p quic connection token", context empty)`. quinn-proto doesn't expose connection IDs. The exporter is bound to the session, as TCP's Noise hash is.

   **Accepted rollout limitation:** a quiche-based peer computes a different token. In a same-direction connection race between mixed versions, the two sides can keep opposite connections and close both. Nothing restarts a settled direct dial, so recovery needs an application or discovery redial, and a repeat race can fail the same way. Release notes recommend upgrading every node that dials, including relays, together. Keeping CID-derived tokens would mean parsing handshake headers that quinn-proto owns, which was rejected (see research).

7. **Inbound admission and Retry.** In this order, for each `Incoming`:
   1. Before `listen()`, the endpoint has no server config, so quinn never reports `NewConnection`. It does generate a stateless reply (a reset) for an unknown Initial, so the adapter **drops every `DatagramEvent::Response` while not listening**. `ConnectionEvent`s for its own outbound connections are still delivered. The result is no state and no response, as today, where the adapter accepts only after `listen()`.
   2. At `QuicLimits::max_connections` → `endpoint.ignore`. As today, the capacity check comes before Retry.
   3. When `require_address_validation` is set and `!incoming.remote_address_validated()` → `endpoint.retry`.
   4. Otherwise → `endpoint.accept`.

   Config: `retry_token_lifetime(10 s)`, today's value, and `validation_token_config(.. sent(0))`, so no NEW_TOKEN is issued and Retry stays the only validation path. quinn's random per-process token key replaces `retry_secret`, and the hand-rolled HMAC token code and its tests are deleted. `dial` checks `max_connections` as today.

8. **Keepalive.** `keep_alive_interval(keepalive_interval_ms(idle_timeout_ms))`, keeping today's clamp `idle_timeout_ms.max(2) / 2`, so a 1 ms idle timeout never yields a zero interval. The custom keepalive code is deleted. A keepalive restarts the idle timer once per receive (RFC 9000 §10.1), as with quiche today, so a dead path closes after roughly the keepalive interval plus the idle timeout.
9. **Defaults, all set explicitly and recorded in the crate README.**
   - stream receive window `STREAM_RECEIVE_WINDOW` (1,000,000) and connection receive window 10,000,000, fixed (quinn doesn't autotune);
   - `send_window` 10,000,000;
   - `max_concurrent_bidi_streams = max_streams_per_connection` and `max_concurrent_uni_streams = 0`;
   - `datagram_receive_buffer_size(None)`, so QUIC DATAGRAM is not advertised, as today;
   - `max_idle_timeout = idle_timeout_ms` (0 is still rejected);
   - PMTU discovery on, quinn's default (initial 1200, probing up; replaces the fixed 1350);
   - CUBIC congestion control, quinn's default;
   - connection migration on, quinn's default, matching quiche's passive migration. `ConnectionEndpoint` keeps the handshake address, as today.
10. **Recorded wire change: unknown-CID packets.** quinn's `Endpoint` answers an unknown-CID short-header packet with a rate-limited stateless reset (`min_reset_interval`). Today such packets are dropped silently. This is the RFC 9000 §10.3 behaviour and is accepted. Routing still never uses the source address. The README's routing paragraph is updated to say so.
11. **Code layout inside `transports/quic`.** `tls.rs` is new. `connection.rs` wraps `quinn_proto::Connection` plus today's stream bookkeeping. `lib.rs` keeps the socket, the wait and the public types, and now owns a `quinn_proto::Endpoint` per socket instead of a `quiche::Config`. The engine is reached through a few calls (handle datagram, service connection, next timeout), so #247 can later move both sockets onto one `Endpoint` without touching stream logic.

## PR stack

### PR 1 — `quic: run on quinn-proto and rustls` (the swap)

Organized as reviewable commits.

**1a. TLS module.**

- `transports/quic/src/tls.rs` holds the verifiers from the spike, plus the `TimeProvider` and per-dial expected-`PeerId` support from Decision 5.
- Add `minip2p_tls::certificate_spki(cert_der) -> Result<Vec<u8>, TlsError>`. minip2p-tls already parses with x509-cert, so the QUIC crate doesn't take on `x509-cert`/`der`.
- Unit tests:
  - one certificate accepted, two rejected, none rejected;
  - a certificate whose libp2p extension doesn't match its key is rejected;
  - CertificateVerify signed by a different key is rejected;
  - a certificate outside its validity at host time is rejected even when the system clock would accept it;
  - an expected-`PeerId` mismatch is rejected.

**1b. Engine and connection rewrite.**

**Endpoint.** One per socket, created with `server_config: None`. `listen()` installs the server config with `set_server_config`. Until then, `Response` events are dropped (Decision 7).

**Receive.** Same bounded batch as today: at most `MAX_DATAGRAMS_PER_POLL` datagrams, `recv_from` into a reused buffer, `BytesMut::from(&buf[..len])`, then `endpoint.handle(now, from, None, None, data, &mut buf)`.

- `ConnectionEvent(ch, ev)` → `conn.handle_event(ev)`, and mark `ch` for service.
- `NewConnection(incoming)` → Decision 7. An accepted connection allocates a minip2p `ConnectionId`, maps it to and from the `ConnectionHandle`, and emits `IncomingConnection` (pre-auth, as today).
- `Response(transmit)` → best-effort stateless send, as today's `send_stateless_datagram`.
- A malformed datagram is dropped without failing the poll, as today.
- The batch records whether it hit its cap (`recv_saturated`) for `next_deadline`.

**Servicing one connection.** Today's sweep runs this for every connection; #328 narrows it later. Repeat until a pass produces nothing new, capped at a small fixed number of passes:

1. `handle_timeout(now)` if `poll_timeout() <= now`.
2. Drain `poll()` app events into the stream logic below.
3. Drain the adapter's send queues and any deferred opens.
4. Pump `poll_endpoint_events()` through `endpoint.handle_event`, and feed every returned `ConnectionEvent` back with `conn.handle_event`. For example, `NewIdentifiers` queues NEW_CONNECTION_ID frames.
5. `poll_transmit(now, 1, &mut buf)` until `None`, retaining on `WouldBlock` exactly as `send_or_retain` does today. Endpoint events are pumped before this final transmit pass, so their output leaves in the same service.

Then cache `poll_timeout()` (quinn needs `&mut self`, while `next_deadline` takes `&self`). Once the connection `is_drained()`, remove it and emit `Closed`.

Every `Transport` call that mutates a connection (`send_stream`, `close_stream_write`, `reset_stream`, `ack_stream`, `open_stream`, `close`) ends by servicing that one connection, so the cached timeout and any output stay current.

**Connection events.**

- `Connected` → read the verified `PeerId` from `peer_identity`, set the token (Decision 6), update the peer index, and emit `Connected`, plus `PeerIdentityVerified` when the peer id changed, as today.
- `ConnectionLost { reason }` → `TransportEvent::Error { message: reason }`, **except** for a local close (`LocallyClosed`) and an orderly peer close (`ApplicationClosed` or `ConnectionClosed` with error code 0). Those emit only `Closed`, matching quiche, whose orderly peer close drains and then reports `Closed` without an error. `Closed` follows on drain in every case.
- `HandshakeDataReady` → ignored.

**Stream events.**

- `Opened { dir: Bi }` → `accept(Bi)` loop. For each accepted stream:
  - run `ensure_stream_discovered`, keeping today's refusal rule: while held remote streams are at `max_streams_per_connection`, call `stop(0)` and `reset(0)` and emit nothing;
  - if the stream is admitted, **scan it once immediately**: a new stream's first frame raises `Opened` only, never `Readable`, so a one-packet request with FIN would otherwise stall.
- `Readable { id }` → scan the stream.
- `Writable { id }` → drain that stream's queue.
- `Stopped { id, error_code }` → the stop path: call `send_stream(id).reset(error_code)` first. quinn only records the stop; quiche reset the send half itself, which discards buffered sends and sends RESET_STREAM. Then run `note_write_stopped`, which drops the adapter queue, closes the write half, emits `StreamWriteStopped` once and keeps the read half open.
- **Ordering of terminal events.** quinn delivers `Opened` ahead of queued stream events, so a scan can see a reset before the `Stopped` event for the same stream is processed. Every scan therefore first checks `send_stream(id).stopped()` and runs the stop path when it reports a code. Events for a stream already reported `StreamClosed` are ignored. This keeps the contract in `crates/transport/src/event.rs`: nothing for a stream after its `StreamClosed`.
- `Available { dir: Bi }` → bind pending opens (below).
- `Finished` → ignored; half-close bookkeeping is the adapter's, as today.

**Reads (ADR 0012).** A scan calls `recv_stream(id).read(true)` and then loops:

- **With budget left** (`room > 0`), call `chunks.next(room)`:
  - `Some(chunk)` → append its bytes to the stream's read buffer and charge `unacked`;
  - `None` → record FIN;
  - `Err(Reset(_))` → record reset;
  - `Err(Blocked)` → stop.
- **With the budget spent**, do one terminal probe, `chunks.next(0)`:
  - `Some(empty)` → data is still waiting, so stop with the stream gated;
  - `Err(Blocked)` (no contiguous bytes yet: a payload of exactly one window without FIN, or data behind a gap) → stop, still gated;
  - `None` → record FIN;
  - `Err(Reset)` → record reset.

  The probe runs at most once per scan and never emits empty `StreamData`. This keeps today's rule that a FIN or reset right behind the window still surfaces.

After the loop, `finalize()`, then emit in this order:

1. the copied `StreamData`, if any;
2. the recorded terminal outcome:
   - FIN → `StreamRemoteWriteClosed` and the close check;
   - reset → **reset the engine's send half** (`send_stream.reset(0)`; quinn's reset read frees only the receive half, and remote stream credit needs both halves freed), then `note_stream_reset`.

Data therefore always precedes FIN, `StreamClosed` and reset, as today. Finally, service the connection if `finalize()` reported `should_transmit`.

**Copying.** What one scan read is emitted as **one copied `Bytes`** of exactly that length: one `StreamData` per stream per scan, as today. Chunks can be slices of larger packet allocations (a whole GRO buffer, in PR 2), and passing them on would pin memory that ADR 0012's receive budget doesn't count. Zero-copy delivery is a possible later optimization, only with an ownership bound.

**Gated streams.** A stream with its budget spent is kept in a `gated: BTreeSet<StreamId>`. `ack_stream` re-scans exactly those streams, with no packet and no event. This replaces `streams_dirty` plus scanning all readable streams.

**Writes.**

- Keep the adapter queue, `max_pending_stream_bytes`, `Full { unsent }`, and the half-free `StreamWritable` rule unchanged.
- The direct write uses `send_stream(id).write_chunks(&mut [bytes])`; a partial write leaves the unsent tail in place.
- `Blocked` queues the rest. `Stopped(code)` follows the same path as the `Stopped` event. `ClosedStream` → `StreamSendFailed`.
- FIN is `finish()`. `reset_stream` is `send_stream.reset(0)` plus `recv_stream.stop(0)`, and a `ClosedStream` error there counts as already done, like quiche's `Done`.

**Opens past peer credit.** quinn's `streams().open(Bi)` returns `None` without peer stream credit and only advances its ids on success. Today `open_stream` succeeds below the local cap and writes queue until credit arrives. The plan keeps that with a pending-open queue whose ids are never cancelled:

- `open_stream` hands out the next sequential local bidi id and pushes it onto `pending_opens` (FIFO). Writes and FIN for it queue in the adapter.
- Whenever service runs (and on `Available`), the pending opens are bound in FIFO order with `open()`. quinn returns ids in the same sequence because the adapter is the only opener. A mismatch fails the connection with an internal error (`fail_connection`), not just a `debug_assert`.
- `reset_stream` on a pending stream behaves like any local reset towards the caller, immediately:
  - its queued bytes and FIN are discarded and their byte accounting freed;
  - its writable is disarmed, and the shared-cap wakeup runs;
  - exactly one `StreamClosed` is emitted, and its stream state is dropped.

  Only its id, marked `reset_on_bind`, stays in `pending_opens`, so the id sequence never diverges.

- Binding a `reset_on_bind` entry calls `open()`, then `send_stream.reset(0)` and `recv_stream.stop(0)`, before any queue drain.
- **Slot accounting.** Each `pending_opens` entry holds one reservation against `max_streams_per_connection`, separate from stream state. Stream-state GC therefore can't release it early. A live pending stream's reservation becomes its open stream's slot when it binds. A `reset_on_bind` entry releases its reservation exactly once, when it binds. The queue is therefore bounded by the local cap.

**Close.** `conn.close(now, 0, b"bye")` sets the state to `Closing` and clears armed writables, as today. A failed send under `fail_connection` becomes `close(now, 1, b"stream send failed")`.

**Dropping the transport** keeps today's order (`lib.rs` `Drop`): retry retained datagrams, close every connection, service each once, and retry retained datagrams again. A close on drop ignores pacing, as today; there is no paced-packet hold left to flush.

**`next_deadline`.**

- Pending events or a saturated receive batch → `IMMEDIATE`.
- Pending retained datagrams → `+1 ms`.
- Otherwise, the earliest cached connection timeout mapped through the poll anchor with millisecond round-up. The keepalive deadline is now part of quinn's timeout.

**`diagnostics` feature**, rebuilt on `Connection::stats()`:

- received datagrams, `udp_tx` datagrams and bytes, flushes, lost packets, cwnd, rtt;
- `DatagramTally` socket counters stay;
- fields that only made sense for quiche (`quiche_done`, `window_limited_packets`) are removed and the bench docs updated;
- the `ConnectionDiagnostics` field changes are a breaking change to a feature-gated API, which is acceptable pre-1.0.

**1c. Tests.**

- **Keep and adapt:** `transport_contract.rs` (wording only where it names quiche), `ping_e2e.rs`, `swarm_e2e.rs`, `stream_send_tests.rs`, `recv_batch_tests.rs` (bounded batch, a poisoned queued datagram, sub-millisecond deadlines), plus the dual-stack and wait tests in `lib.rs`.
- **Rewrite** `two_peer.rs`'s raw-quiche peers as raw quinn-proto peers with hand-built rustls configs: no client certificate, a two-certificate chain, an invalid libp2p certificate, the wrong peer id. Assert `Error` then `Closed` and no `Connected`.
- **Rewrite** `cid_routing.rs`: two quinn-proto clients sharing one UDP socket connect to one `QuicTransport`, and each connection gets only its own data. This guards the "never route by source address" rule at the adapter level.
- **Replace** the Retry token unit tests with behaviour tests (with an injected `TimeSource`):
  - with validation required, an Initial without a token gets a Retry and creates no connection state;
  - a garbage or expired token creates no state;
  - the handshake completes through Retry.
- **New admission tests:**
  - before `listen()`, an Initial creates no state and gets no response;
  - at `max_connections`, an Initial creates no state and gets no Retry.
- **New stream tests**, each derived from one of round 1's findings:
  - a one-packet request with FIN on a new inbound stream is delivered, with no further traffic, and the full event order is `IncomingStream`, `StreamData`, `StreamRemoteWriteClosed` (and `StreamClosed` when the local half is already closed);
  - a FIN exactly at the receive-budget boundary surfaces while gated, and so does a reset, in both cases after the window's `StreamData`;
  - an exact-window payload without FIN stays gated (`Blocked` probe) and resumes on ack;
  - RESET_STREAM and STOP_SENDING in the same packet on a new stream: `StreamWriteStopped` comes before `StreamClosed`, and nothing follows `StreamClosed`;
  - RESET_STREAM alone, with outbound data buffered in the engine: the send half is reset, buffers are released, and the peer's stream credit returns;
  - before `listen()`, an unknown Initial produces no datagram at all (no stateless reset), while an outbound connection on the same socket still works;
  - a gated stream resumes on `ack_stream` with no new packet;
  - STOP_SENDING: the sender's engine buffer is released and RESET_STREAM is sent, the read half keeps working, and the stopped stream's slot is reusable once it settles;
  - tiny payloads arriving in many separate packets with small acks: each emitted `StreamData` owns an allocation of its own length, checked by a capacity assertion on the copied buffer;
  - opens past peer credit: open, open, queue bytes and FIN on the first, reset it, open again, then grant credit. The reset stream's queue is released at once, with one `StreamClosed`, and other writers are woken. Slot accounting never exceeds the cap. Every surviving stream binds to the id it was given and its queued bytes arrive in order. The reset one is reset and stopped on the wire when it binds;
  - an orderly peer close yields `Closed` with no `Error`, and a TLS rejection yields `Error` then `Closed`;
  - DATAGRAM is not advertised (the peer's transport parameters report no `max_datagram_frame_size`);
  - keepalive with a short idle timeout (for example 400 ms): a live idle connection survives several idle periods, and a dead one closes;
  - both ends see the same token.
- `crates/minip2p` tests (`bulk_backpressure`, `simultaneous_dial`, `nat_tests`) must pass unchanged.

**1d. Build, CI and docs cleanup.**

- **Root `Cargo.toml`:** drop `[patch.crates-io]` for boring. In `transports/quic/Cargo.toml`, replace `boring` and `quiche` with `quinn-proto`, `rustls`, `bytes` (already in the lockfile), and drop `hmac` if nothing else uses it.
- **Lockfiles:** regenerate the workspace lockfile and every standalone one CI checks with `--locked`, including `fuzz/Cargo.lock` and `bindings/` lockfiles.
- **Native-build workarounds:**
  - `.cargo/config.toml`: remove `BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_darwin`;
  - `.github/workflows/bindings-native.yml` and `publish.yml` musl jobs: remove `clang20-libclang` and `LIBCLANG_PATH` (keep `CC`/`CXX` if ring's `cc` build needs them);
  - `infra/bench/Dockerfile` and `scripts/relay-builder.Dockerfile`: drop `cmake`, `libclang-dev` and `clang` where only boring needed them, and verify by building the images.
- **Docs and glossary:**
  - `transports/quic/README.md`: rewrite the summary, Clocks (connection timers on the adapter's `Instant` sample; Retry on a system-time `TimeSource`), Routing (Decision 10), Authentication Notes (rejection inside the handshake; the TLS alert instead of app close codes) and Diagnostics. Remove the boring 4.x note.
  - Update the crate rustdoc.
  - `AGENTS.md`, root `README.md` and `docs/pages/index.astro`: "quiche-based" → "quinn-proto-based".
  - `crates/transport/README.md`: QUIC still keeps a fine-grained clock internally, but it is now the adapter's sample.
  - `crates/minip2p/README.md`: remove the BoringSSL allocation note.
  - `GLOSSARY.md` **Connection token**: "QUIC: a TLS exporter value". Update the matching rustdoc in `crates/transport/src/connection_token.rs`.
  - ADR 0012: replace the quiche-specific wording with engine-neutral wording ("the QUIC engine returns credit when bytes are read").
  - New **ADR 0014 "QUIC engine: quinn-proto + rustls"**: the decision, the rejected alternatives (from the research doc), the token change and the accepted rollout limitation.
- **Release notes for the next minor version:** the token change and the coordinated-upgrade recommendation, rejection signalling, stateless-reset replies, PMTU discovery, and the CID length (8 bytes, down from 20).

**Exit criteria for PR 1:**

- `just test`, `just clippy`, `just fmt` and `just check-nostd` are green.
- `cargo tree -i boring` and `cargo tree -i quiche` print nothing.
- `endpoint_throughput/quic` is no worse than `main` measured on the same host in the same session; both numbers go in the PR.
- `endpoint_idle` wakeups are unchanged.
- A manual dispatch of `bindings-native.yml` at the PR head with mobile builds enabled is green, linked in the PR. That workflow doesn't run on pull requests.
- Manual interop, recorded in the PR: rust-libp2p 0.57 in both directions, and the last quiche-based release in both directions, using the spike's peers.

### PR 2 — `quic: quinn-udp socket I/O (GSO, GRO, ECN)`

Wrap each socket in a `quinn_udp::UdpSocketState`.

**Limits stay in logical datagrams.** `max_pending_datagrams` keeps counting individual UDP datagrams, not GSO transmits, so retained memory doesn't grow by the segment count.

**Sending.**

- Before every `poll_transmit`, recompute the allowance: `max_pending_datagrams` minus the retained datagrams. When it is **zero**, stop polling output; this is today's guard, and quinn panics on `max_datagrams == 0`. Otherwise call `poll_transmit(now, min(state.max_gso_segments(), allowance), ..)`. A retained transmit keeps its `segment_size` and counts as `contents.len().div_ceil(segment_size)` datagrams.
- Test: a small `max_pending_datagrams` with forced `WouldBlock`. No panic, and logical-datagram accounting stays within the cap.
- Sending uses `try_send`, and `enable_segmentation_offload` stays on.
- On Linux/Android, when a GSO send fails with `EIO`/`EINVAL`, quinn-udp switches later transmits to single datagrams. The failed batch itself comes back as an error and is treated as lost, so loss recovery resends it.
- Add a test that forces `max_gso_segments == 1`.

**Receiving.**

- `recv` with GRO into one buffer sized `gro_segments() × 64 KiB`, split by `meta.stride`. `meta.ecn` and `meta.dst_ip` are passed to `endpoint.handle`, and transmits pass `ecn` and `src_ip`.
- `MAX_DATAGRAMS_PER_POLL` counts **logical datagrams**: the batch stops issuing `recv` calls once the count reaches the cap. It always finishes splitting the GRO buffer it already read, so it overshoots by fewer than one GRO batch (Linux GRO allows up to 64 segments). That bound is documented, and needs no remainder state.
- A saturated batch reports `IMMEDIATE` through `next_deadline`, as in PR 1.

**Unchanged:** `send_raw_udp` stays a plain `send_to`, since it isn't QUIC traffic, and the readiness wait still works by peeking.

**Exit:**

- `endpoint_throughput/quic` and `relayed` before and after numbers in the PR;
- a `bindings-native.yml` dispatch with mobile enabled, plus macOS and Windows builds;
- a test that a burst larger than the cap is fully consumed without a second readiness edge.

This closes the socket-I/O items of #243. Socket buffer sizes and memory budgets stay under #243.

### Follow-ups (separate issues, not part of this plan)

- **#247:** one `QuicTransport` with one quinn `Endpoint` serving the v4 and v6 sockets, choosing the socket by the transmit's destination family.
- **#328:** service only the connections that received a `ConnectionEvent`, have a due timeout, or were touched through the API. Keep an ordered timer index instead of folding over every connection.
- **#248 / ADR 0013:** register the socket(s) with the swarm's shared poll. Its edge-triggered contract maps onto the `recv_saturated → IMMEDIATE` rule above.
- **Optional:** zero-copy `StreamData` with a bounded-ownership rule, only if measurements show the copy matters.

## Sequencing with open work

- Land **PR 1 before #247** where possible. #247 is simpler after the swap, because quinn's `Endpoint` already serves several sockets. If #247 lands first, PR 1 rebases onto one transport type and nothing in the plan changes except where the `Endpoint` lives.
- Close **#315** (DCID routing without a quiche `Header`) when PR 1 lands.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Edge-triggered `Readable` loses data (first frame, gated streams) | Scan on accept, the `gated` set, the terminal probe, and the tests in 1c |
| Pending-open ids diverge from quinn | Ids are never cancelled (reset-on-bind), the queue is bounded by the local cap, and a mismatch fails the connection; open/reset/open test |
| STOP_SENDING or RESET_STREAM leaves engine-buffered data or stream credit stuck | Explicitly reset the engine's other half in both paths; tests assert release and credit reuse |
| Terminal events out of order (FIN before data, stop after close) | Terminal outcome recorded and emitted after data; stop checked before every scan; event-order tests |
| Retained memory exceeds ADR 0012's bound | Copied, exactly-sized `StreamData`; capacity test |
| Mixed-version same-direction race closes both connections | Accepted and documented; coordinated upgrade recommended in release notes |
| quinn-proto minor bump breaks the API | Pin `0.11.x` and upgrade deliberately in its own PR |
| Throughput regression from adapter overhead (copies, queues) on std UDP | The PR 1 exit criterion against `main` on the same host |
| A target fails to build ring or quinn-udp | `bindings-native.yml` dispatch with mobile enabled is an exit criterion for both PRs |

## Rollback

PR 1 is a single revert. The public API is unchanged, so no downstream code needs to move.
