# Circuit Relay v2 Relay Server for minip2p (seed draft)

> **Status:** Non-canonical seed for the Wayfinder effort. The map and its
> decision tickets are authoritative for unresolved questions. Revise and mark
> this document validated only after the map closes.
>
> **Reference pins:** rust-libp2p `libp2p-relay` 0.22 at
> [`170c3c81ddd80e7c58b0500563e00a09139e8545`](https://github.com/libp2p/rust-libp2p/tree/170c3c81ddd80e7c58b0500563e00a09139e8545/protocols/relay)
> and the Circuit Relay v2 specification at
> [`6b6203ee6f62938ce67efdb33498173f475851c0`](https://github.com/libp2p/specs/blob/6b6203ee6f62938ce67efdb33498173f475851c0/relay/circuit-v2.md).

## Context

minip2p ships the full **client** side of Circuit Relay v2 (`HopReservation`/`HopConnect`/`StopResponder` in `crates/relay`, `CircuitTransport`, `NatAgent` orchestration), but no relay **server** — docs point users at rust-libp2p's relay. Server-ish code exists only as limit-less test fixtures (`tests/support/relay.rs` `RelayMachine`, `crates/test-support` `RelayEmulator`).

This adds a production relay server matching rust-libp2p `relay::Behaviour` semantics (protocols/relay v0.22.0, verified in source), layered sans-I/O like the NAT stack.

**Scope decisions (confirmed):** full-stack layering with an Endpoint `relay-server` feature; no reservation voucher (`voucher: None`, like rust-libp2p); ship `examples/relay-server`; full limits parity including per-peer/per-IP rate limiters with rust-libp2p defaults.

**rust-libp2p reference values:** `max_reservations=128`, `max_reservations_per_peer=4`, `reservation_duration=3600s`, `max_circuits=16`, `max_circuits_per_peer=4` (peer counted as src OR dst), `max_circuit_duration=120s`, `max_circuit_bytes=128KiB`, rate limits: reservations per-peer 30/120s + per-IP 60/60s, circuit-src same; reservations live per (peer, connection), renewed by re-RESERVE on the same connection; HOP denied on relayed (circuit) connections.

A second-round review suggested further corrections; each was verified against source and adopted, adapted, or rejected as noted inline (see "Connection identity" for the main adaptation).

## Crate responsibility boundary

```text
crates/relay                 One stream: what bytes should be parsed or produced?
crates/relay-server          Whole service: should this request be accepted, which
                             reservation owns it, which streams form the circuit,
                             and where should data go?
crates/minip2p/std/relay_server.rs   I/O adapter: execute agent actions against Swarm.
```

- **`crates/relay`** keeps ALL wire protocol: messages (`HopMessage`/`StopMessage`/`Reservation`/`Limit`/`Status`), protocol IDs, framing helpers, wire errors, and the per-stream state machines — existing client roles (`HopReservation`, `HopConnect`, `StopResponder`) plus new relay-side roles (`HopResponder`, `StopInitiator`). Restructure into `src/{lib.rs, message.rs, client.rs, server.rs}` (client machines move from `lib.rs` into `client.rs`, re-exported unchanged). `server.rs` means relay-side **wire roles**, not an operational server. Each machine owns exactly one HOP or STOP stream and knows nothing about reservation/circuit tables, other streams, clocks/expiry, admission policy, rate limits, capacity, byte forwarding, or swarm APIs.
- **`crates/relay-server`** (package `minip2p-relay-server`) holds the whole sans-I/O service: `RelayServerAgent`, reservation + circuit tables, admission policy, expiry/timeouts, limits, peer/IP rate limiting, connection-scoped stream ownership, HOP↔STOP coordination, bridge-forwarding actions, byte/duration accounting, application events. Layout: `src/{lib.rs, agent.rs, config.rs, events.rs, limiter.rs, reservation.rs, circuit.rs, types.rs}` + `tests/`.
- `HopResponder`/`StopInitiator` stay in `crates/relay` beside the client machines — reusable wire primitives, not orchestration.

## Connection identity

> Never route relay-server traffic by PeerId + StreamId alone when an exact ConnectionId is available.

Facts verified in `crates/swarm/src/core.rs`:

- Every stream-scoped `SwarmEvent` already carries `conn_id` (`events.rs:48-73`).
- The swarm is **single-connection-per-peer, last-wins**: `register_connection` (`core.rs:994-1006`) supersedes any existing connection to the same peer; `supersede_connection` (`core.rs:1045`) synchronously emits `ConnectionClosed` for the old conn and purges its `stream_owner`/negotiator/action state. Stream lookups (`require_stream_conn`, `core.rs:811`) check the live `conn_to_peer` mapping, so a stale `(peer, stream_id)` from a superseded connection fails with `StreamNotFound` — it can never mis-route to the new connection.

Consequences (adapting the review's "add `open_stream_on`/`send_stream_on`/… swarm APIs" — **not needed for correctness** given the invariants above; noted in the relay-server README so it's revisited if the swarm ever goes multi-connection):

- The agent still keys everything by exact identity — that part of the review stands:

```rust
pub struct StreamKey { pub conn_id: ConnectionId, pub stream_id: StreamId }
struct ReservationKey { peer_id: PeerId, conn_id: ConnectionId }

pub enum RelayServerAction {
    OpenStream { token: RelayServerToken, dst: PeerId, conn_id: ConnectionId, protocol_id: String },
    SendStream { stream: StreamKey, peer: PeerId, data: Vec<u8> },
    CloseStreamWrite { stream: StreamKey, peer: PeerId },
    ResetStream { stream: StreamKey, peer: PeerId },
}
```

  (`peer` carried alongside `StreamKey` so the driver can call today's peer-keyed swarm APIs; `conn_id` is the authority for the agent's own tables and validation.)
- A reservation dies when its exact connection closes — supersession emits that `ConnectionClosed`, so a reconnecting peer's old reservation is dropped before the new connection registers. Renewal on the same `ReservationKey` replaces (never transiently consumes an extra global/per-peer slot).
- Opening STOP: driver uses the existing `open_stream_with_connection` (`runtime.rs:296`) and reports the returned `(conn_id, stream_id)`; the agent verifies the conn id equals the reservation's `conn_id` and treats a mismatch (supersession race window) as `NoReservation`. This closes the only real race without new swarm APIs.
- Only swarm addition required: `SwarmCore::remote_addr(&self, ConnectionId) -> Option<&Multiaddr>` over the private `conn_to_remote_addr` map (`core.rs:164`) — for the per-IP limiter.
- The review's "two simultaneous connections per peer" tests are not constructible in this swarm; replaced with **supersession tests** (see PR 2 tests).

## Staging — 4 PRs + follow-up

### PR 1 — Server wire roles in `crates/relay`

Restructure into `client.rs`/`server.rs` (pure move + re-export), then add, both `impl minip2p_core::SansIoProtocol` with `Error = RelayError`, reusing `decode_frame`/`checked_outbound_frame`/`enforce_max_size` (widen to `pub(crate)`):

- **`HopResponder`** — one inbound HOP stream, wire-level only. States: `AwaitingRequest → AwaitingDecision(Reserve|Connect) → ResponseQueued → Done | Bridged`. Transport lifecycle stays out of the wire machine: it has no `StreamClosed` input and no transport-level `Closed` state — the *agent* consumes `StreamClosed`/`ConnectionClosed` and tracks its own ownership states (see PR 2 lifecycle).
  - Input: `{Flush, Data(Vec<u8>), RemoteWriteClosed, AcceptReservation { reservation: Reservation, limit: Option<Limit> }, AcceptConnect { limit: Option<Limit> }, Deny(Status)}`
  - Output: `{Request(HopRequest::{Reserve, Connect { dst_peer_id: Vec<u8> }}), Outbound(Vec<u8>), BridgeData(Vec<u8>)}`
  - `AcceptReservation` goes through `checked_outbound_frame` (host addr list can overflow `MAX_MESSAGE_SIZE = 8192`). `AcceptConnect` releases residual `recv_buf` as `BridgeData` (same as `StopResponder::accept`); later `Data` in `Bridged` → `BridgeData`.
- **`StopInitiator`** — outbound STOP stream, near-verbatim mirror of `HopConnect` with `StopMessage` framing. `new(src_peer_id: Vec<u8>, limit: Option<Limit>)` queues `StopMessage{CONNECT, peer:{id: src, addrs: []}, limit}` (relay never forwards src addrs). Input `{Flush, Data, RemoteWriteClosed}` → Output `{Outbound, Outcome(StopConnectOutcome::{Accepted, Refused{status, reason}}), BridgeData}`, incl. pipelined-byte capture and the `pending_error` deferred-oversize pattern.
- **Malformed-request boundary** (one consistent rule; machine surfaces enough info for the agent to apply it):
  - Well-formed frame, wrong kind or missing required field → send the appropriate failure status (400 malformed / 401 unexpected) via `encode_hop_status(Status) -> Vec<u8>` (exported helper), then half-close.
  - Invalid framing, oversized declared frame, or no valid response formable → reset the stream. No overlap between the two rules.
- **Tests:** mirror the existing 21-test style — fragmentation, pipelined bridge bytes, deny, wrong-kind, missing peer on Connect, oversized declared frame, exact-max frame, accept-before-request error, SansIoProtocol conformance, input-after-`Done` behavior, `RemoteWriteClosed` in each state.
- **Fuzz:** `fuzz_relay_server(data)` in `fuzz/fuzz_targets/wire_inputs.rs` feeding arbitrary bytes into both machines' `handle_input`.
- Docs: `crates/relay/README.md` + module docs → "client and server wire roles".

### PR 2 — `crates/relay-server` (+ the one swarm accessor)

`no_std + alloc`, modeled on `crates/nat`. Deps: `minip2p-core`, `minip2p-relay`, `minip2p-swarm`, `minip2p-transport`, `minip2p-platform`, `thiserror`. Re-exports `HOP_PROTOCOL_ID`/`STOP_PROTOCOL_ID`. Includes the `SwarmCore::remote_addr` accessor.

**Config** (`config.rs`) — rust-libp2p defaults above, plus honestly-named stream protections:

```rust
pub max_pending_hop_requests_per_connection: usize,  // 10
pub control_stream_timeout_ms: u64,                  // 60_000
```

These bound *accepted* (post-negotiation) HOP streams awaiting a request/decision and the HOP/STOP exchange deadline — not "in-flight negotiations". **Documented deviation:** rust-libp2p additionally bounds concurrent stream *negotiations* per connection at the handler level (pre-`StreamReady`); minip2p's equivalent would live in `crates/swarm` and is out of scope — stated in README/rustdoc rather than claiming full parity.

Four `Option<RateLimit { limit: u32, interval_ms: u64 }>` fields for reservation/circuit × per-peer/per-IP. **Documented deviation:** all cap checks use consistent "would exceed ⇒ deny" (`>=`) semantics, fixing rust-libp2p's per-peer `>` off-by-one.

**Rate limiter** (`limiter.rs`): token bucket — this *is* rust-libp2p's algorithm (verified: `GenericRateLimiter`, refill-on-access token bucket with a refill schedule), so "same default capacities and intervals, token-bucket semantics" is genuine parity. Keyed by `PeerId` and `IpKey::{V4([u8;4]), V6([u8;16])}` from the connection remote addr's first `Ip4`/`Ip6` component; no IP component ⇒ the IP limiter passes. **Bounded GC:** no full-map scan per request — keep an expiry-ordered schedule (mirroring rust-libp2p's `refill_schedule`) and sweep only due entries per call. Unit tests: refill, boundary at limit, GC removes only full buckets, GC cost bounded under many distinct keys.

**`RelayServerAgent`** (`agent.rs`) — contract shape of `NatAgent`, time via `minip2p_platform::Now` (`monotonic_ms`, `unix_seconds: Option<u64>`):

```rust
new(local_peer_id, config)
set_listen_addrs(&[Multiaddr])
set_enabled(bool)                       // disabled ⇒ deny RESERVATION_REFUSED
handle_event(&SwarmEvent, is_circuit: bool, now: Now) -> bool   // true = claimed
connection_addr(ConnectionId, Option<&Multiaddr>)
handle_tick(now)
stream_open_result(token, Result<(ConnectionId, StreamId), ...>, now)
send_stream_result(stream: StreamKey, Result<(), ...>, now)
poll_action() / poll_event() / next_timeout(now_ms) / owns_stream(StreamKey) / is_idle()
```

No endpoint-composition flags in the agent (no `reject_inbound_stop`) — composition lives in the driver layer (PR 3).

Events: `ReservationAccepted{src, renewed}`, `ReservationDenied{src, status}`, `ReservationClosed{src}`, `CircuitDenied{src, dst, status}`, `CircuitOpened{src, dst}`, `CircuitClosed{src, dst, bytes, reason: CircuitCloseReason::{Eof, ByteLimit, DurationLimit, StreamReset, ForwardFailed, ConnectionClosed}}`.

Semantics:

- **Claiming:** inbound HOP `StreamReady` → own (keyed by `StreamKey`), spawn `HopResponder`, arm `control_stream_timeout_ms`. `is_circuit` ⇒ own + `Deny(PermissionDenied)`. Over `max_pending_hop_requests_per_connection` ⇒ `ResetStream` but retain ownership until terminal close (RejectedControl-style retention). Locally-initiated STOP streams in its registry → claimed. Unrelated inbound STOP → **ignored** (not claimed).
- **RESERVE** (checks in order): enabled → rate limiters (peer, IP) → per-peer count → global count. Renewals consume rate-limit tokens but replace the existing reservation for global/per-peer **capacity** accounting (matches rust-libp2p's unconditional limiters + skipped per-peer check; deliberately fixes their global check denying renewals at capacity — pinned by test). Failure ⇒ `Deny(ResourceLimitExceeded)` (`ReservationRefused` when disabled), half-close, event. Accept ⇒ reservation-addrs helper output + `expire: now.unix_seconds.map(|s| s.saturating_add(duration))` + `Limit{duration, data}`, half-close, `renewed` from existing key. Internal expiry always on `monotonic_ms` (wire `expire` only when `unix_seconds` is available). All deadline arithmetic — reservation expiry, circuit deadlines, control-stream deadlines, limiter refill schedules — uses saturating operations. Exact-connection close (incl. supersession) or expiry ⇒ drop + `ReservationClosed`.
- **Reservation addrs helper** (`reservation.rs`, pure + tested): start from current usable listen addrs; exclude `/p2p-circuit` addrs; exclude unspecified addrs (`0.0.0.0`, `[::]`); strip existing/conflicting trailing `/p2p/...`; append `/p2p/<local-peer-id>` exactly once; dedupe; enforce the 8 KiB encoded-response limit (drop excess addrs deterministically rather than fail).
- **CONNECT(dst):** enabled → circuit rate limiters (src-keyed) → per-peer circuits counting src-or-dst for both endpoints, src==dst counted once → global cap ⇒ `Deny(ResourceLimitExceeded)`; dst reservation lookup ⇒ else `Deny(NoReservation)`. Then `OpenStream{dst, conn_id: reservation.conn_id, STOP_PROTOCOL_ID}` → on result, verify the swarm-selected conn id matches the reservation's (mismatch ⇒ `NoReservation`) → `StopInitiator`. `Accepted` ⇒ `AcceptConnect{limit}`, cross-flush pipelined bytes, `CircuitOpened`. Refusal/failure → HOP status mapping: ResourceLimitExceeded→201, PermissionDenied→202, open-failure/unsupported/timeout/reset→203, wrong-type→401, malformed→400; `CircuitDenied`, both streams cleaned up.
- **Bridging & forwarding failures:** `StreamData` on one leg ⇒ `SendStream` on the other. `SendStream` is **not** fire-and-forget: send rejection is reported to the agent via `send_stream_result` and terminates both circuit legs — remove circuit accounting, `CircuitClosed{ForwardFailed}`. Buffering (documented): the agent does not retain per-circuit payload buffers after actions are pumped; accepted writes are bounded by the selected transport's configured queues and flow-control limits (QUIC stream windows / yamux windows), and `max_circuit_bytes` (default 128 KiB) bounds total forwarded volume per circuit. With `max_circuit_bytes = 0` (unlimited), relay-side memory is bounded by the transport, not the agent — documented deviation from rust-libp2p's `CopyFuture`, which gets backpressure from async writes. Half-closes propagate (`StreamRemoteWriteClosed` ⇒ `CloseStreamWrite` on the peer leg); both EOF ⇒ `Eof`; `StreamClosed` on one leg ⇒ reset the other (`StreamReset`); `ConnectionClosed` sweeps that connection's reservations, circuits, and pending streams (`ConnectionClosed` reason).
- **Byte limit (pinned semantics):** count bytes accepted for forwarding, both directions, one saturating `u64`; check *after* accepting a chunk; the final chunk is forwarded **complete**, then the circuit closes — one-chunk overshoot allowed (matches rust-libp2p's soft cap); `max_circuit_bytes = 0` ⇒ unlimited. Tests pin: exact-boundary chunk, overshooting final chunk delivered then closed, `0` never closes.
- **Duration limit:** deadline armed at circuit open from `max_circuit_duration_secs` (0 ⇒ unlimited) ⇒ reset both legs, `DurationLimit`.
- **Terminal stream lifecycle (agent-side):** the agent's per-stream ownership record tracks `Active → LocalWriteClosed → Closed` and is what consumes `StreamClosed`/`ConnectionClosed` (the wire machine never sees transport lifecycle). After a reservation response or denial the stream stays owned until the terminal event, so trailing events never leak to the app and pending-stream accounting stays correct. Tests: local half-close then remote close; remote half-close; reset after response; connection closure while a response is queued.
- **`next_timeout`:** min over reservation expiries, circuit deadlines, control-stream deadlines (all `monotonic_ms`).

**Tests** (`crates/relay-server/tests/`, scripted `SwarmEvent` style of `crates/nat/tests/`): reservation accept/renew/expire/deny-at-cap; renewal at global capacity succeeds as replacement; connect happy path with pipelined bytes both ways; NO_RESERVATION; per-peer (src and dst accounting, src==dst no double-count) + global circuit caps; byte-limit final-chunk behavior; duration close; rate-limiter denial + bounded GC; control-stream timeout awaiting HOP request; timeout while outbound STOP negotiates; circuit-conn HOP denial; malformed boundary (status+half-close vs reset); forwarding failure on either leg; half-close propagation both directions; **supersession**: reservation on conn A → same peer reconnects (conn B) → old reservation dropped, CONNECT for that dst gets `NoReservation` until re-RESERVE on conn B; stale stream events for conn A after supersession don't corrupt agent state; STOP conn-id-mismatch verification path; closing one connection removes only its reservations/circuits; reservation addr filtering; oversized reservation response. Plus a wire-parity test: two `NatAgent` clients against a `RelayServerAgent` in memory.

### PR 3 — Endpoint feature + driver + end-to-end tests

- **Feature** (`crates/minip2p/Cargo.toml`): `relay-server = ["std", "dep:minip2p-relay-server"]`; `std` list gains `minip2p-relay-server?/std`. Independent of `nat`.
- **Driver** `crates/minip2p/src/std/relay_server.rs` (template `std/nat.rs`): `RelayServerDriver { agent, events, epoch }`; `now()` → `platform::Now`; `ingest`/`tick`/`pump`/`execute`. `execute` maps actions onto the existing peer-keyed swarm APIs (`open_stream_with_connection` for STOP opens, reporting `(conn_id, stream_id)` back via `stream_open_result`; `send_stream` results via `send_stream_result`). `is_circuit` from `ConnectionId::is_circuit` (namespace `0x80`). On `ConnectionEstablished`, feed `agent.connection_addr(conn_id, swarm.core().remote_addr(conn_id))`.
- **Driver ownership** (order **relay-server → nat → pubsub** in `ingest_into_drivers`, `std/mod.rs:563-579`; no changes to `crates/nat`):
  - `RelayServerAgent` claims inbound HOP (always, when active); circuit connections owned + denied.
  - It claims locally-initiated STOP streams in its registry; ignores unrelated inbound STOP.
  - `NatDriver` claims trusted inbound STOP when configured (its `agent.rs:557-597` path untouched).
  - When **no** STOP consumer exists (relay-server without nat), the Endpoint installs a small reserved-protocol rejector — endpoint-level, not an agent flag — that owns-and-resets inbound STOP `StreamReady`s so they never leak as application streams.
  - Connection lifecycle + `PeerReady` observed by all drivers, claimed by none.
- **Builder/plumbing** (`std/mod.rs`): `EndpointBuilder::relay_server()` + `relay_server_config(RelayServerConfig)`; HOP/STOP registered via the existing dedupe (`std/mod.rs:1894-1911`); widen the `any(feature = "nat", feature = "pubsub")` driver cfg gates to include `relay-server`; fold `agent.next_timeout` into `driver_step_deadline`; sync listen addrs alongside `sync_nat_listen_addrs`. Public: `Endpoint::take_relay_server_events()`; re-export `RelayServerConfig`/`RelayServerEvent`/`RateLimit` only — `StreamKey` stays in `minip2p-relay-server` actions and driver plumbing; Endpoint users see configuration and events, nothing stream-level.
- **Integration test** `crates/minip2p/tests/relay_server.rs` (matrix row `nat,relay-server`): relay Endpoint with `.relay_server()`, two peers on the existing client stack (`.relay(addr)`, force_relay, `ReservationPolicy::Always`, same shape as `tests/nat.rs`): reserve → connect → bidirectional data; tiny `max_circuit_bytes` closes the circuit (final-chunk semantics observable); `max_reservations: 0` refusal reaches the client; connect to unreserved peer → NO_RESERVATION at the dialer; HOP over a circuit connection denied; client reconnect (supersession) requires re-reservation before it is dialable again.
- **Portable:** agent is `no_std`-ready; std driver only here. `portable-relay-server` is an explicit follow-up; smoltcp test keeps its hand-rolled `RelayService` for now.

### PR 4 — Example, docs, CI

- `examples/relay-server` (workspace member, `publish = false`), structure of `examples/peer`: `--quic <addr>` / `--tcp <addr>`, optional `--key <path>`, limit override flags; prints its `PeerAddr`, logs `RelayServerEvent`s. Features `["relay-server", "tcp"]`.
- Docs: `docs/md/guides/traverse-nat.mdx` (drop the "bring rust-libp2p's relay" warning; point at `.relay_server()` + example), `docs/md/reference/feature-matrix.mdx` new row, `crates/relay-server/README.md`, `crates/relay/README.md` update. Documented deviations collected in the relay-server README: `>=` cap semantics; no swarm-level negotiation caps; unlimited-bytes backpressure note; single-connection-per-peer assumption and where it's load-bearing.
- `justfile` + `.github/workflows/ci.yml`: check/clippy/test variants `--features relay-server` and `--features nat,relay-server`; `check-nostd` gains `-p minip2p-relay-server`; docs row gains the feature. Verify `just release` picks up the new publishable crate.

### PR 5 (follow-up) — retire `tests/support/relay.rs` internals

Swap `RelayMachine` for a real `.relay_server()` Endpoint behind the existing `RelayServer::spawn/spawn_tcp/cut_all/assert_healthy/trace` surface (`crates/minip2p/tests/{nat,pubsub}.rs`, `crates/ffi/tests/relayed.rs`, `examples/chat/tests/` only gain a dev-dep feature). `RelayEmulator` in `crates/test-support` stays for the `crates/nat` scripted tests. Deferred so PR 3's integration test proves parity first.

## Review points adopted vs. adapted

- **Adopted:** crate boundary + `client.rs`/`server.rs` split; `StreamKey`/`ReservationKey` keying; renewal-as-replacement; honest pending/timeout naming + documented negotiation-cap deviation; `send_stream_result` feedback; pinned byte-limit semantics; token-bucket limiter with bounded GC; terminal stream lifecycle; reservation-addrs helper; endpoint-level STOP rejector instead of an agent flag; consistent malformed boundary.
- **Adapted (with source evidence):** connection-targeted swarm APIs (`open_stream_on` et al.) dropped — the swarm is single-connection-per-peer with last-wins supersession that synchronously purges old-connection stream state, so peer-keyed APIs cannot mis-route; conn-identity *verification* + supersession tests replace them. "Two simultaneous connections" tests replaced by supersession tests. Backpressure knob (`max_forward_queue_bytes`) rejected as unmeasurable at this seam; replaced by an honest documented bound (transport flow control + `max_circuit_bytes`).

## Non-goals

Reservation vouchers (`voucher: None` always); relay discovery/autorelay; ACLs/metrics/proxy-aware IP limits; portable (smoltcp) endpoint feature for the server; swarm-level inbound-negotiation caps (documented deviation). Included, not a non-goal: denying HOP over circuit connections.

## Verification

- Per PR: `just test`, `just clippy`, `just fmt`, `just check-nostd`; `just fuzz 30` for PR 1.
- PR 2: scripted agent tests (deterministic, no I/O) incl. the NatAgent-vs-RelayServerAgent wire-parity test and the supersession suite.
- PR 3: endpoint integration test exercises the real client stack against the new server end to end.
- PR 4: run `examples/relay-server` + two `examples/peer` instances locally (`--relay <addr>`, `circuit=` target), confirm data over the relayed path; optionally deploy to the AWS relay host used for live tests.
