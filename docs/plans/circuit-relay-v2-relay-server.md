# Circuit Relay v2 Relay Server for minip2p

> **Status:** Canonical implementation-ready specification, validated by the
> [Circuit Relay v2 relay-server Wayfinder map](https://github.com/deepso7/minip2p/issues/61).
>
> **Reference pins:** rust-libp2p `libp2p-relay` 0.22 at
> [`170c3c81ddd80e7c58b0500563e00a09139e8545`](https://github.com/libp2p/rust-libp2p/tree/170c3c81ddd80e7c58b0500563e00a09139e8545/protocols/relay)
> and Circuit Relay v2 at
> [`6b6203ee6f62938ce67efdb33498173f475851c0`](https://github.com/libp2p/specs/blob/6b6203ee6f62938ce67efdb33498173f475851c0/relay/circuit-v2.md).

## Goal and boundaries

Add an easily hosted, production-oriented Circuit Relay v2 server while
preserving minip2p's layering: wire machines in `crates/relay`, a deterministic
`no_std + alloc` service in a new `crates/relay-server`, and all sockets, clocks,
waiting, and Endpoint composition in `crates/minip2p`.

The application happy path is intentionally small:

```rust
let endpoint = Endpoint::builder()
    .relay_server()
    .bind(...)?;
```

The implementation may make breaking pre-1.0 changes. Migrate affected callers
and tests atomically; do not add compatibility shims for the old Swarm event or
internal protocol-registration shapes.

Out of scope: reservation vouchers, relay discovery/autorelay, ACLs, metrics,
proxy-aware IP limiting, a portable/smoltcp Endpoint relay-server driver,
Swarm-wide pre-negotiation stream caps, and replacing the existing test relay
fixtures. `voucher` remains `None`. The last two omissions are documented, not
silently described as parity.

## Module boundary

```text
crates/relay                         One HOP or STOP stream's wire state.
crates/swarm                         Directional protocol registration and
                                     connection-close cause.
crates/relay-server                  Whole sans-I/O relay service and policy.
crates/minip2p/src/std/relay_server  I/O adapter and Endpoint composition.
```

- `crates/relay` owns protobuf messages, the 8 KiB frame boundary, protocol
  identifiers, status encoding, and per-stream client/server machines. It owns
  no reservation table, clock, admission policy, or forwarding policy.
- `crates/relay-server` owns reservations, circuits, limiters, deadlines,
  admission, forwarding actions, byte accounting, and public lifecycle events.
  It is `no_std + alloc` and uses `minip2p_platform::Now`.
- `crates/swarm` exposes only the deeper mechanisms shared by NAT and the relay
  server. It does not learn relay policy.
- `crates/minip2p` owns feature composition, the driver, address contributions,
  blocking waits, and the application-facing API.

Actions, action tokens, `StreamKey`, pending-control records, and driver plumbing
remain public only where needed by low-level `minip2p-relay-server` embedders.
They are not re-exported from `minip2p`.

## Frozen public API

### Configuration

```rust
pub struct RateLimit {
    pub capacity: u32,
    pub refill_interval_ms: u64,
}

pub struct RelayServerConfig {
    pub max_reservations: usize,
    pub reservation_duration_secs: u64,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration_secs: u64,
    pub max_circuit_bytes: u64,
    pub max_pending_hop_requests_per_connection: usize,
    pub max_pending_stop_requests_per_connection: usize,
    pub control_stream_timeout_ms: u64,
    pub reservation_rate_limit_per_peer: Option<RateLimit>,
    pub reservation_rate_limit_per_ip: Option<RateLimit>,
    pub circuit_rate_limit_per_peer: Option<RateLimit>,
    pub circuit_rate_limit_per_ip: Option<RateLimit>,
}
```

Defaults:

| Field | Default |
| --- | ---: |
| `max_reservations` | 128 |
| `reservation_duration_secs` | 3,600 |
| `max_circuits` | 16 |
| `max_circuits_per_peer` | 4 |
| `max_circuit_duration_secs` | 120 |
| `max_circuit_bytes` | 131,072 |
| both pending HOP/STOP caps | 10 |
| `control_stream_timeout_ms` | 60,000 |
| reservation/circuit per-peer limiter | capacity 30, one token per 120,000 ms |
| reservation/circuit per-IP limiter | capacity 60, one token per 60,000 ms |

`None` disables an individual limiter. There is no
`max_reservations_per_peer`: the invariant is one committed reservation per
peer.

Each enabled limiter is a token bucket that starts full. An admitted check
consumes one token; access processes every elapsed one-token refill interval up
to `capacity`. A full bucket may be removed because a missing bucket is
equivalent to full. An expiry-ordered refill schedule avoids full-map scans but
does not impose a hard budget when many entries are simultaneously due.

`RelayServerConfig::validate()` returns `RelayServerConfigError { field,
reason }`. Validate before binding sockets and again in `RelayServerAgent::new`.
Reject zero reservation duration, `max_circuit_duration_secs` above the Circuit
Relay `Limit.duration` wire bound (`u32::MAX` seconds), zero control timeout,
and zero capacity or refill interval in an enabled limiter.

Zero reservation/circuit/pending capacities deny new work. Zero circuit
duration and zero circuit bytes mean unlimited and are advertised as `0`.
Never panic or silently saturate a configured duration into the wire `u32`.

### Builder and Endpoint controls

```rust
EndpointBuilder::relay_server() -> Self
EndpointBuilder::relay_server_config(
    RelayServerConfig,
) -> Result<Self, RelayServerConfigError>
EndpointBuilder::relay_server_announce_addrs(
    Vec<Multiaddr>,
) -> Result<Self, RelayServerAnnounceError>

Endpoint::set_relay_server_accepting(
    bool,
) -> Result<(), RelayServerControlError>
Endpoint::set_relay_server_announce_addrs(
    Vec<Multiaddr>,
) -> Result<(), RelayServerControlError>
Endpoint::take_relay_server_events() -> Vec<RelayServerEvent>
Endpoint::next_relay_server_event(
    impl Into<Deadline>,
) -> Result<Option<RelayServerEvent>, Error>
```

`RelayServerAnnounceError` distinguishes validator configuration failures
(`Config`) from invalid announce addresses (`Address`).

Only `relay_server()` and `relay_server_config(...)` enable the service and its
static HOP advertisement. Announce-address calls are order-independent with
those methods but never enable the service. If addresses are pending at bind
without relay-server enablement, bind fails actionably. Runtime controls on an
absent service return `RelayServerControlError::NotConfigured`.

`set_relay_server_accepting(false)` pauses new admissions only: RESERVE returns
`RESERVATION_REFUSED`, CONNECT returns `PERMISSION_DENIED`, HOP remains
advertised, and existing reservations and circuits remain active. Re-enabling
resumes admission without rebuilding state.

Address errors are distinct and actionable:

```rust
pub struct RelayServerAddressError {
    pub index: usize,
    pub address: Multiaddr,
    pub reason: RelayServerAddressErrorKind,
}

pub enum RelayServerAddressErrorKind {
    Wildcard,
    Circuit,
    ConflictingPeerId { expected: PeerId, found: PeerId },
    UnsupportedShape,
}

pub enum RelayServerControlError {
    NotConfigured,
    InvalidAddress(RelayServerAddressError),
}
```

The nested address error is the `source` of `InvalidAddress`. Builder
validation returns it directly. Validate structural address rules immediately;
if builder identity is not yet fixed, repeat the peer-ID match at bind. Runtime
replacement validates the entire input before mutation; one invalid address
preserves the previous override. Empty input clears the explicit override and
returns to automatic address selection.

### Events and supporting types

```rust
pub enum RelayServerEvent {
    ReservationAccepted {
        peer_id: PeerId,
        renewed: bool,
        expires_unix_secs: Option<u64>,
    },
    ReservationDenied { peer_id: PeerId, status: Status },
    ReservationClosed { peer_id: PeerId, reason: ReservationCloseReason },
    CircuitDenied {
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        status: Status,
    },
    CircuitOpened { source_peer_id: PeerId, destination_peer_id: PeerId },
    CircuitClosed {
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        bytes: CircuitByteCounts,
        reason: CircuitCloseReason,
    },
    Error(RelayServerRuntimeError),
}

pub enum ReservationCloseReason {
    Expired,
    ConnectionClosed,
    Superseded,
    InternalFailure,
}

pub enum CircuitDirection { SourceToDestination, DestinationToSource }
pub enum CircuitLeg { Source, Destination }

pub struct CircuitByteCounts {
    pub source_to_destination: u64,
    pub destination_to_source: u64,
}

pub enum CircuitCloseReason {
    Eof,
    ByteLimit { direction: CircuitDirection },
    DurationLimit,
    StreamReset { leg: CircuitLeg },
    ForwardFailed { direction: CircuitDirection },
    ConnectionClosed { leg: CircuitLeg, cause: ConnectionCloseCause },
    InternalFailure,
}
```

Denial events expose the exact `minip2p_relay::Status`, re-exported from
`minip2p`. All event and reason types above, `RelayServerConfig`, `RateLimit`,
the three error types, `RelayServerAddressErrorKind`,
`RelayServerRuntimeError{,Kind}`, and `ConnectionCloseCause` are also
re-exported.

`RelayServerRuntimeError` follows the Swarm error pattern: public `kind`,
optional `peer_id`, and human-readable `detail`, with no connection/stream key
or agent token. `RelayServerRuntimeErrorKind` has stable operation categories
`OpenStream`, `SendStream`, `CloseStream`, `ResetStream`, and
`InternalInvariant`. Synchronous configuration/control failures use returned
errors; asynchronous transport/driver failures use `RelayServerEvent::Error`.
An internal failure that terminates a committed lifecycle emits both its stable
close reason and one diagnostic error event.

Emit each `ReservationDenied`/`CircuitDenied` once when the agent makes the
stable denial decision. Failure to deliver that status adds one runtime error;
it neither suppresses nor duplicates the denial event. Acceptance/open events,
by contrast, require transport acceptance at the commit points defined below.

### Low-level agent/driver seam

`minip2p-relay-server` exposes the caller-driven seam needed by non-Endpoint
hosts without lifting it into `minip2p`:

```rust
pub struct StreamKey {
    pub conn_id: ConnectionId,
    pub stream_id: StreamId,
}

pub enum RelayServerAction {
    OpenStream {
        token: RelayServerToken,
        peer_id: PeerId,
        expected_conn_id: ConnectionId,
        protocol_id: String,
    },
    SendStream {
        token: RelayServerToken,
        peer_id: PeerId,
        stream: StreamKey,
        data: Vec<u8>,
    },
    CloseStreamWrite {
        token: RelayServerToken,
        peer_id: PeerId,
        stream: StreamKey,
    },
    ResetStream {
        token: RelayServerToken,
        peer_id: PeerId,
        stream: StreamKey,
    },
}
```

`RelayServerToken` is opaque. The driver echoes every result through the
matching `stream_open_result`, `send_stream_result`,
`close_stream_write_result`, or `reset_stream_result` method with `Now`;
operation failures carry an allocated diagnostic string. Open success includes
the actual `StreamKey`, which the agent verifies against `expected_conn_id`.
Unknown/stale tokens are ignored after any necessary successful-open cleanup.

`RelayServerAgent` exposes `new`, `set_accepting`, atomic
`replace_announce_addrs`, `set_confirmed_addrs`, `set_listener_addrs`,
`selected_addrs`, `connection_addr`, `handle_event`, `handle_tick`, the four
result methods, `poll_action`, `poll_event`, `next_timeout`, `owns_stream`, and
`is_idle`. `handle_event` receives the driver's direct-versus-circuit
classification and returns whether the event was claimed. The driver calls
`handle_tick(now)` before delivering any event sampled at the same `now`, which
enforces deadline-first ordering. After each claimed input, the driver must
drain actions and echo their synchronous results to quiescence before delivering
the next transport event; this is the load-bearing bound that keeps payload
backpressure in transport queues rather than an unbounded agent queue.

## Swarm and Endpoint foundations

### Directional protocol roles

Replace the internal single protocol registry with independent inbound,
outbound, and Identify-advertised membership. Keep
`SwarmBuilder::protocol`/`SwarmRuntime::add_protocol` behavior unchanged by
registering application protocols in all three sets. Add crate-internal role
registration for composed services.

| Owner | Protocol | Inbound | Outbound | Identify |
| --- | --- | ---: | ---: | ---: |
| relay-server | HOP | yes | no | yes |
| relay-server | STOP | no | yes | no |
| NAT | HOP | no | yes | no |
| NAT | trusted STOP | yes | no | yes |

Do not broaden this migration into unrelated DCUtR/AutoNAT behavior. A
relay-server-only Endpoint owns and resets unsolicited inbound STOP. NAT-only
clients can open HOP but neither advertise nor accept it. Incoming
multistream-select snapshots only the inbound set; outbound opens check only
the outbound set; future Identify responses snapshot only the advertised set.

HOP on a circuit connection still negotiates, then returns
`PERMISSION_DENIED`. This intentional rust-libp2p deviation makes the denial
deterministic instead of failing negotiation.

### Connection-close cause

Make the breaking Swarm event change:

```rust
pub enum ConnectionCloseCause { Transport, Superseded }

SwarmEvent::ConnectionClosed {
    peer_id: PeerId,
    conn_id: ConnectionId,
    cause: ConnectionCloseCause,
}
```

The synchronous last-wins replacement path emits `Superseded`; transport loss
and explicit transport closure emit `Transport`. Migrate every consumer and
fixture in Swarm, NAT, portable/std Endpoint drivers, discovery, pubsub, and
their tests in the same PR. Relay reservation closure maps the two causes to
`Superseded` and `ConnectionClosed` respectively.

The Swarm remains single-connection-per-peer. Relay state stores exact
`ConnectionId`s and verifies an opened STOP stream landed on the reservation's
connection. No new connection-targeted send API is needed while that invariant
holds; document this load-bearing assumption.

### Identify address contributions

The std Endpoint owns a source-keyed address book with independent NAT and
relay-server contributions. NAT no longer calls wholesale
`set_external_addresses` directly. After either contribution changes, Endpoint
builds a stable first-wins union (NAT source, then relay-server source) and
replaces the Swarm external set once. Portable Endpoint's existing caller-owned
setter remains unchanged.

Bound transport addresses remain the Swarm runtime's first Identify source.
The contribution union follows them, with duplicates removed first-wins.
Changes affect future Identify exchanges only; Identify Push and forced
re-identification are out of scope.

## Address and admission policy

### Reservation address selection

For every new reservation or renewal, choose exactly the first non-empty usable
source:

1. explicit relay-server announce-address override;
2. AutoNAT-confirmed public direct addresses, when NAT is enabled; then
3. concrete bound transport listeners.

Never promote raw Identify observed addresses. Normalize in source order and
deduplicate first-wins. The only accepted shapes are
`/{ip4|ip6|dns|dns4|dns6}/.../tcp/<port>` and
`/{ip4|ip6|dns|dns4|dns6}/.../udp/<port>/quic-v1`, each with an optional trailing
`/p2p/<local-peer-id>`. Reject wildcard hosts, any `/p2p-circuit`, a conflicting
peer ID, and every other protocol shape. Strip an optional matching peer ID from
the normalized transport form, then append the local peer ID exactly once when
encoding a RESERVE response.

The normalized selected set contributes to future Identify responses. A
RESERVE response encodes the longest source-order prefix that fits the 8 KiB
relay control frame, dropping only trailing addresses. If no address can be
sent, treat the source as unusable.

With no usable address, deny new reservations and renewals with
`RESERVATION_REFUSED`. A failed renewal keeps its prior reservation and
deadline. Address changes never terminate reservations or circuits; existing
reservations remain valid CONNECT destinations.

### Reservation cardinality and lifecycle

There is at most one committed reservation per peer. The record stores its
owning connection, monotonic deadline, and optional Unix expiry metadata.

- RESERVE on the owning connection is a renewal.
- A new connection supersedes the old one first, emits one `Superseded` close,
  and may then make a fresh reservation.
- If a custom low-level driver reports a replacement connection without the
  expected old-connection close, the agent defensively applies the same
  last-wins supersession before accepting work from the replacement.
- Every request, including renewal, consumes the peer/IP reservation limiter
  tokens. A successful renewal replaces its capacity slot rather than consuming
  another global slot.
- Admission order for every syntactically valid RESERVE is: accepting and a
  usable address set; peer limiter; IP limiter; exact global capacity; response
  acceptance and commit. A denial at the availability step consumes no token.
  The peer token is consumed before the IP check, and a capacity-denied attempt
  consumes both applicable tokens but no slot. Capacity uses would-exceed
  semantics, so equality is allowed and zero denies new work. Renewal performs
  the same checks but treats its existing slot as replacement capacity.

The IP key is the first IP4/IP6 component of the exact connection's remote
transport address. When none exists, the IP limiter is not applicable. Failed
availability returns `RESERVATION_REFUSED`; rate/capacity denial returns
`RESOURCE_LIMIT_EXCEEDED`.

Initial acceptance commits only after the success response is accepted by the
transport. Then emit `ReservationAccepted { renewed: false, ... }`. A failed
initial response creates no reservation and emits a runtime error, not a close.

Renewal commits only after its response is accepted. Replace both deadlines
from renewal time and emit `renewed: true`; do not emit a close. A failed
renewal response preserves the previous reservation and deadline.

Internal lifetime uses only `monotonic_now + reservation_duration`. Optional
`unix_now + duration` is wire/event metadata and uses saturating arithmetic.
When wall time is absent, omit both the wire `Reservation.expire` value and the
event expiry while enforcing the full monotonic lifetime.
Missing, jumping, or saturated wall time never changes expiry. At a timestamp,
process `now >= deadline` before connection events or other inputs. A committed
reservation emits exactly one terminal event: `Expired`, `ConnectionClosed`,
`Superseded`, or `InternalFailure`. Never close an uncommitted/nonexistent
reservation. Administrative pause emits no closure.

### CONNECT admission

CONNECT checks, in order: accepting state; source peer limiter; source IP
limiter; both endpoints' per-peer circuit count (source equals destination
counts once); global capacity; and the destination reservation. The IP key is
the first IP4/IP6 component of the exact connection's remote transport address;
when none exists, that IP limiter is not applicable. Status mapping is
deterministic:

- paused: `PERMISSION_DENIED`;
- no live destination reservation or STOP connection mismatch: `NO_RESERVATION`;
- capacity/rate limit: `RESOURCE_LIMIT_EXCEEDED`;
- malformed/unexpected request: the wire statuses defined below.

A CONNECT admitted through resource checks reserves its circuit slot while the
outbound STOP exchange is pending. Refusal, timeout, or failure releases that
slot without emitting `CircuitOpened` or `CircuitClosed`.

After opening STOP, map the destination result back to HOP exactly:
`ResourceLimitExceeded` stays `RESOURCE_LIMIT_EXCEEDED`, `PermissionDenied`
stays `PERMISSION_DENIED`, open/unsupported/timeout/reset failures become
`CONNECTION_FAILED`, wrong message type becomes `UNEXPECTED_MESSAGE`, and a
well-framed malformed message becomes `MALFORMED_MESSAGE`.

Existing circuits survive pause, address changes, and unrelated connection
closure. Existing reservations remain stored while paused, but every new
CONNECT request during the pause is denied.

## Control streams, forwarding, and limits

### Wire roles and malformed input

Add `HopResponder` and `StopInitiator` to `crates/relay`, beside the existing
client machines and re-export them. Both implement `SansIoProtocol` and retain
payload pipelined with their handshake as directional bridge data.

- A well-framed message with a wrong kind or missing required field receives
  the appropriate malformed/unexpected `Status`, then the write side closes.
- Invalid framing, oversized declarations, or inputs for which no valid status
  can be encoded reset the stream.
- All control frames use the existing 8 KiB maximum. The larger limit versus
  rust-libp2p's 4 KiB is deliberate and documented.

Tests distinguish absent/invalid message type, absent/invalid CONNECT peer ID,
and unknown enum values; the decoder must preserve field presence rather than
letting proto3 defaults turn an absent type into RESERVE.

The HOP timeout runs from inbound negotiated `StreamReady` through request
parsing, decision, and response acceptance. The STOP timeout runs from outbound
open/negotiation through response acceptance. Separate per-connection pending
caps apply after HOP/STOP ownership begins. Minip2p does not add rust-libp2p's
Swarm-level pre-negotiation cap in this work.

At the inbound HOP cap, own and reset the newly negotiated stream and retain
ownership until its terminal event; no denial event exists because a request
may not have parsed. At the outbound STOP cap for a destination connection,
deny the source CONNECT with `RESOURCE_LIMIT_EXCEEDED` without opening STOP.
Zero caps therefore reject every new worker. An inbound HOP timeout resets the
stream and emits a runtime error once a request/response operation is known; an
outbound STOP timeout maps to HOP `CONNECTION_FAILED`. All paths release their
pending-worker count exactly once.

### Circuit commit and duration

After destination STOP accepts, send the HOP CONNECT success response. Commit
the circuit and emit `CircuitOpened` only when that response is accepted by the
source transport; then arm the duration deadline and release buffered
pipelined payload in its correct direction. Failure before commit cleans up
both legs and emits a diagnostic error but no opened/closed lifecycle pair.

The duration deadline is `acceptance_monotonic_now + configured_duration`, so
it covers all committed forwarding, including handshake leftovers. Zero means
unlimited and wire `Limit.duration = 0`. At `now >= deadline`, close with
`DurationLimit` before processing other same-timestamp inputs.

### Forwarding and byte accounting

Forwarding remains action-based. Every send action carries an opaque token and
the agent serializes sends per direction. The driver reports whether the whole
chunk was accepted by the destination transport. Transport/yamux/QUIC queues
provide backpressure; the agent retains only bounded in-flight state.

Maintain independent saturating source-to-destination and
destination-to-source counters. The 128 KiB default applies to each direction,
allowing up to 256 KiB aggregate payload. Count all application payload,
including both sides' pipelined handshake leftovers, only after the destination
transport accepts the send. Equality with the configured limit remains open.
The first non-empty accepted chunk that makes its direction exceed the limit is
delivered completely, included in that direction's total, and then both legs reset.
Opposite-direction traffic consumes none of that allowance. Zero never triggers
and wire `Limit.data = 0`.

A failed crossing send contributes no bytes and closes as
`ForwardFailed { direction }`, not `ByteLimit`. Ignore stale send/timer/stream
results after terminal state. Every committed circuit emits exactly one
`CircuitClosed` with both directional totals; byte-limit closure identifies the
crossing direction. Saturation must not panic or wrap.

EOF propagates half-closes and finishes as `Eof` after both directions close.
Reset, forwarding failure, connection loss, duration, byte limit, and internal
failure clean up the remaining leg without producing a second event.

## Four-PR implementation sequence

### PR 1 — Relay-side wire roles

In `crates/relay`:

- split the implementation into message/client/server modules without changing
  existing client exports;
- add `HopResponder`, `StopInitiator`, status helpers, pipelined-data handling,
  and the malformed-input boundary;
- update crate rustdoc and README;
- test fragmentation, exact/oversized frames, wrong kinds, missing fields,
  decision order, remote closes, and pipelined payload; and
- feed arbitrary input to both new machines from `wire_inputs`.

### PR 2 — Swarm foundations and sans-I/O service

Land the cross-cutting Swarm work first:

- independent inbound/outbound/Identify protocol roles while preserving generic
  application registration;
- `ConnectionCloseCause` and every consumer/test migration;
- exact connection remote-address lookup for IP limiting; and
- tests for outbound-only HOP, advertised inbound HOP, MSS snapshots, and both
  close causes.

Then add `minip2p-relay-server` with the frozen config, errors, events, token
bucket limiters, address normalization, reservation/circuit tables, tokenized
control/forward sends, monotonic scheduling, and exactly-once terminal state.
Limiter maps use an expiry-ordered schedule and sweep only due entries; they do
not scan all peer/IP keys per request. All deadline/refill arithmetic saturates.
Add README/rustdoc for every public item.

Scripted sans-I/O tests cover:

- defaults, invalid/zero/wire-bound config, and disabled limiters;
- limiter refill/boundaries, renewal tokens, IP extraction, and bounded cleanup;
- reservation commit/failure, replacement, supersession, expiry priority,
  wall-clock independence, and exactly-once closure;
- all address precedence, validation, replacement, clearing, deduplication,
  truncation, refusal, and renewal-preservation rules;
- both-end circuit admission, status mapping, pause/resume, circuit HOP,
  separate caps, and end-to-end timeouts;
- directional pipelining, equality/overshoot, failed sends, zero wire values,
  saturation, duration, stale terminals, and exactly-once close; and
- a memory-only `NatAgent` client pair through `RelayServerAgent`.

### PR 3 — std Endpoint feature and integration

Add `relay-server = ["std", "dep:minip2p-relay-server"]`, independent of
`nat`, and implement the action/I/O adapter. This PR owns all composition work:

- complete builder/runtime API and root re-exports;
- early/bind validation and nested error sources;
- static relay roles and NAT outbound-only HOP;
- trusted STOP routing and relay-only unsolicited STOP rejection;
- std Endpoint NAT/relay source-keyed Identify address aggregation;
- AutoNAT-confirmed selection, never raw observed addresses;
- driver order relay-server, NAT, pubsub;
- address recomputation without terminating live state;
- `take_`/`next_` queues, `DriverProgress`, pending-event capacity, counts, wakes,
  and deadlines; and
- runtime error delivery for every failed action.

Compile and integration-test `relay-server`, `nat`, and `nat,relay-server`
with TCP and QUIC matrix variants. Two real minip2p clients reserve, advertise,
connect, exchange bidirectional payload, hit limits, pause/resume, replace
addresses, supersede connections, and observe typed events. Verify NAT-only
Identify omits HOP while outbound reservation succeeds, relay-only Identify
includes HOP, and address sources cannot clobber each other.

### PR 4 — Hosting example, interoperability, docs, and CI

- Add `examples/relay-server` with QUIC/TCP binds, optional persisted key,
  explicit announce addresses, accepting toggle, practical limit flags, and
  readable events/errors. Keep the default path as the three-line example.
- Update the NAT traversal guide, feature matrix, top-level/crate READMEs, and
  public rustdoc. Remove the requirement to bring an external relay.
- Add feature-matrix test/check/clippy rows, no-std coverage, docs coverage, and
  release-package checks.
- Add `just interop-relay-rust` under `tests/interop`, pinned to the reference
  rust-libp2p revision. Run a minip2p server with rust-libp2p reserving/dialing
  clients and verify reservation, Identify/HOP, CONNECT/STOP, and bidirectional
  bytes. Keep the foreign tool outside the workspace and the network-dependent
  test ignored in ordinary unit runs, following the existing harness.

The relay-server README contains one compatibility table covering cardinality,
admission order, renewal, both-end circuit limits, limiter shape, static HOP,
pause semantics, address trust/precedence/truncation, future-only Identify,
circuit-HOP denial, frame/malformed handling, directional bytes, duration,
lifecycles, control caps/timing, forwarding/backpressure, optional wall time,
and `voucher: None`.

## Completion gate

Before each PR: `just fmt`, `just test`, `just clippy`, and `just check-nostd`;
run `just fuzz 30` for PR 1. Before declaring the series complete, run Endpoint
integration and `just interop-relay-rust` and record the pinned foreign result.

The specification is complete only when no behavior above is left to inference,
every deliberate upstream deviation is documented, and every public API has
rustdoc with actionable failure semantics.
