# minip2p DX roadmap

Running document of developer-experience (DX) improvements: what's
landed, what's open, and why. Complements `plan.md` (architecture /
milestones) and `holepunch-plan.md` (the runnable demo).

The priorities are informed by real pain encountered while writing
`examples/peer`. Items without a concrete "observed in" note are
extrapolations from general DX principles.

---

## Landed (PR #5)

These shipped as part of the holepunch-cli / PR #5 work. Most came out
of writing `examples/peer/src/relay.rs` and spotting friction as it
happened.

### `Swarm::local_peer_id() -> &PeerId`

**Observed in**: `relay.rs`, `direct.rs`. Every peer needs its own id
for logging / peer-addr construction.

**Before**: `swarm.transport().local_peer_id().expect("keypair set")` —
`Option<PeerId>` drilled through a transport accessor, with a lie in
the type signature when built via `SwarmBuilder` (which requires a
keypair).

**After**: infallible `&PeerId` cached on the swarm at builder time.

### `Swarm::poll_next(deadline)` and `Swarm::run_until(deadline, pred)`

**Observed in**: the pre-linearization `relay.rs` had 780 LOC of phase
enum + `match (phase, event)` dispatch + destructure-and-reconstruct.
After linearization, 540 LOC of linear `wait_connected(...)`,
`wait_user_stream_data(...)`, etc.

**Before**: `loop { sleep(5ms); for event in swarm.poll()? { match ... } }`
everywhere.

**After**: `swarm.run_until(deadline, |ev| { print_event(ev); matches!(...) })`.
Predicate sees every event (natural place for logging), filters and
stops on its own. Net: -239 LOC in `examples/peer/src`.

### `POLL_IDLE_SLEEP` 5ms → 1ms

**Observed in**: `ping rtt=6ms` on loopback, far above the ~200μs
actual UDP round-trip.

**Before**: 5ms sleep between polls → two wakeup windows per RTT → ~10ms floor.

**After**: 1ms sleep → RTT floor is 1–2ms on loopback. Transport's
non-blocking `recvfrom()` is cheap when idle so CPU cost is negligible.

### `Transport::local_addresses() -> Vec<Multiaddr>`

**Observed in**: relay verification showed `listen_addrs: []` in
rust-libp2p's Identify log. The builder's old `listen_addr_bytes`
method was impossible to use correctly — the bound address isn't
known until after the transport is created.

**After**: trait method with default empty; `QuicTransport` overrides
to return the bound multiaddr. The swarm driver snapshots it on every
`poll()` tick and auto-populates Identify's `listen_addrs`. Zero caller
ceremony. `SwarmBuilder.listen_addr_bytes` removed as dead weight.

### `Transport::active_connection_count() -> usize`

**Observed in**: the listener in relay mode couldn't detect hole-punch
success without mTLS (Milestone 6). Needed a coarse "did a new QUIC
connection show up?" signal.

**After**: trait method with default 0; `QuicTransport` overrides to
`self.connections.len()`. Used by `examples/peer/src/relay.rs` as an
early-exit heuristic that cut listener exit time from 25s to 2s.

### DCUtR `&[Multiaddr]` API + binary multiaddr codec

**Observed in**: rust-libp2p's relay rendered our `observed_addr` and
`listen_addrs` as empty because we were sending display-string bytes
instead of the spec-correct multicodec binary encoding.

**After**: `DcutrInitiator::new(&[Multiaddr])` and
`DcutrResponder::new(&[Multiaddr])`; outcome/event types surface both
the parsed `Vec<Multiaddr>` and the raw bytes. `Multiaddr::to_bytes()`
and `Multiaddr::from_bytes()` implement the multicodec binary format in
`minip2p-core`.

### Identify varint length prefix (interop fix)

**Observed in**: rust-libp2p rejected our Identify with
`Deprecated("group")`; we rejected theirs with "unsupported wire
type 4."

**After**: length-prefixed framing per the libp2p Identify spec on
both encode and decode paths. Four regression tests guard against
future drift.

## Landed (`dx-core` branch)

These are the breaking DX cleanup items that keep the Sans-I/O core intact:
all lifecycle state is pure data in `SwarmCore`, while listen convenience stays
in the std driver.

### `SwarmEvent::PeerReady { peer_id, protocols }`

The swarm now has an explicit application-ready lifecycle event. It fires only
after the peer id is stable and the first Identify message from that peer has
been processed.

**Before**: callers waited for `IdentifyReceived` to avoid racing peer-id
migration and unknown protocol support.

**After**: callers wait for `PeerReady` before calling `ping()` or opening user
protocol streams.

### Typed `SwarmEvent::Error`

`SwarmEvent::Error { message: String }` is replaced by
`SwarmEvent::Error(SwarmRuntimeError)`, with a machine-testable
`SwarmErrorKind`, optional peer/connection context, and a human-readable
`detail` string.

### `Swarm::listen_on_bound_addr()`

The common quickstart path is now one swarm-level call that returns the local
`PeerAddr`. Examples no longer need to drill into `transport_mut()` just to
listen on the already-bound QUIC socket and then query `local_peer_addr()`.

### User-protocol fail-fast on `open_user_stream`

Once a peer is ready, `open_user_stream` now checks the peer's Identify
protocol list before opening a stream. If the remote did not advertise the
protocol, the call fails synchronously instead of surfacing a later
multistream-select runtime error.

### Peer introspection accessors

`SwarmCore` and the std `Swarm` driver now expose read-only helpers for
`connected_peers()`, `peer_info(&PeerId)`, and `is_peer_ready(&PeerId)`, so
applications do not need to rebuild this state from events.

### `PeerAddr::quic_v1(IpAddr, u16, PeerId)`

The core crate has a typed constructor for the common QUIC peer-address shape,
avoiding string formatting/parsing in examples and FFI hosts.

### Clock injection on `Swarm<T>`

The std driver now accepts an injected `Clock` via `Swarm::with_clock` and
`SwarmBuilder::build_with_clock`. The Sans-I/O core remains clockless; the
driver just passes injected monotonic milliseconds into the core.

### `justfile` for common workflows

Common contributor commands are captured as `just fmt`, `just test`,
`just check`, `just check-nostd`, `just peer-direct`, and `just docs`.

---

## Open — Tier 1 (high leverage, small scope)

Most of these are natural follow-ups to what's already in PR #5.

The original Tier 1 items (`PeerReady`, typed errors, swarm-level listen
ergonomics, and user-protocol fail-fast) have landed on the `dx-core` branch.

---

## Open — Tier 2 (ergonomic papercuts)

Keypair file persistence is intentionally not tracked as a core-library DX
task. `Ed25519Keypair::secret_key_bytes()` and
`Ed25519Keypair::from_secret_key_bytes()` already provide the no_std-friendly
primitive; file format, encryption, keychain/KMS integration, and rotation are
application concerns.

---

## Open — Tier 3 (polish, tooling)

### `tracing` feature gate on `minip2p-swarm` and `minip2p-quic`

**Motivation**: `println!("[role] event")` is what the CLI uses. Real
apps want structured spans. Gate behind a feature so `no_std` core
stays clean.

**Effort**: ~100 LOC across two crates.

### Doc-test the READMEs

Adopt `#![doc = include_str!("../README.md")]` on each `lib.rs`.
Requires examples in READMEs to be actually compilable. Some
(`ping/README.md`) will need minor rework to become `no_run`.

**Effort**: ~30 min per crate × 8 crates.

### `CHANGELOG.md`

Root-level, Keep-a-Changelog format. Bootstrap from existing commit
history.

**Effort**: ~1 hour.

---

## Architectural follow-ups (out of scope for DX-only PRs)

### Milestone 6 — mutual TLS on QUIC

Server side uses `verify_peer(false)` today. Direct consequence
observed in `examples/peer`: the listener can't verify the remote's
peer id on an inbound hole-punched connection, so we rely on a
2-second grace timer as a proxy for "remote's ping probably finished."

Proper fix requires either:
- `quiche`'s `boringssl-boring-crate` feature with a custom verify
  callback, or
- An upstream `quiche` change to expose an in-memory cert-verify hook.

Tracked in `plan.md` Milestone 6. Completing it would:
- Make `SwarmEvent::PeerReady` fire for inbound connections from the
  listener's perspective (removing the grace-period hack).
- Let server-side applications know *who* is connecting at handshake
  time without the synthetic-peer-id dance.

### Binary multiaddr in foreign-peer `observed_addr` round-trip

We send binary multiaddr correctly (verified against rust-libp2p).
But foreign-peer binary addresses in inbound `observed_addr` fields
are currently discarded if they don't parse. `examples/peer/src/relay.rs`
has a defensive `eprintln!` noting dropped entries. If `minip2p-core`
grew support for more multicodec codes (e.g. `/tcp/`, `/certhash/`,
`/webrtc-direct/`), fewer entries would be silently dropped.

### Noise + Yamux on the relay bridge

Known non-goal in `holepunch-plan.md`. Needed for interop with
non-minip2p peers on the far side of the relay bridge. DX impact:
adds a fourth layer of state machines to compose; cleanest if added
only after `PeerReady` / typed errors / `Swarm::listen()` are
in place to keep the composition sane.

---

## Prioritization suggestion for the next DX PR

In order of bang-for-buck given current state:

1. Doc-test the READMEs so examples cannot drift.
2. Add optional `tracing` feature gates for structured runtime diagnostics.
3. Add `CHANGELOG.md` before the next public API cut.

The high-leverage core DX items have landed on `dx-core`. The next work should
either be docs/tooling polish or architecture work such as Milestone 6 mTLS.
