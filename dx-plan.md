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

---

## Open — Tier 1 (high leverage, small scope)

Most of these are natural follow-ups to what's already in PR #5.

### `SwarmEvent::PeerReady { peer_id }`

**Motivation**: today's DX has a subtle foot-gun — once you see
`ConnectionEstablished { peer_id }`, the peer id might still be under
peer-id migration (synthetic → verified via `PeerIdentityVerified`),
and you don't yet know what protocols the peer supports. The existing
workaround is "wait for `IdentifyReceived` before calling anything
protocol-specific":

```rust
// Today, everywhere we open a user stream:
swarm.run_until(deadline, |ev| matches!(
    ev, SwarmEvent::IdentifyReceived { peer_id, .. } if peer_id == &target
))?;
swarm.ping(&target)?; // safe now
```

That's what `examples/peer/src/direct.rs:64-69` does explicitly, and
what the relay paths implicitly depend on.

**Proposed event**: `SwarmEvent::PeerReady { peer_id, protocols: Vec<String> }`
— fires **after** both of:
1. The final (verified) peer id is bound to the connection.
2. The first `IdentifyReceived` from that peer has been processed.

Semantics: "this peer id is stable and we know what they support."

```rust
// With PeerReady:
let ready = swarm.run_until(deadline, |ev|
    matches!(ev, SwarmEvent::PeerReady { peer_id, .. } if peer_id == &target)
)?;
swarm.ping(&target)?;
```

**Second win**: once Milestone 6 (mTLS) lands, the listener side of
the hole-punch can fire `PeerReady` for an inbound direct connection
and exit *exactly* when the dialer's ping completes, eliminating the
2s grace window in `examples/peer/src/relay.rs`.

**Breaking**: adds a variant to `SwarmEvent` — technically breaking
for exhaustive matches, but no existing in-repo caller is exhaustive.

**Effort**: ~60 LOC in `SwarmCore` (gate on the peer-id migration +
first identify event), ~30 LOC of tests. Use site delta in
`examples/peer` removes ~6 lines of identify-wait boilerplate.

### Typed `SwarmEvent::Error`

**Motivation**: today it's `SwarmEvent::Error { message: String }`.
`transports/quic/tests/swarm_e2e.rs:213` literally greps for
`message.contains("ping register error")`, which is a smell.

**Proposed**:
```rust
pub enum SwarmEvent {
    // ...
    Error(SwarmRuntimeError),
}
pub struct SwarmRuntimeError {
    pub kind: SwarmErrorKind,
    pub peer_id: Option<PeerId>,
    pub conn_id: Option<ConnectionId>,
    pub detail: String,
}
pub enum SwarmErrorKind {
    Transport,
    Multistream,
    Identify,
    Ping,
    UserProtocol { protocol_id: String },
    IdentifyStreamRejected,
    OpenStreamFailed,
}
```

**Breaking**: yes, by design. ~15 call sites in `SwarmCore` to migrate.

**Effort**: ~2 hours.

### `Swarm::listen_str(&str)` helper

**Motivation**: `relay.rs` and `direct.rs` both have the three-liner

```rust
swarm.transport_mut().listen_on_bound_addr()?;
let our_addr = swarm.transport().local_peer_addr()?;
println!("[role] bound={our_addr}");
```

with a QUIC-specific method (`listen_on_bound_addr`) drilled through
`transport_mut()`. The plan.md principle "fast first success" says
this should be one call.

**Proposed**:
```rust
impl<T: Transport> Swarm<T> {
    pub fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, SwarmError>;
}
impl QuicSwarmExt for Swarm<QuicTransport> {
    fn listen_on_bound(&mut self) -> Result<PeerAddr, SwarmError>;
}
```

Return the resolved multiaddr so the caller can print it without a
second call.

**Breaking**: no; additive.

**Effort**: ~40 LOC.

---

## Open — Tier 2 (ergonomic papercuts)

### `Ed25519Keypair` persistence (`to_protobuf_bytes` / `from_protobuf_bytes`)

**Motivation**: every `examples/peer` run generates a fresh identity.
To re-test against the same relay with stable PeerIds you want a
`--key-file` flag; there's no stable serialization API today.

**Proposed**: add `to_bytes() -> [u8; 64]` and
`from_bytes(&[u8; 64]) -> Self` on `Ed25519Keypair`; optionally
`to_pkcs8_pem()` / `from_pkcs8_pem()` behind `std`.

**Effort**: ~40 LOC.

### User-protocol fail-fast on `open_user_stream`

**Motivation**: calling `open_user_stream("/myapp/1.0.0")` on a peer
that doesn't advertise `/myapp/1.0.0` today silently fails at
multistream-select time and surfaces as a string-typed `Error`. No
signal that the remote explicitly doesn't support it.

**Proposed**: if we have the peer's Identify message, check the
advertised protocols list at `open_user_stream` time and return
`SwarmError::RemoteDoesNotSupport { protocol_id }` eagerly. Fold in
nicely with `PeerReady`: if the peer isn't ready yet, defer the check
until it becomes ready.

**Effort**: ~30 LOC.

### `Swarm::connected_peers()` / `Swarm::peer_info(&PeerId)`

**Motivation**: to answer "who am I connected to?" or "what does
peer X advertise?" today, the caller has to accumulate events
themselves.

**Proposed**: accessors backed by the core's existing maps.

**Effort**: ~50 LOC.

### `PeerAddr::quic_v1(IpAddr, u16, PeerId)` constructor

**Motivation**: the most common address shape is
`/ip4|ip6/<addr>/udp/<port>/quic-v1/p2p/<peer-id>`. Today you build
it by string-parsing. A typed constructor is 3 lines.

**Effort**: ~20 LOC.

### Clock injection on `Swarm<T>`

**Motivation**: `SwarmCore` is clockless (good) but the `Swarm<T>`
driver reads `Instant::now()` internally. Time-dependent tests
(ping timeout) need real sleeps. Low user-value but high test-value.

**Proposed**: `Swarm::with_clock(transport, identify_cfg, ping_cfg,
keypair, Arc<dyn Clock>)`. Default constructor unchanged.

**Effort**: ~80 LOC including test migration.

---

## Open — Tier 3 (polish, tooling)

### `tracing` feature gate on `minip2p-swarm` and `minip2p-quic`

**Motivation**: `println!("[role] event")` is what the CLI uses. Real
apps want structured spans. Gate behind a feature so `no_std` core
stays clean.

**Effort**: ~100 LOC across two crates.

### `justfile` for common workflows

`cargo check --no-default-features -p ...` is a ~9-flag incantation
today. `just check-nostd` would capture that plus `fmt`, `lint`,
`test`, `doc`.

**Effort**: trivial.

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

1. **`PeerReady` event** (removes identify-wait boilerplate in
   examples; unlocks cleaner hole-punch exit once mTLS lands).
2. **Typed `SwarmEvent::Error`** (stops the `message.contains(...)`
   anti-pattern before more callers grow around it).
3. **`Swarm::listen()` helper** (small but user-visible on the
   quickstart path).
4. Keypair persistence (required for any long-running demo / daemon).
5. User-protocol fail-fast (leans on #1).

Items 1-3 together are estimated at ~1 day of focused work and would
notably sharpen the "fast first success" story.
