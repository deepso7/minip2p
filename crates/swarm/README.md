# minip2p-swarm

Orchestration layer that composes minip2p's protocol state machines into a single, DX-friendly swarm: one portable `no_std + alloc` type plus an `std`-gated blocking wrapper.

## Two layers

- **`SwarmCore<T: Transport, E: EntropySource>`** (`no_std + alloc`): the swarm. Owns a concrete transport, composes `IdentifyProtocol`, `PingProtocol`, and `MultistreamSelect`, and tracks connections and streams, but reads no clock and draws no randomness of its own — the caller passes a `Now` into `poll(now)` and every timed command, and injects an entropy source. `next_deadline(now)` folds the transport's timer together with the swarm's protocol timers so a host can idle rather than spin. Build one with `SwarmBuilder::build_core(transport, entropy)`.
- **`Swarm<T: Transport>`** (`std` feature, default): a `SwarmCore` plus a monotonic clock and blocking drive loops (`poll_next`, `run_until`). It keeps only what needs its clock — `ping`, `disconnect`, `open_stream`, `send_stream`, `close_stream_write`, `reset_stream`, `abandon_stream`, `poll` — so those calls need no `now_ms`. Everything else (listening, dialing, protocol registration, peer and connection queries) is on `swarm.core()` / `swarm.core_mut()`; commands called through `core_mut()` take the caller's time, so sample `swarm.now().monotonic_ms` first.

## Features

- One-call peer interactions via `SwarmBuilder`:
  ```rust
  let swarm = SwarmBuilder::new(&keypair)
      .agent_version("my-app/0.1.0")
      .protocol("/myapp/1.0.0")
      .build(transport)?;
  ```
  Built-in ids (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` -- see `RESERVED_PROTOCOL_IDS`) belong to the swarm's own handlers; registering one via `protocol(...)` makes `build` fail with `SwarmError::ReservedProtocol`.
- Auto-opens identify on every new connection and surfaces `SwarmEvent::IdentifyReceived`.
- Emits `SwarmEvent::PeerReady { peer_id, conn_id, protocols }` once the peer id is stable and the connection's first Identify message has been processed. Readiness belongs to a connection: it fires once per connection, and a `PeerReady` whose `conn_id` is no longer the peer's current connection is stale.
- `swarm.ping(peer_id)` opens / reuses a ping stream with no manual protocol negotiation.
- `swarm.core_mut().listen_on_bound_addrs()` starts listening on every bound transport address and returns the local `PeerAddr`s. `listen_on_bound_addr()` remains as a first-address convenience for single-socket transports.
- `connected_peers()`, `peer_info(&peer_id)`, and `is_peer_ready(&peer_id)` on `SwarmCore` expose read-only peer state. `peer_readiness(&peer_id)` returns the current connection and its Identify info together once that connection is ready, the coherent snapshot a ready wait should check before waiting for `PeerReady`. `has_tracked_connections()` is also true for inbound handshakes that have not yet emitted `ConnectionEstablished`.
- Commands return `DriverError`, keeping transport failures and swarm state rejections distinguishable; protocol registration returns `SwarmError`. `open_stream` and `send_stream` return their own transport failure directly and emit no event for it; work the swarm does on its own (negotiation, Identify, ping, half-close and reset dispatch) reports failures as `SwarmEvent::Error`.
- Ordering: each transport event's work runs to completion before the next event is read, and timers tick after the batch. Transport work runs before events are delivered; a replaced connection's close waits until the caller has drained every queued event, including across commands issued between deliveries.
- Waits (`poll_next`, `run_until`) accept `impl Into<Deadline>`: an `Instant` (absolute), a `Duration` (relative), or `Deadline::NEVER` to block until an event arrives -- no far-future sentinel timestamps needed.
- `run_until` preserves non-matching events in order, so convenience waits do not steal unrelated application events. Once the deadline expires it still scans everything already synchronously available (buffered events plus one final transport poll), so a buffered match is found regardless of position. Use a consuming `poll_next` loop instead when handling has side effects (logging, dispatch).
- Generic user-protocol hook for anything else (relay, DCUtR, custom app protocols):
  ```rust
  swarm.core_mut().add_protocol("/myapp/1.0.0")?;
  let (conn_id, stream_id) = swarm.open_stream(&peer_id, "/myapp/1.0.0")?;
  match swarm.send_stream(&peer_id, conn_id, stream_id, data) {
      Ok(()) => {}
      // Hold `unsent`; resend it on SwarmEvent::StreamWritable.
      Err(DriverError::Full { unsent, .. }) => held = Some(unsent),
      Err(error) => return Err(error),
  }
  // receive via SwarmEvent::StreamData { ... }
  ```
- Read backpressure (ADR 0012): the core acknowledges the bytes it consumes itself (multistream negotiation, ping, Identify, and data for streams it no longer routes). Bytes it hands out in `SwarmEvent::StreamData` are the application's to acknowledge with `SwarmCore::ack_stream`; a stream delivers at most one receive window that has not been acknowledged.
- Write backpressure (ADR 0012): payloads are `Bytes`. `send_stream` accepts as much as the stream can queue and returns `DriverError::Full` with the exact unsent tail; the caller holds it and resends on the one-shot `SwarmEvent::StreamWritable`, which never fires after the write side ended. The swarm is the caller for its own protocols (multistream negotiation, ping, Identify): it holds their tails, keeps later writes and closes behind them, and resets a stream whose peer makes it hold more than 64 KiB. `HeldWrites` packages that bookkeeping for hosts that write on many streams.
- Stream ids are unique only per connection, so every user-stream operation (`send_stream`, `close_stream_write`, `reset_stream`, `abandon_stream`) names the stream by `(peer_id, conn_id, stream_id)`, as stream events do. An operation for a connection that is no longer the peer's fails with `SwarmError::StreamNotFound` and queues nothing, so it can never reach a same-numbered stream on the peer's newer connection. On the peer's current connection, the operation must name a negotiated user stream, with one exception: `abandon_stream` also accepts an outbound stream still negotiating (its id came from `open_stream` before `StreamReady`) and queues a reset for it. Abandoning a live stream again is a no-op. A stream the transport already closed is abandoned only while its `StreamClosed` is still queued: its dropped data is acknowledged instead of reset, and a later call fails with `SwarmError::StreamNotFound`, since nothing distinguishes it from a stream that never existed.
- Application registration grants independent inbound, outbound, and Identify-advertised roles. Composed services can register only the roles they own. Incoming negotiations snapshot inbound membership at stream arrival; outbound opens consult only outbound membership, and future Identify responses snapshot only advertised membership.
- Connection lifecycle events: `ConnectionEstablished` (the peer went from disconnected to connected), `ConnectionClosed` (its last connection closed), and `ConnectionReplaced { peer_id, old, new }`. Exact remote transport addresses remain queryable by `ConnectionId`, so policy never accidentally inspects a last-wins replacement connection.
- Connection replacement: the swarm keeps one connection per peer, and the newest wins, including a connection whose identity is verified late (`PeerIdentityVerified`). The exception is a connection race, where a new direct connection meets a direct current connection younger than `SIMULTANEOUS_DIAL_WINDOW_MS` (5 s) and both peers must keep the same one whatever order each sees them in. In opposite directions (a simultaneous dial) the new one wins only if the lower peer id dialed it; in the same direction (two of one peer's candidate dials) it wins only with the lower `ConnectionToken`, the value both ends of a connection share, or when either has no token. That fallback is plain newest-wins, so a transport without tokens can still leave the two peers on different connections in a same-direction race. A loser is closed unannounced (if it was our dial, it completes as `DialFailed`). A peer reconnecting the same way within the window, such as a restart with the same identity, looks like a candidate race and may lose to its old connection; past the window the newest wins again. The hand-over is reported only as `ConnectionReplaced`, before the transport is asked to close `old`; the peer stays connected in every state snapshot. Everything that belonged to `old` ends with it, without per-stream terminal events: its streams, pending opens, and the peer's readiness and Identify info. The swarm re-identifies on `new`, so a fresh `PeerReady` follows; until then the peer is connected but not ready, and `open_stream` does not reject protocols from stale Identify data. A ping pending or in flight on `old` is re-sent on `new` with a fresh timeout, and no `PingTimeout` is reported for the hand-over. Later transport events for `old` (a late identity, stream data, its `Closed`) are ignored.
- Identify lifecycle: `IdentifyReceived { peer_id, info }` with observed-addr populated from the transport endpoint.
- Ping lifecycle: `PingRttMeasured`, `PingTimeout`.
- User-stream lifecycle: `StreamReady`, `StreamData`, `StreamWritable`, `StreamRemoteWriteClosed`, `StreamWriteStopped`, `StreamClosed`. A write stop on an identify, ping, or still-negotiating stream resets it instead.
- Synthetic-`PeerId` path for transports that don't authenticate the remote at handshake time; promotes the id to the verified one via `TransportEvent::PeerIdentityVerified`, migrating all per-peer state and queued events atomically. A connection that closes before its identity is verified takes its placeholder's undelivered events with it.

## Portable usage

```rust
use minip2p_swarm::{SwarmBuilder, Now};

let mut core = SwarmBuilder::new(&keypair)
    .protocol("/myapp/1.0.0")
    .build_core(transport, entropy)?;
core.listen_on_bound_addrs()?;

loop {
    let now: Now = clock_sample();
    for event in core.poll(now)? {
        // hand to app; commands take the same `now.monotonic_ms`
    }
    // Idle until `core.next_deadline(now)` or transport input, whichever is first.
}
```

`poll` drives one iteration: it reads the transport, runs the work each event causes, advances timers, and returns the events. Hosts sleep until `next_deadline`, which is immediate while undelivered events or deferred closes are waiting.

## Std driver usage

See `transports/quic/tests/swarm_e2e.rs` and `transports/tcp/tests/upgrade.rs` for end-to-end examples over QUIC and TCP (auth, muxing, Identify, and app streams).

## no_std

Disable default features:

```toml
[dependencies]
minip2p-swarm = { path = "crates/swarm", default-features = false }
```

The `no_std` build omits only the blocking `Swarm<T>` wrapper. `SwarmBuilder` remains available: call `build_core(transport, entropy)` to construct a portable `SwarmCore`. `SwarmCore` and the event and error types all remain available without `std`.

## Scope

This crate orchestrates the protocol state machines. It does **not** implement the protocols themselves -- see `minip2p-identify`, `minip2p-ping`, `minip2p-multistream-select`, `minip2p-relay`, `minip2p-autonat`, `minip2p-dcutr`. It does not implement transports either -- see `minip2p-transport` for the contract, `minip2p-quic` for the std-only QUIC adapter, and `minip2p-tcp` for the portable TCP adapter.
