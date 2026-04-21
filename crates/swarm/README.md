# minip2p-swarm

Orchestration layer that composes minip2p's protocol state machines into a single, DX-friendly `Swarm`. Split into a Sans-I/O core (`no_std + alloc`) and an `std`-gated driver.

## Two layers

- **`SwarmCore`** (`no_std + alloc`): pure state machine. Consumes `TransportEvent` values (with caller-supplied `now_ms`), emits `SwarmAction` commands and `SwarmEvent` notifications. No sockets, no async runtime, no clock reads. Composes `IdentifyProtocol`, `PingProtocol`, and `MultistreamSelect`; tracks connections, streams, and pending stream opens.
- **`Swarm<T: Transport>`** (`std` feature, default): thin driver around `SwarmCore`. Owns a concrete transport, reads `std::time::Instant` for `now_ms`, and shuttles events and actions between the transport and the core. Preserves the one-call DX (`swarm.dial`, `swarm.ping`, `swarm.open_user_stream`).

## Features

- One-call peer interactions via `SwarmBuilder`:
  ```rust
  let swarm = SwarmBuilder::new(&keypair)
      .agent_version("my-app/0.1.0")
      .build(transport);
  ```
- Auto-opens identify on every new connection and surfaces `SwarmEvent::IdentifyReceived`.
- `swarm.ping(peer_id)` opens / reuses a ping stream with no manual protocol negotiation.
- Generic user-protocol hook for anything else (relay, DCUtR, custom app protocols):
  ```rust
  swarm.add_user_protocol("/myapp/1.0.0");
  let stream_id = swarm.open_user_stream(&peer_id, "/myapp/1.0.0")?;
  swarm.send_user_stream(&peer_id, stream_id, data)?;
  // receive via SwarmEvent::UserStreamData { ... }
  ```
- Connection lifecycle events: `ConnectionEstablished`, `ConnectionClosed`.
- Identify lifecycle: `IdentifyReceived { peer_id, info }` with observed-addr populated from the transport endpoint.
- Ping lifecycle: `PingRttMeasured`, `PingTimeout`.
- User-stream lifecycle: `UserStreamReady`, `UserStreamData`, `UserStreamRemoteWriteClosed`, `UserStreamClosed`.
- Synthetic-`PeerId` path for transports that don't authenticate the remote at handshake time; promotes the id to the verified one via `TransportEvent::PeerIdentityVerified`, migrating all per-peer state and buffered events atomically.

## Sans-I/O usage

```rust
use minip2p_swarm::{SwarmCore, SwarmEvent};
use minip2p_identify::IdentifyConfig;
use minip2p_ping::PingConfig;

let mut core = SwarmCore::new(identify_config, PingConfig::default());
core.add_user_protocol("/myapp/1.0.0");

// Drive it:
// core.on_transport_event(event, now_ms);
// core.on_tick(now_ms);
// for action in core.take_actions() { execute(action); }
// for event in core.poll_events() { ... }
```

## Std driver usage

See `transports/quic/tests/swarm_e2e.rs` for a full round-trip example (two swarms over QUIC, auto-identify, user-protocol echo, rapid-ping regression).

## no_std

Disable default features:

```toml
[dependencies]
minip2p-swarm = { path = "crates/swarm", default-features = false }
```

The `no_std` build omits the `Swarm<T>` driver and `SwarmBuilder`; only `SwarmCore` and its event / action / error types remain.

## Scope

This crate orchestrates the protocol state machines. It does **not** implement the protocols themselves -- see `minip2p-identify`, `minip2p-ping`, `minip2p-multistream-select`, `minip2p-relay`, `minip2p-dcutr`. It does not implement transports either -- see `minip2p-transport` for the contract and `transports/quic` for a concrete adapter.

## DX roadmap

See `dx-plan.md` at the repo root for the tracked DX backlog. A few items that land in the swarm crate specifically:

- **`SwarmEvent::PeerReady { peer_id }`** -- fire after the peer-id migration *and* the first `IdentifyReceived`. Removes the current "wait for Identify before calling `ping()`" gate in user code.
- **Typed `SwarmEvent::Error`** -- replace the string-only `Error { message }` variant with a structured enum so callers can match on kinds instead of grepping on message contents.
- **`Swarm::listen(&Multiaddr)` helper** -- one-call listen bring-up that wraps `transport.listen(...)` and returns the resolved bound address.

PRs welcome; see `dx-plan.md` for the full priority list and motivation for each.
