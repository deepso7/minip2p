# minip2p-swarm

Orchestration layer that composes minip2p's protocol state machines into a single, DX-friendly `Swarm`. Split into a Sans-I/O core (`no_std + alloc`) and an `std`-gated driver.

## Two layers

- **`SwarmCore`** (`no_std + alloc`): pure state machine. Consumes `SwarmInput` values through `handle_input`, emits `SwarmOutput` values through `poll_output`, and reports quiescence with `is_idle`. Outputs wrap `SwarmAction` commands for the driver and `SwarmEvent` notifications for the application. No sockets, no async runtime, no clock reads. Composes `IdentifyProtocol`, `PingProtocol`, and `MultistreamSelect`; tracks connections, streams, and pending stream opens.
- **`Swarm<T: Transport>`** (`std` feature, default): thin driver around `SwarmCore`. Owns a concrete transport, reads `std::time::Instant` for `now_ms`, and shuttles events and actions between the transport and the core. Preserves the one-call DX (`swarm.dial`, `swarm.ping`, `swarm.open_user_stream`).

## Features

- One-call peer interactions via `SwarmBuilder`:
  ```rust
  let swarm = SwarmBuilder::new(&keypair)
      .agent_version("my-app/0.1.0")
      .user_protocol("/myapp/1.0.0")
      .build(transport);
  ```
- Auto-opens identify on every new connection and surfaces `SwarmEvent::IdentifyReceived`.
- Emits `SwarmEvent::PeerReady` once the peer id is stable and the first Identify message has been processed.
- `swarm.ping(peer_id)` opens / reuses a ping stream with no manual protocol negotiation.
- `swarm.listen_on_bound_addrs()` starts listening on every bound transport address and returns the local `PeerAddr`s. `listen_on_bound_addr()` remains as a first-address convenience for single-socket transports.
- `swarm.connected_peers()`, `swarm.peer_info(&peer_id)`, and `swarm.is_peer_ready(&peer_id)` expose read-only peer state.
- Synchronous application failures use `DriverError`, preserving whether the
  transport or Sans-I/O core rejected an operation.
- `run_until` preserves non-matching events in order, so convenience waits do
  not steal unrelated application events.
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
use minip2p_swarm::{SwarmCore, SwarmInput, SwarmOutput};
use minip2p_identify::IdentifyConfig;
use minip2p_ping::PingConfig;

let mut core = SwarmCore::new(identify_config, PingConfig::default());
core.add_user_protocol("/myapp/1.0.0");

// Drive it:
// core.handle_input(SwarmInput::Transport { event, now_ms });
// core.handle_input(SwarmInput::Tick { now_ms });
// while let Some(output) = core.poll_output() {
//     match output {
//         SwarmOutput::Action(action) => execute(action),
//         SwarmOutput::Event(event) => { /* hand to app */ }
//     }
// }
```

### Driver loop contract

The core is deterministic when callers use a simple mutate-then-drain loop:

1. Feed exactly one external input into the core with `core.handle_input(...)`, or call one application intent such as `ping`, `open_user_stream`, or `send_user_stream`.
2. Drain `core.poll_output()`.
3. Execute each `SwarmOutput::Action` against your transport.
4. Feed driver results back with `SwarmInput::StreamOpened`, `SwarmInput::OpenStreamFailed`, or `SwarmInput::RuntimeError`.
5. Hand each `SwarmOutput::Event` to the application.
6. Before waiting on I/O again, `core.is_idle()` should be true.

That shape mirrors the std `Swarm<T>` driver while keeping sockets, clocks, sleeps, async runtimes, and allocation policy outside the Sans-I/O core.

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

This crate orchestrates the protocol state machines. It does **not** implement the protocols themselves -- see `minip2p-identify`, `minip2p-ping`, `minip2p-multistream-select`, `minip2p-relay`, `minip2p-autonat`, `minip2p-dcutr`. It does not implement transports either -- see `minip2p-transport` for the contract and `transports/quic` for a concrete adapter.
