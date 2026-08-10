# minip2p-swarm

Orchestration layer that composes minip2p's protocol state machines into a single, DX-friendly `Swarm`. Split into a Sans-I/O core and a portable action pump (both `no_std + alloc`) plus an `std`-gated blocking wrapper.

## Three layers

- **`SwarmCore`** (`no_std + alloc`): pure state machine. Consumes `SwarmInput` values through `handle_input`, emits `SwarmOutput` values through `poll_output`, and reports quiescence with `is_idle`. Outputs wrap `SwarmAction` commands for the driver and `SwarmEvent` notifications for the application. No sockets, no async runtime, no clock reads. Composes `IdentifyProtocol`, `PingProtocol`, and `MultistreamSelect`; tracks connections, streams, and pending stream opens.
- **`SwarmRuntime<T: Transport, E: EntropySource>`** (`no_std + alloc`): the action pump. Owns a concrete transport and shuttles events and actions between it and the core, but reads no clock and draws no randomness of its own — the caller passes a `Now` into `poll(now)` and injects an entropy source. `next_deadline(now)` folds the transport's timer together with the core's protocol timers so a host can idle rather than spin.
- **`Swarm<T: Transport>`** (`std` feature, default): wraps the runtime with a monotonic clock and blocking drive loops (`poll_next`, `run_until`). Preserves the one-call DX (`swarm.dial`, `swarm.ping`, `swarm.open_stream`) without threading `now_ms` through every call.

## Features

- One-call peer interactions via `SwarmBuilder`:
  ```rust
  let swarm = SwarmBuilder::new(&keypair)
      .agent_version("my-app/0.1.0")
      .protocol("/myapp/1.0.0")
      .build(transport)?;
  ```
  Built-in ids (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` -- see
  `RESERVED_PROTOCOL_IDS`) belong to the swarm's own handlers; registering one
  via `protocol(...)` makes `build` fail with `SwarmError::ReservedProtocol`.
- Auto-opens identify on every new connection and surfaces `SwarmEvent::IdentifyReceived`.
- Emits `SwarmEvent::PeerReady` once the peer id is stable and the first Identify message has been processed.
- `swarm.ping(peer_id)` opens / reuses a ping stream with no manual protocol negotiation.
- `swarm.listen_on_bound_addrs()` starts listening on every bound transport address and returns the local `PeerAddr`s. `listen_on_bound_addr()` remains as a first-address convenience for single-socket transports.
- `swarm.connected_peers()`, `swarm.peer_info(&peer_id)`, and `swarm.is_peer_ready(&peer_id)` expose read-only peer state.
- Every public `Swarm` method returns `DriverError`, keeping transport
  failures, Sans-I/O state rejections, and driver-invariant violations
  distinguishable; asynchronous action failures are emitted as
  `SwarmEvent::Error`.
- Waits (`poll_next`, `run_until`) accept `impl Into<Deadline>`: an `Instant`
  (absolute), a `Duration` (relative), or `Deadline::NEVER` to block until an
  event arrives -- no far-future sentinel timestamps needed.
- `run_until` preserves non-matching events in order, so convenience waits do
  not steal unrelated application events. Once the deadline expires it still
  scans everything already synchronously available (buffered events plus one
  final transport poll), so a buffered match is found regardless of position.
  Use a consuming `poll_next` loop instead when handling has side effects
  (logging, dispatch).
- Generic user-protocol hook for anything else (relay, DCUtR, custom app protocols):
  ```rust
  swarm.add_protocol("/myapp/1.0.0")?;
  let stream_id = swarm.open_stream(&peer_id, "/myapp/1.0.0")?;
  swarm.send_stream(&peer_id, stream_id, data)?;
  // receive via SwarmEvent::StreamData { ... }
  ```
- Connection lifecycle events: `ConnectionEstablished`, `ConnectionClosed`.
- Identify lifecycle: `IdentifyReceived { peer_id, info }` with observed-addr populated from the transport endpoint.
- Ping lifecycle: `PingRttMeasured`, `PingTimeout`.
- User-stream lifecycle: `StreamReady`, `StreamData`, `StreamRemoteWriteClosed`, `StreamClosed`.
- Synthetic-`PeerId` path for transports that don't authenticate the remote at handshake time; promotes the id to the verified one via `TransportEvent::PeerIdentityVerified`, migrating all per-peer state and buffered events atomically.

## Sans-I/O usage

```rust
use minip2p_swarm::{SwarmCore, SwarmInput, SwarmOutput};
use minip2p_identify::IdentifyConfig;
use minip2p_ping::PingConfig;

let mut core = SwarmCore::new(identify_config, PingConfig::default());
core.add_protocol("/myapp/1.0.0")?;

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

1. Feed exactly one external input into the core with `core.handle_input(...)`, or call one application intent such as `ping`, `open_stream`, or `send_stream`.
2. Drain `core.poll_output()`.
3. Execute each `SwarmOutput::Action` against your transport.
4. Feed driver results back with `SwarmInput::StreamOpened`, `SwarmInput::OpenStreamFailed`, or `SwarmInput::RuntimeError`. If executing a `SwarmAction::ResetStream` fails, also call `core.reset_stream_failed(conn_id, stream_id)` so a later reset can be retried.

`SwarmRuntimeError` carries `peer_id`, `conn_id`, and `stream_id` whenever the
corresponding identity is known. In particular, asynchronous outbound
multistream and unsupported-protocol failures retain the stream id needed by
hosts to correlate an open request.
5. Hand each `SwarmOutput::Event` to the application.
6. Before waiting on I/O again, `core.is_idle()` should be true.

That shape mirrors the std `Swarm<T>` driver while keeping sockets, clocks, sleeps, async runtimes, and allocation policy outside the Sans-I/O core.

## Std driver usage

See `transports/quic/tests/swarm_e2e.rs` and
`transports/tcp/tests/upgrade.rs` for end-to-end examples over QUIC and TCP
(auth, muxing, Identify, and app streams).

## no_std

Disable default features:

```toml
[dependencies]
minip2p-swarm = { path = "crates/swarm", default-features = false }
```

The `no_std` build omits only the blocking `Swarm<T>` wrapper. `SwarmBuilder`
remains available: call `build_runtime(transport, entropy)` to construct a
portable `SwarmRuntime`. `SwarmCore`, the event / action / error types, and the
full caller-driven runtime all remain available without `std`.

## Scope

This crate orchestrates the protocol state machines. It does **not** implement the protocols themselves -- see `minip2p-identify`, `minip2p-ping`, `minip2p-multistream-select`, `minip2p-relay`, `minip2p-autonat`, `minip2p-dcutr`. It does not implement transports either -- see `minip2p-transport` for the contract, `minip2p-quic` for the std-only QUIC adapter, and `minip2p-tcp` for the portable TCP adapter.
