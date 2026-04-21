# minip2p

A minimal, educational [libp2p](https://libp2p.io/) implementation in Rust.

The project is built around four non-negotiables:

- **Sans-I/O architecture** for protocol and transport state machines.
- **`no_std`-friendly core crates** (`alloc`-based where needed).
- **Top-notch DX** with clear defaults, actionable errors, and easy local bring-up.
- **FFI-friendly APIs** so Rust boundaries can later map cleanly to WASM/TypeScript hosts.

## Workspace status

Sans-I/O core crates (`no_std + alloc`):

- `crates/identity` (`minip2p-identity`): peer identity primitives, Ed25519 keys, varint helpers.
- `crates/core` (`minip2p-core`): transport-agnostic types (`Multiaddr`, `PeerAddr`, `Protocol`, `PeerId` re-export).
- `crates/transport` (`minip2p-transport`): transport contract, shared lifecycle types (trait + data types only).
- `crates/tls` (`minip2p-tls`): libp2p TLS certificate generation and peer verification, transport-agnostic.
- `crates/multistream-select` (`minip2p-multistream-select`): `/multistream/1.0.0` negotiation state machine.
- `crates/ping` (`minip2p-ping`): `/ipfs/ping/1.0.0` state machine with RTT measurement.
- `crates/identify` (`minip2p-identify`): `/ipfs/id/1.0.0` state machine for protocol and address exchange.
- `crates/relay` (`minip2p-relay`): Circuit Relay v2 *client-side* state machines (`HopReservation`, `HopConnect`, `StopResponder`).
- `crates/dcutr` (`minip2p-dcutr`): DCUtR hole-punch coordination state machines (`DcutrInitiator`, `DcutrResponder`).
- `crates/swarm` (`minip2p-swarm`): `SwarmCore` Sans-I/O orchestrator that composes the protocol state machines, tracks connections and streams, drives multistream-select, and emits actions/events for the driver.

Runtime adapters (`std`):

- `transports/quic` (`minip2p-quic`): QUIC transport adapter built on `quiche`, with libp2p TLS baked in.
- `crates/swarm` (also ships a thin `std` driver `Swarm<T: Transport>` behind the `std` feature).

Current validated behavior:

- Two local peers connect over QUIC in integration tests, with libp2p TLS peer authentication.
- Bidirectional stream data exchange with half-close propagation.
- Multistream-select negotiation with spec-compliant varint framing.
- Ping protocol round-trips with RTT measurement over negotiated streams.
- Identify protocol exchange with observed-address plumbing from the transport.
- Transport contract with documented lifecycle guarantees and conformance tests.
- End-to-end stack via `SwarmBuilder`: QUIC transport + multistream-select + identify + ping with a single builder call.
- Pure-state-machine integration test covering Circuit Relay v2 + DCUtR (reservation, connect, stop, hole-punch coordination).

## Architecture boundaries

- Core crates listed above are designed to remain `no_std + alloc`. Protocol state machines (`ping`, `identify`, `relay`, `dcutr`, `multistream-select`) never depend on sockets, async runtimes, or wall clocks.
- Runtime networking concerns (UDP/TCP sockets, DNS resolution, timers) belong in transport adapter crates.
- Transport-specific address validation belongs in transport adapters, not `crates/core`.
- `crates/swarm` splits into a Sans-I/O `SwarmCore` (no_std) and a `std`-gated driver that owns a concrete `Transport` and reads the wall clock.

## Quick start

Prerequisites:

- Rust stable toolchain
- Cargo

Build and run tests:

```bash
cargo test
```

Check `no_std` builds for the core crates:

```bash
cargo check --no-default-features -p minip2p-core -p minip2p-identity \
    -p minip2p-transport -p minip2p-tls -p minip2p-identify \
    -p minip2p-ping -p minip2p-relay -p minip2p-dcutr -p minip2p-swarm
```

## Documentation

Every crate has a README and rustdoc on all public APIs. Internal methods and types are commented for contributor onboarding.

Generate the full API docs with:

```bash
cargo doc --workspace --no-deps --open
```

## Roadmap focus

- [x] Local QUIC connectivity and integration coverage.
- [x] Multistream-select with spec-compliant varint framing.
- [x] Ping protocol with RTT measurement and timeout handling.
- [x] End-to-end protocol stack tests (QUIC + multistream + ping).
- [x] Rustdoc and internal comments across all crates.
- [x] Transport contract hardening with documented guarantees and conformance tests.
- [x] libp2p TLS peer authentication (automatic PeerId verification after handshake on the dialer side).
- [x] Identify protocol (`/ipfs/id/1.0.0`).
- [x] Swarm / connection management layer with builder DX.
- [x] Circuit Relay v2 client state machines.
- [x] DCUtR hole-punching state machines.
- [ ] Runnable hole-punch CLI against a real relay (see `holepunch-plan.md`).
- [ ] Mutual TLS on the QUIC transport so the listener learns the client PeerId at handshake time.
- [ ] Additional transport adapters (TCP, WebSocket, WebRTC).

See `plan.md` for the detailed execution plan and milestones, `holepunch-plan.md` for the ongoing CLI work, and `dx-plan.md` for the developer-experience roadmap (landed improvements + prioritized backlog).
