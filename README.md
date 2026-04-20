# minip2p

A minimal, educational [libp2p](https://libp2p.io/) implementation in Rust.

The project is built around four non-negotiables:

- **Sans-I/O architecture** for protocol and transport state machines.
- **`no_std`-friendly core crates** (`alloc`-based where needed).
- **Top-notch DX** with clear defaults, actionable errors, and easy local bring-up.
- **FFI-friendly APIs** so Rust boundaries can later map cleanly to WASM/TypeScript hosts.

## Workspace status

Current crates:

- `packages/identity` (`minip2p-identity`): peer identity primitives and validation.
- `packages/core` (`minip2p-core`): transport-agnostic address/types (`Multiaddr`, `PeerAddr`, `PeerId` re-export).
- `packages/transport` (`minip2p-transport`): transport contract types, connection lifecycle, events, and errors.
- `transports/quic` (`minip2p-quic`): `std` QUIC transport adapter built on `quiche`.

Current validated behavior:

- Two local peers connect over QUIC in integration tests.
- Peers exchange bytes bidirectionally.
- Multiple simultaneous connections per peer are supported.
- Identity upgrade events are emitted and peer indexing updates correctly.

## Architecture boundaries

- `packages/identity`, `packages/core`, and `packages/transport` are designed to remain `no_std + alloc` friendly.
- Runtime networking concerns (sockets, DNS, timers) belong in transport adapter crates.
- Transport-specific address validation belongs in transport adapters, not `packages/core`.

## Quick start

Prerequisites:

- Rust stable toolchain
- Cargo

Build and run tests:

```bash
cargo test
```

## Roadmap focus

- [x] Local QUIC connectivity and integration coverage.
- [ ] Harden transport contract guarantees for long-term multi-transport support.
- [ ] Improve QUIC ergonomics and operational diagnostics.
- [ ] Add core protocols (Noise XX, ping, identify, gossipsub).
- [ ] Introduce additional transport adapters (TCP, WebSocket, WebRTC).

See `plan.md` for the detailed execution plan and milestones.
