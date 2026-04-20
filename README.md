# minip2p

A minimal, educational [libp2p](https://libp2p.io/) implementation in Rust, designed around explicit state machines and a future WebAssembly/TypeScript host API.

## Why this project exists

- **Sans-IO architecture**: protocol logic produces I/O intents; host runtimes execute network/timer I/O.
- **FFI-friendly APIs**: crate boundaries and data types are chosen to support future WASM interop.

## Current status

This repository is an early-stage workspace with four crates:

- `packages/identity` (`minip2p-identity`): implemented and tested.
- `packages/core` (`minip2p-core`): shared types (`Multiaddr`, `PeerAddr`, `PeerId` re-export).
- `packages/transport` (`minip2p-transport`): sans-IO transport trait + connection types/events.
- `transports/quic` (`minip2p-quic`): synchronous QUIC adapter built on `quiche`.

The stack now supports local two-peer QUIC connectivity, multi-connection-per-peer routing,
peer identity upgrade events, and byte exchange in integration tests.

## Quick start

### Prerequisites

- Rust stable toolchain
- Cargo

### Build and test

```bash
cargo test
```

## Planned architecture

The roadmap targets a modular libp2p stack with explicit state machines and WASM-facing APIs:

- **Core**: `PeerId`, `Multiaddr`, shared primitives.
- **Crypto**: Noise XX handshake state machine.
- **Transport**: connection abstraction and host-driven network I/O.
- **Protocols**: multistream-select, ping, identify, gossipsub.
- **Swarm**: central coordinator emitting `Action` intents and `SwarmEvent`s.
- **FFI**: callback-based bridge for JavaScript/TypeScript.

## Milestone roadmap

- [ ] Raw connectivity over QUIC (`/quic-v1`).
- [ ] Encrypted connections using Noise XX.
- [ ] Ping protocol with latency + timeout handling.
- [ ] Identify protocol for peer metadata exchange.
- [ ] GossipSub pub/sub mesh behavior.
- [ ] Documentation polish, examples, and benchmarks.

## Design principles

- **Pure state machines**: no hidden async runtime in protocol logic.
- **Clear action/event boundaries**: host executes I/O; library describes intent.
- **FFI-safe surface area**: explicit conversions and error handling.
- **Educational clarity**: predictable behavior and testable components.

## Next focus areas

Short-term, this repository is expected to expand from identity primitives into:

1. Shared core types (`Multiaddr`, common errors/types).
2. Transport + connection lifecycle state management.
3. Initial swarm orchestration and action/event plumbing.
4. Protocol negotiation and baseline ping/identify flows.
