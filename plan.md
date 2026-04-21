## MiniP2P Plan (DX + Sans-I/O + no_std)

This plan reflects the current repository state and the next execution steps.

## Non-Negotiables

- **Sans-I/O first**: protocol and transport logic are state machines, not runtime-bound loops.
- **`no_std + alloc` core**: core packages remain portable across embedded and constrained targets.
- **DX-first API design**: local setup should be easy, defaults should be practical, and errors should be actionable.
- **Transport extensibility**: architecture must support QUIC now, then TCP/WS/WebRTC without core rewrites.
- **FFI-friendly boundaries**: public APIs should be designed so future WASM/TypeScript integration is straightforward.

## Current Baseline

Implemented crates:

- `crates/identity` (`minip2p-identity`)
- `crates/core` (`minip2p-core`)
- `crates/multistream-select` (`minip2p-multistream-select`)
- `crates/ping` (`minip2p-ping`)
- `crates/identify` (`minip2p-identify`)
- `crates/relay` (`minip2p-relay`)
- `crates/dcutr` (`minip2p-dcutr`)
- `crates/transport` (`minip2p-transport`)
- `crates/tls` (`minip2p-tls`)
- `crates/swarm` (`minip2p-swarm`) -- see "Runtime adapters" below
- `transports/quic` (`minip2p-quic`)

Current validated capabilities:

- Local two-peer QUIC connectivity in integration tests.
- Bidirectional stream data exchange with half-close propagation.
- Multistream-select with spec-compliant varint-length-prefixed framing.
- Ping protocol: outbound RTT measurement, inbound echo, fragmentation buffering, configurable timeouts.
- End-to-end protocol stack: QUIC transport + multistream-select + ping in integration tests.
- Transport contract with documented lifecycle guarantees and 12 conformance tests.
- Varint helpers shared via `minip2p-identity` and re-exported through `minip2p-core`.
- Rustdoc on all public APIs. Internal comments on all private functions and types.

## Architecture Boundaries

### Core (`no_std + alloc`, Sans-I/O)

Pure state machines. No sockets, no async runtime, no wall-clock reads.
Callers pump events and bytes in; the crate emits actions/events out.

- `crates/identity`: peer identity primitives.
- `crates/core`: transport-agnostic address and shared types.
- `crates/transport`: transport contract, shared connection/event/error types (trait + data types only; concrete impls are adapters).
- `crates/tls`: libp2p TLS certificate generation and peer verification. Transport-agnostic.
- `crates/multistream-select`: `/multistream/1.0.0` negotiation state machine.
- `crates/ping`: `/ipfs/ping/1.0.0` state machine.
- `crates/identify`: `/ipfs/id/1.0.0` state machine.
- `crates/relay`: Circuit Relay v2 client state machines (`HopReservation`, `HopConnect`, `StopResponder`).
- `crates/dcutr`: DCUtR hole-punch coordination state machines (`DcutrInitiator`, `DcutrResponder`).
- `crates/swarm` (core): `SwarmCore` -- Sans-I/O orchestration state machine. Composes the protocol state machines, tracks connections and streams, drives multistream-select for inbound and outbound streams, emits `SwarmAction` for the driver to execute and `SwarmEvent` for the application.

### Runtime adapters (`std`)

Concrete I/O, real clocks, async-friendly orchestration. Consumed by
applications.

- `transports/quic`: QUIC implementation over a non-blocking UDP socket.
- `crates/swarm` (driver only): thin `std` wrapper around `SwarmCore`
  that owns a concrete `Transport`, reads the wall clock, and preserves
  the one-call DX (`swarm.dial`, `swarm.ping`, `swarm.open_user_stream`).
  The actual orchestration logic lives in `crates/swarm`'s Sans-I/O
  core (see above).
- Future `transports/tcp`, `transports/ws`, `transports/webrtc`
  adapters follow the same pattern.

### Ownership rules

- Runtime concerns (UDP/TCP sockets, DNS resolution, timers, wall clock)
  belong in adapter crates.
- Transport-specific address validation belongs in adapters, not in
  `crates/core`.
- Shared crates define generic contracts and common semantics only.
- Protocol state machines (`ping`, `identify`, `relay`, `dcutr`,
  `multistream-select`) stay Sans-I/O -- they must never grow a `Transport`
  dependency or a clock.

### Pending architectural work

Tracked concretely under the roadmap milestones; see Milestone 6
(mutual TLS on the QUIC transport) for the remaining architectural
cleanup item.

## DX Principles

- **Fast first success**: new users should get two peers connected in under 5 minutes.
- **Progressive complexity**: simple default path first, advanced tuning second.
- **Consistent semantics**: same event and error shape across transport adapters.
- **Actionable failures**: errors should include context and suggested next fix.
- **Docs as product**: quickstart and troubleshooting are part of the API quality bar.

## Transport Extensibility Policy

- `PeerAddr` remains transport-agnostic and only guarantees terminal `/p2p/<peer-id>` semantics.
- Each transport crate validates its own accepted address shapes.
- Transport crates may expose ergonomic helper APIs while conforming to shared transport contracts.

## Roadmap (Outcome-Driven)

### Milestone 0: Docs and boundary alignment -- DONE

- [x] Keep root docs aligned with actual workspace crates and capabilities.
- [x] Document no_std boundaries and adapter responsibilities.
- [x] Clarify transport-agnostic vs transport-specific validation responsibilities.
- [x] Rustdoc on all public types/methods across all crates.
- [x] Internal comments on all private functions, types, and fields.
- [x] READMEs for every crate.

**Exit criteria**
- New contributors can run tests and explain crate boundaries in under 10 minutes.

### Milestone 1: Transport contract hardening -- DONE

- [x] Document connection lifecycle, stream lifecycle, and event ordering on Transport trait.
- [x] Add 12 conformance tests for transport contract behavior.
- [x] Fix ping memory leak (`entry().or_default()`), stale state, dead error variant.

**Exit criteria**
- Shared transport behavior is explicit and test-backed.

### Milestone 2: libp2p TLS peer authentication -- DONE

New crate: `crates/tls` (`minip2p-tls`) -- `no_std + alloc` compatible.

- [x] Add `minip2p-tls` crate for cert generation and verification per the libp2p TLS spec.
- [x] Generate self-signed X.509 certs with embedded libp2p public key (OID `1.3.6.1.4.1.53594.1.1`).
- [x] Verify peer certs after TLS handshake and derive PeerId automatically.
- [x] Wire into QUIC transport: accept `Ed25519Keypair`, auto-verify on connect.
- [x] Validate against libp2p TLS spec test vectors (Ed25519, ECDSA, secp256k1).
- [x] Transport-agnostic: reusable by future TCP/WS/WebRTC adapters.
- [x] Dependencies: `x509-cert` (RustCrypto, `no_std`) for cert building, `der` for DER parsing.

**Exit criteria**
- Two QUIC peers connect and the dialer automatically knows the listener's PeerId without manual verification.
- Spec test vectors pass (Ed25519 full verification; ECDSA/secp256k1 parsing + PeerId extraction).

### Milestone 3: Identify protocol -- DONE

- [x] Add `crates/identify` for `/ipfs/id/1.0.0`.
- [x] Peers exchange supported protocols, observed addresses, agent version after connecting.
- [x] Required foundation for relay and hole punch (peers need to know each other's addresses).

**Exit criteria**
- After connecting, both peers learn each other's supported protocols and observed address. Auto-run by the swarm on every new connection.

### Milestone 4: Swarm and connection management -- DONE

- [x] Introduce a swarm layer that orchestrates connections, protocol negotiation, and address tracking.
- [x] Handle "connect to peer X" by picking transport, negotiating protocols, managing lifecycle.
- [x] Generic user-protocol hook: `add_user_protocol` + `open_user_stream` + `UserStream*` events so relay and DCUtR can ride on top without baking them into the core.
- [x] DX: `SwarmBuilder`, auto-allocated connection ids, internal clock, one-call `swarm.ping(peer)`.
- [x] Sans-I/O `SwarmCore` + `std` `Swarm<T: Transport>` driver split so core logic is `no_std + alloc` and portable.

**Exit criteria**
- A swarm connects two peers, negotiates protocols, and runs ping without manual wiring. [done]
- `cargo check --no-default-features -p minip2p-swarm` succeeds.

### Milestone 5: Relay client and DCUtR state machines -- DONE (demo pending)

- [x] `crates/relay`: Circuit Relay v2 client state machines (HopReservation, HopConnect, StopResponder), `no_std + alloc`.
- [x] `crates/dcutr`: DCUtR hole-punch coordination state machines (Initiator, Responder), `no_std + alloc`.
- [x] Pure-state-machine integration test covering the full RESERVE + CONNECT + STOP + DCUtR flow with an in-memory relay emulator.
- [ ] CLI binary `examples/peer` exercising the full stack against a real relay (local rust-libp2p for first iteration, VM-hosted relay later). See `holepunch-plan.md`.

**Exit criteria**
- Two minip2p peers connect via a real relay server, negotiate DCUtR, attempt hole punch, and succeed (direct ping) or fall back to relay ping.
- Deferred (larger scope): STUN client for address discovery, relay server binary, production-grade refusal handling.

### Milestone 6: Architectural cleanup

- [ ] Mutual TLS on the QUIC transport so the listener side learns the real client PeerId without the synthetic-placeholder dance. Requires either `quiche`'s `boringssl-boring-crate` feature with a custom verify callback, or an upstream change.

**Exit criteria**
- `TransportEvent::PeerIdentityVerified` fires on the server side of a mutual-TLS QUIC handshake; the synthetic PeerId path in Swarm is exercised only as a fallback, not as the default.

### Milestone 7: Additional transports and operational polish

- TCP + TLS transport adapter (reuses `minip2p-tls`).
- WebSocket transport adapter.
- FFI boundaries for WASM/TypeScript.
- Runnable examples and troubleshooting docs.

**Exit criteria**
- One end-to-end example runs from docs without hidden steps.

## Developer experience

DX improvements and roadmap live in `dx-plan.md`. Includes a backlog
of Tier 1/2/3 items (e.g. `SwarmEvent::PeerReady` for peer-ready
signaling, typed `SwarmEvent::Error`, `Swarm::listen()` helper,
keypair persistence) derived from real pain observed while writing
`examples/peer`.

## Quality Gates

- Unit tests for core parsing/types and error behavior.
- Integration tests for two-peer connectivity per transport.
- `cargo check --no-default-features` for `crates/identity`, `crates/core`, `crates/transport`, and `crates/tls`.
- Stable, documented error messages for common misconfiguration paths.
- Dependency and footprint discipline for core crates.

## Decision Log

- Keep **Sans-I/O** as architecture baseline.
- Keep **`no_std + alloc`** support for shared/core crates.
- Keep **QUIC-first** while designing for **multi-transport** expansion.
- Keep `transports/quic` as a **single crate** with internal layering for logic and runtime ergonomics.
- Optimize for **DX** without compromising explicit architecture boundaries.
- Varint helpers live in `minip2p-identity` (public) and are re-exported through `minip2p-core` to avoid circular deps.
- `multistream-select` depends on `minip2p-core` for shared varint code rather than duplicating it.
- Dropped `segment` index fields from `MultiaddrError`/`PeerAddrError` -- the protocol name and value in the error message are sufficient context.
- Use `x509-cert` (RustCrypto) for cert generation/verification -- `no_std + alloc` compatible, replaces `rcgen` (std-only).
- `minip2p-tls` is transport-agnostic: generates and verifies libp2p TLS certs, reusable across QUIC/TCP/WS.
- Follow the libp2p TLS spec for QUIC peer authentication -- QUIC's built-in TLS handles encryption, Noise XX would be redundant.
- Relay-first approach for NAT traversal, with hole punch (DCUtR) as optimization on top.
