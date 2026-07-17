# minip2p

minip2p is a minimal libp2p implementation in Rust: small, portable, understandable, and pleasant to use.

## Goals

- Awesome DX: clear APIs, sensible defaults, and actionable errors.
- Sans-I/O: keep core logic deterministic; I/O belongs in adapters.
- `no_std + alloc` core crates.
- No `async`/`.await`; remain caller-driven and executor-independent.
- QUIC only; other transport adapters are out of scope.

Additional constraints: `unsafe` is forbidden workspace-wide; sockets, clocks, and timers live only in adapters/drivers; pre-1.0, breaking API changes are fine.

## Commands

`just` mirrors CI (`.github/workflows/ci.yml`):

```bash
just test          # cargo test + minip2p feature matrix (nat, pubsub, nat+pubsub)
just clippy        # -D warnings, includes the separate fuzz/ workspace
just fmt           # also formats fuzz/
just check-nostd   # no_std check on thumbv7em-none-eabi
just fuzz 30       # needs nightly + cargo-fuzz
```

Single test: `cargo test -p minip2p-ping test_name`. Facade features: `cargo test -p minip2p --features nat` (or `pubsub`, `nat,pubsub`). `fuzz/` is outside the workspace — use `--manifest-path fuzz/Cargo.toml`.

## Architecture

Three layers, strictly separated:

1. **Sans-I/O protocol crates** (`no_std + alloc`), one per protocol: `multistream-select`, `ping`, `identify`, `relay`, `autonat`, `dcutr`, `pubsub`; plus `identity`, `core`, `tls`, and `transport` (trait contract only).
2. **Sans-I/O orchestrators**: `crates/swarm` (`SwarmCore`; also a `std`-gated `Swarm<T>` driver) and `crates/nat` (`NatAgent`: direct-dial vs. relay race + DCUtR hole punching).
3. **`std` adapters**: `transports/quic` (quiche-based, owns UDP/DNS, exposes deadlines) and `crates/minip2p` — the `Endpoint` facade; features `nat`/`pubsub` layer on without changing the base API.

The default swarm composes only identify + ping + protocols registered via `SwarmBuilder::protocol`/`EndpointBuilder::protocol`; relay/AutoNAT/DCUtR policy belongs to the host. `code-ref/` is read-only reference checkouts, not part of the build.

## Conventions

- Every crate has a README and rustdoc on all public APIs; keep both current.
- Wire-facing decoders get fuzz coverage via the `wire_inputs` target in `fuzz/`.
