# minip2p

minip2p is a minimal libp2p implementation in Rust: small, portable, understandable, and pleasant to use.

## Goals

- Awesome DX: clear APIs, sensible defaults, and actionable errors.
- Sans-I/O: keep core logic deterministic; I/O belongs in adapters.
- `no_std + alloc` core crates.
- No `async`/`.await`; remain caller-driven and executor-independent.
- QUIC and TCP side by side: QUIC is `std`-only; TCP is portable down to `no_std`.

Additional constraints: `unsafe` is forbidden workspace-wide; sockets, clocks, and timers live only in adapters/drivers; pre-1.0, breaking API changes are fine.

## Commands

`just` mirrors CI (`.github/workflows/ci.yml`):

```bash
just test          # nextest + doctests over the Endpoint feature matrix; needs cargo-nextest
just clippy        # -D warnings, Endpoint TCP/discovery/mDNS variants, and fuzz/
just fmt           # also formats fuzz/
just check-nostd   # all no_std crates on thumbv7em-none-eabi
just fuzz 30       # needs nightly + cargo-fuzz
```

Single test: `cargo test -p minip2p-ping test_name` (plain `cargo test` is fine
for one test; the full matrix uses nextest because it runs every binary's tests
at once instead of one binary at a time). Endpoint features:
`cargo test -p minip2p-rs --features tcp` (or `mdns`, `discovery`,
`discovery,mdns,tcp`; see `justfile` for the full matrix). `fuzz/` is outside the
workspace — use `--manifest-path fuzz/Cargo.toml`.

Publish a release end to end with:

```bash
just release 0.3.2
```

The command bumps every public package and local dependency, regenerates
lockfiles, waits for push CI, publishes the GitHub release, waits for the native
build and registry workflow, and verifies crates.io and npm. The default path
leaves the full matrix to GitHub to avoid running it twice; use
`just release 0.3.2 --full-local` to run it locally before pushing as well.


## Architecture

Four layers, strictly separated:

1. **Sans-I/O protocol crates** (`no_std + alloc`), one per protocol: `multistream-select`, `ping`, `identify`, `relay`, `autonat`, `dcutr`, `pubsub`, `mdns` (agent plus the portable `MdnsDriver` over an `MdnsIo` seam, with `MdnsSockets` behind `std` and `SmoltcpMdnsIo` behind `smoltcp`); plus `identity`, `core`, `tls`, `platform` (`Clock`/`Now`/`Deadline`/`EntropySource` contracts), `secure-mux` (multistream-select + Noise XX + Yamux over an ordered byte stream, shared by circuit and TCP), and `transport` (the `Transport`/`BlockingTransport` contracts, plus `TransportSet`, which routes several transports behind one of them).
2. **Sans-I/O orchestrators**: `crates/swarm` (`SwarmCore`, the `no_std` `SwarmRuntime` that drives a transport against it, and a `std`-gated `Swarm<T>` that adds a clock and a blocking wait), `crates/nat` (`NatAgent`: direct-dial vs. relay race + DCUtR hole punching), `crates/relay-server` (`RelayServerAgent`: reservation admission and relay forwarding), and `crates/discovery` (`BeaconAgent` + `PeerDiscoveryAgent`: signed beacons and the shared multi-source book/dial policy).
3. **Transport adapters**: `transports/quic` (`std`-only, quiche-based, owns UDP/DNS, exposes deadlines) and `transports/tcp` (`no_std + alloc`; `TcpTransport` over a pluggable `TcpProvider` byte-stream seam, with `StdTcpProvider` on `mio` behind `std` and `SmoltcpTcpProvider` behind `smoltcp`).
4. **`std` adapters**: `crates/minip2p` — the application-facing `Endpoint` API, which composes the transports it is asked to bind into a `TransportSet` and routes by address, and whose features layer on without changing the base API — `crates/ffi-core`, the binding-agnostic detached driver, event carry, and endpoint lifecycle — and `crates/ffi`, the thin UniFFI binding shell.

The default swarm composes only identify + ping + protocols registered via `SwarmBuilder::protocol`/`EndpointBuilder::protocol`; relay/AutoNAT/DCUtR policy belongs to the host. `code-ref/` is read-only reference checkouts, not part of the build.

## Conventions

- Every crate has a README and rustdoc on all public APIs; keep both current.
- Wire-facing decoders get fuzz coverage via the `wire_inputs` target in `fuzz/`.

## Coding Preferences

- Prefer concise, simple solutions over clever or heavy abstractions. Channel "YAGNI" principles and avoid over-engineering.
- Typesafety is useful, take advantage of it.
- If a substantially simpler approach exists, use it or surface it clearly.
- Comments are a great way to clarify functionality and how code is used. Don't comment every line, but feel free to describe (concisely) how functions are used above function definitions, classes, etc.
- Keep comments up to date! When making changes, it's important to keep things in sync.
- Look for ways to reduce complexity when solving problems.
- Tests are good! Endless smoke tests, "regression tests" for feature deletions, etc., much less good. Tests should be focused, not slop.

## Coding preferences (Typescript focused)

- `any` is the enemy. Inferred types are our friend. Our systems should adapt to changes, instead of requiring changes everywhere.
- If your TS code looks like a Python dev wrote it, it is bad TS code.
- Avoid one-line functions that are just casting wrappers.
- Write TypeScript in ways that Matt Pocock and Theo would be proud of.
- Prefer Effect for application services, concurrency, resource management, and typed errors; don’t introduce it into trivial pure code.

## Don'ts

- Killing processes: Never use `pkill -f`, `pgrep | kill`, or kill a PID found by matching a name, path, or worktree string. Kill only a PID you captured when starting the process, or the listener returned by `lsof -nP -iTCP:<port> -sTCP:LISTEN -t`. Before killing a port owner, confirm its working directory with `lsof -a -p <pid> -d cwd -Fn`. Use `kill <pid>` first; use `kill -9 <pid>` only if termination fails.

## Questions are read-only

- A question is a request for an answer, not for changes. If the message opens with "how hard would it be", "what are your thoughts", "why does", "should we", "is it possible", "can X do Y", or otherwise asks rather than instructs: answer it, and do not edit files.
- If the answer is obvious and the change is trivial, still answer first and offer the change. Ask before making it.

## Agent skills

### Issue tracker

Issues and specs are tracked in GitHub Issues for this repository. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default canonical triage labels. See `docs/agents/triage-labels.md`.

### Domain docs

Use a single-context layout with `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
