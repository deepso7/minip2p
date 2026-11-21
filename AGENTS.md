# minip2p

minip2p is a minimal libp2p implementation in Rust: small, portable, understandable, and pleasant to use.

## Goals

- Awesome DX: clear APIs, sensible defaults, and actionable errors.
- Sans-I/O: keep core logic deterministic. Adapters and drivers own I/O, clocks, and timers.
- `no_std + alloc` core crates.
- No `async`/`.await`; remain caller-driven and executor-independent.
- QUIC and TCP side by side: QUIC is `std`-only; TCP is portable down to `no_std`.
- `unsafe` is forbidden, except one scoped call in `minip2p-quic` (ADR 0019) and napi-rs's generated code in `crates/nodejs`.
- Pre-1.0: breaking API changes are fine.

## Commands

`just` mirrors CI; `just --list` shows every recipe.

```bash
just dev           # fast loop: fmt check, workspace clippy, workspace nextest
just test          # nextest + doctests + the feature matrix's `ci` rows; needs cargo-nextest
just clippy full   # every feature-matrix row, as CI lints them; run before pushing feature-gated code
just fmt           # also formats fuzz/
```

- Single test: `cargo test -p minip2p-ping test_name`. Endpoint features: `cargo test -p minip2p-rs --features tcp`; `scripts/run-feature-matrix.sh list` prints every matrix row.
- `fuzz/` is outside the workspace: use `--manifest-path fuzz/Cargo.toml`.
- Release: `just release <version>` bumps versions, pushes, and publishes. The release workflow runs the full matrix; add `--full-local` to run it locally first.

## Architecture

Four layers, strictly separated; layers 1, 2, and 4 live in `crates/`. Each published crate's README covers its API.

1. **Sans-I/O protocol crates** (`no_std + alloc`): `multistream-select`, `ping`, `identify`, `relay`, `pubsub`, `mdns`, plus `identity`, `core` (incl. `platform` time/entropy contracts), `tls`, `secure-mux` (Noise + Yamux session, shared by circuit and TCP), `transport`, `circuit`, and `smoltcp`.
2. **Sans-I/O orchestrators**: `swarm` (`SwarmCore`; `std` adds `Swarm<T>`), `nat` (AutoNAT v1, DCUtR, `NatAgent`), `relay-server`, `discovery`.
3. **Transport adapters**: `transports/quic` (`std`, quinn-proto), `transports/tcp` (`no_std`, pluggable `TcpProvider`), `transports/webtransport` (`no_std`, HTTP/3 codec and browser client). QUIC and the bundled TCP providers take `/ip4`/`/ip6` only; the `std` `Endpoint` resolves `/dns*`.
4. **Application and binding adapters**: `minip2p` (package `minip2p-rs`: the application-facing `Endpoint`, portable without `std`), `ffi-core`, `ffi` (UniFFI), `nodejs` (napi-rs), `web` (wasm, `@minip2p/web`).

The default swarm composes only identify + ping + protocols registered via `SwarmBuilder::protocol`/`EndpointBuilder::protocol`; relay/AutoNAT/DCUtR policy belongs to the host. `code-ref/` holds read-only reference checkouts outside the build.

Before adding an Endpoint capability or Cargo feature, an `EndpointEvent` variant, or a binding method or config field, read `docs/agents/change-recipes.md`: each touches several layers in a fixed set of places.

## Conventions

- Keep rustdoc current on all public APIs, and a README current for every published crate.
- Wire-facing decoders get fuzz coverage via the `wire_inputs` target in `fuzz/`.
- Add the `bench` label to PRs touching a perf-sensitive path, and review the results comment for regressions.

## Coding preferences

- YAGNI: concise, simple solutions over clever or heavy abstractions. If a substantially simpler approach exists, use it or surface it.
- Lean on the type system.
- No implementation comments (`//`, `/* */`, `#` in scripts); rustdoc and JSDoc are fine. Let names and types carry the meaning, record a non-obvious decision in an ADR, and file an issue for a known shortcut instead of excusing it. `scripts/check-comments.py` ratchets the remaining count down in CI; `/delete-comment` runs a sweep.
- Tests are focused: no endless smoke tests or "regression tests" for deleted features.
- TypeScript: inferred types, never `any`; no one-line casting wrappers; idiomatic TS that Matt Pocock and Theo would be proud of. Prefer Effect for application services, concurrency, resource management, and typed errors; keep it out of trivial pure code.

## Killing processes

Kill only a PID you captured when starting the process, or the listener from `lsof -nP -iTCP:<port> -sTCP:LISTEN -t` after confirming its cwd with `lsof -a -p <pid> -d cwd -Fn`. Never match by name, path, or worktree string (`pkill -f`, `pgrep | kill`). Use `kill <pid>`, then `kill -9` only if that fails.

## Questions are read-only

A message that asks rather than instructs ("how hard would it be", "should we", "why does", "is it possible", "can X do Y") gets an answer, not edits. If the change is obvious and trivial, offer it and ask first.

## Agent skills

- Issues and specs live in GitHub Issues: `docs/agents/issue-tracker.md`.
- Triage uses the five default canonical labels: `docs/agents/triage-labels.md`.
- Domain docs use a single-context layout with `GLOSSARY.md` and `docs/adr/` at the root: `docs/agents/domain.md`.
