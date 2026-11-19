# Plan: DX, performance, and binary-size improvements

> **Status:** Draft. Informed by the current workspace architecture, two downstream consumers (`minipaw` and `qop` across Rust, Node, React Native, and Web/WASM), and a code-verified review of the initial draft.

## Goal

Improve developer experience, runtime performance, and binary size (especially WASM/mobile/embedded) while keeping minip2p's core invariants untouched:

- Sans-I/O protocol and orchestration cores
- `no_std + alloc` core crates
- No `async`/`.await` (caller-driven, executor-independent)
- Pre-1.0 breaking API changes are acceptable

Today, real applications (`minipaw`, `qop`) hit recurring friction points:

- **Rust stream ergonomics:** Callers pass `(ConnectionId, StreamId)` tuples everywhere (`qop` defines its own `type StreamKey`), wire a sidecar `StreamWriter` manually on every event (and sweep `is_pending` on every event to detect dropped writes), or hand-roll partial-write/retry buffers (`minipaw`). Using `?` on bare `send_stream` silently drops the unsent tail inside `DriverError::Full`. Both `ffi-core` (`writes.rs`) and `crates/web` (`host.rs`) duplicate write-tracking around `StreamWriter`.
- **Duplicated endpoint surface:** `crates/minip2p/src/std/mod.rs` and `crates/minip2p/src/portable/mod.rs` maintain parallel forwarding APIs over the same `Engine`, so every new endpoint API has to be built twice.
- **Lifecycle and relay rough edges:** Short-lived tools loop `endpoint.wait(Duration::ZERO)` up to 16 times to flush final frames/FINs before closing (`minipaw`). Callers inspect `old.is_circuit() && !new.is_circuit()` to detect relay-to-direct upgrades. `minipaw/web` pre-dials its configured relay before calling `connect(peerId)`.
- **WASM packaging & size:** `@minip2p/web` already loads `.wasm` via `import.meta.url` by default (`bindings/ts/web/src/wasm.ts:28`), but bundlers that pass the asset explicitly (e.g. Vite `?url`) have to reach into `../node_modules/@minip2p/web/wasm/minip2p_web_bg.wasm?url` because the `.wasm` asset is not exported. The uncompressed `.wasm` is ~3.6 MB (~0.5 MB compressed), and `crates/web` unconditionally includes `pubsub` and `serde-wasm-bindgen`.

Non-goals:

- Adding `async`/`.await` or a runtime dependency to core crates.
- Replacing the static capability pass in `Engine` with a `NetworkBehaviour`-style trait/macro system.
- Changing wire protocols or breaking libp2p interoperability.
- Speculative perf/size rewrites without measurements (`BuiltinTransport` enum over `TransportSet`, `ffi-core` driver lock rewrites, `DatagramExt` trait splitting, or shortening actionable error messages).

---

## Decisions

### 1. Small standalone wins

1. **`PeerId: Copy`.**
   - `PeerId` (`crates/identity/src/peer_id.rs`) wraps `Multihash`, which is already `Copy` — derive `Copy` on `PeerId` to remove `.clone()` noise across callers.
   - Keep `peer_id` on stream events: `peer_of(conn_id)` can fail once a connection is gone (e.g. `StreamClosed` arriving around `ConnectionClosed`), and keeping the field avoids unnecessary binding churn.
   - Shrinking `PeerId`'s inline digest size (`Multihash<64>` → ~56 bytes at `Multihash<42>`) is deferred unless measurements justify splitting the `minip2p_identity::Multihash` alias shared with Noise certhashes (`crates/secure-mux/src/noise.rs:499`).

2. **Safe partial-write return type (`SendOutcome`).**
   - Change bare `send_stream` (renamed or kept as `try_send_stream`) to return `Result<SendOutcome, DriverError>` where `#[must_use] pub enum SendOutcome { Accepted, Full { unsent: Bytes } }`. That way `?` propagates fatal errors without ever silently dropping `unsent`.

3. **Path metadata on `ConnectionReplaced`.**
   - Carry `old_path: Path` and `new_path: Path` on `EndpointEvent::ConnectionReplaced` so callers never inspect `ConnectionId::is_circuit()` to tell a planned relay-to-direct upgrade from a lost link.

4. **Export `./wasm` in `@minip2p/web`.**
   - Add `"./wasm": "./wasm/minip2p_web_bg.wasm"` to `bindings/ts/web/package.json` `exports` so callers passing a custom `WasmSource` (such as Vite `?url`) don't import from `../node_modules/...`.

### 2. Unify `Endpoint` and `PortableEndpoint` first

- Collapse the parallel forwarding APIs in `crates/minip2p/src/std/mod.rs` and `crates/minip2p/src/portable/mod.rs` behind one `Endpoint<P>` surface (defaulting `P = StdPlatform` under `std`), where `P` supplies only clock, transport binding, name resolution, and blocking wait.
- Landing this before the stream/lifecycle changes means `StreamKey`, the built-in write queue, `ProtocolId`, and `flush` are implemented once instead of twice.

### 3. Stream & endpoint ergonomics

1. **First-class `Copy` `StreamKey`.**
   - Introduce `StreamKey` in `minip2p-transport` (wrapping `ConnectionId` + `StreamId`, with `.conn_id()` and `.stream_id()` accessors).
   - `open_stream` returns `StreamKey`; `send_stream`, `try_send_stream`, `close_stream_write`, `reset_stream`, `ack_stream`, and stream events take/carry `StreamKey`.
   - `crates/ffi-core` and the bindings keep flattening `StreamKey` into two numeric fields (`conn_id`, `stream_id`) on the carry and binding boundary, so the TypeScript surface does not change.

2. **Move bounded write queuing into `Endpoint` and delete `StreamWriter`.**
   - Remove the separate `StreamWriter` sidecar type.
   - `Endpoint` owns the optional bounded write queue (configured via `.write_budget(bytes)` on the builder, `0` = zero-overhead opt-out for callers using `try_send_stream` directly).
   - `Endpoint` automatically retries on `StreamWritable` and emits `StreamWriteAccepted { stream }` / `StreamWriteAborted { stream }` when a held write finishes or its stream/connection ends.
   - `crates/ffi-core` (`writes.rs`) and `crates/web` (`host.rs`) drop their own write-tracking wrappers and delegate to `Endpoint`.

3. **Interned `ProtocolId` handles (typed convenience).**
   - Keep `.protocol(&str) -> Self` fluent on the builder (so dynamic/config-driven callers like `qop` and `ffi-core` stay ergonomic), and expose `ProtocolId(u16)` lookup (`endpoint.protocol_id(&str) -> Option<ProtocolId>`, `endpoint.protocol_name(id) -> &str`) carried on `StreamReady`.

4. **`Endpoint::flush(deadline)` and flush-before-close.**
   - Add `flush(deadline)` to drive queued outbound frames/FINs onto the wire until drained or the deadline expires, replacing the `wait(Duration::ZERO)` loop workaround.
   - Ensure `close_within(timeout)` flushes pending outbound writes/FINs before tearing down connections.

5. **Auto-relay on `connect(peer_id)` when relays are not yet connected.**
   - Investigate and fix the case seen in `minipaw/web/lib/chat.ts` where `connect(peer_id)` requires the caller to pre-dial a configured relay first; when relays are configured, `connect(peer_id)` should initiate/wait on the relay connection within the same `ConnectionAttempt`.

6. **Evaluate exposing `ffi-core`'s detached driver for Rust apps.**
   - `qop/desktop/src/node.rs` reimplements a detached `Endpoint` driver thread + command channel + stream handles in Rust. Evaluate making `ffi-core`'s detached driver usable directly from Rust (without FFI string/serde flattening) rather than building a second thread-hosted wrapper.

### 4. Measurement-gated performance & binary-size work

Each item here is gated on measuring first so we only take on complexity that pays for itself:

1. **Box cold/large event variants.**
   - Measure `size_of::<TransportEvent>()`, `size_of::<SwarmEvent>()`, and `size_of::<EndpointEvent>()`, then box infrequent large variants (`IdentifyMessage`, `ConnectOutcome`, `ConnectionEndpoint`, `PeerReady` protocol lists) and benchmark `endpoint_throughput` / `endpoint_ping_load`.

2. **WASM size audit (`twiggy top`) before changing `crates/web`.**
   - Profile `minip2p_web_bg.wasm` with `twiggy top` and `twiggy dominators` to see what actually drives the ~3.6 MB size.
   - Likely candidates to evaluate from the profile:
     - Making `pubsub` optional in `minip2p-web` (so stream+relay apps don't pay for Gossipsub).
     - Replacing `serde-wasm-bindgen` with a compact binary `Uint8Array` bridge (weighing `.wasm` savings against maintaining a TS decoder).
     - Pushing non-generic orchestration out of `Engine<T, E, M>` to reduce monomorphization.

3. **Zero-alloc `poll(&mut self, now, out: &mut Vec<_>)` (only if benchmarks justify it).**
   - Idle ticks already do not allocate (`Vec::new()` is zero-alloc), and changing `Transport::poll` touches every transport and ~10 test transports. Profile active throughput allocations first (`endpoint_throughput`, `endpoint_ping_load`) before committing to the trait break.

### 5. Internal maintainability (non-breaking)

- Split `crates/swarm/src/state.rs` (~3,400 lines prod) into focused submodules (`connections`, `streams`, `identify`, `ping`). (`std/mod.rs` is already broken up during PR 2's `Endpoint<P>` unification.)

---

## PR stack

Order: **small wins → merge endpoints → stream ergonomics → measured perf/size**. Breaking architectural decisions (`Endpoint<P>`, `StreamKey`, `Endpoint`-owned write queue, `ProtocolId`) each include an ADR in `docs/adr/` and updated terms in `GLOSSARY.md`.

1. **Small wins (can be 1–4 tiny PRs):**
   - `@minip2p/web`: export `./wasm` in `bindings/ts/web/package.json`.
   - `PeerId: Copy`.
   - `EndpointEvent::ConnectionReplaced` carries `old_path` / `new_path`.
   - `try_send_stream -> Result<SendOutcome, DriverError>`.
2. **Unify `Endpoint` and `PortableEndpoint`:** single `Endpoint<P>` surface (ADR + glossary), splitting `std/mod.rs` into submodules as part of the move; check WASM size before/after to catch monomorphization regressions.
3. **Stream ergonomics:** `StreamKey` across transport/swarm/endpoint (ADR + glossary; `ffi-core` keeps flattened `conn_id`/`stream_id` fields) + `Endpoint`-owned bounded write queue deleting `StreamWriter`, `ffi-core/src/writes.rs`, and `web`'s `StreamWriter` glue (ADR + glossary). Add the `bench` PR label (`send_stream` is the hottest path).
4. **Protocol handles & lifecycle UX:** interned `ProtocolId` (ADR), `Endpoint::flush(deadline)` + flush-before-close, and auto-relay on `connect(peer_id)`.
5. **Measured perf:** box cold/large event variants (with `bench` PR label); only pursue `poll(&mut Vec)` if throughput allocation profiling justifies the trait break.
6. **Measured WASM size:** run `twiggy top` on `minip2p_web_bg.wasm`, then land the highest-yield size reductions (e.g. optional `pubsub`, `serde-wasm-bindgen` replacement if warranted, non-generic `Engine` helpers).
7. **Internal cleanup & Rust driver reuse (optional):** split `crates/swarm/src/state.rs` into submodules; evaluate exposing `ffi-core`'s detached driver for Rust consumers.

## Verification

- **Perf:** Run `endpoint_throughput`, `endpoint_rtt`, `endpoint_idle`, and `endpoint_ping_load` via the `bench` PR label on PR 3, PR 5, and any `poll` changes.
- **Size:** Track raw and brotli/gzip sizes of `minip2p_web_bg.wasm` and `just check-nostd` / `just check-wasm` on PR 2 (monomorphization check) and PR 6 (with `twiggy top`).
- **DX:** Update `docs/snippets/custom-stream`, `examples/peer`, and verify downstream simplification against `minipaw` and `qop`.
