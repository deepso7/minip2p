# Plan: Codebase simplification for humans and agents

> **Status:** Draft — ready for execution. Synthesized from a two-round, three-provider council (GPT 6.2 Sol high, Claude Opus 5.5 medium, Gemini 4 Neon high): Round 1 explored simplification opportunities and rejected four risky abstractions; Round 2 scored v1 (6.5/10 Claude, 7/10 GPT Sol, 7/10 Gemini) and surfaced concrete file-level invariants, all folded into this v2 stack.

## Goal

Reduce the fan-out, duplication, and verification friction of working on `minip2p` — for both human contributors and coding agents — while keeping every core invariant intact:

- Sans-I/O protocol and orchestration cores (`no_std + alloc`, no `async`/`.await`)
- Zero runtime throughput/latency regression
- Zero linked WASM (`crates/web`) or embedded (`thumbv7em-none-eabi`) binary-size regression
- Explicit, readable orchestration over clever abstractions (ADR 0008, ADR 0020, ADR 0029)

Today, small changes pay an unnecessary tax across five places:

1. **Verification drift and slow local loops:** Feature/target lists are hand-copied across six places (`scripts/run-feature-matrix.sh`, `justfile` ×3 blocks, `.github/workflows/ci.yml`, `.github/workflows/publish.yml`), `just clippy` builds all 34 feature-matrix rows locally, and `.github/workflows/publish.yml:768-792` maintains a hand-ordered 23-crate publish list.
2. **Missing contributor/agent navigation maps:** `AGENTS.md` describes the four layers well, but has no "how to change X" checklist, `.agents/skills/` (symlinked from `.claude/skills/`) loads ~30 overlapping skills, `scripts/` has 18 unindexed scripts, and `docs/research/quinn-proto-spike/` pollutes repo-wide searches for `SwarmBuilder`.
3. **Oversized inline test modules:** Several core files are 50–75% inline `#[cfg(test)]` (`connect.rs`, `circuit/src/lib.rs`, `swarm/src/driver.rs`, `swarm/src/core.rs`, `ffi-core/src/endpoint.rs`, `secure-mux/src/yamux/session.rs`, `portable/mod.rs`), and two test files exceed 2,800–4,500 LOC (`swarm/src/state/tests.rs`, `minip2p/src/std/tests.rs`), blowing up human and agent context windows.
4. **Three duplicated endpoint builders:** ADR 0029 unified `Endpoint<P>`, but `EndpointBuilder` (`std/builder.rs`), `PortableEndpointBuilder` (`portable/mod.rs:370`), and `SmoltcpEndpointBuilder` (`portable/mod.rs:708`) still duplicate ~17 setters, protocol registration rules, and ~140 `#[cfg(feature = ...)]` sites.
5. **Duplicated binding lifecycle & TS enum mirrors:** `crates/ffi-core` and `crates/web` duplicate `open_stream`/`abandon_stream` carry/ack policy; `bindings/ts/core/src/types.ts` and `bindings/ts/react-native/src/adapter.ts` (`ENUM_FIELDS`) hand-mirror Rust enums with silent runtime breakage on drift.

## Non-goals (explicitly excluded)

Do **not** introduce any of the following in this stack:

- **No dynamic `Capability` trait or `dyn RelayLegProvider` in `crates/minip2p`.** `Engine::drive` (`crates/minip2p/src/engine.rs:677`) has load-bearing ordering constraints (relay-server claims streams first, NAT routing precedes discovery/settlement, mDNS forces an extra transport poll on shared stacks). Keep explicit drive order and zero-cost `LegProvider<T>`/`Legs` (ADR 0008).
- **No moving React Native onto a JSON/serde bridge.** Keep UniFFI typed records and byte payloads intact; eliminate drift via codegen instead.
- **No blind pruning of `minip2p-rs` Cargo features.** Embedded (`thumbv7em-none-eabi`) and browser (`wasm32-unknown-unknown`) targets rely on compiling subsets without unused code. Fix matrix/builder duplication first; only evaluate feature pruning later with linked size measurements.
- **No folding `minip2p-autonat` / `minip2p-dcutr` into `minip2p-nat` or retiring `Swarm<T>`.** `crates/swarm/Cargo.toml:41` dev-depends on `minip2p-dcutr` while `crates/nat/Cargo.toml:33` depends on `minip2p-swarm` (creating a dev-dependency cycle), folding widens deps for standalone/fuzz consumers, and `Swarm<T>` is backed by ADR 0013 and QUIC/TCP integration tests. Treat any future change to those as a separate ADR.
- **No changing `crates/nodejs` config conversion or `crates/ffi` forwarders here.** Keep binding scope narrow and high-signal.

---

## Performance & binary-size gates

`cargo check` verifies target compatibility only; it does **not** prove binary-size parity.

- **PRs 1, 2, 3:** Touch zero production code (zero perf/size risk).
- **PR 4 (shared `CommonBuilder`) & PR 5 (shared stream lifecycle helper):**
  - Compare linked WASM output from `pnpm --filter @minip2p/web wasm:build` (both default and `--no-default-features`) before vs. after against the merge base.
  - Compare linked `thumbv7em-none-eabi` size (or `cargo size`/object `.text` delta on `minip2p-rs` with `smoltcp,relay,discovery,relay-server`) before vs. after PR 4 to verify non-generic `CommonBuilder` introduces zero monomorphization growth.
  - Add the `bench` label on PR 5 (touches native `open_stream`/`abandon_stream` command path) and verify no regression in throughput/latency.
- **PR 6 (TS codegen):** Generator must be strictly a dev/build-time tool with zero runtime or proc-macro dependencies added to `minip2p-ffi-core`.

---

## PR Stack

Land these as **6 independent, small PRs** in order (PR 3 before PR 4 keeps PR 4's diff clean by moving `portable/mod.rs`'s inline tests out first).

### PR 1 — Single-source verification matrix, faster local loop, and publish-order verification

**Problem:** Feature and target commands are duplicated across 6 places:

- `scripts/run-feature-matrix.sh` (34 rows: 10 `ci`, 24 `release`)
- `justfile:33-85` (`check-nostd`, `check-wasm`, `docs`, `package-check`)
- `.github/workflows/ci.yml:92-128` (4 redundant `cargo check` lines + copy-pasted `nostd`, `wasm`, `docs`, `package-check`, already drifted on `--allow-dirty` and `grep` vs `rg`)
- `.github/workflows/publish.yml:180-188` (drifted `cargo doc` subset)
- `.github/workflows/publish.yml:768-792` (hand-ordered 23-crate publish list)

**Changes:**

1. **Unify the matrix definition into one data file + driver script** (e.g. `scripts/matrix.tsv` or structured rows inside `scripts/run-feature-matrix.sh` plus a single target-check driver script) covering:
   - Host feature rows (`check`, `clippy`, `test`, `test-full`) with **unique short row names** so a human or agent can run a single row (e.g. `just matrix clippy smoltcp` or `scripts/run-feature-matrix.sh clippy --row <name>`).
   - `nostd` (`thumbv7em-none-eabi`), `wasm` (`wasm32-unknown-unknown`), `docs`, and `package-check` lists.
2. **Preserve CI coverage while speeding up local defaults:**
   - Add a fast workspace-only `just dev` recipe (`cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo nextest run --workspace`).
   - Make `just clippy` default to `ci` rows (plus workspace and `fuzz/`), with `just clippy full` (or `just clippy clippy-full`) running all 34 rows.
   - **Keep `.github/workflows/ci.yml` and `scripts/release.sh:213` (`--full-local`) explicitly calling full-matrix clippy** so PR CI does not silently lose lint coverage on release-tier feature combinations (`publish.yml` does not run clippy).
   - Remove the 4 redundant `cargo check -p minip2p-rs` lines at `.github/workflows/ci.yml:92-95` (already covered by `run-feature-matrix.sh clippy`).
3. **Eliminate CI ↔ `justfile` copy-paste:**
   - Have `.github/workflows/ci.yml` and `.github/workflows/publish.yml:180-188` call the shared scripts instead of repeating `cargo check`/`cargo doc`/`cargo package` commands.
   - Keep `--allow-dirty` strictly on local `just package-check` (not CI), and use standard POSIX `grep` consistently instead of `rg` so it works on bare CI runners too.
   - Preserve or update the workflow test assertion in `bindings/ts/tests/workflows/publish.test.mjs:97` (`/run-feature-matrix\.sh test-full/u`).
4. **Verify (or derive) the 23-crate publish order in `.github/workflows/publish.yml:768-792`:**
   - Add a small verification check (run in `package-check` / `ci.yml`) that computes the topological publish order from `cargo metadata --no-deps --format-version 1` — filtering `publish != []`, **excluding `kind == "dev"` edges** (important: `crates/circuit/Cargo.toml:35` has an unversioned TCP dev-dep that is not a publish prerequisite), **including `optional == true` normal/build deps**, with deterministic tie-breaking — and either drives `publish.yml` directly or fails CI if the list in `publish.yml` drifts from workspace metadata.
   - Keep `publish.yml`'s existing per-crate HTTP 200 skip + retry loop intact (do not blindly swap to `cargo publish --workspace` without preserving resumability on partial release failures).

**Verification:**

- `just fmt`, `just dev`, `just clippy full`, `just test`, `just check-nostd`, `just check-wasm`, `just docs`, `just package-check`
- `node --test bindings/ts/tests/workflows/publish.test.mjs`
- Verify single-row invocation works (e.g. running one named row only)

---

### PR 2 — Agent & contributor navigability

**Problem:** Agents waste turns rediscovering implicit registration sites, skill prompts carry ~30 overlapping vendored skills, `scripts/` is an ungrouped 18-file folder, and `docs/research/quinn-proto-spike/` injects `libp2p::SwarmBuilder` into repo-wide searches.

**Changes:**

1. **Add a concise "Change recipes" table to `AGENTS.md`** mapping common tasks to exact touch points and focused verification commands:
   - Adding a new application protocol (`SwarmBuilder::protocol` / `EndpointBuilder::protocol`)
   - Adding a new endpoint capability / Cargo feature (crate, `crates/minip2p/Cargo.toml`, `setup.rs`, `engine.rs`, builder, matrix data file, `ffi-core` config if exposed)
   - Adding a new `EndpointEvent` variant (`swarm/src/events.rs`, `minip2p/src/portable/event_stream.rs`, `ffi-core/src/events.rs`, TS bindings)
   - Adding a new binding method/config field (`minip2p`, `ffi-core`, `ffi`, `nodejs`, `web`, `bindings/ts/*`)
   - Document the remaining useful `just` recipes (`dev`, `check`, `docs`, `package-check`, `bindings-check`, `bench-build`) and note `crates/circuit`, `crates/smoltcp`, `crates/test-support` in the layer summary.
2. **Add lightweight directory maps:**
   - `scripts/README.md` grouping the 18 scripts into _local dev/CI_, _benchmarks_, _release_, and _relay container/installer_ (avoid moving script paths unless every workflow/justfile reference is updated).
   - `tests/README.md` accurately documenting **both** `tests/interop/` (linking to `tests/interop/README.md`) **and** `tests/support/` (`endpoint.rs`, `relay.rs`, `relay_interop.rs`, included via `#[path = ...]` across `crates/minip2p`, `crates/ffi`, and `examples/chat`).
   - Add a one-line historical note in `docs/adr/` (or `docs/adr/README.md` / `0015-withdrawn.md` if appropriate) explaining the `0014` → `0016` numbering gap only if confirmed unused.
3. **Exclude `docs/research/quinn-proto-spike/` from code search:**
   - It is git-tracked measurement provenance linked from `docs/research/quinn-proto-migration.md:10`. Keep it in git, and add `docs/research/quinn-proto-spike/` to a root `.rgignore` (or `.ignore`) file so ripgrep/agent code searches skip it without hiding it from git.
4. **Clean up `.agents/skills/` safely:**
   - **Keep `docs/agents/*.md` untouched** (these are the repo's filled-in configuration files, not duplicates of upstream templates).
   - Audit `.agents/skills/` against `skills-lock.json` and `.claude/skills/` (every entry in `.claude/skills/` is a symlink to `../../.agents/skills/*`). Remove only genuinely unused/redundant overlapping skills (e.g. duplicate `grill-*` / `implement-*` / `improve-*` variants), updating **`skills-lock.json`** and removing the corresponding **`.claude/skills/*` symlinks** in lockstep so zero broken symlinks remain. Leave `docs/.agents/skills/` untouched.

**Verification:**

- `find .claude/skills -xtype l` returns empty (no broken symlinks)
- `rg SwarmBuilder` no longer hits `docs/research/quinn-proto-spike/`
- `just docs-site` and `just test` pass

---

### PR 3 — Extract oversized inline `#[cfg(test)]` modules & split giant test files

**Problem:** Production files carry 850–2,000 LOC of inline unit tests, and two standalone test files are 2,848–4,518 LOC, hurting readability and agent context budgets. (Note: `crates/relay-server/src/agent.rs:3164` only has 26 lines of inline tests — do **not** touch it.)

**Changes (strictly zero behavior change):**

1. **Extract large inline `#[cfg(test)]` modules using the repo's `#[path = "..._tests.rs"]` convention** (following `crates/minip2p/src/setup.rs:538-540`, so tests retain `super::*` access to private items without widening production visibility to `pub(crate)`):
   - `crates/minip2p/src/connect.rs` (inline tests starting ~line 1563, ~1,900 LOC) → `connect_tests.rs`
   - `crates/minip2p/src/portable/mod.rs` (inline tests starting ~line 951, ~857 LOC) → `portable/tests.rs` _(do this before PR 4!)_
   - `crates/circuit/src/lib.rs` (inline tests starting ~line 1216, ~2,000 LOC) → `tests.rs`
   - `crates/swarm/src/driver.rs` (inline tests starting ~line 620, ~1,830 LOC) → `driver_tests.rs`
   - `crates/swarm/src/core.rs` (inline tests starting ~line 1098, ~1,403 LOC) → `core_tests.rs`
   - `crates/ffi-core/src/endpoint.rs` (inline tests starting ~line 1127, ~1,453 LOC) → `endpoint_tests.rs`
   - `crates/secure-mux/src/yamux/session.rs` (inline tests starting ~line 1214, ~1,417 LOC) → `session_tests.rs`
2. **Split the two giant test files by behavior into submodules:**
   - `crates/swarm/src/state/tests.rs` (4,518 LOC) → `crates/swarm/src/state/tests/{mod.rs, connections.rs, streams.rs, identify.rs, ping.rs, ...}`
   - `crates/minip2p/src/std/tests.rs` (2,848 LOC) → `crates/minip2p/src/std/tests/{mod.rs, ...}`
3. **Invariants to watch:**
   - Adjust relative `include_bytes!` certificate fixture paths if `std/tests.rs` moves one directory deeper (see `crates/minip2p/src/std/tests.rs:776`).
   - Check `.config/nextest.toml:36` test-name filters so no filter silently stops matching after module renames.
   - Preserve every `#[cfg(feature = ...)]` gate on test submodules.

**Verification:**

- Capture test count before and after via `cargo nextest list --workspace` and across `ci` feature-matrix rows — **exact same test count** (zero tests dropped or skipped).
- `just clippy full`, `just test`, `just check-nostd`, `just check-wasm`

---

### PR 4 — Share builder state & protocol registration via non-generic `CommonBuilder`

**Problem:** `EndpointBuilder` (`crates/minip2p/src/std/builder.rs`), `PortableEndpointBuilder<E, C>` (`crates/minip2p/src/portable/mod.rs:370`), and `SmoltcpEndpointBuilder<D, E, C>` (`crates/minip2p/src/portable/mod.rs:708`) duplicate ~17 shared option setters, capability flags, and protocol registration logic (with subtle drift: `std/builder.rs:348` deduplicates `protocol()`, while `portable/mod.rs:411` does not; `manual_ack_protocol()` exists only on `Std`, forcing a post-build loop in `crates/web/src/host.rs:128-135`).

**Design (avoid public typestate churn & embedded monomorphization bloat):**

1. **Introduce a private, non-generic `pub(crate) struct CommonBuilder`** (e.g. in `crates/minip2p/src/builder_common.rs` or `setup.rs`) holding all platform-independent builder state:
   - `agent_version`, `simultaneous_dial_window_ms`, `connect_deadline_ms`, `write_budget`, `timeouts`
   - `protocols: Vec<String>` (unified deduplication preserving first-seen registration order and stable `ProtocolId` handle numbering across duplicate calls)
   - `manual_ack_protocols: Vec<String>` (shared across `Std`, `Portable`, and `Smoltcp`, eliminating the post-build loop in `crates/web/src/host.rs:128-135`)
   - `capabilities: Capabilities` (store `relay_server` directly in `capabilities.relay_server` on `Std` too so relay-server options are shared, while keeping `Std`'s pre-bind validation in `prepare()` before `bind_transports()` opens sockets — see `std/builder.rs:629` and `669-690`)
2. **Keep the three public builder types intact** (`EndpointBuilder`, `PortableEndpointBuilder<E, C>`, `SmoltcpEndpointBuilder<D, E, C>`) — or evaluate a thin wrapper only if it adds zero public breakage and zero `Portable<T, E, C>` (`platform.rs:78`) collision:
   - Every shared setter on the three builders becomes a one-line delegation to non-generic `CommonBuilder::set_*` methods (or a tiny internal `macro_rules! delegate_common_builder!` in `crates/minip2p` so adding a new shared option touches **one** struct + **one** macro instead of three files).
   - Keep genuinely divergent platform methods on their concrete builders:
     - `mdns` (3 distinct signatures across `std/builder.rs:590`, `portable/mod.rs:571`, `portable/mod.rs:791`)
     - `keypair` (`Option<Ed25519Keypair>` on `Std`, required `Ed25519Keypair` on `Portable`/`Smoltcp`)
     - `Std`-only transport/cert/relay-mesh knobs (`quic_limits`, `webtransport_*`, `relay_mesh`, `listen`, `bind`)
     - `Smoltcp`-only knobs (`tcp_config`, `circuit_limits`, `provider_config`, `smoltcp` transition sharing `SharedEntropy`)
3. **Preserve `Std`'s pre-bind invariant:** Validation (`prepare()`) must still reject bad configs/reserved protocols/relay-server configs **before** opening any UDP/TCP sockets (`bind_transports()`).
4. **Preserve portable assembly:** Both `build(transport)` and `build_with_circuits(circuit_transport)` paths and the `PortableEndpointBuilder::smoltcp(stack)` transition must carry all `CommonBuilder` state forward unchanged.

**Verification:**

- `just test`, `just clippy full`, `just check-nostd`, `just check-wasm`, `just docs`
- Add unit tests verifying `protocol()` deduplication & handle numbering parity and `manual_ack_protocol()` across `Std`, `Portable`, and `Smoltcp` builders.
- **Size gate:** Compare linked `minip2p_web_bg.wasm` bytes (default + `--no-default-features`) and `thumbv7em-none-eabi` build output against merge base; confirm no growth from monomorphization.

---

### PR 5 — Share `open_stream` & `abandon_stream` carry/ack policy between `ffi-core` and `crates/web`

**Problem:** `crates/web/src/host.rs` already uses ADR 0029's `endpoint.at(now)` and already reuses `ffi-core`'s `send_whole`, `stream_key`, `parse_peer_id`, and `map_driver_error`. The remaining high-risk duplicated lifecycle logic is **`open_stream` and `abandon_stream`** (`crates/ffi-core/src/endpoint.rs:569-587, 646-672` vs. `crates/web/src/host.rs:347-363, 404-426`), where both hosts must coordinate connection-seen tracking, carry cleanup, and discarded-byte acknowledgements.

**Design (narrow, lock-safe, zero-cost):**

1. **Add two small generic helpers in `crates/ffi-core`** (e.g. alongside `writes.rs::send_whole<P>`, available under `no-default-features` so `crates/web` compiles them without `driver`):
   - `open_stream<P: Platform>(endpoint: &mut Endpoint<P>, peer_id: &str, protocol_id: &str, with_carry: impl FnOnce(&mut EventCarry)) -> Result<OpenStreamResult, FfiError>`
   - `abandon_stream<P: Platform>(endpoint: &mut Endpoint<P>, conn_id: u64, stream_id: u64, with_carry: impl FnOnce(&mut EventCarry) -> (bool, usize)) -> Result<(), FfiError>` (or pass a `with_carry: impl FnOnce(&mut EventCarry) -> R` closure that computes `accepted` + `dropped_data` inside the closure so the lock guard drops immediately when the closure returns!)
2. **Preserve critical locking and snapshot invariants:**
   - **Never widen the `events` mutex on native `P2pEndpoint`:** `endpoint.open_stream(...)` and `endpoint.abandon_stream(...)` run _before_ locking `events`, the `events` mutex is acquired _only_ inside `with_carry` to update `EventCarry`, and **dropped before calling `endpoint.stream_consumed(stream, dropped_data)`** (`ffi-core/src/endpoint.rs:661-669`). On `crates/web`, `Host` simply passes `|carry| ...` directly over `&mut self.carry`.
   - **Do NOT touch `P2pEndpoint::connected_peers`** (`ffi-core/src/endpoint.rs:360`) — it intentionally reads the driver-published snapshot without interrupting or locking the driver (pinned by `connected_peers_neither_waits_for_nor_interrupts_the_driver`).
   - **Keep `ffi-core` minimal-feature builds compiling:** do not pull `driver`/`pubsub`/`relay`-only items into the shared module; `cargo check --target wasm32-unknown-unknown -p minip2p-ffi-core --no-default-features --features serde` must stay green.
   - Leave browser-specific `.at(now)` call sites, discovery stubs, and lifecycle handling in `crates/web/src/host.rs`.

**Verification:**

- Test both native (`crates/ffi-core`) and browser (`crates/web/tests/host.rs`) for:
  1. `open_stream` marks connection seen so a subsequent `ConnectionClosed` is never elided by carry.
  2. Stale `abandon_stream` returns error without dropping pending writes.
  3. `abandon_stream` on a stream with a carried `StreamClosed` and unread carried bytes succeeds, removes carried events, and acknowledges the discarded bytes via `stream_consumed`.
- `just test`, `just check-wasm`, `just bindings-check`
- **Perf/size gate:** Check linked `minip2p_web_bg.wasm` bytes (default + `--no-default-features`) and run PR with `bench` label.

---

### PR 6 — Dev-only TS wire-enum & React Native `ENUM_FIELDS` codegen

**Problem:** `bindings/ts/core/src/types.ts` hand-mirrors ~10 Rust enum const objects and the `P2pEvent` union from `crates/ffi-core/src/{events,error}.rs`, and `bindings/ts/react-native/src/adapter.ts:461-482` hand-maintains `ENUM_FIELDS` (mapping event tags to flat numeric enum fields) — forgetting a new enum field causes silent runtime failures in React Native. Furthermore, `.github/workflows/publish.yml:653` checks `git status --porcelain -- react-native web`, omitting `core`.

**Design (phased, zero runtime/WASM dependency):**

1. **Build a dev/build-time generator** (e.g. a small Rust binary/xtask or Node/Rust `syn`-based script reading `crates/ffi-core/src/{events,error}.rs` — adding **zero** runtime or proc-macro dependencies to `minip2p-ffi-core` so WASM and UniFFI builds are completely unaffected).
2. **Split generated vs. hand-authored TS cleanly:**
   - Generate a dedicated module `bindings/ts/core/src/generated/wire-enums.ts` (re-exported by `bindings/ts/core/src/types.ts`) containing:
     - All wire enum const objects + types (`PingFailure`, `Reachability`, `DiscoverySource`, `MdnsFailureKind`, `IdentifyFailure`, `ConfigCapability` from `error.rs`, `DriverFailureKind`, `EndpointErrorKind`, `NatErrorKind`, `CloseOutcome`, etc.)
     - Event tag constants / discriminants
   - Generate `bindings/ts/react-native/src/generated/enum-fields.ts` imported by `bindings/ts/react-native/src/adapter.ts`, including **only flat/unit enums** (matching `typeof value === "number"` at `adapter.ts:568`), explicitly excluding tagged enums (`PathKind`, `ConnectionCloseReason`) and preserving special handling for `EndpointClosed` (`adapter.ts:116`).
   - Keep hand-authored SDK types (`Minip2pConfig`, `Minip2pNamedEventMap`, `Path`, `OpOptions`, JSDoc) in `types.ts`.
   - **Phase 2 (optional follow-up, only if clean):** Extending codegen to the full `P2pEvent` union requires an explicit mapping table for non-uniform Rust `u64` fields (`StreamWriteStopped.errorCode` at `types.ts:838` and `ConnectionCloseReason::Remote.code` at `types.ts:713` map to `bigint`; IDs/counts/timestamps map to `number`; `Vec<u8>` maps to `ArrayBuffer`). Do not auto-generate the full union without pinning that mapping explicitly.
3. **Wire freshness checks into local + CI + release:**
   - Add a root pnpm script (e.g. `pnpm bindings:generate-types`) and call it from `just bindings-check`, `.github/workflows/bindings.yml:60`, and `.github/workflows/publish.yml:651-653`.
   - Update `.github/workflows/publish.yml:653` to check `git status --porcelain -- core react-native web` (keeping `bindings/ts/tests/workflows/publish.test.mjs:31` passing and ignoring downloaded Node artifacts).

**Verification:**

- `pnpm --workspace-root typecheck && pnpm --workspace-root test && pnpm --workspace-root lint`
- `just bindings-check` (confirm running the generator twice produces a clean diff)
- `node --test bindings/ts/tests/workflows/publish.test.mjs`
- `just check-wasm` (confirm zero new deps in `minip2p-ffi-core` / `minip2p-web`)

---

## Deferred / future standalone decisions

- **`WaitDeadline` module cleanup:** Moving `WaitDeadline` out of `crates/swarm/src/driver.rs:40` (and removing the unused `Swarm` / `PollNext` re-exports in `crates/minip2p/src/std/mod.rs:85`) is a tiny standalone cleanup if desired later, independent of `Swarm<T>`'s public status (ADR 0013).
- **Measured Cargo feature consolidation on `minip2p-rs`:** Only revisit after PRs 1 and 4 land, backed by linked `thumbv7em` and `wasm32` size measurements.
