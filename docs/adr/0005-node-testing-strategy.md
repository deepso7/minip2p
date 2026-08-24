# Testing strategy for @minip2p/node

`@minip2p/node` is tested by one vitest suite: mock-driven unit tests for the JS surface plus real-socket integration tests — two endpoints in a single Node process on `127.0.0.1`, dialing each other over TCP and QUIC, mirroring `crates/ffi/tests/loopback.rs`, plus one circuit-relay scenario to prove relay config plumbs through napi. The drain-protocol invariants of ADR 0003 (doorbell rings only on empty→non-empty, drain-to-empty, `EventsDropped` accounting) are proven by deterministic Rust unit tests in `minip2p-ffi-core`; each JS binding keeps exactly one event-flood test as an end-to-end sanity check. Alongside this, the whole `bindings/ts` workspace migrates from `node --test` against built output to **vitest against TS sources**.

## Considered Options

- **Rust-first drain proof** (chosen) over a family of JS stress tests: empty→non-empty edges are only deterministically testable where the queue lives, without racing a live event loop; JS-side interleaving tests would be racy slop. One flood test per binding covers the doorbell-tsfn glue.
- **Single-process loopback** (chosen) over child-process orchestration (slower, flakier) or a Rust peer binary (adds a build dependency); real sockets exercise the full napi boundary and drain path while staying orchestrable in a test runner.
- **vitest** (chosen) over keeping the `node --test`-against-`dist/` convention: watch mode and TS-native transforms are worth the dependency, and running two runners in one workspace is worse than migrating `core`'s and `react-native`'s existing suites. Testing sources instead of built output forfeits nothing: the release pipeline's pack → verify → install-smoke already exercises the shipped artifact.
- **Shared mock, no parameterized contract suite**: `MockBackend` (contract-complete, currently private to `core/tests/sdk.test.mjs`) is extracted to an unpublished workspace fixture so node and RN tests can script backend behavior. A dual mock/real contract suite was rejected — TypeScript already enforces contract shape, and a real native backend can't be scripted into the drop/abort interleavings the behavior tests need, so shared cases would degrade to smoke.

## Consequences

- CI: PR CI (`bindings.yml`) stays linux-x64 — build the napi binary, run the JS suites against it (per ADR 0004). The weekly `bindings-native.yml` cron additionally *executes* the suite on every target with a real GitHub runner (linux gnu x64/arm64, darwin x64/arm64, win32-x64) and on musl in a container; emulated targets stay build-only — qemu-run tests validate the emulator, not the binding.
- The RN pull-migration's declared safety net (ADR 0002, amended) becomes real: `adapter.ts` — today untested — gains drain-loop unit tests against a fake native `P2pEndpoint` (fake doorbell, scriptable drain), where lost-wakeup bugs would land in JS. The Expo example smoke suite stays a documented manual pre-release ritual, not CI.
- The push-listener tests ADR 0003 invalidates (the `driver.rs` carry tests, the panicking-listener and listener-re-entrancy loopback tests in `crates/ffi/tests/`) are reshaped onto the doorbell/drain seam in `minip2p-ffi-core`, not deleted.
- The vitest migration touches every `bindings/ts` package and retires the build-before-test convention; `turbo.json`'s `test` task inputs change accordingly.
