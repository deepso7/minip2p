# Extract minip2p-ffi-core; bindings become thin shells

> **Amended by [ADR 0003](0003-pull-based-event-delivery.md)**: event delivery is now pull-based on both platforms, which intentionally changes the RN UniFFI surface (listener → doorbell + drain). The regenerate-and-empty-diff check below no longer applies; the RN test suite is the extraction's safety net.

`crates/ffi` mixed the embedding logic — the detached driver thread, event flattening, and endpoint lifecycle (~2,300 lines plus tests) — with the UniFFI annotations that expose it to React Native. With napi-rs chosen for Node (ADR 0001), we extract that logic into a binding-agnostic crate, `crates/ffi-core` (`minip2p-ffi-core`), and make each binding a thin shell over it: `crates/ffi` keeps UniFFI scaffolding, `#[uniffi::remote]` mirrors of the moved types, and a delegating object — its exported surface stays name- and signature-identical so the checked-in ubrn-generated React Native bindings survive a regenerate-and-empty-diff check — and the new `crates/nodejs` (`minip2p-nodejs`) is the napi-rs backend for `@minip2p/node`. Both new crates are workspace members with `publish = false`. Coupling evidence: [docs/research/ffi-uniffi-coupling.md](https://github.com/deepso7/minip2p/blob/research/ffi-uniffi-coupling/docs/research/ffi-uniffi-coupling.md).

## Considered Options

- **Extract the core** (chosen): one copy of the driver logic, two independent binding shells; the `uniffi =0.31.0` pin stays a mobile-only constraint.
- **Wrap `minip2p-ffi` as-is**: zero up-front cost and technically safe (the rlib is plain Rust), but it permanently ties `@minip2p/node` releases to the RN toolchain's uniffi pin and leaves one crate serving two binding surfaces.
- **Duplicate the driver over `minip2p-rs`**: every future fix lands twice; rejected.

## Consequences

- New events or endpoint methods are two-touch: core plus the ffi mirror/delegation. Drift fails to compile.
- `#[uniffi::remote(Error)]` on `FfiError` is the least-exercised corner of the mechanism. We deliberately skipped an up-front spike; if it snags during implementation, the documented fallback (a wrapping type in `crates/ffi`) preserves this layout.
