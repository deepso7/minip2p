# napi-rs for the Node.js bindings

`@minip2p/node` needs a native binding over the FFI layer: the Rust side owns its UDP (quiche) and TCP (mio) sockets and runs a detached driver thread, and the `Minip2pBackend` contract in `bindings/ts/core` is synchronous. We chose **napi-rs** (v3) over reusing the existing UniFFI surface via uniffi-bindgen-react-native's Node target, and over a hand-written C ABI loaded with koffi. Full comparison: [docs/research/node-binding-mechanisms.md](https://github.com/deepso7/minip2p/blob/research/node-binding-mechanisms/docs/research/node-binding-mechanisms.md).

## Considered Options

- **napi-rs** (chosen): `ThreadsafeFunction` maps directly onto the detached-driver/`P2pEventListener` dispatch with explicit queue bounds and event-loop-liveness control; sync `#[napi]` functions fit the synchronous backend contract natively; `@napi-rs/cli` gives turnkey per-platform prebuilt npm packages; and it keeps the `uniffi =0.31.0` pin a mobile-only constraint.
- **UniFFI via ubrn (`@ubjs/node`)**: zero new Rust surface, but self-described as not production-ready, no npm distribution tooling, and it would extend the `=0.31.0` pin to Node.
- **C ABI + koffi**: no pin, but the largest bespoke marshaling surface, and `unsafe`-adjacent in a workspace where `unsafe` is forbidden.
- **boltffi**: raised late; its only JavaScript target is WASM, which cannot own sockets or spawn the driver thread, so it cannot serve a native Node binding at all. Relevant only to a hypothetical browser/WASM build of the sans-I/O cores.

## Consequences

- Two binding surfaces (UniFFI for mobile, napi-rs for Node) must stay in sync. The shared `Minip2pBackend` contract and a binding-agnostic core extracted from `crates/ffi` are the mitigation.
- The napi-rs dependency is pinned to a minor (napi-rs v3 ships minors roughly weekly) and bumped deliberately.
- Two convergence paths could later re-unify the JS bindings: ubrn's Node target maturing (everything on UniFFI), or Callstack's `react-native-node-api` maturing (everything on napi-rs — permitted, since pre-1.0 breaking changes are fine). Neither is production-ready today; revisit as a fresh effort if one lands.
