# Rust-facing detached Endpoint driver (`DetachedEndpoint`)

`minip2p` does not ship a public background-thread wrapper (`DetachedEndpoint`) over the std `Endpoint`. Rust applications that want to drive an `Endpoint` on a background thread hold it behind their own lock, clone `Endpoint::wait_handle()` to interrupt waits, and forward events on a channel. The detached driver in `minip2p-ffi-core` stays internal to the foreign-language bindings.

## Why this is out of scope

- **Only one Rust consumer exists today.** Plan §3.6 (`docs/plans/dx-perf-size-evolution.md`) evaluated extracting `ffi-core`'s detached driver for `qop/desktop`. Most of what `qop` previously hand-rolled was eliminated by the single `Endpoint<P>` (ADR 0029), `StreamKey` and the Endpoint-owned write queue (ADR 0030), `ProtocolId` (ADR 0031), and `Endpoint::flush` / `close_within` (ADR 0032).
- **Duplicating or sharing the kernel has high cost for low return.** Only the thread lifecycle and lock handoff (interrupt + tuned command linger, draining on stop, panic handling) would be shared; `ffi-core`'s string IDs, flattened `P2pEvent`, and carry-buffer elision/shedding are binding-specific. Writing a second copy duplicates the trickiest concurrency code in the workspace, while refactoring `ffi-core` to share a generic kernel touches every binding's throughput path for a single consumer whose wrapper already works.
- **Unresolved backpressure trade-off for Rust consumers.** Unlike `ffi-core`'s `EventCarry` (which bounds droppable control events with shedding), a public Rust `mpsc::Receiver<EndpointEvent>` must choose between an unbounded channel, a bounded channel that can stall the driver, or exposing carry-style shedding policy in the Rust API — unnecessary API surface without concrete callers.

## When to revisit

Revisit when a second Rust application needs a detached background `Endpoint` driver, or when `qop`'s own wrapper drifts meaningfully from `ffi-core`'s interrupt/linger/shutdown behavior. At that point, extract one shared driver kernel parameterized on event sink and snapshot hooks rather than maintaining two copies.

## Prior requests

- #567: "Rust-facing detached Endpoint driver (DetachedEndpoint) — deferred"
