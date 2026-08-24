# minip2p

A minimal libp2p implementation in Rust with sans-I/O cores, transport adapters, and foreign-runtime bindings.

## Language

### Bindings

**FFI core**:
The binding-agnostic embedding layer (`minip2p-ffi-core`): the detached driver thread, event flattening, and endpoint lifecycle that every binding shell builds on.

**Binding shell**:
A thin crate adapting the FFI core to one foreign toolchain — UniFFI for React Native (`minip2p-ffi`), napi-rs for Node (`minip2p-nodejs`). Shells hold no driver or lifecycle logic of their own.
_Avoid_: wrapper

**Backend contract**:
The synchronous `Minip2pBackend` interface in `@minip2p/core` that each JS binding implements; the TypeScript-facing seam shared by React Native and Node.

**Platform package**:
A binary-only npm package (`@minip2p/node-<target>`) carrying one prebuilt Node binding binary, selected at install time through `optionalDependencies`. Holds nothing but the binary and its manifest.

**Carry buffer**:
The FFI driver's single bounded event queue (4096 events, payload-first drops, `EventsDropped` diagnostic). The only place events wait or drop between the driver and a binding.

**Doorbell**:
The coalesced, edge-triggered ready signal a binding registers with the FFI core; rung only when the carry buffer goes empty→non-empty. Replaces per-event push through the listener seam.

**Drain**:
A binding's synchronous `drain_events(limit)` command pulling a batch from the carry buffer in order. A binding that hears the doorbell must drain until empty.
