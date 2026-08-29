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

### SDKs

**TypeScript SDK**:
The one TypeScript API minip2p presents on every JS runtime: the `@minip2p/core` API plus a runtime's binding package. Documented as a single "TypeScript" docs section.
_Avoid_: Node SDK, React Native SDK (they are the same SDK on different runtimes)

**Runtime**:
The host a TypeScript SDK app runs on — Node.js or React Native. Runtimes differ in setup and a short list of one-sided extras; the API is otherwise shared. Distinct from the binding shell that serves it.

### NAT traversal

**Circuit**:
The hop/stop bridged byte pipe through a Circuit Relay v2 hop, before Noise and Yamux have turned it into a Relayed path.
_Avoid_: connection (until that upgrade finishes)

**Relayed path**:
A swarm connection whose transport is a circuit. Identify, ping, and application streams use it like any other connection.
_Avoid_: fallback connection

**DCUtR**:
The `/libp2p/dcutr` protocol that coordinates a hole punch over an existing Relayed path. It is an upgrade, not the circuit handshake.
_Avoid_: using DCUtR as the Noise barrier

**force_relay**:
Keep the selected path Relayed: no direct candidate dials and no hole punch. The circuit upgrade is the same as without the flag.
