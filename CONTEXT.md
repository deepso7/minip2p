# minip2p

A minimal libp2p implementation in Rust with sans-I/O cores, transport adapters, and foreign-runtime bindings.

## Language

### Bindings

**FFI core**: The binding-agnostic embedding layer (`minip2p-ffi-core`): the detached driver thread, event flattening, and endpoint lifecycle that every binding shell builds on.

**Binding shell**: A thin crate adapting the FFI core to one foreign toolchain — UniFFI for React Native (`minip2p-ffi`), napi-rs for Node (`minip2p-nodejs`). Shells hold no driver or lifecycle logic of their own. _Avoid_: wrapper

**Backend contract**: The synchronous `Minip2pBackend` interface in `@minip2p/core` that each JS binding implements; the TypeScript-facing seam shared by React Native and Node.

**Platform package**: A binary-only npm package (`@minip2p/node-<target>`) carrying one prebuilt Node binding binary, selected at install time through `optionalDependencies`. Holds nothing but the binary and its manifest.

**Carry buffer**: The FFI driver's single bounded event queue (4096 events, payload-first drops, `EventsDropped` diagnostic). The only place events wait or drop between the driver and a binding.

**Doorbell**: The coalesced, edge-triggered ready signal a binding registers with the FFI core; rung only when the carry buffer goes empty→non-empty. Replaces per-event push through the listener seam.

**Drain**: A binding's synchronous `drain_events(limit)` command pulling a batch from the carry buffer in order. A binding that hears the doorbell must drain until empty.

### SDKs

**TypeScript SDK**: The one TypeScript API minip2p presents on every JS runtime: the `@minip2p/core` API plus a runtime's binding package. Documented as a single "TypeScript" docs section. _Avoid_: Node SDK, React Native SDK (they are the same SDK on different runtimes)

**Runtime**: The host a TypeScript SDK app runs on — Node.js or React Native. Runtimes differ in setup and a short list of one-sided extras; the API is otherwise shared. Distinct from the binding shell that serves it.

### NAT traversal

**Connection attempt**: One application-level effort to reach a peer. It may start several Transport dials, establish a Relayed path, and later upgrade that path, but it has one identity and one cancellation lifecycle. _Avoid_: dial

**Transport dial**: One mechanism-level attempt to establish a transport connection to one peer address. Several Transport dials may belong to one Connection attempt. _Avoid_: connection attempt

**Connect ID**: The endpoint-local identity of a Connection attempt. It remains the same across candidate Transport dials, relay fallback, and direct-path upgrades.

**Connection target**: What an application supplies to start a Connection attempt: a peer ID, one complete peer address, or a non-empty set of complete peer addresses that all name the same peer. Each address retains its transport shape and peer ID so it can be copied as advertised.

**Endpoint event stream**: The endpoint's single public, ordered source of connection, protocol, discovery, and diagnostic events. Applications correlate events with operation IDs and build selective waits above this stream; the endpoint does not expose competing focused queues or waits.

**State snapshot**: The endpoint's authoritative view of durable current state, such as active connections, selected paths, known peer addresses, and listener addresses. Events announce transitions; applications query a State snapshot to recover or answer what is true now.

**Circuit**: The hop/stop bridged byte pipe through a Circuit Relay v2 hop, before Noise and Yamux have turned it into a Relayed path. _Avoid_: connection (until that upgrade finishes)

**Relayed path**: A swarm connection whose transport is a circuit. Identify, ping, and application streams use it like any other connection. _Avoid_: fallback connection

**DCUtR**: The `/libp2p/dcutr` protocol that coordinates a hole punch over an existing Relayed path. It is an upgrade, not the circuit handshake. _Avoid_: using DCUtR as the Noise barrier

**force_relay**: Keep the selected path Relayed: no direct candidate dials and no hole punch. The circuit upgrade is the same as without the flag.

### Wire codecs

**Protobuf wire vocabulary**: The shared field-framing helpers in `minip2p-core` (tags, varints, length-delimited reads, unknown-field skipping, `WireError`). Protocol crates wrap these failures in contextual errors and keep their own message semantics. Distinct from stream length-prefix framing (`encode_frame` / `decode_frame`).
