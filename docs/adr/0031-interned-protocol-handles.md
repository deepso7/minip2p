# Interned protocol handles

An Endpoint application dispatches every stream by its protocol: `StreamReady` carried the negotiated protocol as a `String`, and applications compared it against their constants on every stream, or kept their own string-to-enum maps ([plan](../plans/dx-perf-size-evolution.md), Decision 3.3). Config-driven callers (qop, the FFI core) register protocols by string and must keep doing so. We decided:

- **`ProtocolId(u16)` is an endpoint-issued handle for an application protocol.** Each endpoint numbers the protocols it registers in registration order: the builder's `.protocol(&str)` (unchanged, still fluent) first, then `add_protocol` and `add_manual_ack_protocol`, which now return the handle (and the same handle again for a protocol already registered). `endpoint.protocol_id(&str) -> Option<ProtocolId>` looks one up, `endpoint.protocol_name(id) -> Option<&str>` turns it back; both return `None` for anything the endpoint did not register, including a handle from another endpoint. The table only grows, so a handle stays valid for the endpoint's life.
- **`StreamReady` carries `protocol: ProtocolId` beside `protocol_id: String`.** The string stays: a close report's events outlive the endpoint that could name the handle, `convert_endpoint_event` in the FFI core turns events into binding events without the endpoint at hand, and the swarm already allocated it, so keeping it costs a move. A dispatcher compares `protocol` with a handle it looked up once.
- **`open_stream` takes `impl Into<ProtocolRef>`**: a `&str` (or `&String`) or a `ProtocolId`. Existing calls compile unchanged. An unknown handle fails like an unregistered string, with `SwarmError::ProtocolNotRegistered`, naming the handle.
- **The table lives in the Endpoint engine, not the swarm.** The swarm keeps strings; nothing below the Endpoint gains from a handle, and capability protocols (relay, DCUtR, AutoNAT, Gossipsub) never reach the application. A `StreamReady` for a protocol the table does not hold is numbered as it is converted.

## Rejected alternatives

- **Dropping the string from `StreamReady`.** It saves no allocation (the swarm made it), and every consumer that outlives or does not hold the endpoint (close reports, the FFI conversion, logging) would need the endpoint to name the protocol.
- **Handles in the swarm's `SwarmEvent`.** Every swarm consumer and test would change for a convenience only the application uses.
- **A `u32` handle, or a handle holding an `Arc<str>`.** Sixty-five thousand application protocols is far past any real endpoint, and an `Arc` makes the handle neither `Copy`-cheap nor `no_std`-portable to targets without atomics.

## Consequences

- Patterns that list `StreamReady`'s fields without `..` add `protocol` (or `..`).
- `add_protocol` and `add_manual_ack_protocol` return `Result<ProtocolId, DriverError>`; `?` and `.expect(..)` callers are unaffected. An endpoint refuses its 65,536th distinct application protocol.
- The bindings are unchanged: they register and receive strings.
