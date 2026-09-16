# Single endpoint event stream

The application-facing endpoint exposes one public, ordered `EndpointEvent` stream. Connection, protocol, discovery, and diagnostic transitions all leave through that stream. Operations return correlation IDs immediately: in particular, `connect` returns one `ConnectId` for the whole Connection attempt, including its candidate Transport dials, relay fallback, and direct-path upgrade. Applications correlate events by these IDs and implement selective waits in their own event loop or in a higher-level adapter.

Stopping a wait does not stop its operation. Cancellation is an explicit endpoint command such as `cancel_connect(connect_id)`, and its outcome is reported through the Endpoint event stream. Events preserve their endpoint emission order, but concurrent transport attempts have no promised completion order. Durable current state is exposed through State snapshots; events report transitions rather than serving as an authoritative event log.

## Considered Options

- **One public stream with operation IDs** (chosen): matches the single-owner, caller-driven endpoint; keeps progress explicit without an executor; gives every event one ownership and ordering policy; and lets Rust, FFI, and TypeScript choose their own waiting conveniences above the same core semantics.
- **Focused endpoint waits and queues**: methods such as `next_connection_event` or `wait_for_peer_ready` make simple call sites shorter, but each capability adds queueing, skip, overflow, interruption, and ordering behavior to the endpoint. Unrelated events must be buffered or yielded through a second path, duplicating the application event loop.
- **Narrow operation and capability event sources**: resembles iroh's connection handles, path watchers, discovery streams, and protocol acceptors. Iroh can drive those sources concurrently with background async tasks; in minip2p's no-async, caller-driven model they would require additional pollable handles, queues, borrowing rules, and coordination machinery.

## Consequences

- `Endpoint::connect` is the policy-owning application operation and returns one `ConnectId`. Raw mechanism-level dialing remains on `SwarmRuntime`.
- The Endpoint event stream reports logical Connection-attempt outcomes, not each internal QUIC, TCP, relay, or DNS attempt as an unrelated application operation. Address-level failures may be retained as diagnostics on the logical outcome.
- Public focused waits and capability-specific endpoint queues are removed. A Rust application dispatches unrelated events while waiting for a matching ID; adapters may offer promises, callbacks, or `waitFor` without changing endpoint semantics.
- Operation cancellation always requires an explicit command. Dropping or abandoning application-side waiting state has no network side effect.
- Internally, protocol agents may retain private queues as implementation details, but `Endpoint` is their single public event boundary.
- The FFI carry buffer from ADR 0003 consumes this stream and retains its documented bounded drop policy; this decision does not add another public queue.
- Adding a capability normally adds event variants and snapshot state, not another event source or waiting mechanism.
