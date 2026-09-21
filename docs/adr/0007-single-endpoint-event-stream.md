# Single endpoint event stream

The application-facing endpoint exposes one public, ordered `EndpointEvent` stream. Connection, protocol, discovery, and diagnostic transitions all leave through that stream. Operations return correlation IDs immediately: in particular, `connect` returns one `ConnectId` for the whole Connection attempt, including its candidate Transport dials, relay fallback, and direct-path upgrade. Applications correlate events by these IDs and implement selective waits in their own event loop or in a higher-level adapter.

Every admitted Connection attempt produces exactly one terminal outcome: connected, failed, or cancelled. Synchronous errors are limited to malformed targets or failure to admit the attempt; lack of a currently usable route is a terminal event. Cancelling an unsettled attempt closes every provisional path it opened, stops its remaining Transport dials and direct-path upgrade, and emits cancelled. Cancelling a settled or unknown Connect ID is an idempotent no-op; disconnecting an established connection is a separate command. Stopping a wait does not stop its operation.

A blocking endpoint wait returns one of three Endpoint wait outcomes: event, deadline, or interrupted. Deadline and interruption remain visible so adapters can service timers and commands, but they are not additional event sources. The old driver-progress outcome and its capability-draining contract are removed.

Events preserve their endpoint emission order, but concurrent transport attempts have no promised completion order. State snapshots are authoritative getter operations, not one atomic mega-snapshot. State changes before its corresponding event is queued, so separate getters may be ahead of the Endpoint event stream but never behind their own already-emitted transition.

## Considered Options

- **One public stream with operation IDs** (chosen): matches the single-owner, caller-driven endpoint; keeps progress explicit without an executor; gives every event one ownership and ordering policy; and lets Rust, FFI, and TypeScript choose their own waiting conveniences above the same core semantics.
- **Focused endpoint waits and queues**: methods such as `next_connection_event` or `wait_for_peer_ready` make simple call sites shorter, but each capability adds queueing, skip, overflow, interruption, and ordering behavior to the endpoint. Unrelated events must be buffered or yielded through a second path, duplicating the application event loop.
- **Narrow operation and capability event sources**: resembles iroh's connection handles, path watchers, discovery streams, and protocol acceptors. Iroh can drive those sources concurrently with background async tasks; in minip2p's no-async, caller-driven model they would require additional pollable handles, queues, borrowing rules, and coordination machinery.

## Consequences

- `Endpoint::connect` is the policy-owning application operation and returns one `ConnectId`. Raw mechanism-level dialing remains on `SwarmRuntime`. `SwarmEvent::DialFailed` reports a raw outbound dial that closed before `ConnectionEstablished`; attempt-owned dials are consumed by the Connection-attempt engine and never surface there.
- One sans-I/O Connection-attempt engine in the application-facing crate owns the attempt (identity, direct racing, deadline, provisional path, terminal). `NatAgent` provides the relay leg keyed by the shared `ConnectId` in `minip2p-core`. Standard and portable Endpoint compositions use that engine; they do not build parallel attempt state machines.
- The Endpoint event stream reports logical Connection-attempt outcomes, not each internal QUIC, TCP, relay, or DNS attempt as an unrelated application operation. Address-level failures may be retained as diagnostics on the logical outcome.
- Public focused waits and capability-specific endpoint queues are removed. A Rust application dispatches unrelated events while waiting for a matching ID; adapters may offer promises, callbacks, or `waitFor` without changing endpoint semantics. The standard adapter retains the three Endpoint wait outcomes needed to drive blocking loops.
- Operation cancellation always requires an explicit command. Dropping or abandoning application-side waiting state has no network side effect.
- Internally, protocol agents may retain private queues as implementation details, but `Endpoint` is their single public event boundary.
- The FFI carry buffer from ADR 0003 consumes this stream and retains its documented bounded drop policy. If it drops a terminal Connection-attempt event, its diagnostic identifies the affected Connect ID and every pending foreign-runtime wait for that ID settles with an explicit delivery-loss error; State snapshot getters remain available for recovery. A dropped terminal event must never leave a promise pending indefinitely.
- In TypeScript, a timeout bounds only the local wait. Aborting with an `AbortSignal` is explicit cancellation intent and invokes the cancellation command. Cancel-on-timeout, if offered, is a separate opt-in policy.
- Adding a capability normally adds event variants and snapshot state, not another event source or waiting mechanism.
