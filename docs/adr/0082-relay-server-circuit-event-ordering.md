# Relay server: circuit payload ordering, event claiming and teardown order

Ordering rules in `RelayServerAgent` (crate `minip2p-relay-server`) for circuits, beyond the acknowledgement contract of ADR 0012:

- **Control bytes are acknowledged as read; circuit payload only once the other leg accepts it.** That includes payload a client pipelines behind CONNECT before the circuit commits: a HOP responder holds it unacknowledged until the decision, and on acceptance (`accept_pending_circuit`) it is written after the success reply and before anything buffered since. `HopResponderOutput::BridgeData` is ignored in `drain_hop` for that reason. On a forward, bytes past the holding node's STATUS can only come from the same read, since an earlier read held no complete frame. When a circuit closes, bytes still queued were never forwarded, so the origins' credit for them is released.
- **Stream events are routed circuit first.** A committed source leg keeps its HOP worker, so `circuits` is checked before `hop_workers`. The `hop_workers` probe uses `contains_key` rather than `get`, because yielding the worker measurably slowed every unowned stream's miss.
- **Every relay stream's events are claimed, so none reach the application.** `StreamWritable` on control streams is claimed even though they never hold a tail (a Full control send fails). The claim is decided before resuming a circuit direction, because resuming can finish or fail the circuit and remove it. A retired STOP stream stays claimed until its terminal event; a holding node ends a forward only after its STATUS.
- **Connection teardown order.** `on_connection_closed` first drops a backbone member's directory entries (so its pending forwards look elsewhere), then closes affected circuits in source-stream order (circuits are keyed by source stream, so source legs are a key range and destination legs come through `stop_to_source`), then pending circuits (aborted if the source leg closed, otherwise the forward retries the next claim or the STOP is dropped), and retires STOP streams last because the cleanup above may have retired more.
- **A new reservation can unblock a waiting mesh CONNECT.** A CONNECT waiting on a member's snapshot (for example because the local STOP failed to open on a replaced connection) is re-resolved when the destination reserves or its reservation moves locally, rather than timing out on the wait. Only peers with a circuit pay for that check.
- **A mesh node routes even a local reservation through resolution,** so a local STOP that fails to open falls through to remote claims (ADR 0027).
- **Agent behaviour is tested through the shared fake swarm in `tests/common`;** unit tests inside `agent.rs` cover private helpers only.

## Benign command errors in the swarm adapter

The `RelaySwarm` impl for `SwarmCore` (`swarm.rs`) swallows some errors on purpose:

- **`ack_stream` ignores a gone stream or connection** (`StreamNotFound`, `ConnectionNotFound`, `ConnectionClosed`, `PollError`): a stream or connection that is gone, or torn down by this acknowledgement's own flush, released its bytes with it (ADR 0012). Any other error, such as acknowledging past what was delivered, means the agent's accounting is broken and trips a `debug_assert`.
- **`reset_stream` treats `StreamNotFound` as success:** a stream that is gone, or whose connection is, is already reset.
