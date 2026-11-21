# One report per failure in the swarm

Every failure the swarm reports reaches the host exactly once, through one channel, so hosts (the connect engine, the Endpoint, pubsub) can act on it without de-duplicating:

- **Synchronous commands report through `Err` only.** A failed `open_stream` or `send_stream` returns the error and queues no `SwarmEvent::Error` for it. Callers that commit state when a stream closes (the pubsub one-shot sender) depend on seeing a rejected write synchronously, not an `Ok` followed by an event.
- **Queued work keeps reporting as events.** A command flushes earlier queued work first; that work's failures (say a queued ping open, reported as `PingFailed`) are not tied to the command and stay events.
- **A dial reports through `DialFailed`.** A transport `Error` on a connection still dialing (or vetoed) is stored as the dial's `last_error` and becomes `DialFailed`'s reason when the connection closes, rather than also surfacing as `SwarmEvent::Error`, which the connect engine could not consume.
- **A connection ends with at most one event** (`handle_connection_closed`): `DialFailed`, `ConnectionClosed`, or a transport error for a connection that failed before establishing. A connection in `ConnPhase::Closing` (a race loser, a vetoed dial, a placeholder) was already reported, or needed no report, when the swarm closed it, so its later transport events are bookkeeping only: its close is silent and its data is acknowledged and dropped.
- **Our close after a failed first Identify names Identify** as the close reason rather than reporting `Local`.
