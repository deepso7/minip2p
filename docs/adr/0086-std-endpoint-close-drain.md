# The std Endpoint's close drain

`Endpoint::close_within(timeout)` (std) flushes (ADR 0032), then disconnects and drains until the connections are gone or the timeout passes, and returns a `CloseReport`. The drain loop is shaped by these decisions:

- **Close never stops at the first failure.** The mDNS goodbye's failure (`shutdown_mdns`) is queued as an `EndpointEvent::MdnsFailed` and drained with the rest, not returned. Out of time, or after a failed poll, the drain hands over what the swarm already buffered (a disconnect's close failure, say) with `take_buffered_events` instead of polling again; after the last pass it does the same once more, since that pass's own work (a driver's reset the transport refused) can queue more swarm events.
- **Interrupts only end a drain sleep early.** A `WaitHandle` interrupt does not end the close; the drain keeps going until it is quiet or out of time.
- **No agent tick or discovery sweep runs while closing.** The drain only ingests swarm events and settles attempts, so the report carries connection, attempt and capability events (a relay reservation closing, say), not new NAT or discovery work.
- **A relay mesh's backbone closes alongside.** Its swarm is shut down with the public one, its timers are in the drain's sleep budget, and it is polled in the same loop; a backbone failure ends the drain (`CloseOutcome::Failed`), as a public swarm failure does. Its leftover connections count in `CloseReport::unfinished`.
- **Queued writes die with the endpoint.** Whatever the Endpoint's write queue still holds when the drain ends is aborted (`StreamWriteAborted` in the report), as ADR 0030 says.
