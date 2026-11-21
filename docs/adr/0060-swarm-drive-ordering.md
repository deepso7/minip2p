# Swarm drive ordering

`SwarmCore::drive` runs its steps in a fixed order, and `SwarmState` relies on it:

- **Deferred closes first.** `drive` flushes before it polls the transport, so a close deferred behind events the host has since drained (a Connection replacement's `ConnectionClosed` for the old connection) reaches the transport before that connection can produce another batch.
- **Addresses before events.** The local-address snapshot Identify advertises (`refresh_local_addresses`, including a `Listening` move such as a WebTransport certificate rotation) is refreshed right after the poll and before any of its events is handled, so an Identify reply built from that batch already advertises the moved address.
- **One event at a time.** Each transport event's actions are flushed before the next event is ingested: a later event must never see state that assumes an earlier event's transport work already ran.
- **Timers after the batch.** `handle_tick` runs after the whole transport batch, so a reply in the batch beats a deadline due in the same drive. Code that acts on a deadline mid-batch (a ping during a Connection replacement) must check it itself.
- **Protocol outputs are attributed at queue time.** Ping and Identify outputs are drained immediately after the input that produced them (`collect_protocol_events`, `drain_ping_outputs`, `drain_identify_outputs`), so the peer's current connection is the one the event came from; a later replacement must not re-attribute a queued event.
- **Commands go behind queued work.** `SwarmCore::open_stream` and `send_stream` flush before acting, so earlier queued writes for a stream go out first, and failures of earlier queued work keep flowing as events instead of being mistaken for the command's own.
