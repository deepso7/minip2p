# Stream backpressure contract

A full send buffer used to tear things down or lose data instead of slowing the sender (#234): the TS SDK wrote fire-and-forget and dropped reads past a cap, TCP closed the connection at its outbound ceiling, circuits died on a full bridge, relays closed on a full destination, and Yamux and QUIC returned receive credit on arrival rather than on consumption. One contract now governs every layer. Queues stay bounded; nothing moves buffering somewhere unbounded instead.

## Writing

- `send_stream` accepts as much of the payload as the stream can queue and returns `Ok(())` when every byte was accepted, or `Full` carrying the **unsent tail** (the whole payload when nothing fit). Full is retryable, never a fault. Peer credit does not decide acceptance; accepted bytes queue until credit drains them. Bytes count against the stream and connection send caps until they reach the transport's output, including bytes already framed but not yet written.
- **Accepted means accepted locally, never delivered.** `Ok(())`, an SDK write resolving, and the stream writer's completion all say only that the stack took the bytes.
- **No stream starves another.** Every transport has both a per-stream and a per-connection send cap, so one stream stalled on peer credit can fill only its own share (#327 finding 16). QUIC matches Yamux: 256 KiB per stream, admission into the engine round-robin across streams. A small reserve inside the connection cap is kept for the swarm's own control streams (ping, Identify, multistream negotiation), so application streams cannot starve them.
- The **caller** holds the unsent tail. Swarm core is the caller for its own protocols (ping, identify, multistream negotiation). The relay keeps an in-order queue per direction, bounded by the receive budget it granted the source. ffi-core holds one pending tail per stream on behalf of the bindings.
- A Full arms **Writable** for that stream in the same call, so no wakeup is lost. It fires once, when the stream can again queue at least half of the smaller of its stream and connection send caps; freeing a shared cap wakes every armed stream on it. It never fires if `StreamWriteStopped`, a reset or a close ends the write side first; that event tells the holder to drop its tail.
- Closing the write side is a barrier: FIN is sent only after every admitted write and held tail has been accepted. Writes after the close request are rejected. The transport can only order FIN after bytes it accepted; a tail the caller holds is the caller's to finish, and the `minip2p` stream writer (on the std `Endpoint`, shared with ffi-core) is how an application gets "send all of this, then FIN" without writing that loop itself. rust-yamux, quinn, go-yamux and quic-go draw the same line.
- **Ending the connection is an abort, not a drain.** Connection replacement, connection close and circuit close discard bytes that were accepted but not yet sent, along with held tails and deferred FINs; a circuit with output still buffered resets its bridge rather than FIN it. Draining was rejected (#327 findings 11 and 12): it would keep hidden sessions and their events alive, and on replacement the other peer may already have closed the loser, so one side delaying guarantees nothing. Applications that need delivery acknowledge at the application level.
- Secure-mux pulls frames from Yamux only when its downstream (socket or circuit bridge) has room, so ciphertext stays bounded. Control frames use a bounded reserve above the cap; exhausting it is a protocol violation that closes the connection. Received data never waits behind outbound frames, and reading never waits on write capacity.
- The SDK's `Stream.write` resolves once the whole payload is accepted. Each stream admits writes up to a high-water mark (default: the send cap, counting the in-flight write) and rejects past it with `WriteBufferFull`.

## Reading

- Each stream delivers at most its **receive budget** of unacknowledged bytes, equal to the transport's per-stream receive window. Acknowledging bytes replenishes the budget. On Yamux, receive credit returns only as bytes are acknowledged, because the window update is withheld until then. On QUIC, the engine returns credit when bytes are read, so the transport stops reading once the budget is spent and resumes on acknowledgement without waiting for another packet; QUIC's windows are pinned at their initial size, bounding the engine's own buffer to the same window, so a QUIC stream can hold about twice its window in total.
- An **unsettled stream** keeps its stream slot, even after it closes, until its delivered bytes are acknowledged or abandoned; new inbound streams past the limit are refused. Received data per connection is therefore bounded by max streams × stream window, using per-stream credit alone, and Yamux input never has to stop.
- **The bound outlives the connection** (#356). Delivered bytes can still wait in the swarm, the Endpoint, ffi-core's carry or the application after their connection ends, so an **unsettled connection** keeps its per-stream counts and its connection slot (a circuit keeps its circuit slot) until every stream settles; only that accounting and ownership survive, and everything else is torn down as before. Received data per transport is bounded by its connection limit × max streams × stream window, in every churn pattern. Each layer that can tear a session down (Yamux close and protocol failure, SecureMux fatal errors) hands its counts over first. A replacing connection is admitted like any other: the old unsettled connection still counts. Circuits get their own admission limit, `max_circuits` (64 by default), reserved before STOP is accepted or HOP CONNECT is sent and released on every failure.
- **A full transport refuses, it never forgets.** With every slot held, dials fail with `ResourceExhausted` and inbound connections are refused as today. Timeouts do not free delivered bytes; only acknowledging or abandoning them does. A reader that does neither can lock the transport out of new connections; that is the price of a real bound. No memory budget backs these counts (ADR 0022).
- Whoever consumes the bytes acknowledges them: swarm core for its own protocols, gossipsub after decoding a frame, the relay when its forward is accepted (which is what pauses the source), and the circuit when its inner session takes bridge bytes. The Rust Endpoint acknowledges user-stream data when the app pulls the event, unless the protocol was registered for manual acknowledgement. Every protocol registered through FFI uses manual acknowledgement; the SDK acknowledges when `read()` returns a chunk or a `data` listener returns.
- Acknowledging more than a stream's unacknowledged bytes is an error naming the stream and both counts. Acknowledging a closed stream releases its outstanding bytes, also after its connection ended, without sending credit or producing events; acknowledging a settled or unknown stream is a no-op. The swarm acknowledges data it discards from a replaced connection or a race loser, and replacement keeps queued acknowledgements. The SDKs keep an acknowledgement-only handle to a stream after its connection ends, released when the stream settles.
- Abandoning a stream after its connection ended works top-down: the SDK, the carry, the Endpoint and the swarm each drop what they hold for it, then the transport settles it outright. The application gives up any bytes it holds.
- Stream events (ready, data, Writable, and stream and connection terminals) are never dropped, in ffi-core's carry or in the SDK, and keep their relative order on one path. Adjacent data events for one stream coalesce, so the byte budgets bound their count. Only non-stream payload events, such as gossipsub messages, may still be dropped.
- Two exceptions keep churn from growing an undrained queue, since a stream or connection that carried no data frees its slot at once. A peer-opened stream that closes without data before its `StreamReady` was taken leaves with all its events. A connection that ends without data before the binding took any of its events, whichever side dialed it, leaves with every event naming it; if it is replaced instead, its undrained `ConnectionEstablished` is rewritten to name the successor and the `ConnectionReplaced` goes (when the cap already dropped that `ConnectionEstablished`, the `ConnectionReplaced` goes too). Connection-attempt terminals are separate events and are never elided. ffi-core's carry and the SDK's lossless queue apply the same rules. The Rust Endpoint's own queue is the caller's to drain.

## Memory retained by slices

A layer that keeps a slice of a payload shorter than half the payload's original length copies it into its own buffer, so retained allocations stay within twice the counted bytes. A caller that passes a `Bytes` viewing a much larger allocation owns that memory.

## Rejected alternatives

- **All-or-nothing writes.** Today's QUIC and Yamux behaviour; a write larger than the send window plus the queue cap could never be accepted. Handing back the unsent tail removes that wedge and matches rust-libp2p and go-libp2p, which also accept partial writes.
- **A POSIX-style byte count.** `Ok(0)` is easy to mishandle, and Full stops being a distinct, typed result.
- **The refusing layer holds the write.** Every layer would need a parking slot and a completion event, and "accepted" would mean two things.
- **Pausing and resuming reads.** Coarse, and leaves delivery unbounded between a burst and the pause.
- **Per-peer carry-over** of a closed connection's unsettled streams into the peer's next connection (#356). Fairer to other peers, but many peer identities still accumulate unbounded total, and the transport would need peer identity, race handling and cross-transport coordination.
- **Discarding undelivered data when a connection ends** (#356). It loses bytes in the ordinary write, FIN, close pattern, and cannot reclaim bytes the application already holds under manual acknowledgement.
- **A per-connection receive budget.** Yamux has only per-stream credit, and stopping its ordered input would hide control frames another stream needs. Holding stream slots bounds the same memory without it.

## Consequences

- Every `send_stream` and every stream reader changes, in Rust, ffi-core and the SDKs. #255 applies the write side, #256 the read side, and #257 relay forwarding.
- The SDK's fire-and-forget write path and its dropping read queue go away.
- A peer that stops reading can no longer force a teardown through our buffers; it is left to the idle and keep-alive timeouts.
- An application that stops acknowledging can, with enough peer churn, hold every connection slot, and the transport then refuses new connections until it acknowledges or abandons (#356).

## Amendments: implementation details

Where delivery stops without acknowledgement:

- A reader that never acknowledges sees delivery stop at about one stream window, but the exact point differs by transport (`tests/bulk_backpressure.rs` depends on it). On Yamux (TCP), part of the initial window was spent on the multistream negotiation the endpoint consumed itself, and Yamux returns credit in half windows, so delivery stops just short of the window. On QUIC the gate is the delivery budget, which the endpoint restores for the bytes it consumed itself, so delivery reaches the full window.
- Payloads meant to exercise backpressure must exceed QUIC's default connection queue (1 MiB) plus its send and connection windows (2 and 3 MiB), and Yamux's 256 KiB stream cap plus the kernel socket buffer. A reader that never acknowledges is measured against the window its endpoint actually advertises: `TcpConfig::std_default()`'s 2,432 KiB on the std endpoint (ADR 0120), not `YamuxConfig::default()`'s 256 KiB.

Circuits (`minip2p-nat`):

- **A full circuit table fails the whole relay leg.** The circuit limit (`max_circuits`) is local, so no other relay would do better: when it is reached before HOP CONNECT, `Attempt` fails the relay leg with `ResourceExhausted` instead of rotating to the next relay, and CONNECT is never sent. Inbound, `InboundCircuit` reserves its circuit slot before accepting STOP and refuses with `RESOURCE_LIMIT_EXCEEDED` past the limit.

Yamux settlement (`YamuxSession` in `minip2p-secure-mux`):

- An unsettled stream id is still in use: a SYN reopening it (from either side's parity) is a protocol error ("duplicate SYN for an existing stream"), since reopening would replace its unacknowledged count.
- Settling an unsettled stream with `reset` needs no wire, so it works after the session has ended too.
- On protocol failure (`fail`), `Data` events still queued are dropped and never delivered, so their bytes are subtracted from the stream's unacknowledged count (including a stream that already closed within the same input); only bytes actually delivered stay the host's to settle.
- When every write side ends (GoAway or failure), `Writable` events already queued are retracted too, not just future ones. When a reset removes a stream whose bytes were still unframed, those bytes leave the shared connection cap without a frame being pulled, so streams blocked on that cap are woken there.

Swarm (`SwarmCore`):

- **Control-stream demotion waits for held negotiation bytes.** When a stream negotiated for an application protocol still has negotiation bytes held after a `Full`, its `SetControlStream { control: false }` is deferred (`pending_demotions`) until `handle_stream_writable` replays the tail, so those bytes keep the control reserve. `forget_stream` hands the owed bytes to the new owner as application writes and re-applies a pending demotion after them.
- **Writes behind held bytes stay behind them.** `hold_action` appends a later write or close for a held stream to the held tail. A `StreamWritable` queued while a replayed tail came back `Full` again is swallowed by `next_event` (and re-armed unless a close is queued), so the application is woken only once the held bytes are all accepted.
- **Exceeding `MAX_HELD_PER_STREAM` resets the stream** and drops its still-queued writes first, so none goes out ahead of the reset.
- **The swarm acknowledges data no consumer will read**, beyond the replaced and race-loser cases: data arriving on a connection the swarm is closing unannounced, `StreamData` dropped with a discarded placeholder peer, and data dropped by `abandon_stream` for a stream the transport already closed (no reset is coming to settle it). Left unacknowledged, the muxer would hold the stream's slot against its stream limit for good.

ffi-core carry:

- When the carry overflows, only dropped Connection-attempt terminals are reported (their Connect IDs, in `OverflowDiagnostic::terminal_connect_ids`): a lost stream terminal or write settlement cannot happen, since stream events are never dropped. Each Connect ID settles exactly one terminal, so the list has no duplicates.
- A connection counts as seen by the binding once it drains any event naming it, except `PeerReady`, `IdentifyReceived`, `IdentifyFailed`, `EndpointError` and the other informational events listed in `Carry::track_connection`; anything else naming it is something the binding acts on. A connection also becomes seen when the binding opens a stream on it (`mark_connection_seen`, used by ffi-core and the web host), so its end is never elided. Connection-attempt terminals are delivered even when they name a connection the binding never saw, since they answer the application's own connect.

TS SDK (`Stream` and `Minip2p` in `core/src/sdk.ts`):

- A stream's unread-chunk FIFO is unbounded in the SDK, because native delivers at most one unconsumed receive window per stream; the bound lives in the receive budget.
- An empty write buffer admits any write, whatever its size, so a payload larger than the high-water mark can still go out; only writes behind it are refused with `WriteBufferFull`.
- `#emitData` reads `byteLength` before calling `data` handlers, because a handler may transfer the buffer and detach it; the consumed count must still be right.
- `StreamClosed` carries no cause. Once a remote FIN established EOF, a later full closure does not turn the receive side into a failure: buffered bytes stay readable before EOF.
- `StreamData` for a stream the SDK no longer tracks is consumed at once (`consumeUntracked`). Nothing will read it, and an abandon that native refused (the stream had already closed there) would otherwise leave the bytes holding the native stream slot.
- `openStream` marks its connection as seen, so the SDK queue never elides that connection's end: the application now knows the connection and must hear it close.
