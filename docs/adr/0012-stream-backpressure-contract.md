# Stream backpressure contract

A full send buffer used to tear things down or lose data instead of slowing the sender (#234): the TS SDK wrote fire-and-forget and dropped reads past a cap, TCP closed the connection at its outbound ceiling, circuits died on a full bridge, relays closed on a full destination, and Yamux and QUIC returned receive credit on arrival rather than on consumption. One contract now governs every layer. Queues stay bounded; nothing moves buffering somewhere unbounded instead.

## Writing

- `send_stream` accepts as much of the payload as the stream can queue and returns `Ok(())` when every byte was accepted, or `Full` carrying the **unsent tail** (the whole payload when nothing fit). Full is retryable, never a fault. Peer credit does not decide acceptance; accepted bytes queue until credit drains them. Bytes count against the stream and connection send caps until they reach the transport's output, including bytes already framed but not yet written.
- The **caller** holds the unsent tail. Swarm core is the caller for its own protocols (ping, identify, multistream negotiation). The relay keeps an in-order queue per direction, bounded by the receive budget it granted the source. ffi-core holds one pending tail per stream on behalf of the bindings.
- A Full arms **Writable** for that stream in the same call, so no wakeup is lost. It fires once, when the stream can again queue at least half of the smaller of its stream and connection send caps; freeing a shared cap wakes every armed stream on it. It never fires if `StreamWriteStopped`, a reset or a close ends the write side first; that event tells the holder to drop its tail.
- Closing the write side is a barrier: FIN is sent only after every admitted write and held tail has been accepted. Writes after the close request are rejected.
- Secure-mux pulls frames from Yamux only when its downstream (socket or circuit bridge) has room, so ciphertext stays bounded. Control frames use a bounded reserve above the cap; exhausting it is a protocol violation that closes the connection. Received data never waits behind outbound frames, and reading never waits on write capacity.
- The SDK's `Stream.write` resolves once the whole payload is accepted. Each stream admits writes up to a high-water mark (default: the send cap, counting the in-flight write) and rejects past it with `WriteBufferFull`.

## Reading

- Each stream delivers at most its **receive budget** of unacknowledged bytes, equal to the transport's per-stream receive window. Acknowledging bytes replenishes the budget. On Yamux, receive credit returns only as bytes are acknowledged, because the window update is withheld until then. On QUIC, quiche returns credit inside `stream_recv`, so the transport stops calling it once the budget is spent and resumes on acknowledgement without waiting for another packet; QUIC's windows are pinned at their initial size, bounding quiche's own buffer to the same window, so a QUIC stream can hold about twice its window in total.
- An **unsettled stream** keeps its stream slot, even after it closes, until its delivered bytes are acknowledged or abandoned; new inbound streams past the limit are refused. Received data per connection is therefore bounded by max streams × stream window, using per-stream credit alone, and Yamux input never has to stop.
- Whoever consumes the bytes acknowledges them: swarm core for its own protocols, gossipsub after decoding a frame, the relay when its forward is accepted (which is what pauses the source), and the circuit when its inner session takes bridge bytes. The Rust Endpoint acknowledges user-stream data when the app pulls the event, unless the protocol was registered for manual acknowledgement. Every protocol registered through FFI uses manual acknowledgement; the SDK acknowledges when `read()` returns a chunk or a `data` listener returns.
- Acknowledging more than a stream's unacknowledged bytes is an error naming the stream and both counts. Acknowledging a closed stream releases its outstanding bytes; acknowledging a settled or unknown stream is a no-op.
- Stream events (ready, data, Writable, and stream and connection terminals) are never dropped, in ffi-core's carry or in the SDK, and keep their relative order on one path. Adjacent data events for one stream coalesce, so the byte budgets bound their count. Only non-stream payload events, such as gossipsub messages, may still be dropped.

## Memory retained by slices

A layer that keeps a slice of a payload shorter than half the payload's original length copies it into its own buffer, so retained allocations stay within twice the counted bytes. A caller that passes a `Bytes` viewing a much larger allocation owns that memory.

## Rejected alternatives

- **All-or-nothing writes.** Today's QUIC and Yamux behaviour; a write larger than the send window plus the queue cap could never be accepted. Handing back the unsent tail removes that wedge and matches rust-libp2p and go-libp2p, which also accept partial writes.
- **A POSIX-style byte count.** `Ok(0)` is easy to mishandle, and Full stops being a distinct, typed result.
- **The refusing layer holds the write.** Every layer would need a parking slot and a completion event, and "accepted" would mean two things.
- **Pausing and resuming reads.** Coarse, and leaves delivery unbounded between a burst and the pause.
- **A per-connection receive budget.** Yamux has only per-stream credit, and stopping its ordered input would hide control frames another stream needs. Holding stream slots bounds the same memory without it.

## Consequences

- Every `send_stream` and every stream reader changes, in Rust, ffi-core and the SDKs. #255 applies the write side, #256 the read side, and #257 relay forwarding.
- The SDK's fire-and-forget write path and its dropping read queue go away.
- A peer that stops reading can no longer force a teardown through our buffers; it is left to the idle and keep-alive timeouts.
