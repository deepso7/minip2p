# Flush, and flush before close

A short-lived sender (a CLI that sends a file and exits) wrote its last bytes and FIN, then closed the endpoint, and the peer often got neither: the bytes were still in the Endpoint's write queue (ADR 0030), in a Yamux session, or in QUIC's send buffers, and closing a connection discards them (QUIC) or aborts the socket (TCP). Applications looped `wait(Duration::ZERO)` a few times and hoped ([plan](../plans/dx-perf-size-evolution.md), Decision 3.4). Nothing could tell them when the bytes were gone. We decided:

- **`Transport::has_pending_writes(&self) -> bool`, defaulting to `false`.** It is `true` while stream bytes or FINs the transport accepted are still on their way out on a connection that is not closing: TCP's bytes the socket has not taken and its session's frames and window-blocked stream bytes; QUIC's queued writes, datagrams waiting on the socket, and every FIN the peer has not acknowledged yet (the engine's `Finished`); a circuit's ciphertext the bridge refused, its session's output, and the inner transport's own. `TransportSet` asks every member, WebTransport counts bytes until the platform reports them written, and a FIN until the platform reports its close done (`IoEvent::WriteClosed`, the browser's `writer.close()` resolving).
- **What "drained" means is per transport, and documented.** TCP output counts until the socket (the operating system, or smoltcp) has taken it: past that the kernel delivers it, and a graceful close follows. QUIC has no per-stream acknowledgement for a stream left open, so bytes there count until the engine sent them (quinn-proto exposes no unsent count either, so the adapter counts the bytes it wrote since the engine last caught up against the bytes the connection has put on the wire since, and a stream reset stops that count); a finished stream counts until the peer has acknowledged every byte and the FIN, which is what makes "send, close the write side, flush, close" reliable.
- **`Endpoint::has_pending_writes()`** adds the Endpoint's write queue (held bytes and deferred FINs) to the transport's answer.
- **std: `flush(deadline) -> Result<bool, Error>`** drives the endpoint, sleeping on readiness and timers like `wait`, until nothing is pending or the deadline passes, and returns whether it drained. It returns at once when nothing is pending, drives once past a passed deadline, keeps the events it produces queued for the next `wait` or `poll`, and does not stop for a `WaitHandle` interrupt (the next `wait` reports it).
- **portable: `flush() -> Result<bool, DriverError>`** runs one drive batch when something is pending and returns whether nothing is left. It never blocks; the host repeats it, polling between attempts (queued events keep `next_deadline` immediate, so flushing without polling spins) and then waiting on `next_deadline` and its transport's readiness, as it does for `poll`.
- **std `close_within(timeout)` flushes first, within the same timeout,** then disconnects and drains as before. `close()` (500 ms) and the bindings' stop and close inherit it. A failed flush is the close's failure (`CloseOutcome::Failed`), and teardown still runs. A portable `close()` still does not wait; its host flushes first.

## Rejected alternatives

- **Counting a QUIC stream's bytes until acknowledged.** quinn-proto exposes no per-stream acknowledged offset; tracking it would mean mirroring its send buffers. The FIN's `Finished` already gives the guarantee a short-lived sender needs.
- **Flushing in `disconnect`.** It is also how an application drops a misbehaving peer, at once; waiting there would surprise it. Close is where the application says it is done.
- **A swarm-level query.** The swarm writes through to the transport and holds no stream bytes of its own; the Endpoint's write queue and the transport are the two places bytes wait.

## Consequences

- A sender ends with `send_stream`, `close_stream_write`, then `close()` (or `flush(deadline)` first, to know whether it drained), instead of a `wait(Duration::ZERO)` loop.
- Over QUIC a flush waits a round trip for the FIN's acknowledgement, so the peer must be driving its endpoint; a close deadline caps it.
- `close_within(Duration::ZERO)` now flushes once (one drive) before tearing down.
- Transports implemented outside this repository keep the default and report nothing pending, as before.
