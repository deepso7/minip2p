# QUIC poll, service order and deadlines

How `QuicTransport::poll`, `next_deadline` and `QuicConnection::service` keep a caller-driven host from losing work or spinning, and the platform constraints the socket layer is built around.

## Poll and next_deadline

- **Two clocks.** The engine runs on a fine-grained `Instant` sampled once per `poll`; the host's millisecond `Now` anchors `next_deadline` and is never handed to the engine as time (ADR 0014). With no sample yet there is no timeline, so an idle, never-polled transport reports `None`.
- **Events are taken only at the end of a poll.** They accumulate in `pending_events` for the whole poll, so an error path leaves the batch queued for the next call instead of dropping it.
- **Each socket gets its own receive bound** (`MAX_DATAGRAMS_PER_POLL`), so one IP family's traffic cannot starve the other. Connections defer their output to the service that runs after the batch.
- **`next_deadline` is `IMMEDIATE` whenever work is buffered outside the engine's timers**: events queued between polls by `listen`, `open_stream`, `send_stream`, `close_stream_write` or `reset_stream`; a dispatched readiness event; a receive batch cut off by its bound (no fresh readiness edge will report the rest); datagrams retained behind socket writability (a readable peek cannot wake them); and connections a service left unfinished. The datagram and unfinished checks come before the "no sample" check, because `dial` queues datagrams before the first `poll`, and a host that idled on `None` would never flush them. `IMMEDIATE` is due on any timeline.
- **Engine timeouts round up to the next millisecond.** Truncating turned "due in 300 µs" into "due now", so a driver took a zero-length budget and spun until wall time caught up. Only a timeout that is genuinely zero maps to `now`.
- **A dial fails at once when its first flight is refused** (no route) rather than at the handshake timeout; the abandoned connection's queued `Error`/`Closed` are removed, since the caller learns from the error.
- **`Drop` sends every connection's CONNECTION_CLOSE** before the sockets go: nothing polls afterwards. The retry queues are flushed first so a full queue has room for them. A WebTransport session's close capsule and FIN go out with the close, but its Closing phase is cut short because nothing would end it.

## Connection service order

`QuicConnection::service` runs one connection's work in a fixed order:

- The WebTransport handshake deadline is checked first (unless closing); a WebTransport Closing phase ends only after this service's events are in.
- Endpoint events (new connection IDs, retirements, the final `Drained`) are handed to the endpoint before the transmit, so their output leaves in the same service.
- The connection's timeout is the earlier of the engine's timer and the WebTransport session's.
- The transmit allowance is recomputed for every transmit, since retained datagrams shrink it. A transmit for a family the transport has no socket for is dropped like any unroutable packet. A hard send error stops the service rather than retrying a dead route within it.

Close reasons: every cause records itself, so a connection drained without one was ended locally (`ConnectionCloseReason::Local`). A local failure closes with QUIC's `INTERNAL_ERROR` (1). On a WebTransport session, HTTP/3's orderly `H3_NO_ERROR` maps to minip2p's code 0. `expire` handles the close timer directly: closing stops every other engine timer, so the one left is the close.

The connection token is a TLS exporter value (ADR 0014); if the exporter fails the token is left unset rather than guessed, as the transport contract asks. An accepted Initial never passes through `handle_event`, so admission counts it in the connection's diagnostics itself.

## Socket I/O constraints

- **Receive through the registered clone once attached.** On Windows mio re-arms readiness only when it sees the `WouldBlock` itself, so `recv_batch` reads through the registered clone's `try_io`; a receive on the original socket would hide the `WouldBlock` and leave later datagrams with no wakeup (ADR 0013's edge-triggered contract).
- **Registration is all or nothing.** If attaching any socket fails, every clone already registered is deregistered explicitly: a clone shares the socket's file description, so dropping it would not drop the registration.
- **Path MTU discovery only when no socket may fragment.** It needs datagrams the network drops, not fragments, when they are too large.
- **A hard send error affects one destination.** A datagram the socket refuses outright (an IPv6 destination on an IPv4 socket, a dead route) is dropped and the poll carries on; it never aborts the whole endpoint.
