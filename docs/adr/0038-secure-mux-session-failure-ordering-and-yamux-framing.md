# SecureMux session failure, output ordering and Yamux framing

How `SecureMuxSession` (`minip2p-secure-mux` `session.rs`) behaves at the edges of its lifecycle, so a host draining outputs always sees a consistent picture:

- **An early stream call does not consume the session.** Stream operations run only in `Phase::Ready`; any other phase is a live session mid-upgrade, so the phase is put back and the call is rejected, and the upgrade can still finish.
- **Failures inside a stream operation are fatal like failures on input.** A local reset of a peer-opened stream can exhaust Yamux's control reserve (`YamuxError::ControlReserveExhausted`); that fails Yamux like a protocol error on input, so its GoAway is flushed and the phase stays taken. A failed drain likewise leaves the phase taken, exactly as in `handle_input`. Once failed, every later call errors rather than operating on a half-torn-down session.
- **`Established` comes first, and only if the upgrade completes.** When the final handshake input carries a pipelined Yamux remainder, the remainder is handled first and `Established` is then inserted ahead of whatever it produced, so a caller applying connection policy sees `Established` before any stream output. If the remainder is fatal, everything it produced is truncated with the `Established`: hosts drain outputs even after an error (to flush queued bytes), and must not see a dead session announced as up or substream traffic on a connection they were never told came up.
- **No `StreamWritable` after the stream or session ends.** When Yamux reports a stream closed (reset or GoAway can end it before the caller drains), or the Yamux session fails, any `StreamWritable` already moved to the output queue by an earlier pump is retracted.
- **Shutdown is reported precisely.** The first `GoAwayReceived` code is kept, since it ended the session. A remote orderly GoAway surfaces as `SessionError::GoAway { code: 0 }`, so the host can close quietly instead of reporting a fault, and the outputs drained after it carry `StreamClosed` for every substream, exactly as a local shutdown does, so none leak.
- **`StreamId` is never truncated.** Converting the public `u64` `StreamId` to a Yamux `u32` id fails with `SessionError::UnknownStream` when it does not fit; truncation would alias an id congruent modulo 2^32 onto someone else's live substream.

## Yamux framing

Details in `YamuxSession` (`yamux/session.rs`) that are easy to "simplify" away:

- The inbound `FrameDecoder` limit is the configured `receive_window`, not `max_frame_len`: a peer may frame up to the credit it was granted, and a window larger than `max_frame_len` must not fail the session.
- Resetting a stream whose SYN never went out sends no RST; the peer has never heard of it.
- Only a PING ACK carrying our own probe nonce clears the keepalive probe; a stray ACK is ignored.
- `data_frame` picks the next sendable stream starting strictly after `send_cursor` (an excluded bound, wrapping around), so round-robin is fair and a sendable stream with id `u32::MAX` cannot keep the turn.
