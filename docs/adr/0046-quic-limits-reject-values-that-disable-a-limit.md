# QuicLimits validation rejects values that silently disable a limit

`transport_config` (in `minip2p-quic`) validates `QuicLimits` before any socket is bound, so a bad limit fails `QuicTransport::bind` with `InvalidLimit` instead of misbehaving later:

- **`max_pending_bytes_per_stream` must be non-zero**, and the connection queue must leave application streams room beyond the control reserve. Writable fires once a stream can queue half of its smaller send cap (ADR 0012); a zero queue can never free half of itself, so a `Full` write would never be told it can retry.
- **`idle_timeout_ms` must be non-zero.** QUIC treats a zero idle timeout as "no timeout", which would keep dead connections alive forever, the opposite of what a limit promises. A zero datagram retry queue is rejected for the same reason: it could never retain a packet.
- **`packet_threshold >= 3` and `1.0 <= time_threshold <= 10.0`.** The floors are RFC 9002's: lower thresholds declare packets lost that are only reordered or still in flight. The ceiling on `time_threshold` keeps quinn's `Duration::mul_f32` by it from overflowing (which panics), and the range check also rejects NaN and infinity.
- **`connection_receive_window`: `usize::MAX`, or anything past what a QUIC `VarInt` can express, means unlimited (`VarInt::MAX`).** `usize::MAX` is matched explicitly because on 32-bit targets it would otherwise be a finite 4 GiB window (complements ADR 0022).
