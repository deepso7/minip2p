# QUIC receive gating and stream terminal order

How `QuicConnection` scans peer streams under ADR 0012's receive budget:

- **A new stream is scanned at once.** A packet carrying a stream's opening, data and FIN raises only `Opened` in the engine, so the adapter scans the stream on `Opened` instead of waiting for `Readable`.
- **Stops before resets.** The engine delivers `Opened` ahead of queued stream events, so a scan can meet a reset before the `Stopped` for the same stream; the scan checks the send half's stop first, so the stop is always reported first.
- **One terminal probe at a spent budget.** With no room left the scan does a zero-length read: a FIN or reset right behind the window still surfaces, data waiting keeps the stream gated, and nothing is read. Credit for what was read goes out with the service that follows every scan, and an acknowledgement resumes a gated stream without waiting for a packet.
- **A read reset frees only the receive half.** The peer's stream credit needs the send half freed too, so the adapter resets its own send half.
- **Nothing follows a stream's `StreamClosed`.** A partial take of a held chunk is copied out so it never pins the rest (ADR 0012's slice rule).
