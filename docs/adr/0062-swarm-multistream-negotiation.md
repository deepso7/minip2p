# Swarm multistream-select negotiation

- **Inbound listeners survive `na`.** After answering `na`, an inbound negotiator stays open so the dialer can offer its next protocol on the same stream, as multistream-select specifies. An outbound negotiation treats `NotAvailable` as terminal and resets the stream.
- **The outbound deadline starts at `StreamOpened`.** `Transport::open_stream` returns the stream id at once, but a transport may hold the open (QUIC waits for the peer's stream credit); the negotiation deadline (`SwarmTimeouts::negotiation_ms`) is armed only when the transport reports the stream opened, unless the stream's own protocol deadline (Identify, ping) already covers it.
- **A stop mid-negotiation keeps reading only if the proposal went out.** If the proposal is still held after a `Full`, it never reached the peer and no reply will come, so the stop is handled at once; otherwise the negotiator waits for the reply (see `handle_stream_write_stopped`).
