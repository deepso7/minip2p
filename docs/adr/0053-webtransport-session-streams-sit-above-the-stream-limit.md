# WebTransport session streams sit on top of the stream limit

The CONNECT and Noise streams belong to the WebTransport session, not the application. When an `h3` connection completes its QUIC handshake, `QuicConnection` raises the engine's peer bidirectional stream credit by two on top of `max_streams_per_connection` (`reserve_wt_streams`), and the adapter keeps enforcing that limit for application streams. After authentication only the CONNECT stream stays the session's, so one extra credit remains reserved; the Noise stream's slot is freed and counts as an ordinary stream slot until it settles. Bytes of the Noise reply spend draft-14 session data credit, so an application stream gets only what is left.

The connection's endpoint address becomes `/…/quic-v1/webtransport` at that point, so a browser's address is never a hole-punching candidate (ADR 0023).
