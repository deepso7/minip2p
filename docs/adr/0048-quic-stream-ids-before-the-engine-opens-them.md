# QUIC stream IDs are handed out before the engine opens them

`QuicConnection::open_stream` returns a stream ID at once, even when the peer has granted no stream credit yet. The stream is opened in the engine (and reported as `StreamOpened`) by a later service once credit arrives; writes and FIN queue until then. Its slot counts against `max_streams_per_connection` from the moment it is handed out.

- The adapter is the only opener of local streams, so IDs follow its own sequence (`next_local_bidi_stream_id`, step 4). An engine ID that differs from the expected one fails the connection.
- Resetting a stream that is not on the wire yet completes it for the caller immediately and marks it `reset_on_bind`: it is still opened in the engine when credit arrives, then reset, so the ID sequence never diverges. Closing the connection ends every send half, bound or not; an unbound stream then never opens.
- A closing connection opens nothing more. On a WebTransport session a pending open may also wait on the client's session stream credit.
