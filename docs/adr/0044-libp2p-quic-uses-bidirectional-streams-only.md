# libp2p QUIC connections use bidirectional streams only and no DATAGRAM

libp2p over QUIC uses bidirectional streams only. `transport_config` therefore advertises zero peer unidirectional streams and does not advertise QUIC DATAGRAM (`datagram_receive_buffer_size(None)`), and the adapter never opens a local unidirectional stream.

Sockets that also serve WebTransport (ADR 0023) must advertise both for HTTP/3, so a libp2p peer on such a socket may open unidirectional streams and send DATAGRAMs. `QuicConnection` stops every peer unidirectional stream on a libp2p connection without surfacing it, and drains and drops every received DATAGRAM (`Event::DatagramReceived`): neither is served. Half-close is the adapter's own bookkeeping, so the engine's other stream events need no handling.
