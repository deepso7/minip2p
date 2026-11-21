# Listening and per-socket server configs on one quinn endpoint

One quinn `Endpoint` serves every socket of a `QuicTransport` (ADR 0014). How it listens:

- **No server config until `listen`.** `bind` creates the endpoint with no server config, so it accepts nothing. `listen` installs it once for the whole endpoint; admission then checks that the socket an Initial arrived on is itself listening.
- **A socket that is not listening sends nothing.** quinn answers an unknown Initial with a stateless reset even when it has no server config. The adapter drops every endpoint `Response` (a reply to a datagram no connection owns) on a socket that is not listening, so before `listen` a node is silent while the same socket still dials out (ADR 0014: "a socket that is not listening still sends no reply to anything").
- **Listening again is the same listener.** A second `listen` for a socket reports its address without announcing `Listening` twice; callers may still ask for the address after bind.
- **The receiving socket picks the server config.** libp2p-only sockets keep the endpoint's config; WebTransport-serving sockets get their own (ALPN `h3`, or both, ADR 0023). Those per-socket configs are built as clones of the endpoint's `ServerConfig`, so the Retry tokens the endpoint issues stay valid whichever config accepts the connection.
- **Retry is the only address validation.** No NEW_TOKEN is issued (`ValidationTokenConfig::sent(0)`), so every inbound connection goes through Retry (ADR 0019/0022). `RETRY_TOKEN_LIFETIME` outlives the Endpoint's connect deadline (#471).
- **The connection limit counts inbound and outbound alike, across sockets.** `dial` refuses with `ResourceExhausted` at `max_connections`, and admission enforces the same bound for incoming Initials.
