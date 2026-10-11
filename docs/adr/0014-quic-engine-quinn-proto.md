# QUIC engine: quinn-proto + rustls

`minip2p-quic` ran on Cloudflare's quiche with BoringSSL. quiche read `Instant::now()` internally, so the adapter carried a second clock next to the host's. BoringSSL needed CMake, libclang bindgen workarounds and a patched `boring` fork for Android, and the adapter hand-rolled Retry tokens, connection-ID and reset-token routing, a paced-packet hold and keepalives. The research is in [Replacing quiche with quinn-proto](../research/quinn-proto-migration.md), and the plan in [Plan: run `minip2p-quic` on quinn-proto](../plans/quic-quinn-proto-migration.md).

## Decision

- **Engine: quinn-proto `0.11`**, without default features, plus `rustls-ring`. It is a Sans-I/O state machine: it owns no sockets and runs every connection timer on the `Instant` its caller passes in. The adapter samples one `Instant` per `poll` and maps engine timeouts onto the host's timeline, as before. The host's millisecond `Now` is never handed to the engine, because it is too coarse on low-RTT paths. Retry tokens use quinn's system-time `TimeSource`.
- **TLS: rustls `0.23` with the `ring` provider**, TLS 1.3 only, ALPN `libp2p`. Custom verifiers authenticate the peer inside the handshake: exactly one certificate, libp2p verification at host time, CertificateVerify against the certificate's own key, and on a dial the expected `PeerId`. A rejected peer gets a TLS alert instead of the application close codes `0x01`–`0x04` it got before.
- **Socket I/O: quinn-udp** for GSO, GRO, ECN and packet info, through its synchronous `try_send`/`recv` on non-blocking std sockets. Limits keep counting logical datagrams.
- **Connection token: a TLS exporter value.** quinn-proto doesn't expose connection IDs, so the token is 32 bytes of `export_keying_material` with the label `minip2p quic connection token` and an empty context. Like TCP's Noise hash, it is bound to the session.
- **One `QuicTransport` type** over one or two sockets, at most one per IP family, served by one quinn-proto `Endpoint` (#247). `QuicEndpoint` and `DualQuicTransport` are gone. `bind` takes one or two addresses, and `dual_stack` binds both wildcards.

## Rejected alternatives

- **Stay on quiche and add quinn-udp GSO.** That gets most of the throughput but keeps BoringSSL, the patched fork, the internal clock and all the hand-rolled Retry, routing and pacing code.
- **`quinn` (async) instead of quinn-proto.** It needs an async runtime.
- **aws-lc-rs as the rustls provider.** It is rustls's default and FIPS-capable, but heavier to build, and has needed CMake or NASM on some targets. ring needs only a C compiler. aws-lc-rs stays possible behind a feature if FIPS is ever needed.
- **Keep CID-derived Connection tokens by sniffing handshake headers.** It would tie the adapter back to packet formats the engine owns. Pre-1.0, the exporter is the cleaner contract.

## Consequences

- **Accepted rollout limitation.** A quiche-based minip2p peer derives a different Connection token for the same connection. In a same-direction connection race between mixed versions, the two sides can keep opposite connections and close both. Nothing restarts a settled direct dial, so recovery needs an application or discovery redial, and a repeat race can fail the same way. Opposite-direction races are unaffected: they compare peer IDs. We recommend upgrading every node that dials, relays included, together.
- Other wire-visible changes: once listening, a short-header packet with an unknown connection ID gets a rate-limited stateless reset (RFC 9000 §10.3) instead of silence; path MTU discovery is on (from 1200 bytes) instead of a fixed 1350; connection IDs are 8 bytes instead of 20. A socket that is not listening still sends no reply to anything.
- An established connection's idle timeout or stateless reset now gives only `Closed`. A loss while handshaking gives `Error` then `Closed`, and an orderly close gives no `Error`.
- Native builds need only a C compiler for ring. The BoringSSL build steps (CMake, libclang, bindgen flags) are gone from CI, the bindings workflows and the Docker images.
- quinn-proto is 0.x and breaks its API between minors, so its version is pinned and upgraded deliberately.
- The `diagnostics` counters are rebuilt on quinn's connection stats. The quiche-only fields are removed.
