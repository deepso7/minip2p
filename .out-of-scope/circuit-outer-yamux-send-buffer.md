# Shallow per-circuit send cap on outer Yamux relay bridges

`CircuitTransport::write_bridge` pumps inner encrypted frames into the relay bridge stream until the outer transport returns `TransportError::Full`. Over a TCP relay leg, the outer Yamux stream buffers up to `YamuxConfig::max_buffered_send` (256 KiB by default) before reporting `Full`, so a relayed circuit can queue up to 256 KiB of inner ciphertext ahead of the inner Yamux session's round-robin scheduler.

## Why this is out of scope

- **Requires a new cross-layer `Transport` seam.** `Transport` has no per-stream send-cap override or queued-bytes query. Adding one means plumbing a new method through `Transport`, `TransportSet`, `CircuitTransport`, `TcpTransport`, and `SecureMuxSession`/`YamuxSession` — and tuning `StreamWritable` wake thresholds so a tiny bridge cap does not cause excessive wake churn or hurt bulk relayed throughput.
- **Half the buffering lives on the relay server.** Even if the client caps its outer Yamux bridge stream to one or two inner frames, `relay-server`'s `Forward` path still buffers up to the origin leg's receive budget (256 KiB portable TCP, 1,664 KiB native TCP per ADR 0120, or 1.25 MB QUIC) plus the target leg's send buffer. Solving multi-stream fairness end-to-end on relayed circuits requires coordinating buffer depth across both hops.
- **Narrow impact.** Most relayed paths run over QUIC (where `quinn-proto` manages stream pacing and windows differently) or upgrade off the relay via DCUtR. The 256 KiB outer Yamux queue primarily affects concurrent bulk streams staying on a slow TCP relay link (e.g., 256 kbit/s).

## When to revisit

Revisit if concurrent multi-stream fairness over slow TCP-relayed circuits becomes a real deployment requirement (for instance, `force_relay` over TCP on constrained links where control or small RPC streams are delayed behind bulk streams). At that point, measure both client-side outer bridge caps and `relay-server` forwarding buffers together, and benchmark `endpoint_throughput/relayed` to ensure throughput does not regress.

## Prior requests

- #509: "circuit: relay ciphertext queues up to 256 KiB per circuit in the outer Yamux stream, ahead of the inner round-robin"
