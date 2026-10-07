# TypeScript feature mapping

`@minip2p/core` describes the portable host API. React Native implements that contract through UniFFI; Node and WASM adapters can implement the same contract without changing application code.

| Rust `Endpoint` capability | TypeScript SDK |
| --- | --- |
| Identity, peer ID, bound addresses | `@minip2p/react-native` exports `generateSecretKey` and `peerIdFromSecretKey`; the portable `@minip2p/core` endpoint API exposes `peerId` and `listenAddrs` |
| Address-shaped QUIC and TCP listeners | `listen` configuration |
| Ping | Promise-returning `ping`, plus typed ping events |
| Identify readiness and snapshots | `isPeerReady`, `waitPeerReady` (follows the peer's current connection), `peerInfo`, `connectionInfo(peerId).readyProtocols`, Identify events |
| Connection lifecycle | `connectionEstablished`, `connectionReplaced` (the peer stays connected; streams on the old connection end), and `connectionClosed` (the peer disconnected) events |
| Custom protocol registration | `protocols` configuration, `addProtocol` |
| Negotiated streams | Promise-returning `openStream` and `Stream` handles with `write`, `read`, `closeWrite`, `reset`, and `abandon`; each operation names the stream's own connection, so it never reaches a stream on a newer connection. `write` resolves once native accepted every byte, rejects with `WriteBufferFullError` when bytes are already buffered and the write would push them past `writeHighWaterMark` (a write into an empty buffer is always admitted), and `closeWrite` follows every earlier write. Before the endpoint processes a replacement or close, `write` on the old connection rejects and `closeWrite` and `reset` throw (a `closeWrite` queued behind pending writes reports the end through the stream's terminal event instead); afterwards the stream has ended: `write` rejects, `closeWrite`, `reset`, and `abandon` do nothing, and reads reject (`StreamClosedError` after a replacement) |
| Connection targets and Connect IDs | Promise-returning `connect(target)`, split-phase `startConnect(target)`/`waitConnectResult`/`cancelConnect`, and typed terminal events |
| Relay, AutoNAT, DCUtR | Driven by `connect`; `path(peerId)` and typed path/reachability events |
| State snapshots | `connectedPeers`, `path`, `connectionInfo`, `knownPeers`, `listenAddrs`, `activeReservation` |
| Pubsub | gossipsub subscribe/unsubscribe/publish, pubsub events |
| Signed discovery | discovery configuration, `knownPeers`, discovery events |
| mDNS | mDNS configuration, merged `knownPeers`, source-tagged discovery events |
| Shutdown | `close`, `onClose`, and `Symbol.dispose`; the low-level native export also provides `stop`/`waitStopped` |
| One Endpoint event stream and its blocking wait (event, deadline, interrupted) | Driven by each platform backend; surfaced as typed events, State getters, and Promise waits such as `waitFor` and `waitConnectResult` |

Resource-policy tuning remains native configuration until it has consistent semantics across every backend.
