# TypeScript feature mapping

`@minip2p/core` describes the portable host API. React Native implements that contract through UniFFI; Node and WASM adapters can implement the same contract without changing application code.

| Rust `Endpoint` capability | TypeScript SDK |
| --- | --- |
| Identity, peer ID, bound addresses | `@minip2p/react-native` exports `generateSecretKey` and `peerIdFromSecretKey`; the portable `@minip2p/core` endpoint API exposes `peerId` and `listenAddrs` |
| QUIC direct dial (dual family, IPv4, IPv6) | `dial`, `dialIp4`, `dialIp6` |
| Ping | Promise-returning `ping`, plus typed ping events |
| Identify readiness and snapshots | `isPeerReady`, `waitPeerReady`, `peerInfo`, Identify events |
| Custom protocol registration | `protocols` configuration, `addProtocol` |
| Negotiated streams | Promise-returning `openStream` and `Stream` handles with `write`, `read`, `closeWrite`, `reset`, and `abandon` |
| Relay, AutoNAT, DCUtR | Promise-returning `connect*`, advanced `startConnect*`/`waitConnectResult`, `path(peerId)`, and typed path/reachability events |
| Pubsub | gossipsub or floodsub selection, subscribe/unsubscribe/publish, pubsub events |
| Signed discovery | discovery configuration, `knownPeers`, discovery events |
| mDNS | mDNS configuration, merged `knownPeers`, source-tagged discovery events |
| Shutdown | `close`, `onClose`, and `Symbol.dispose`; the low-level native export also provides `stop`/`waitStopped` |
| Caller-driven polling and focused waits | Implemented by each platform backend; surfaced as callbacks, queries, and typed Promise waits |

Rust-only escape hatches such as `swarm()`/`swarm_mut()` are implementation accessors rather than portable endpoint features and are intentionally not part of the cross-platform SDK. Resource-policy tuning remains native configuration until it has consistent semantics across every backend.
