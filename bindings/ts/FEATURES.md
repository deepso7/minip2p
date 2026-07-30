# TypeScript feature mapping

`@minip2p/core` describes the portable host API. React Native implements that contract through UniFFI; Node and WASM adapters can implement the same contract without changing application code.

| Rust facade capability | TypeScript SDK |
| --- | --- |
| Identity, peer ID, bound addresses | `react-native-minip2p` exports `generateSecretKey` and `peerIdFromSecretKey`; the portable `@minip2p/core` endpoint API exposes `peerId` and `listenAddrs` |
| QUIC direct dial (dual family, IPv4, IPv6) | `dial`, `dialIp4`, `dialIp6` |
| Ping | `ping`, `waitPingRtt`, ping events |
| Identify readiness and snapshots | `isPeerReady`, `waitPeerReady`, `peerInfo`, Identify events |
| Custom protocol registration | `protocols` configuration, `addProtocol` |
| Raw negotiated streams | `openStream`, `sendStream`, `closeStreamWrite`, `resetStream`, `abandonStream`, stream events |
| Relay, AutoNAT, DCUtR | relay/AutoNAT configuration, `connect*`, `cancelConnect`, path and reachability events |
| Pubsub | gossipsub or floodsub selection, subscribe/unsubscribe/publish, pubsub events |
| Signed discovery | discovery configuration, `knownPeers`, discovery events |
| mDNS | mDNS configuration, merged `knownPeers`, source-tagged discovery events |
| Shutdown | `close`; the low-level native export also provides `stop`/`waitStopped` |
| Caller-driven polling and focused waits | Implemented by each platform backend; surfaced as callbacks, queries, and typed Promise waits |

Rust-only escape hatches such as `swarm()`/`swarm_mut()` are implementation accessors rather than portable endpoint features and are intentionally not part of the cross-platform SDK. Resource-policy tuning remains native configuration until it has consistent semantics across every backend.
