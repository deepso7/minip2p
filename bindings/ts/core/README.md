# @minip2p/core

Platform-neutral types and SDK behavior for minip2p.

Applications normally install a platform package such as `@minip2p/react-native` or `@minip2p/node`; those packages bind the SDK to a native backend and re-export the public core types.

Adapter authors implement the deliberately small contract exported from `@minip2p/core/backend`. The core package never imports React Native, Node.js, UniFFI, napi-rs, or generated native code.

The shared endpoint API covers identity and Identify snapshots, QUIC connections, explicit ping, relay/AutoNAT/DCUtR state, gossipsub or floodsub, signed discovery, mDNS, and arbitrary negotiated protocols/streams. Platform adapters own the background driver that implements Rust's caller-driven poll/wake contract.
