# minip2p-ffi

UniFFI bindings for embedding minip2p in React Native and other mobile hosts.
The ABI, generated bindings, event enums, and error enums are pre-1.0 and may
change between releases.

The current surface contains identity and relay-address helpers plus validated
endpoint construction, immutable identity/listen-address queries, and a live
connected-peer query. Secret key bytes are passed separately to the constructor
so the host-visible configuration record cannot stringify them. Driver lifecycle,
commands, and events will be added in the next implementation slice.

Android currently pins `boring` and `boring-sys` to the immutable fix proposed
in [cloudflare/boring#518](https://github.com/cloudflare/boring/pull/518).
Remove the workspace patch when an upstream crates.io release contains that
fix.
