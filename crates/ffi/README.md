# minip2p-ffi

UniFFI bindings for embedding minip2p in React Native and other mobile hosts.
The ABI, generated bindings, event enums, and error enums are pre-1.0 and may
change between releases.

The current surface contains identity and relay-address helpers. Endpoint
construction, lifecycle, events, and signed discovery will be added in the next
implementation slice; they are intentionally not exported before an endpoint
object consumes them.

Android currently pins `boring` and `boring-sys` to the immutable fix proposed
in [cloudflare/boring#518](https://github.com/cloudflare/boring/pull/518).
Remove the workspace patch when an upstream crates.io release contains that
fix.
