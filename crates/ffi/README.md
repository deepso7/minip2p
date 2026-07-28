# minip2p-ffi

UniFFI bindings for embedding minip2p in React Native and other mobile hosts.
The ABI, generated bindings, event enums, and error enums are pre-1.0 and may
change between releases.

The current surface contains identity and relay-address helpers plus validated
endpoint construction, immutable identity/listen-address queries, and a live
connected-peer query. Secret key bytes are passed separately to the constructor
so the host-visible configuration record cannot stringify them. The lifecycle
surface includes detached background driving, listener callbacks, activity
hints, running-state inspection, flag-only stop, and bounded stopped-state
waits. Swarm, NAT, pubsub, and signed-discovery events are converted to the
flattened `P2pEvent` model. Network commands and state snapshot queries remain
to be added.

`IdentifyReceived` is represented by the later `PeerReady` event, so the raw
Identify event is not delivered. User-stream events are omitted because the v1
FFI exposes neither user-protocol registration nor stream commands. Listener
callbacks run on the native driver thread and must not block waiting for that
same driver to stop; `wait_stopped` called from a listener returns `false`
immediately.

Android currently pins `boring` and `boring-sys` to the immutable fix proposed
in [cloudflare/boring#518](https://github.com/cloudflare/boring/pull/518).
Remove the workspace patch when an upstream crates.io release contains that
fix.
