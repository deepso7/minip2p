# minip2p-ffi

`minip2p-ffi` is the UniFFI shell for embedding minip2p in mobile applications.
The binding-agnostic driver, endpoint lifecycle, event conversion, and bounded
carry live in `minip2p-ffi-core`. This crate contains only UniFFI type mirrors
and method delegation.

Create a `P2pEndpoint`, register a `P2pEventDoorbell` with `start`, and call
`drain_events(limit)` when the doorbell rings. Drain until the method returns an
empty batch. The core rings the doorbell only when its carry changes from empty
to non-empty, and it never pushes individual events through the binding.

`stop` requests shutdown. `wait_stopped` observes complete driver exit and
socket release. Dropping the last endpoint reference requests the same shutdown.

The crate builds as an rlib, static library, and dynamic library. It is an
internal workspace component and is not published.
