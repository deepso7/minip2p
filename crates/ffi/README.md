# minip2p-ffi

`minip2p-ffi` is the UniFFI shell for embedding minip2p in mobile applications. The binding-agnostic driver, endpoint lifecycle, event conversion, and bounded carry live in `minip2p-ffi-core`. This crate contains only the UniFFI object, the doorbell callback interface, and method delegation. The records, enums and errors it exports are UniFFI types of `minip2p-ffi-core` itself, derived behind that crate's `uniffi` feature, so the generated bindings carry a second `minip2p_ffi_core` namespace.

Create a `P2pEndpoint`, register a `P2pEventDoorbell` with `start`, and call `drain_events(limit)` when the doorbell rings. Drain until the method returns an empty batch. The core rings the doorbell only when its carry changes from empty to non-empty, and it never pushes individual events through the binding.

`stop(timeout_ms)` requests shutdown: the driver disconnects peers and drains for up to `timeout_ms` (`0` tears down at once, best effort), then delivers `EndpointClosed { outcome, unfinished }` as its last event. The deadline bounds teardown time only, not delivery of accepted writes. `wait_stopped` observes complete driver exit and socket release. Dropping the last endpoint reference requests the same shutdown with a 500 ms drain.

The crate builds as an rlib, static library, and dynamic library. It is an internal workspace component and is not published.
