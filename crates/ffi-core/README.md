# minip2p-ffi-core

`minip2p-ffi-core` is the binding-agnostic embedding layer for minip2p. It owns
the detached endpoint driver, lifecycle, flattened event model, and bounded
event carry shared by foreign-language bindings.

Bindings register an [`EventDoorbell`](https://docs.rs/minip2p-ffi-core/latest/minip2p_ffi_core/trait.EventDoorbell.html)
when starting an endpoint. The core rings it only when the carry changes from
empty to non-empty. Bindings then call `P2pEndpoint::drain_events` synchronously
until it returns an empty batch. The carry holds at most 4096 events, discards
payload events first, and reports loss with `P2pEvent::EventsDropped`.

The crate is an internal workspace component and is not published.
