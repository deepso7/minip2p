# minip2p-ffi-core

`minip2p-ffi-core` is the binding-agnostic embedding layer for minip2p. It owns the detached endpoint driver, lifecycle, flattened event model, and bounded event carry shared by foreign-language bindings.

Bindings register an [`EventDoorbell`](https://docs.rs/minip2p-ffi-core/latest/minip2p_ffi_core/trait.EventDoorbell.html) when starting an endpoint. The core rings it only when the carry changes from empty to non-empty. Bindings then call `P2pEndpoint::drain_events` synchronously until it returns an empty batch. The carry holds at most 4096 events, discards payload events first, and reports loss with `P2pEvent::EventsDropped`.

Connection attempts follow one contract: `connect(target)` admits an attempt under a single Connect ID and the event stream carries exactly one terminal for it — `PathEstablished`, `ConnectFailed`, or `ConnectCancelled` after `cancel_connect`. If the carry drops a terminal, `EventsDropped::terminal_connect_ids` names its Connect ID so a foreign wait settles with a delivery-loss error and recovers through the State getters (`connected_peers`, `connection_info`, `path`, `known_peers`, `listen_addrs`). The detached driver owns the endpoint's wait outcomes — event, deadline, interrupted — and releases ownership on interruption so commands never deadlock.

Listening is address-shaped: `EndpointConfig::listen` takes multiaddresses whose shape selects QUIC or TCP. Leaving it `None` binds the QUIC dual-stack defaults; an explicit empty list is rejected.

The crate is an internal workspace component and is not published.
