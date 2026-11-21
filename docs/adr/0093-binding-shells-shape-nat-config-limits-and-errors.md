# Binding shells: NAT config only for what has no setter, and how limits and errors are shaped

How ffi-core and the binding shells (`crates/nodejs`, `crates/web`) turn binding options into an Endpoint configuration, and the choices in them that look arbitrary but are deliberate.

## NAT config

- **ffi-core builds a NAT config only for options without a setter.** NAT defaults come from the configured relays and AutoNAT servers alone. A base `NatConfig` is submitted only to carry what has no builder setter: `force_relay`, and a non-default `max_circuits` (only when relays are configured, since only relays use it).
- **`force_relay` is never silently dropped.** Without any relay, ffi-core still submits it (with `ReservationPolicy::Never`, as there is nothing to reserve on), and the web host's `Host::new` sets the NAT config when relays are given _or_ `force_relay` is set, so Endpoint setup refuses the contradictory configuration instead of the flag disappearing.
- **Browsers always reserve and never upgrade.** A browser is never publicly reachable and cannot hole punch, so the web host uses `ReservationPolicy::Always` and `dcutr: false`.

## Node

- **Limits are converted by the constructor.** `TryFrom<NodeEndpointConfig>` leaves `limits: None`; the `P2pEndpoint` constructor converts them itself so it can tag limit errors with their field path.
- **`limits.quic.timeThreshold` is narrowed to `f32` before validation.** The native threshold is an `f32`, so validation sees the rounded value the endpoint will actually use.
- **A JS error that cannot be built falls back to the message.** `to_js_error` builds a tagged `Error` (`code`, `detail`, `capability`); that only fails when the engine is unusable, and then `Error::from_reason(error.to_string())` is still the most useful thing to throw.

## Web

- **Application protocols use manual acknowledgement** (`manual_ack_protocol`), so stream data is acknowledged when the JS reader consumes it (`stream_consumed`), not when the pump pulls the event (ADR 0012).
- **`abandon_stream` ignores the result of acknowledging dropped data.** After a reset the acknowledgement is moot, and a stream closed on a live connection is released by it, so an error there carries no information for the caller.
