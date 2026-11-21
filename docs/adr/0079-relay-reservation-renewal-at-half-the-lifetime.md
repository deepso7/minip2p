# Relay reservation renewal and policy

The reservation manager in `minip2p-nat`'s housekeeping:

- **`WhenPrivate` reserves unless reachability is confidently Public.** A NAT'd listener must be dialable while AutoNAT evidence is still gathered, so Unknown reserves. A verdict flip reconciles the reservation in the same input cascade (`Reservations::sync`).
- **Renewal is at half the remaining lifetime.** With both a reported `expire` and a wall clock, renewal is at half of `expire - now`, clamped to `reservation_default_ttl_secs`; otherwise at half the default TTL (clockless renewal is approximate by design). A fixed margin before expiry was rejected: a lifetime just past the margin renewed every second indefinitely, a relay clock running ahead made renewal land after the reservation was gone, and a 1 s TTL must still renew strictly inside its lifetime.
- **The relay's `expire` is untrusted.** Clamping to the default TTL keeps a far-future value from postponing renewal indefinitely, the monotonic renewal deadline is computed with saturating arithmetic so a large value cannot wrap it, and an expiry at or before now (stale, or clock skew) is treated as no expiry, so renewal does not fire at once and loop on the same stale value.
- **Relay keep-alive pings are fire-and-forget.** Liveness is re-established from connection lifecycle events, so a refused ping changes nothing.
