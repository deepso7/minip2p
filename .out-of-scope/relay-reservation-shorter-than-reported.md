# Detecting a relay reservation that ends before its reported expiry

A reservation stays advertised until its scheduled renewal, the relay connection drops, or a renewal fails. If a relay quietly drops a reservation before the `expire` it reported, the listener keeps advertising its `/p2p-circuit` address until the next renewal.

## Why this is out of scope

- **The protocol has no way to detect it.** Circuit Relay v2 has no message that asks whether a reservation is still held. Sending another RESERVE is the only check, and that is what renewal already does.
- **The knob already exists.** `NatConfig::reservation_default_ttl_secs` caps any lifetime a relay reports, and reservations renew at half that cap. A host that distrusts its relays can lower it and get a short re-RESERVE interval whatever `expire` says. The field's rustdoc describes this exact case.
- **Well-behaved relays keep their promise.** minip2p's relay server expires reservations on the same deadline it reports. ADR 0079 already treats the reported `expire` as untrusted and records why it is capped.
- **Inferring loss from dialers does not work.** A dialer that gets `NO_RESERVATION` from the relay tells the listener nothing; the listener never sees that response.

## When to revisit

Revisit if a relay seen in practice drops reservations well before its reported expiry, so that the default cap leaves hosts advertising dead addresses for long. The first step would then be lowering the default `reservation_default_ttl_secs`, not adding a probe.

## Prior requests

- #589: "Relay reservation can silently expire while still advertised"
