# CA-signed WebTransport certificates

Self-signed WebTransport certificates rotate every 13 days, so any address with a `/certhash` that is hardcoded or announced goes stale within about 26 days. A relay we host needs one browser address that never changes ([plan](../plans/webtransport-ca-certificates.md)). The libp2p WebTransport spec allows a node with a CA-signed certificate to serve it and to leave `/certhash` out of its addresses; the browser then checks the chain like any HTTPS page, and Noise still authenticates the peer ID. We decided:

- **One certificate source per transport (plan Decision 2).** `QuicNodeConfig` takes `WebTransportCertificates::Derived` (the rotating self-signed certificates, still the default) or `Provided { chain, key }`, an operator's CA-signed chain. A provided certificate is presented to every `h3` client, never rotates, and has no rotation deadline. At bind the key must match the leaf and the leaf must not have expired; a soon-to-expire or not-yet-valid leaf is accepted and left to the host to monitor. `libp2p` clients on the same socket still get the libp2p certificate.
- **Noise lists the leaf's hash (Decision 3).** The server still sends `webtransport_certhashes`, as the spec requires, with `sha256(leaf DER)`. A browser that dialed without a certhash has nothing to compare, so the list cannot fail it. Pinning a CA leaf by hash is not supported: the W3C limits for `serverCertificateHashes` (at most 14 days' validity, no RSA) rule out ordinary 90-day certificates, so CA-mode addresses are always hash-free.
- **Listening addresses carry no certhash (Decision 4).** In provided mode the transport reports `/<ip>/udp/<port>/quic-v1/webtransport`. A browser that learns the IP form fails WebPKI cleanly, because the certificate names a domain; the address browsers use is the operator's `/dns/…/webtransport` announce. The Endpoint enforces the announce shape by mode: a WebTransport announce needs its certhash with derived certificates and must not have one with a provided certificate.

## Rejected alternatives

- **Choosing the certificate by SNI, so one socket serves both modes.** It works (an IP certhash dial sends no SNI, a `/dns` dial sends the name), but nobody needs both yet, and it doubles the Listening-address and Noise-list logic. It is the natural extension if someone does.
- **An ACME client in minip2p.** Certificates come from files the operator manages with certbot or similar; minip2p stays free of HTTP challenges and account state.
- **Live certificate reload.** The node loads its certificate at startup, and a renewal restarts it (about every 60 days). The resolver cell could be swapped at runtime if restarts start to hurt.

## Consequences

- A relay with a domain gets one permanent browser address: `/dns/<domain>/udp/<port>/quic-v1/webtransport/p2p/…`.
- Each renewal restarts the relay and drops its reservations and circuits; clients reconnect.
- Let's Encrypt no longer emails expiry notices, so the relay logs a warning when its leaf has fewer than 14 days left, at startup and daily.
- The option is native-only for now: `ffi-core`, UniFFI and the web shell do not expose it.
