# WebTransport certificate swaps keep handshakes consistent

How `minip2p-quic` swaps WebTransport certificates (derived rotation, ADR 0023, and `replace_webtransport_certificate`, ADR 0024) without a handshake seeing a certificate and a Noise certhash list from different generations:

- **One writer at a time.** `Certificates::replace` holds the context's write lock across the whole swap, so concurrent replaces take turns and the certificate and the hashes Noise lists never come from two of them.
- **The previous leaf stays listed.** A handshake whose certificate resolved just before a swap reads the context after it, so the new context keeps listing the previous leaf's hash. Reloading the same leaf keeps the list as it was, so a dial pinned to both hashes still finds both.
- **The session reads the context after TLS.** `QuicConnection` takes the context for `WtSession` only once the QUIC handshake completes, so whatever certificate the handshake got, a context at least as new lists its hash.
- **A poisoned lock still holds a whole certificate.** A writer that panicked replaced the context atomically or not at all, so readers recover the poisoned value instead of failing.
- **Clock before the first poll.** Until the first poll's sample, the system clock picks the derived period or judges a provided certificate's expiry at bind. The next rotation boundary is part of `next_deadline`.
