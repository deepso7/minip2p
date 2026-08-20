# Pinned rust-libp2p relay client

This standalone, non-published tool supplies the foreign side of
`just interop-relay-rust`. Its lockfile and git dependency pin rust-libp2p
`libp2p-relay` 0.22 at `170c3c81ddd80e7c58b0500563e00a09139e8545`.

The ignored minip2p integration test starts the relay and passes its loopback
TCP peer address to this binary. Two rust-libp2p swarms then verify reservation,
Identify HOP advertisement, CONNECT/STOP, and ping bytes in both directions.
See the parent [interoperability README](../README.md) for the audited Circuit
Relay v2 pin, command, environment, result, and coverage boundary.
