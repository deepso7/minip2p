# minip2p

App-facing facade for minip2p.

This crate glues identity, QUIC transport, and the std swarm driver into a
small `Endpoint` API. Lower crates remain available directly for Sans-I/O and
`no_std + alloc` users.
