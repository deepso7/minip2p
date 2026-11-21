# A direct connection outranks a circuit to the same peer

`CircuitTransport` itself arbitrates between a relayed and a direct connection to the same peer, because the secure-mux session leaves that policy to its host and the wrapper is the host. A verified direct connection always wins, and the circuit is closed with `ConnectionCloseReason::Local` (our own decision, not a peer or transport failure), with no separate `Error` event.

- `record_direct` sweeps every circuit to that peer that is still negotiating and fails it as soon as the direct connection is known.
- `pump` arbitrates again when a session reports `SessionOutput::Established`: if `direct_by_peer` already holds a connection to that peer, the circuit is torn down instead of emitting `Connected`. This is a backstop, not a duplicate: the invariant "no established circuit to a peer that already has a direct connection" must not rest on the sweep alone (a direct connection can be registered without it, and the test `a_circuit_completing_after_a_direct_connection_never_reports_connected` pins it).
