# Test relay support: teardown races are not relay faults

The in-process relay in `tests/support/relay.rs` (`RelayServer`) bridges two streams and fails the test on any relay fault, so it has to tell races from faults:

- A FIN can race teardown of the other bridge half; that stale close must not replace the original lifecycle event.
- A replaced connection ends its streams without per-stream `StreamClosed` events, exactly like a closed one, so the bridge drops both halves on either.
- Data can likewise race teardown: the other half's connection may already be closing before its `ConnectionClosed` arrives, and the transport rejects writes there. That ends the bridge; any other write failure, `Full` included, is a relay fault.
- `CutAll` disconnects a snapshot of connected peers; a peer may close in between, and its lifecycle event stays authoritative, so the disconnect error is ignored.
- On drop, the relay thread may already have stopped after recording a failure, so a failed `Stop` send is ignored and joining plus `assert_healthy` preserve that outcome.
- Mesh tests (`tests/support/relay_interop.rs`, `examples/relay-server/tests/cli.rs`) pick each node's backbone port from a probe socket that is released before binding, holding both probes until both ports are picked so they differ, so each node can list the other before either binds.
