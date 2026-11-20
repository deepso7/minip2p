# TS SDK readiness waits judge trailing events against native state

Native state snapshots run ahead of the event stream (ADR 0007), and a peer's connection can be replaced (dual-stack races and direct upgrades hand the peer from one connection to another via `connectionReplaced`). `Minip2p.waitPeerReady` (`sdk.ts`) therefore:

- Takes one `connectionInfo` snapshot so readiness, connection and protocols agree, and resolves at once if it already says ready.
- Counts a queued `peerReady` only if its `connId` is still the peer's current connection; a replaced connection's readiness never resolves the wait.
- Counts an `identifyFailed` if it names the peer's current connection or, once native has no connection for the peer, the last connection this wait knew. The failed connection may already be gone natively, so requiring it to be current would hang the wait.

On `ConnectionReplaced`, native ends the replaced connection's streams without per-stream terminal events, so `#dispatchNative` ends them itself via `#connectionEnded`.

Tests that need a connection to be settled poll until the announced events catch up with `connectionInfo` rather than trusting the first `connect` result.
