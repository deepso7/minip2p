# Ping attempts own their deadline

`SwarmState` tracks each peer's ping as a `PingAttempt` whose deadline (`SwarmTimeouts::ping_ms`) starts at the `ping` call and is the one the host sees through `next_deadline`. The `minip2p-ping` handler's own `Timeout` is only a backstop: the attempt's deadline always fires first, and both end in the same single `PingFailed`.

On a Connection replacement, `retire_for_replacement` hands an in-flight or pending ping over to the new connection with a fresh deadline, so the hand-over reports no failure. Because timers tick only after the transport batch (ADR 0060), it first times out a ping already past its deadline at that instant; only that peer's ping, since another peer's reply may still be later in the batch. The in-flight payload is read from the ping handler before its per-peer state is reset. A failed ping forgets its stream, so the next ping opens a new one.
