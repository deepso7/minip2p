# Tests wait on observable state, not on OS timing

Integration tests across the workspace run real sockets and real protocol timers. Beyond the general timing rules in `.config/nextest.toml` (drive until observable, poll once more after a window closes, backstops are failure guards only), they rely on orderings, clock choices and protocol facts that a tidy-up would plausibly "simplify" away.

## Endpoint (`crates/minip2p/tests/`)

- **Relay-mesh interop tests build the external client before the relays bind** (`relay_go_interop`, `relay_rust_interop`). Nothing drives the relays while the client builds, and an idle relay-mesh backbone left undriven that long goes stale.
- **`relay_server` judges forwarding before the clients go**, since their teardown can race a last forward.
- **`reconnect_churn` drives the remote peer on its own thread** (`spawn_driver`) so a QUIC close can complete; otherwise `Drop` would be the only path that notifies the peer. The driver thread leaves when its stop channel disconnects (the test panicked before `stop()`) instead of driving on to its backstop and panicking detached, which would bury the real failure under 30 s of silence; a failed stop send means the thread already left on its backstop, which `join` reports.
- **Portable clocks start well after zero** (`smoltcp_relay`, e.g. 50 000 ms) to catch deadlines anchored to an internal epoch instead of the caller's clock.
- **WebTransport certificate rotation tests use the next real rotation boundary** (`minip2p_tls::webtransport::next_boundary` of the wall clock), so the libp2p certificates presented over the same socket stay valid.
- **Unit tests share the integration-test harnesses.** `crates/minip2p/src/lib.rs` declares `extern crate self as minip2p` under `cfg(test)` so crate-internal tests can include the shared `tests/support` harnesses, which are written against the public `minip2p::` paths. A second copy written against `crate::` paths would drift.

## QUIC (`minip2p-quic`)

- **Loopback can deliver a datagram after the poll that sent it** (macOS does). Tests that need a peer's MAX_STREAM_DATA or FIN wait until it is observable, or until it is queued on the receiving socket (`socket::has_queued_input`, which peeks and leaves it there), rather than assume it arrived; tests that must isolate one reply first sleep and drain stragglers.
- **Junk the endpoint drops unread**: datagrams without QUIC's fixed bit, short headers with an unknown DCID (answered at most by a stateless reset), unparseable bytes and runts. Tests use these to fill receive batches and GRO trains without creating connections.
- **Latency tests take the best of three trials** against their bound, so one descheduled thread on a busy runner cannot fail them.
- **Idle-timeout tests** pick timeouts long enough that a stall between the handshake and the check cannot expire the connection. The engine's effective idle timeout is max(idle, 3×PTO), so a stretched PTO can hide a missing keepalive from a test that only checks the connection stays up. The keepalive test (`quiet_connection_sends_keepalives_past_the_idle_timeout`) therefore asserts the cadence of the server's keepalive packets at a raw peer, which no PTO affects; the remaining "stays up" tests run alone (`threads-required`) to keep PTO near loopback scale.

## TCP (`transports/tcp/tests/loopback.rs`)

These run over real kernel sockets, so they avoid asserting OS tuning:

- The read-fairness test (a socket with more buffered than one poll's 128 KiB read budget) runs on Linux only: it needs the loopback send buffer to exceed that budget, which Linux guarantees in CI, while default buffers on macOS and Windows can be smaller.
- With `TCP_NOTSENT_LOWAT`, a backed-up socket drains in steps paced by the peer's delayed ACKs (up to ~40 ms), so tests waiting for a parked state wait for quiet rather than a fixed time slice, and the quiet slice outlasts those steps.
- Which readiness wakes a parked dialer (socket room or the peer's Yamux window update) is deliberately not asserted: loopback buffering makes a socket that stays full unreliable to arrange.

## FFI (`crates/ffi/tests/loopback.rs`, `relayed.rs`; `crates/web/tests/host.rs`)

- **Gossipsub publish waits on the publisher's view of the subscription.** Before publishing, a test waits for the _publisher's_ `PeerSubscribed` for the receiver, not only the receiver's view of the publisher. The publisher's view decides whether the message is forwarded at all; waiting only on the other side lets the publisher send to nobody and leaves the receiver waiting out the full timeout.
- **Relay loss over QUIC takes the idle timeout.** Dropping the relay cannot signal an immediate close over UDP; the endpoint notices only through QUIC's 30-second idle timeout once keepalive pings go unanswered. `RELAY_LOSS_TIMEOUT` in `relayed.rs` covers that wait plus slow CI scheduling.
- **The web host's stalled-peer fixture returns the peer instead of dropping it.** Dropping an endpoint disconnects it, so the helper returns `b` to keep a peer that stays connected but silent.
