# Bench drivers measure the stack, not the harness

Load and poll benchmarks must not let the harness itself become the bottleneck or the source of noise, so each one drives the stack the way a real host would and keeps its own work out of the measured interval.

## Endpoint load drivers

In `crates/minip2p/benches/` (`support/bulk.rs`, `endpoint_ping_load.rs`, `endpoint_throughput.rs`):

- **The sender drives with `Endpoint::wait`, not `next_event`.** The sink rings the sender's `WaitHandle` as bytes arrive; `wait` returns on that interrupt so the in-flight window refills at once, while `next_event` would swallow the interrupt and sleep out its deadline.
- **The sink publishes its count before reporting a transfer's end**, so the client's reset of the counter for the next transfer cannot be overwritten by the finished transfer's count.
- **The gossipsub publisher always waits on a future deadline** (clamped to 100 µs..5 ms), so a step that hit `PublishError::Backpressure` still polls and drains the outbound queue before retrying.
- **Gossipsub load starts only once every node has seen its neighbours' subscriptions**, and the measurement waits for first delivery, since the first messages may predate the hub's mesh.
- **A ping sample past its deadline is still checked against the timeout**, because a wait may hand over an event polled just past its deadline.
- **`endpoint_throughput`'s marks use fixed arrays**, so taking a mark allocates nothing inside the measured interval.

## TCP readiness benches

`transports/tcp/benches/readiness_poll.rs` measures `StdTcpProvider` and `TcpTransport` poll cost over 1 to 512 connections.

- Every measured poll is driven as a std host drives it (ADR 0013): the polled side is attached to a `SharedPoll` once setup is done, and each poll follows a zero-timeout harvest. An unattached provider would treat every open socket as possibly ready and read each one on every poll, measuring the wrong thing.
- The 512-connection provider sweeps need at least 1,027 open file descriptors, and the transport sweeps (which hold both ends) about 1,040; the bench container raises `nofile` for this (`scripts/run-bench-container.sh`).

## Node FFI benches

In `bindings/ts/node/benches/ffi.bench.ts`:

- **`raw_drain_events` waits on the native doorbell between drains**, as an embedder would; a timer poll would round each wait up to the event loop's timer. Because the doorbell is edge-triggered (ADR 0003), it rings only when the queue turns non-empty, so the bench waits only after a short drain, and `drainAllEvents` empties the queue before returning.
- **`sdk_stream_transfer` measures per-write and per-chunk cost**: 1 MiB in 16 KiB writes, read by a flowing `data` handler on the remote. The remote SDK registers a `stream` handler that accepts every stream, to match the raw remote, which drains ready events without rejecting them.
