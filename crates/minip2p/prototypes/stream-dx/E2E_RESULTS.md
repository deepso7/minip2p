# Endpoint comparison with equal receive-credit rules

The later [current-interface benchmark](CONSUMER_RESULTS.md) supersedes this report's recommendation to adopt pull by default. The measurements below remain the historical prototype comparison.

THROWAWAY, issue #149, branch `prototype/stream-dx`. Measured 2026-09-05 on Apple M2 Pro, macOS 26.5.2, rustc 1.98.0, Cargo release profile. The commit containing this report contains the measured source and lockfile.

## Decision

Use `read_into` as the default application receive API, with consumption-driven credit and a small caller-driven continuation helper. Use borrowed partial writes with a helper that retains the unaccepted suffix. Keep owned chunks out of the initial default API.

This is a DX decision supported by comparable measured performance, not a claim that copying is faster. With identical credit rules, both approaches bounded the paused reader. Owned chunks were about 1.5% faster in the fast-reader case and slightly slower in the paused-reader case. That does not justify a second obligation to release credit on every consumption path.

An owned chunk with explicit release is viable for applications that retain received data. It avoids copying into a caller buffer. But holding all available chunks without releasing them exhausted the stream window in the experiment. Polling did not restore credit; releasing the chunks did. A forgotten release would have the same flow-control effect. Our chunk has no automatic Drop action. Making that automatic requires a way for Drop to communicate with a caller-driven connection, which this comparison does not evaluate.

Pull also has an obligation. The host must keep scheduling a partially consumed readable stream until it gets WouldBlock. The earlier helper prototype addresses this by retaining runnable state. These Endpoint measurements query on each drive turn; they do not establish the production readiness-event contract.

## What ran

Run `just prototype-e2e` in the throwaway worktree. The runner creates a deterministic pseudorandom 8 MiB source file using Python seed 149 and temporary output files. Two Endpoint instances negotiate three application streams over localhost TCP. Two transfer the source into separate real files; the third carries an 8-byte echo probe. Both file senders half-close. Both readers observe EOF and the output files match the source byte for byte.

The path includes Endpoint binding/dialing, Swarm protocol negotiation and lifecycle, TransportSet routing, StdTcpProvider, Noise, and Yamux. New prototype Endpoint methods route application payload operations directly to the transport through the Swarm's transport accessor. They do not send payload through the old SwarmCore StreamData dispatcher. The application asserts that old StreamData events do not escape in the measured transfer loop.

Both receive modes use the same per-stream Yamux consumption-credit accounting. `prototype_read` copies into a reusable 64 KiB destination and returns credit. `prototype_chunk` transfers an existing frame without credit; `prototype_release` consumes its token and returns credit. Both use the same borrowed partial-write path. There is no old emission-credit baseline in these measurements.

The stream mode is enabled on both sides after StreamReady and before payload starts. This coordinated setup avoids the production negotiation/payload race. A real implementation must select the receive policy before application payload can arrive, rather than expose this late enable switch.

Each sender reads from a File into its reusable buffer and preserves partial-write offsets. Each receiver writes to a File. Filesystem reads/writes are timed, but file creation, network setup, source generation, final comparison, and lifecycle edge checks are not. File writes use the OS cache; no fsync or durable-storage throughput claim is made.

The host drives both endpoints synchronously in one thread. It sends and consumes at most one bulk chunk per stream per turn and rotates send order. It polls directly and only sleeps in part of the paused phase after both senders have submitted FIN. Thus it can busy-poll while the paused stream has blocked writes. This is the same schedule for both modes, not an idle-efficient production driver or a test of blocking wakeups. Probes have at most one outstanding request and a 1 ms minimum interval.

Five measured runs per mode and pause setting, with alternating mode order and discarded warmups. Twenty timing runs use an uninstrumented binary; twenty allocation runs use stats_alloc. Raw data is in [e2e-timing.csv](results/e2e-timing.csv) and [e2e-allocations.csv](results/e2e-allocations.csv). Rerunning replaces those two CSV files.

## Measurements

Medians over five runs. Probe p99 is the median of per-run percentiles.

| Case | Mode | Combined MiB/s | Both files and EOF, ms | Fast file and EOF, ms | Sampled unread/loaned payload | Probe p99, ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Both readers active | Pull | 236.0 | 67.80 | 67.78 | 192 KiB | 0.987 |
| Both readers active | Owned + release | 239.4 | 66.83 | 66.80 | 192 KiB | 0.997 |
| Second reader paused 200 ms | Pull | 67.6 | 236.61 | 39.85 | 383.96 KiB | 0.510 |
| Second reader paused 200 ms | Owned + release | 67.1 | 238.44 | 39.11 | 383.96 KiB | 0.496 |

Both modes asserted that unread plus loaned bulk payload stayed within the combined two-stream receive window of 512 KiB. The table reports turn-boundary samples, not a strict high-water mark. It excludes kernel buffers, sender queues, allocation overhead, and transient decoder storage. Negotiation has already consumed some initial credit, so these samples need not match the earlier session-only experiment.

Fast-reader throughput ranged from 233.9 to 241.9 MiB/s for pull and 237.5 to 242.3 MiB/s for chunks. These short local runs do not establish a general performance ranking.

| Allocation case | Pull calls | Owned calls | Pull cumulative bytes | Owned cumulative bytes |
| --- | ---: | ---: | ---: | ---: |
| Both readers active | 10,516 | 10,449 | 135,055,474 | 135,051,746 |
| Second reader paused | 112,597 | 112,764 | 147,638,330 | 147,647,648 |

Allocation counts cover both endpoints, transport processing, and the timed caller loop. Setup and initial buffers are excluded. Timing-build allocation columns contain zero placeholders, meaning unmeasured. The paused case includes many extra polls and probes; do not interpret its allocation count as a per-byte cost or an owned-versus-pull allocation regression. Neither API removes existing frame, crypto, or polling allocations. Improving those paths is separate work.

## Caller code

The actual comparison is in `consume` in [endpoint_e2e.rs](src/bin/endpoint_e2e.rs). Ignoring provisional method prefixes, the distinction is:

```rust
// Pull: consumption and credit advancement are one operation.
if let Some(n) = endpoint.read_into(stream, &mut scratch)? {
    sink.write_all(&scratch[..n])?;
}

// Owned: consumption and credit advancement are separate operations.
if let Some(chunk) = endpoint.next_chunk(stream)? {
    sink.write_all(chunk.data())?;
    endpoint.release(chunk)?;
}
```

These snippets illustrate the choice, not a finalized signature. In the owned example, an early return from the sink operation skips release. That may be appropriate if the stream is then reset, but it needs an explicit lifecycle policy. The owned token is non-Clone and stores its connection/stream ids, preventing accidental duplicate release through the Endpoint wrapper. Prototype tokens are not bound to an Endpoint instance, so cross-Endpoint misuse is another unfinished part of that design.

## Correctness and scope

All 40 recorded runs passed exact file comparisons and reached EOF on both bulk streams. Every run also exercised an untimed fresh-connection scenario for its mode:

- Pull read seven bytes, yielded, then read another seven with buffered data remaining. Reset with unread data rejected further reads.
- Owned chunks exhausted credit while held. One hundred further polls delivered no extra chunks. Releasing them resumed delivery. Reset invalidated a subsequently held chunk's release.
- A second negotiated stream delivered data after the first was reset.

Existing Endpoint std+tcp tests passed. Existing Yamux, secure-mux, TransportSet, TCP, and Swarm suites and doctests passed. Clippy and formatting passed. The five portable protocol/transport/orchestration crates compiled for thumbv7em-none-eabi without default features.

This does not cover QUIC, FFI, multiple peers, WAN conditions, automatic Drop credit, both sides closing with unread/loaned data, connection replacement, or all cancellation races. The prototype uses raw connection/stream ids and a provisional error shape. It is evidence for the API choice, not a mergeable implementation.

## Contract to implement next

Choose pull as the default, then implement its contract rather than carry these prototype methods into main:

- A positive read consumes exactly that prefix and advances only its credit. A nonempty destination returning zero means EOF after buffered data. An empty destination must not be confused with EOF.
- WouldBlock means no progress now. A continuation helper retains runnable state after positive reads; readiness wakes it after WouldBlock. The host includes local runnable work before sleeping.
- A partial write accepts a prefix locally. The caller/helper retains the remaining suffix and its buffer lifetime. Acceptance is not delivery acknowledgement.
- Handles identify a particular connection and stream. Reset and terminal connection failure have explicit effects on buffered input, outstanding writes, and future calls.
- Select consumption-driven receive handling during stream setup, before payload. Keep I/O, clocks, and waits in the driver. Preserve no_std + alloc and the absence of async Rust in the core.

Keep an owned receive option as a later extension only if a real retention use case warrants its lifecycle machinery. No further API-comparison prototype is needed before writing this implementation contract. Main remains unchanged.
