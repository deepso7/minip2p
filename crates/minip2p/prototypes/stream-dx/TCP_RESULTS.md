# Real TCP stream experiment

THROWAWAY, issue #149, branch `prototype/stream-dx`. Measured 2026-09-05 on Apple M2 Pro, macOS 26.5.2, rustc 1.98.0, default Cargo release profile. The commit containing this report contains the measured code. Dependencies are pinned by the prototype's Cargo.lock.

## Question and verdict

Does consumption-driven receive credit bound a paused reader without stopping unrelated streams? Yes in this workload. Pull retained about 512 KiB across the receiver streams while owned delivery retained about 8 MiB. The fast stream finished earlier with pull. Every transferred byte and echoed sequence matched.

This does not establish a performance win for a borrowed API. Fast-reader throughput was slightly lower with pull. Pull reads still copy from allocated Yamux frames, and writes still allocate through the existing sender. Allocation counts did not improve consistently.

I would adopt consumption-driven receive credit as a design requirement. This result alone does not choose between `read_into` and owned chunks with explicit credit release. Both could tie credit to application consumption. The current owned baseline releases credit on event emission, and its caller deliberately retains those events while paused. That caller behavior is allowed by the API; it is not evidence of a library memory leak.

## Workload

Run `just prototype-tcp`. Python creates an 8 MiB deterministic pseudorandom file using seed 149. Both concurrent streams transfer the complete file. An 8-byte request/echo stream shares their connection, with at most one probe outstanding and a 1 ms minimum interval. One case reads both streams immediately; the other pauses the second reader for 200 ms. Both endpoints run in one synchronous thread over nonblocking localhost TCP, with actual multistream negotiation, Noise authentication/encryption, and Yamux framing.

Each bulk stream gets one send attempt and one receive attempt per turn. Chunks and read destinations are 64 KiB. Send order rotates. Socket drives allow four reads and four writes per phase. The loop sleeps 50 microseconds when no bytes move. The pull caller retains its write offset and read continuation flag; readiness is queried after driving. It does not use the in-memory helper type directly. This is not a full event/readiness implementation.

Five measured runs per mode and case, alternating order, following one discarded warmup per mode. Timing uses an uninstrumented release binary. Allocation measurements use a separate release build with `stats_alloc`. There are 40 recorded runs. Raw data is in [timing.csv](results/timing.csv) and [allocations.csv](results/allocations.csv). The runner overwrites those files on rerun.

## Timing results

Values are medians across five runs. Probe p99 is the median of each run's p99, not a pooled percentile.

| Case | Mode | Combined MiB/s | Both files done, ms | Fast file done, ms | Peak unread payload, MiB | Probe p99, ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Both readers fast | Owned | 278.2 | 57.5 | 57.5 | 0.25 | 1.32 |
| Both readers fast | Pull | 271.0 | 59.0 | 59.0 | 0.25 | 1.34 |
| Second reader paused | Owned | 79.6 | 201.1 | 58.2 | 8.06 | 1.33 |
| Second reader paused | Pull | 69.8 | 229.2 | 31.1 | 0.50 | 0.86 |

The slow owned case finishes almost immediately after resuming because its file is already buffered at the receiver. Pull needs another 29 ms to deliver the remaining data. That is the cost of holding receive credit back. The fast stream finishes about 27 ms earlier in this case because the paused stream stops competing for most of the transfer.

Fast-reader throughput ranged from 274.5 to 281.6 MiB/s for owned and 222.1 to 272.6 MiB/s for pull. There was a pull timing outlier. These short local runs support the buffering observation much more strongly than small timing differences. They are not WAN results or release performance claims.

## Allocations

Median counts from separate instrumented runs:

| Case | Mode | Allocation calls | Reallocation calls | Cumulative allocated bytes, MiB |
| --- | --- | ---: | ---: | ---: |
| Both readers fast | Owned | 5142 | 8 | 128.74 |
| Both readers fast | Pull | 5076 | 8 | 129.83 |
| Second reader paused | Owned | 7867 | 13 | 128.87 |
| Second reader paused | Pull | 8657 | 8 | 142.87 |

This includes both endpoints and the driver during transfer, excluding file loading, handshake, stream setup, initial scratch buffers, and initial metric-vector reservations. Counts include probes. The longer pull run sends more probes, so the slow-case counts do not isolate the bulk stream API. `stats_alloc` reports allocator calls and cumulative allocated bytes; these are not live heap peaks. See its [Stats documentation](https://docs.rs/stats_alloc/0.1.10/stats_alloc/struct.Stats.html).

## What the counters mean

`peak_held_bytes` samples unread receiver payload after the first socket-drive phase of each turn, before application reads. It sums the owned caller's queued payload and Yamux's pull queue across streams. `paused_held_bytes` samples the same quantity only during the pause. Neither includes kernel buffers, sender queues, decoder storage, allocator capacity, or transient copies. These are sampled payload counts, not process memory or strict high-water marks.

`peak_wire_bytes` samples pending encrypted output after a drive; zero means that sampling point found it drained. `turn_p99_us` measures loop work before its idle sleep. Elapsed time includes the pause and sleep but excludes setup. Throughput divides the combined 16 MiB by that elapsed time. Allocation columns contain placeholders of zero when `alloc_stats=false`; those zeros mean unmeasured. CSV probe counts show the sample size for each reported percentile.

## Verification and limits

All 40 runs completed with exact file-byte and probe comparisons. The existing Yamux and secure-mux suites passed, 42 tests total. Clippy passed for those crates and the prototype. Both protocol crates compile without default features for `thumbv7em-none-eabi`. Rust formatting checks passed.

This bypasses Endpoint, Swarm, StdTcpProvider, FFI, and QUIC. It does not test multiple peers, loss, kernel memory bounds, remote network scheduling, an actual disk sink, or cryptographic performance in isolation. TCP carries the file loaded into memory before timing. Pull lifecycle handling remains incomplete, including FIN cleanup and reset behavior with unread data. Empty read destinations also use a provisional return convention. Do not merge this branch as the API implementation.

The useful next implementation decision is when to return receive credit. The production design still needs a convenient consumption contract, correct shutdown/readiness behavior, and allocation work through the frame/crypto pipeline.
