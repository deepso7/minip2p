# Does the current interface need replacing?

The buffering concern is real. These measurements do not justify replacing the current public interface by themselves. They supersede the earlier recommendation to choose pull as the default based on two prototype variants.

Keep the current interface unless reliable, bounded per-stream consumption is a requirement you want the library to guarantee. When an application controls both peers, its own acknowledgement window can provide that behavior today. Pull is a possible library-level implementation, not a consequence of these benchmark results.

## The scenario where consumption credit helps

A peer sends a large stream to a worker that consumes more slowly than the network can receive. The network loop must keep running because a second stream or small control messages share the connection. The receiver therefore cannot simply stop driving everything while the worker catches up.

With current StreamData delivery, popping the event is enough for Yamux to return credit. The application can then retain the payload while the sender continues. Buffer growth is the difference between bytes received and bytes processed. In our deliberately paused case, nearly the complete slow transfer accumulated in the application's queue.

This is not a library memory leak. Those bytes belong to the caller, and retaining them is permitted by the interface. An application willing to discard data or reset the stream can cap its queue, but that changes the requirement from lossless streaming. This benchmark requires every accepted payload byte to reach the consumer in order.

A concrete use case is a bulk download feeding a slow storage or database worker while a chat/control stream must remain responsive. If receivers keep up, or transfers are small enough that their backlog is acceptable, we have not demonstrated a benefit that warrants a redesign. These tests simulate consumer pacing; they do not claim that any particular disk or database consumes at the chosen rate.

## Four implementations, one caller

- `current`: the unmodified current public Endpoint interface. StreamData payloads wait in application queues until their consumer is ready.
- `pull`: the experimental receiver returns Yamux credit on read. Only the receiver changes. The sender uses the same public send_stream method as every other mode.
- `ack`: unmodified current Endpoint plus an application protocol. The sender keeps at most 256 KiB per stream unacknowledged; the receiver sends an 8-byte cumulative count after each consumed 64 KiB. Both peers must implement this extra protocol.
- `pause`: unmodified current Endpoint. The receiver stops polling its entire Endpoint whenever its application queue reaches a 256 KiB threshold. This is a simple queue-management workaround, not a hard byte cap; one poll can exceed the threshold.

The three current-interface modes compile the same caller against actual main at `aae6a75267d1c1880fcbb0bac6db82550d6c7025`. They do not use the prototype build with its flag switched off. The pull mode compiles against this throwaway branch. Registry dependency versions common to both builds are checked for equality. The baseline lockfile, source hash, revisions, environment, and parameters are captured in [metadata.json](results/consumers/metadata.json) and [baseline.Cargo.lock](results/consumers/baseline.Cargo.lock).

## Results that matter

Each bulk stream transfers 32 MiB. One reader pauses for 750 ms while the other reads immediately. An 8-byte echo probe shares the connection. Values are medians over seven separate runs.

| Mode | Peak queued bulk payload | Process peak RSS | Fast stream finishes | Largest probe RTT in each run |
| --- | ---: | ---: | ---: | ---: |
| Current | 32.06 MiB | 35.83 MiB | 241 ms | 1.51 ms |
| Pull | 0.375 MiB | 4.77 MiB | 135 ms | 1.05 ms |
| Current + application ACK | 0.375 MiB | 4.30 MiB | 132 ms | 0.95 ms |
| Current + pause Endpoint | 0.313 MiB | 4.89 MiB | 998 ms | 750 ms |

Current delivery keeps the probe responsive already. Its cost in this case is the accumulated payload. Pausing the whole Endpoint controls that queue, but stalls unrelated work. Both per-stream credit approaches avoid that tradeoff, and let the fast stream finish sooner because the paused stream stops taking a share of the transfer work.

Reducing the slow transfer from 32 MiB to 8 MiB reduces current queued payload from 32.06 MiB to 8.06 MiB. Pull and the application ACK mode remain near 0.375 MiB in both cases. Process RSS follows the same broad change, so this is not only an accounting-counter observation.

For a consumer processing 8 MiB at 4 MiB/s, current queued payload peaks at 7.875 MiB. Pull and application ACK stay at 0.375 MiB. The unrelated fast stream finishes in 61 ms with current delivery, 35 ms with pull, and 34 ms with application ACK. Pausing the whole Endpoint delays it to 1.92 seconds. All four finish the slow transfer in approximately two seconds, as the workload requires.

## No general speed win

With both readers active, each transferring 32 MiB:

| Mode | Median throughput | Peak queued payload |
| --- | ---: | ---: |
| Current | 268.5 MiB/s | 192 KiB |
| Pull | 259.2 MiB/s | 192 KiB |
| Current + application ACK | 258.1 MiB/s | 192 KiB |

Pull is about 3.5% slower in this workload. That is an observation about this prototype and machine, not a universal cost of pull. It supplies no evidence for a speed-motivated rewrite. Application acknowledgements have a similar small throughput cost here.

Bounded buffering also defers work. In the 32 MiB paused case, both streams finish in 774 ms with current delivery, 879 ms with pull, and 882 ms with application ACK. Current can finish sooner after the pause because its data is already waiting in memory. There is no free throughput gain from holding credit back.

Allocation results show no general improvement either. In the active case pull makes fewer allocation calls, but allocates more cumulative bytes. The current send method takes an owned Vec and reports a full Yamux send buffer as an error. When receive credit is held back, the benchmark retries that same public method at most once per millisecond, allocating a Vec on each attempt. That increases allocation traffic in the pull and whole-Endpoint-pause modes. This comparison deliberately does not attribute benefits from a different partial-write interface to the receive change.

See [the generated summary](results/consumers/summary.md) for every case's medians, throughput ranges, allocation results, and CPU measurements. Raw data is in [timing.csv](results/consumers/timing.csv), [allocations.csv](results/consumers/allocations.csv), and [branch-control.csv](results/consumers/branch-control.csv). No recorded outliers are discarded.

## Reproduce and audit

From this worktree:

```sh
just prototype-consumers
python3 crates/minip2p/prototypes/stream-dx/summarize_consumers.py
```

The runner expects a clean sibling checkout named minip2p for the baseline. To select another clean checkout, run bench_consumers.py with `--baseline /absolute/path`. The baseline source revision is recorded on each run; reproducing these measurements requires the revision named above. The main checkout is read and built as path dependencies, without editing it. Both builds use Cargo release defaults and pinned shared dependency versions.

There are four workload cases, four modes, seven timing repetitions and three separate allocation repetitions per cell. That is 112 timing and 48 instrumented runs. Runs are serial, mode order is shuffled with seed 149, and warmups are discarded before recorded samples. Each process creates fresh endpoints, authenticates and negotiates three streams, then checks deterministic generated payload bytes and reaches EOF on both bulk streams. The generator distinguishes stream and byte position and avoids a giant preloaded fixture affecting memory measurements. Verification work is identical across modes. Current and ACK consumers inspect their owned payload directly; pull copies into a reusable destination before the same check.

A control runs current behavior from both main and the prototype branch. Their three throughputs were 242.4, 266.8, 267.7 MiB/s on main and 243.4, 267.5, 266.8 MiB/s on the branch. These include the initial cold control, precede the measured-mode warmups, and are not included in the seven-repetition tables.

The host is synchronous and caller-driven. It gives each bulk stream one send and one consume opportunity per turn, rotates send order, and prioritizes a probe send opportunity. It sleeps for 100 microseconds when no application data/control progress occurs. A rejected send waits one millisecond before retrying. The paced consumer processes 64 KiB batches every 15.625 ms. An earlier continuous-byte pacer encouraged tiny reads and excessive polling; it was replaced before the recorded final matrix. The other workload definitions are unchanged.

Measurement environment is Apple M2 Pro, macOS 26.5.2, rustc 1.98.0. No build or test job ran alongside the measured processes. This is a normal desktop, not isolated benchmark hardware; ranges and raw samples are provided rather than asserting statistical significance for small differences.

Payload counters sample unread application/Yamux bytes after the receive poll. The pull accessor is read-only and never pumps or flushes protocol output. These samples exclude sender queues, transient decoder buffers, allocator capacity, and kernel buffers. They are not whole-process memory bounds.

`/usr/bin/time -l` supplies process peak RSS, peak physical footprint, and user/system CPU time. Those encompass both endpoints and setup; timed throughput excludes setup. CPU times have coarse hundredth-second resolution. stats_alloc runs separately from uninstrumented timing. Its sampled live-heap delta subtracts deallocated bytes from allocated bytes since transfer start, excluding setup reservations; it is not a strict instantaneous peak. Cumulative allocated bytes are allocation traffic, not retained memory.

Probe columns are per-run percentiles and maxima, summarized across runs. At most one probe is outstanding, so a long stall reduces probe samples. The maximum RTT and inter-reply gap reveal that stall; a p99 alone can conceal it. This is not an independent open-loop request-arrival latency benchmark.

## What this settles, and what it does not

The lossless slow-consumer backlog and the whole-Endpoint-pause penalty are demonstrated. Application-level ACKs demonstrate that the current interface can avoid them when the application controls both ends. They change the application wire protocol and cannot simply be inserted into arbitrary existing protocols or imposed on a peer that does not cooperate.

Library-owned consumption credit is valuable if bounded per-stream delivery should work for every caller without each application building its own window. It still does not dictate read_into versus another consumption interface. The earlier owned-plus-release experiment already showed equal credit rules give similar buffering.

My earlier recommendation overextended the evidence. We had a valid flow-control observation, then treated it as justification for a preferred interface and additional lifecycle work. These benchmarks support a conditional requirement, not a universal rewrite or a claim of improved DX.

Recommendation: keep the current public interface for now. If the concrete requirement is generic, reliable, bounded per-stream delivery with independently slow consumers, plan that focused change and evaluate its caller contract. If the need is only a custom bulk-transfer protocol, an application ACK window is a demonstrated alternative. Small messages and consumers that keep up provide no measured reason to switch.

This is actual Endpoint over localhost TCP, not QUIC, FFI, WAN, lossy transport, or embedded performance evidence. Consumer pacing is synthetic. The pull prototype still does not implement production blocking readiness and complete lifecycle semantics. These measurements do not validate shipping that code or decide its DX for all callers.

Existing Yamux, secure-mux, transport, TCP, and Swarm tests pass, along with formatting and Clippy. The five portable crates compile for thumbv7em-none-eabi without default features. All benchmark changes remain on the throwaway branch; main is unchanged.
