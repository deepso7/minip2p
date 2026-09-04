# Throwaway stream DX prototype

Question: does replacing owned stream-data events with partial writes and pull reads make minip2p easier to use? Does a small caller helper improve that experience?

Three runnable Rust callers share a bounded in-memory model. A standalone HTML walkthrough exposes the awkward states. Neither uses minip2p's real transports. Nothing here should be merged as a transport implementation.

## Run

From the repository root:

```sh
just prototype-stream-dx
just prototype-stream-dx owned
just prototype-stream-dx partial
just prototype-stream-dx helper
just prototype-stream-dx yield
just prototype-stream-dx helper-yield
just prototype-stream-dx fin
```

Without `just`:

```sh
cargo run --manifest-path crates/minip2p/prototypes/stream-dx/Cargo.toml -- all
```

Open `prototype.html` directly in a browser. Select **With caller helper**, then **Helper resumes after yield**. If the file is already open, refresh it to load this version. It has no server, dependencies, network calls, or persistence. Its JavaScript model is separate from the Rust implementation.

The Rust library, including the helpers, has no dependencies and is `no_std`. The trace-printing executable uses std. Check the library with:

```sh
cargo check --manifest-path crates/minip2p/prototypes/stream-dx/Cargo.toml --lib --target thumbv7em-none-eabi
```

## The three callers

`src/main.rs` contains complete caller loops. All use 8-byte send and receive capacities, a four-byte drive budget, the same 24-byte input, and a reader paused for five turns. Every turn prints relevant state. Raw partial I/O and helper I/O both attempt at most one write and one five-byte read per turn. This deliberately makes their handlers yield. The owned sketch receives whole available chunks, so its consumption cadence differs. This is a caller comparison, not a throughput comparison.

| Caller | What the application manages |
| --- | --- |
| `owned_transfer` | Six-byte chunk sizing, the next chunk offset, and retries after whole-chunk rejection; receive bytes arrive in owned Vecs. |
| `partial_transfer` | The unaccepted write offset, writable state, readable continuation, EOF, and a reusable read buffer. |
| `helper_transfer` | One borrowed `PendingWrite`, one `ReadContinuation`, event forwarding, the read buffer, and scheduling runnable helpers. |

The owned sketch borrows the current interface shape. Its buffering and flow control are the model's, not a reproduction of current QUIC/TCP behavior. Large real transfers also need chunk sizing and a retry policy.

All callers collect output solely to display and compare the message. A real sink could process slices immediately. The demo is not a filesystem transfer.

## What the helper does

`src/helper.rs` contains two structs. Neither allocates payload storage, starts a runtime, or drives I/O. `PendingWrite` borrows one buffer and retains its unaccepted suffix. This is not an unbounded queue of writes; the buffer must remain alive until the operation ends. `ReadContinuation` retains readiness after every positive read. Each `step` makes at most one stream call.

The host forwards events with `on_event`. Events remain visible to the application. It then schedules helpers whose `is_runnable()` is true, including turns with no new events. A positive read keeps that flag true. `WouldBlock` clears it until fresh readiness. EOF or a terminal error stops the helper. An empty destination returns `EmptyBuffer`, never EOF. A failed write retains its unaccepted suffix for inspection or caller recovery; retrying it automatically on a new connection is outside the helper's contract.

The host must include helper readiness before sleeping. Calling the helper only from a Readable callback would still stall after an early yield. When the application deliberately pauses, the host stops scheduling that read helper and resumes it when the application resumes. Neither helper secretly calls an application handler in a drain loop.

## Observations

- All three callers deliver the same 24 bytes in order after the reader resumes. The raw and helper callers use the same one-read-per-turn cadence. Their application and transport snapshots match across all 11 turns.
- Pausing the reader fills its receive storage. More drive calls move zero bytes. Popping a notification alone frees no capacity; reading does.
- The naive raw early-yield case still stalls. Pop Readable, read two of eight bytes, then wait for another notification. Three further drives leave six bytes unread with no event.
- The helper case pops the same notification and reads two bytes per turn. It stays runnable while the remaining six, four, and two bytes are consumed. The next read observes `WouldBlock`; the helper then stops issuing reads. Fresh data or EOF wakes it again.
- The complete raw caller works too, by keeping its own readable flag. The helper automates this state; it does not remove the need to schedule it.
- FIN follows accepted bytes. Reads return the buffered prefix and then EOF. Writes after FIN fail. Replaced connection handles fail, and a failed helper becomes non-runnable while retaining unaccepted write bytes.

## Verdict after the helper comparison

The helper improves the raw caller by making read continuation and write offsets reusable. It fixes the demonstrated early-yield mistake when the host schedules runnable helpers. The improvement is modest for this one-stream example: event forwarding, buffer lifetime, and the host's sleep decision remain explicit. The owned-data caller still asks less of the reader.

I would carry this helper design into a narrow real-transport experiment before choosing a default. That experiment must include a host loop that schedules the helpers correctly, a slow reader, and more than one stream. It must measure the copies, allocations, and throughput that this model cannot reveal. I would not remove StreamData from the default Endpoint based on this result alone.

Main is unchanged. Issue #149 remains a proposal for maintainer review.

## Limits and verification

One ready stream per endpoint, fixed in-memory capacities, and a manually driven link. No transport, crypto, negotiation, packet loss, multi-peer fairness, cancellation, FFI, or full shutdown lifecycle. Connection replacement explicitly aborts buffered bytes; it does not model retained data after connection failure. The eight-byte capacity is a demonstration value, not an achievable Yamux receive-window setting. Byte counts exclude allocator and protocol overhead. No allocation or timing benchmark was run.

Ran the three Rust transfers and the edge-case walkthroughs, compiled the library for the embedded target, and ran Clippy and formatting checks. Executed the HTML model cases offline with Node and checked its scripts parse. No test suite was added. The in-app browser previously blocked the local file URL, so the HTML layout has not been visually verified there.
