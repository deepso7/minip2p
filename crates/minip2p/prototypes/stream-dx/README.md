# Throwaway stream DX prototype

Question: does replacing owned stream-data events with partial writes and pull reads make minip2p easier to use?

This branch contains a runnable Rust model and a standalone HTML walkthrough. It implements the proposed caller contract over bounded memory, not over minip2p's current transports. Nothing here should be merged as a transport implementation.

## Run

From the repository root:

```sh
just prototype-stream-dx
just prototype-stream-dx partial
just prototype-stream-dx owned
just prototype-stream-dx yield
just prototype-stream-dx fin
```

Without `just`:

```sh
cargo run --manifest-path crates/minip2p/prototypes/stream-dx/Cargo.toml -- all
```

Open `prototype.html` directly in a browser for free-play buttons and four guided cases. It has no server, dependencies, network calls, or persistence. The browser model is a separate small JavaScript implementation, not Rust compiled to WebAssembly.

The Rust library has no dependencies and is `no_std`. The trace-printing executable uses std. Check the library with:

```sh
cargo check --manifest-path crates/minip2p/prototypes/stream-dx/Cargo.toml --lib --target thumbv7em-none-eabi
```

## What to look at

`src/main.rs` contains the complete `owned_transfer` and `partial_transfer` callers. Both use 8-byte send and receive capacities, a four-byte drive budget, the same 24-byte input, and a reader paused for five turns. The output prints the relevant state after each turn. `src/lib.rs` is the model.

The owned sketch accepts or rejects a whole six-byte chunk and returns received data in an owned Vec. It illustrates the current interface shape. Its buffering and flow control are the model's, not a measurement or reproduction of current QUIC/TCP behavior. Real callers must also choose chunk sizes and retry rejected sends.

The proposed caller retains the unaccepted suffix through an offset, waits for `Writable` after rejection, and reuses a five-byte receive buffer. It reads until `WouldBlock` or EOF after each `Readable`. The output collector allocates solely to display and compare the received message; a real application could process each borrowed slice immediately.

## Observations from running it

- Both loops deliver the same 24 bytes in order after the reader resumes.
- Pausing the reader fills its eight-byte receive buffer. Further drive calls move zero bytes. Popping the notification alone frees no capacity; reading does.
- The partial writer needs an offset and a flag indicating whether it should retry. There is no need for a rejected-length wake registration.
- Early read yield is the important DX problem. After an eight-byte arrival, pop the notification and read two bytes. Three more drive calls produce no new notification, while six bytes remain unread. The application must retain its own continuation. Reading the remainder and then observing `WouldBlock` re-arms the next notification.
- FIN follows accepted bytes. The reader can consume the buffered prefix and then get EOF, even if it already popped the remote-close notification. Writes after FIN fail.
- A deliberately replaced model connection rejects its saved old handle. Replacement explicitly aborts buffered bytes; this does not exercise graceful shutdown or retained data after connection failure.

## Verdict

Partial writes are workable, but this prototype does not establish better default DX. It replaces ownership of receive chunks with a reusable buffer and an obligation to manage read readiness correctly. A consumer that yields after a partial read can stall just as easily as today's caller can mishandle separate event queues.

I would keep pull I/O as a candidate for the low-level interface and keep the default Endpoint decision open. Before removing `StreamData`, compare an application helper that retains read/write continuations against the owned-event caller. That helper must demonstrate what happens when a handler deliberately yields; hiding the offset alone is not enough.

No production decision is folded into main from this experiment. Issue #149 remains a proposal for maintainer review.

## Limits

One ready stream per endpoint, fixed in-memory capacities, and a manually driven link. No actual transport, crypto, negotiation, packet loss, fairness across peers, cancellation, FFI, or full shutdown lifecycle. The eight-byte capacity is a demonstration value, not an achievable Yamux receive-window setting. Byte counts exclude allocator and protocol overhead. Neither timing nor allocation counts are benchmarked.

The Rust callers were run, and the HTML model walkthroughs were executed offline with Node. No test suite was added. The in-app browser blocked the local file URL, so the HTML layout was not visually verified there.
