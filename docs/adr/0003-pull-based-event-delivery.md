# Pull-based event delivery for the JS bindings

The FFI driver dispatched events by pushing each one through the listener seam (`P2pEventListener::on_event`), which put a second, uncontrolled queue between the driver thread and the JS thread: napi-rs's ThreadsafeFunction on Node (blocking the driver when full, or unbounded), and ubrn's opaque runtime queue on React Native (no bound or drop accounting we control). We invert the seam to **pull**: the driver's carry buffer becomes the single event queue, the listener shrinks to a coalesced, edge-triggered doorbell (`on_events_ready`, rung only when the carry goes empty→non-empty), and each binding drains with a synchronous `drain_events(limit)` command until empty, yielding to its event loop between batches. Both bindings — Node and React Native — use pull; the FFI core carries one delivery mode, not two.

## Considered Options

- **Pull: doorbell + drain** (chosen): one queue with one policy — the existing carry cap (4096, payload-first drops, `EventsDropped` diagnostic) governs all buffering; the driver never blocks on delivery, so the network stays serviced under a slow consumer; batched drains replace per-event bridge crossings; on mobile, an OS-suspended JS thread accumulates events under the carry's drop policy instead of an opaque runtime queue.
- **Push, bounded + blocking queue**: preserves the existing seam unchanged, but a sustained-slow JS consumer blocks the driver thread, stalling packet processing and keepalives — the node degrades its own connections to apply backpressure.
- **Push, unbounded queue**: driver never stalls, but memory is unbounded under a slow consumer and the carry's overflow policy becomes dead code.
- **Node-only pull, RN stays push**: smallest blast radius, but leaves two delivery modes in the FFI core forever and RN on an unbounded opaque queue; rejected in favor of one mode everywhere (pre-1.0 breakage is acceptable).

## Consequences

- The backend contract's `start(listener)` stays push at the TypeScript layer; the drain loop is invisible glue inside each binding shell. Application-facing DX is unchanged.
- The RN UniFFI surface changes (listener → doorbell, new drain method), so ADR 0002's regenerate-and-empty-diff check is amended: the bindings are intentionally regenerated, and the extraction's safety net is the React Native test suite instead of an empty diff.
- Lost wakeups are prevented by protocol, not timing: the doorbell rings only on the empty→non-empty transition, and a binding that hears it must drain until empty.
- Node process liveness rides the doorbell: a strong ThreadsafeFunction refs the event loop, so a started endpoint keeps the process alive until `close()`, like a listening server.
