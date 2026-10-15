# QUIC admission through memory reservations

Supplements ADR 0012. ADR 0012 bounds received data per transport by connection limit × stream limit × stream window, but QUIC's numbers made that bound meaningless: `max_connections` (1024) counted per socket, so dual-stack allowed 2048, and each connection could commit an 8 MiB pending-send queue, a 10 MB engine send buffer, a 10 MB connection receive window and up to 128 peer streams of 1 MB each, about 284 MB per connection (#243). We decided:

- **One QUIC memory budget per transport.** `QuicLimits::memory_budget_bytes` (512 MiB by default) covers every socket of a `QuicTransport`, and `max_connections` now counts across sockets too. The budget caps the transport's worst-case queued memory.
- **Connections and streams hold memory reservations against it.** A connection reserves its fixed part at admission: twice its pending-send queue (a queued write may keep a slice of the caller's payload, and ADR 0012 bounds the allocation it pins only to twice the bytes it counts), the engine's send buffer and its connection receive window (`QuicLimits::connection_reservation_bytes`). It releases that part when it drains, because that memory is gone. A stream reserves its receive window when it opens or is admitted (`stream_reservation_bytes`) and keeps it until it settles, which for delivered bytes means acknowledged or abandoned, also after its connection ended. An unsettled connection therefore keeps its streams' reservations and its connection slot, but not its fixed part.
- **What does not fit is refused, never queued.** A local dial or `open_stream` fails with `ResourceExhausted { resource: "QUIC memory budget" }`. An inbound connection from an address validated by Retry gets `CONNECTION_REFUSED`; one from an unvalidated address gets silence, as at the connection limit, so a spoofed source cannot use the refusal as a reflector. Retry runs before the budget check, so a client the budget refuses still learns why instead of timing out. An inbound stream that does not fit is refused like one over the stream limit.
- **Full and Writable stay per connection**, as ADR 0012 has them. There is no shared write pool and no per-connection receive gate: ADR 0012 rejected those, and they starve or deadlock streams. The budget only decides admission.
- **The windows are limits, sized to the budget.** The send, stream and connection windows became `QuicLimits` fields, and a budget too small for one connection plus one stream is `InvalidLimit`. The defaults shrink the fixed part (send window 10 MB → 2 MiB, connection window 10 MB → 3 MiB, pending queue 8 MiB → 1 MiB, chosen with the throughput bench). The queue stays well above the control reserve plus one stream's cap, so one stalled stream cannot fill the application share; the connection window stays above a few stream windows, so a few gated streams cannot spend the credit control streams need so the default budget admits at least 64 connections with a stream each. Tuning the windows at a real RTT is #361.
- **Hosts size the budget from their own limits.** The relay binary derives its budget from its relay configuration: (max reservations + max circuits + 8) × (fixed part + 4 streams), where circuit sources need no reservation and the 8 cover dial races and reconnects whose old connection has not drained.

## The `unsafe` exception for Apple's fast datapath

The workspace forbids `unsafe`. One call is exempt: quinn-udp's `unsafe fn set_apple_fast_path`, made once per socket on every Apple target, iOS included, which switches quinn-udp to the private `sendmsg_x`/`recvmsg_x` (#359). It beat the regular path by 31% on the macOS bench. quinn-udp resolves both symbols through `dlsym` and falls back to `sendmsg`/`recvmsg` when either is missing, which is the guard the call relies on. `minip2p-quic` lowers `unsafe_code` from `forbid` to `deny` and scopes the call with one `#[expect(unsafe_code)]`; its `SAFETY` comment carries the justification, and `AGENTS.md` is unchanged. Apps distributed through the App Store accept the private-API review risk.

## Rejected alternatives

- **A shared write pool or a per-connection receive gate** to share the budget dynamically. ADR 0012 rejected both: a shared pool lets one connection starve the rest, and a receive gate stalls control frames other streams need.
- **Queueing admissions until memory frees up.** A dial or stream that waits for room hides the overload from the caller and holds state for work that may never run; refusing keeps every layer's view honest.
- **Reserving lazily as bytes arrive.** Admission would succeed and later fail mid-stream, which is the teardown ADR 0012 removed.
- **Sending a refusal before Retry.** It answers unvalidated, possibly spoofed sources.

## Consequences

- A transport's queued QUIC memory is at most `memory_budget_bytes`, whatever the churn pattern; dual-stack no longer doubles any limit.
- With the default windows, a single connection buffers less in flight (2 MiB send and 3 MiB connection windows instead of 10 MB). On loopback this costs nothing measurable; at a real RTT the windows are #361's to tune within the budget.
- A reader that never acknowledges now exhausts the budget, not just the connection slots: new streams and connections are refused until it acknowledges or abandons.
- TCP and circuits have no memory budget yet (#357).
