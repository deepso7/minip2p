# Yamux inbound SYN priority over queued local opens

When a Yamux session reaches `YamuxConfig::max_streams`, local `open_stream` calls queue FIFO in `waiting_opens` and are admitted lazily when the write path frames their `SYN`. Inbound `SYN` frames share the same stream slot pool and are not held back while local opens are waiting, so an inbound `SYN` that arrives after a slot frees (before the local write path runs) can take that slot ahead of a queued local open.

## Why this is out of scope

- **Not a regression.** Before #613, hitting `max_streams` failed local `open_stream` calls immediately with `TooManyStreams`. Queuing local opens FIFO with caller-side timeouts is already a strict improvement over immediate failure.
- **Reserving slots alters inbound admission policy.** Rejecting or resetting valid inbound `SYN`s while local opens wait in `waiting_opens` turns an otherwise open slot into a remote stream reset (`RST`) even when the local open has not yet been transmitted, coupling inbound admission to lazy write-side framing.
- **Splitting the cap reduces flexibility.** Partitioning `max_streams` into fixed inbound and outbound pools halves the usable concurrency for asymmetric workloads (for example, a peer that primarily opens or primarily accepts streams) and introduces a second configuration surface for an edge case.
- **Caller timeouts already bound starvation.** A peer that continuously saturates every slot can hold queued local opens only until the caller's open timeout fires, which is already the expected behavior against a saturated peer.

## When to revisit

Revisit if real workloads observe local stream opens timing out under normal (non-adversarial) bidirectional load because inbound `SYN` bursts repeatedly starve queued local opens. At that point, weigh reserving freed slots for `waiting_opens` (while preserving the pre-`StreamOpened` `Full`/`Writable` contract) against separate inbound/outbound stream limits.

## Prior requests

- #616: "Yamux: inbound SYNs can take freed slots ahead of queued local opens"
