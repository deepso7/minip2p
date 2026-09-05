# minip2p-yamux

`minip2p-yamux` is a small, caller-driven, Sans-I/O implementation of the
libp2p Yamux stream multiplexer (`/yamux/1.0.0`). It runs with `no_std + alloc`
and leaves sockets, clocks, and task scheduling to its caller. A quiet session
emits a keepalive ping every 30 seconds when the host drives
`YamuxSession::poll` with a time sample; the session never reads a clock.

The session bounds inbound frame lengths, stream count, per-stream queued
sends, and aggregate queued sends. Receive windows are replenished as data is
surfaced because the push-based API has no downstream read-backpressure.

Clients allocate odd stream IDs and servers allocate even stream IDs. The
default receive window is 256 KiB, matching the Yamux specification.

## Throwaway stream experiment

On `prototype/stream-dx`, the `prototype_*` methods support the real TCP experiment for issue #149. Pull receive credit advances only when the caller reads. The option defaults off. This is an open-stream experiment; cancellation, reset, FIN cleanup, and the full Endpoint readiness contract remain unfinished. See [the experiment report](../minip2p/prototypes/stream-dx/TCP_RESULTS.md).

The later [Endpoint experiment](../minip2p/prototypes/stream-dx/E2E_RESULTS.md) enables consumption credit per negotiated application stream and compares pull reads with owned chunks and explicit release. Half-close EOF and reset cases are exercised there; the full lifecycle is still unfinished.

The latest [consumer benchmark](../minip2p/prototypes/stream-dx/CONSUMER_RESULTS.md) compares actual main and adds read-only payload instrumentation on this branch. It demonstrates a slow-consumer benefit without establishing a need to replace the public interface.
