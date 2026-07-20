# minip2p-yamux

`minip2p-yamux` is a small, caller-driven, Sans-I/O implementation of the
libp2p Yamux stream multiplexer (`/yamux/1.0.0`). It runs with `no_std + alloc`
and leaves sockets, clocks, and task scheduling to its caller.

The session bounds inbound frame lengths, stream count, per-stream queued
sends, and aggregate queued sends. Receive windows are replenished as data is
surfaced because the push-based API has no downstream read-backpressure.

Clients allocate odd stream IDs and servers allocate even stream IDs. The
default receive window is 256 KiB, matching the Yamux specification.
