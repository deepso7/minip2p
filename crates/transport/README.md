# minip2p-transport

Sans-IO transport trait and connection/stream types for minip2p. `no_std` + `alloc` compatible.

This crate defines the transport abstraction that concrete adapters implement — TCP and QUIC today, anything ordered and multiplexed in principle. It contains no runtime or networking code.

## Features

- `Transport` trait with a `poll(now)`-based event model; the host supplies the time.
- `ConnectionId` and `StreamId` identifiers, with `ConnectionNamespace` keeping each transport's id space disjoint.
- Connection lifecycle events (`Connected`, `Closed`, `IncomingConnection`, `PeerIdentityVerified`, `Listening`).
- Stream lifecycle events (`StreamOpened`, `IncomingStream`, `StreamData`, `StreamRemoteWriteClosed`, `StreamClosed`).
- Host intents via trait methods: `dial`, `listen`, `open_stream`, `send_stream`, `close_stream_write`, `reset_stream`, `close`.
- Typed error model with transport, connection, and stream context.

## Running several transports at once

`TransportSet` is a `Transport` that owns several and routes between them, so a host speaks TCP and QUIC at once without the swarm above it knowing there is more than one of anything. It owns no I/O: every decision it makes is a lookup, and both lookups use information the types already carry.

- **Which member dials this address?** `Multiaddr::transport_kind()` says whether an address is `/tcp` or `/udp/quic-v1`, and each member claims one shape.
- **Which member owns this connection?** `ConnectionId` carries the namespace its allocator stamped, and each member claims the namespaces it allocates in.

Both claims are checked when a member joins, so neither question can have two answers by the time it is asked. A member claims an address *shape* rather than an address family — one TCP transport serves `/ip4` and `/ip6` alike, matching how the adapters are actually built — and a member that splits by family internally, as the dual-stack QUIC transport does, claims both of its namespaces and keeps that split to itself. The namespaces a member names have to be every namespace it allocates in: a dial that produced an id from one it did not claim would hand back a connection nothing could route, so the set refuses and closes it instead. A refused join returns the transport with the reason, in a `RejectedTransport`, rather than dropping a bound socket where the caller can no longer reach it.

A member that fails a `poll` does not cost its siblings the events they produced in the same round — those are delivered by the next `poll`, before any member is driven again, so a transport that stays broken cannot bury a healthy one's events or grow a queue behind itself.

Under `std` a member must also implement `BlockingTransport`, so the set can park a driver instead of spinning; since every method of that trait has a default, `impl BlockingTransport for MyTransport {}` is the whole of it. The set alternates short readiness waits across the members that can park — a member that reports `Unsupported` is probed once and then left out of the budget — and its `WaitHandle` wakes all of them, reading the member list when it fires rather than when it was taken, so a handle survives a member joining later. One `interrupt` is worth one `Interrupted`: the members that lost the race are drained before the set answers, so a single wake cannot come back several times over.

## Connection id namespaces

A host can run TCP and QUIC at once, each split per address family, with relay circuits layered on top — and every one of them hands connection ids to the same swarm. `ConnectionId` packs an 8-bit `ConnectionNamespace` alongside a 56-bit sequence number so those id spaces are disjoint by construction: a router can tell which transport an id belongs to just by looking at it, and no transport has to remap another's ids.

Allocate ids with `ConnectionIdAllocator` rather than building them by hand. Sequence numbers are never reused, so allocation fails once a namespace is exhausted instead of wrapping onto live ids.

```rust
use minip2p_transport::{ConnectionIdAllocator, ConnectionNamespace};

let mut ids = ConnectionIdAllocator::new(ConnectionNamespace::TCP_IPV4);
let id = ids.allocate().expect("fresh namespace");

assert_eq!(id.namespace(), ConnectionNamespace::TCP_IPV4);
assert_eq!(id.to_string(), "tcp/ip4#1");
```

The registered namespaces (`QUIC_IPV4`, `QUIC_IPV6`, `TCP_IPV4`, `TCP_IPV6`, `CIRCUIT`, and `UNSPECIFIED` for transports that don't participate in routing) live on `ConnectionNamespace`; adding a constant there is what guarantees disjointness. `CIRCUIT` is `0x80`, so every circuit id has the top bit of its `u64` set and stays trivially distinguishable from the base transport ids it is layered over.

## Usage

Implement the `Transport` trait for your adapter:

```rust
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_platform::{Deadline, Now};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

struct MyTransport;

impl Transport for MyTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        todo!("initiate outgoing connection and return its allocated id")
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        todo!("start listening")
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        todo!("open a new outbound stream")
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        todo!("write stream data")
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        todo!("half-close stream write side")
    }

    fn reset_stream(&mut self, id: ConnectionId, stream_id: StreamId) -> Result<(), TransportError> {
        todo!("reset stream")
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        todo!("close connection")
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        todo!("drive transport and emit events using the caller's time sample")
    }

    fn next_deadline(&self) -> Option<Deadline> {
        todo!("return the next protocol deadline, if any")
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        todo!("return bind/listen addresses, if the adapter has any")
    }
}
```

## Time

The host samples time once per drive iteration and passes that `Now` to `poll()`, so every transport, agent, and runtime in one iteration observes the same instant. An adapter that schedules work retains the last sample it was given and reports the resulting absolute `Deadline` from `next_deadline()`, which the host uses to decide how long it may idle.

A portable adapter should read no clock of its own. An adapter wrapping a library that keeps its own internal clock may still do so — `minip2p-quic` wraps quiche, which reads `Instant::now()` internally — but everything it reports back to the host, deadlines above all, must be expressed on the timeline of the samples it was given. An adapter with its own clock is inherently `std`-only.

## Blocking waits (`std` only)

Blocking a thread needs an OS to block on, so it is not part of the portable contract. Adapters that own a socket implement the `std`-gated `BlockingTransport` extension with a real readiness wait (e.g. a blocking peek with a read timeout) so idle drivers sleep for the whole timer budget instead of spinning on a fixed cadence:

```rust
use std::time::Duration;
use minip2p_transport::{BlockingTransport, WaitOutcome};

impl BlockingTransport for MyTransport {
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        todo!("wait for socket readiness without consuming input")
    }
}
```

The default implementation returns `WaitOutcome::Unsupported`, so `impl BlockingTransport for MyTransport {}` is enough to opt a transport into blocking drivers with a sleep fallback. A `no_std` host skips this entirely and idles however its platform allows, using `next_deadline()` to decide for how long.

`BlockingTransport::wait_handle()` returns a cloneable, transport-neutral `WaitHandle` that interrupts a wait from another thread — a background task nudging a blocked drive loop after queueing work. Interrupting when no wait is active makes the *next* wait return immediately, so a handle cannot lose a wakeup to a race. `WaitHandle::combined` folds several into one for hosts driving more than one transport, and the default `WaitHandle::noop()` is inert for adapters with nothing to wake (that costs latency, never correctness).

The two defaults are only correct together, for a leaf transport. A transport that wraps another and forwards `wait_for_input` **must** also forward `wait_handle`, or callers get an inert handle while the wait still blocks inside the inner transport.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-transport = { path = "crates/transport", default-features = false }
```

## Scope

This crate defines the transport contract only. Concrete adapters live in separate crates: `minip2p-tcp` (`no_std + alloc`, over a pluggable byte-stream provider) and `minip2p-quic` (`std`-only, quiche-based).
