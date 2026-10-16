# minip2p-transport

Sans-IO transport trait and connection/stream types for minip2p. `no_std` + `alloc` compatible.

This crate defines the transport abstraction that concrete adapters implement — QUIC and TCP today, anything ordered and multiplexed in principle. It contains no runtime or networking code.

## Features

- `Transport` trait with a `poll(now)`-based event model; the host supplies the time.
- `ConnectionId` and `StreamId` identifiers, with `ConnectionNamespace` keeping each transport's id space disjoint.
- Connection lifecycle events (`Connected`, `Closed`, `IncomingConnection`, `PeerIdentityVerified`, `Listening`).
- `ConnectionToken`: a 32-byte value both ends of one connection compute identically, set on the `ConnectionEndpoint` of `Connected`/`PeerIdentityVerified` by transports that can derive one (QUIC from a TLS exporter value, TCP from the Noise handshake hash). The swarm uses it to settle two same-direction connections to one peer the same way on both sides; transports without one leave it `None`.
- Stream lifecycle events (`StreamOpened`, `IncomingStream`, `StreamData`, `StreamWritable`, `StreamRemoteWriteClosed`, `StreamWriteStopped`, `StreamClosed`). `StreamWriteStopped` is QUIC's STOP_SENDING; byte-stream transports never emit it.
- Stream payloads are `Bytes` (`minip2p_core::Bytes`, re-exported here), so fan-out and forwarding clone a handle instead of the bytes.
- Read backpressure (ADR 0012): each stream delivers at most its receive budget (its per-stream receive window) of `StreamData` bytes that were not acknowledged with `ack_stream`. Whoever consumes the bytes acknowledges them, which is what returns credit to the sender, so a reader that never acknowledges stalls its sender. A closed stream with unacknowledged bytes keeps its slot until they are acknowledged or a local `reset_stream` abandons them, and inbound streams past the limit are refused. Over-acknowledging is `TransportError::AckExceedsDelivered`, naming the stream and both counts; acknowledging a settled or unknown stream is a no-op.
- The bound outlives the connection (ADR 0012): a connection that ends with unsettled streams becomes an unsettled connection, keeping only its per-stream counts and its connection slot until every stream settles. `ack_stream` releases its bytes and `reset_stream` abandons them after `Closed`, with no events; with every slot held, `dial` fails with `ResourceExhausted` and inbound connections are refused. `UnsettledConnections` is the shared ledger transports keep those counts in.
- Each transport also has a memory budget (ADR 0019, ADR 0021): every connection and stream holds a memory reservation against it, and what does not fit is refused. `MemoryLedger` is the shared arithmetic each transport builds its budget on, and `InvalidLimit` the error for a limit that cannot work.
- Write backpressure (ADR 0012): `send_stream` accepts as much as the stream can queue and returns `TransportError::Full` carrying the exact unsent tail when not every byte fit. Full is retryable, never a fault: the caller holds the tail, and a one-shot `StreamWritable` fires once the stream can queue at least half of its smaller send cap again. It never fires after the write side ended (`StreamWriteStopped`, a reset, `close_stream_write`, `StreamClosed`, `Closed`). Every transport caps each stream's share of its connection's send queue, so a stream stalled on peer credit cannot starve the others, and keeps a reserve inside the connection cap for control streams, which the caller marks with `set_control_stream` (a no-op by default, for transports without a reserve). `close_stream_write` sends its FIN after every accepted byte. Any other `send_stream` error may follow a partial queue (a transport may queue a prefix and then fail), so it is not safe to resend the payload.
- Host intents via trait methods: `dial`, `listen`, `open_stream`, `send_stream`, `close_stream_write`, `reset_stream`, `close`.
- Typed error model with transport, connection, and stream context. Platform failures are `TransportError::Io { operation, kind, detail }` and `ListenFailed { addr, kind, detail }`, classified by the portable `minip2p_core::platform::IoErrorKind`, so `no_std` and hosted adapters report the same kinds; `NotListening`, `LocalPeerAddr`, and `Entropy` name the remaining setup failures. `PollError` is kept for faults inside a transport's own session or negotiation, not the platform under it.

## Running several transports at once

`TransportSet` is a `Transport` that owns several and routes between them, so a host speaks QUIC and TCP at once without the swarm above it knowing there is more than one of anything. It owns no I/O: every decision it makes is a lookup, and both lookups use information the types already carry.

- **Which member dials this address?** `Multiaddr::transport_kind()` says whether an address is `/udp/quic-v1` or `/tcp`, and each member claims one shape.
- **Which member owns this connection?** `ConnectionId` carries the namespace its allocator stamped, and each member claims the namespaces it allocates in.

Both claims are checked when a member joins, so neither question can have two answers by the time it is asked. A member claims an address _shape_ rather than an address family — one TCP transport serves `/ip4` and `/ip6` alike, matching how the adapters are actually built — and a member that splits by family internally, as the dual-stack QUIC transport does, claims both of its namespaces and keeps that split to itself. The namespaces a member names have to be every namespace it allocates in: a dial that produced an id from one it did not claim would hand back a connection nothing could route, so the set refuses and closes it instead. A refused join returns the transport with the reason, in a `RejectedTransport`, rather than dropping a bound socket where the caller can no longer reach it.

A member that fails a `poll` does not cost its siblings the events they produced in the same round — those are delivered by the next `poll`, before any member is driven again, so a transport that stays broken cannot bury a healthy one's events or grow a queue behind itself.

Under `std` a member must also be a `BlockingTransport` — a `Transport` that is also a `PollSource` — and be `Send`, so the set can register every member with the host's one shared readiness poll and a host can move an endpoint onto the thread that drives it. Attaching the set gives each member its own `TokenSpace` under an 8-bit prefix of the set's space, so an event's token says which member it is for and routing needs no table; a member inserted after the set is attached is attached as it joins, and `insert` reports `TransportSetError::AttachFailed { kind, detail }` (handing the transport back) if that fails. There is no wait of the set's own: the host blocks once on the shared poll for every member, so input on any of them wakes it at once, on every platform mio supports.

## Connection id namespaces

A host can run QUIC and TCP at once, each split per address family, with relay circuits layered on top — and every one of them hands connection ids to the same swarm. `ConnectionId` packs an 8-bit `ConnectionNamespace` alongside a 56-bit sequence number so those id spaces are disjoint by construction: a router can tell which transport an id belongs to just by looking at it, and no transport has to remap another's ids.

Allocate ids with `ConnectionIdAllocator` rather than building them by hand. Sequence numbers are never reused, so allocation fails once a namespace is exhausted instead of wrapping onto live ids. That guarantee belongs to the namespace rather than to the allocator, so a namespace gets exactly one: the allocator is deliberately not `Clone`, since a copy would carry the same next sequence and mint every id a second time.

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
use minip2p_core::{Bytes, Multiaddr, PeerAddr};
use minip2p_core::platform::{Deadline, Now};
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
        data: Bytes,
    ) -> Result<(), TransportError> {
        todo!("queue what fits; return TransportError::Full with the unsent tail")
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

`local_addresses_revision` lets the swarm cache the address list Identify advertises. Return a counter that advances whenever `local_addresses` may report something different -- a new listener, or an interface address a wildcard listener answers on -- and never goes backwards (`TransportSet` adds its members' counters). The default, `None`, makes the swarm re-read `local_addresses` on every poll, which is always correct.

`send_datagram` is the one method most adapters should leave alone. It sends a single packet outside any connection, which is what DCUtR's simultaneous open needs before a connection exists to carry one, and the default answer is `TransportError::Unsupported` — the honest one for a stream transport, which has nowhere to put a lone packet. Callers read that as "not available here" rather than as a failed send.

## Time

The host samples time once per drive iteration and passes that `Now` to `poll()`, so every transport, agent, and runtime in one iteration observes the same instant. An adapter that schedules work retains the last sample it was given and reports the resulting absolute `Deadline` from `next_deadline()`, which the host uses to decide how long it may idle.

A portable adapter should read no clock of its own. An adapter that needs finer time than the host's millisecond samples may still keep a clock — `minip2p-quic` samples `Instant::now()` once per poll and runs its QUIC engine's timers on that — but everything it reports back to the host, deadlines above all, must be expressed on the timeline of the samples it was given. An adapter with its own clock is inherently `std`-only.

## Waiting on readiness (`std` only)

Blocking a thread needs an OS to block on, so it is not part of the portable contract. Under `std` a host -- the swarm's `Swarm<T>` -- owns one `SharedPoll`: one edge-triggered `mio::Poll` and its one `Waker`. Every source of input registers with it (ADR 0013), so a wait blocks once, for everything, until the earliest `next_deadline()` or the caller's timeout. A `no_std` host skips all of this and idles however its platform allows, using `next_deadline()` to decide for how long.

A std adapter implements `PollSource`, which makes it a `BlockingTransport` automatically:

```rust
use std::sync::Arc;
use minip2p_transport::mio::{Registry, Waker, event::Event};
use minip2p_transport::{PollSource, TokenSpace};

impl PollSource for MyTransport {
    fn attach(&mut self, registry: Registry, tokens: TokenSpace, waker: Arc<Waker>) -> std::io::Result<()> {
        todo!("register sockets with tokens from `tokens`; keep `registry` for sockets opened later")
    }

    fn dispatch(&mut self, event: &Event) {
        todo!("record readiness for one of this source's tokens; the next poll consumes it")
    }
}
```

- **`attach`** is called once. The source keeps the registry clone to register sockets it opens later and takes tokens only from its `TokenSpace` (`token(index)`, `index_of(token)`). It may reuse a token after deregistering its socket; a stale event for the old socket is then a spurious wake on the new one, which is harmless because sources read until `WouldBlock`. Splitting a space (`subspace`) is checked and fails with a typed `TokenSpaceError` rather than overflowing into a sibling. mio allows one `Waker` per poll, so a source never creates its own: one with no socket (an in-memory transport) keeps the host's and calls it when input arrives.
- **`dispatch`** hands over readiness for a token the source registered.
- **Edge-triggered rule:** after `dispatch`, a source reads each ready socket until `WouldBlock`, or remembers what it has not read yet and reports `next_deadline()` as due now until a poll has consumed it. The edge will not come again, so readiness must never be lost when a source is dispatched to but not polled before the next wait.
- **Before attach** (a `SwarmCore` host driving a std transport directly), a source treats every socket as possibly ready on each poll, so it still makes progress.
- **Wrappers** (`CircuitTransport`) forward both methods to the transport they wrap.

`SharedPoll::harvest` collects one bounded batch, dispatching the transport's share, and records the rest: readiness in a space handed to a host-owned source (`attach_host_source`, used for mDNS sockets) and `Waker` events become a pending host wake, read with `take_wake`. `SharedPoll::wait_handle()` returns a cloneable `WaitHandle` that sets an interrupt flag, then wakes; interrupts sent before one is taken coalesce, and `take_interrupt` is the only thing that clears the flag. `wake_handle()` returns a `WakeHandle` that only wakes. `EINTR` is retried against the original deadline; any other poll error is returned.

## Bench counters (`bench` feature)

The `bench` feature (off by default, implies `std`) counts the blocking waits a `SharedPoll` makes -- every harvest with a non-zero timeout -- by whether readiness ended it (`ready`) or it ran out its timeout (`timed_out`). That is the std swarm's wait, so these are an idle endpoint's wakeups. `minip2p_transport::bench::wait_counters()` returns the calling thread's counts; subtract two snapshots with `WaitCounters::since`. It exists for idle benchmarks such as `minip2p-rs`'s `endpoint_idle`; without the feature none of it is compiled.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-transport = { path = "crates/transport", default-features = false }
```

## Scope

This crate defines the transport contract only. Concrete adapters live in separate crates: `minip2p-tcp` (`no_std + alloc`, over a pluggable byte-stream provider) and `minip2p-quic` (`std`-only, quinn-proto-based).
