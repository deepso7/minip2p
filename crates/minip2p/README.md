# minip2p-rs

Application-facing `Endpoint` API for minip2p.

```bash
cargo add minip2p-rs
```

The package is named `minip2p-rs` on crates.io and its library target remains `minip2p`, so application imports stay concise:

This crate provides the existing batteries-included std `Endpoint` and a caller-driven portable endpoint behind the same entry point.

```rust
let mut endpoint = minip2p::Endpoint::builder()
    .agent_version("my-app/0.1.0")
    .protocol("/myapp/1.0.0")
    .listen_default()?
    .bind()?;

for address in endpoint.listen_all()? {
    println!("{address}");
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Listening is address-shaped: pass complete multiaddresses to `EndpointBuilder::listen_on` (or `listen_on_multiaddr`), or use `listen_default` for dual-stack QUIC wildcards. The transport is inferred from each address. `bind` starts accepting on every listen address, QUIC and TCP alike; `listen_all` reports them.

The listen setters reject a malformed or unsupported address at once with an `EndpointOptionsError`, and `bind` returns a `BindError` naming what failed: `Options` for inconsistent options (no transport, a second QUIC address for one family, ...), `Quic` or `Listen` for a socket the platform refused (a port in use, say, with its `IoErrorKind`), and `Swarm`, `RelayServer`, `Gossipsub`, or `Mdns`/`MdnsSocket` for that part's own configuration or setup. `?` converts an `EndpointOptionsError` into a `BindError`, so a builder chain needs only the one error type. Bind errors happen before any event is polled; nothing later reuses them.

## Connecting and the event loop

`Endpoint::connect` is the one Connection-attempt entry point. It takes a `PeerId`, one complete peer address, or a list of complete addresses naming the same peer, and returns a `ConnectId` immediately. Candidate racing, Name resolution, relay fallback, and direct-path upgrade all belong to that attempt, which ends with exactly one `EndpointEvent::ConnectSettled` (connected, failed, or cancelled). A failure is `ConnectFailure::NoUsableRoute` only when no route ever started; once a dial or a relay started, it is `AllRoutesFailed` (or `Timeout`), carrying one `RelayFailure` per relay tried, each naming the relay's address. With a relay leg, a Relayed path settles Connected once the direct upgrade stops: the remote never started DCUtR within `NatConfig::dcutr_start_timeout_ms` (10 s), an exchange or the whole upgrade ran out its budget, or every hole-punch round failed (ADR 0017). `cancel_connect` is the explicit cancellation; giving up a local wait never cancels anything.

`Endpoint::wait` is the one blocking wait over the one Endpoint event stream. The canonical loop dispatches unrelated events while it waits for a correlated one:

```rust,no_run
use std::time::{Duration, Instant};
use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};

let mut endpoint = Endpoint::builder().listen_default()?.bind()?;
let target: PeerAddr =
    "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()?;
let connect_id = endpoint.connect(target)?;
let deadline = Instant::now() + Duration::from_secs(10);
loop {
    // `wait` still serves events once the deadline has passed: enforce it here.
    if Instant::now() >= deadline {
        endpoint.cancel_connect(connect_id); // explicit: the deadline is only local
        break;
    }
    match endpoint.wait(deadline)? {
        EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled { connect_id: id, outcome, .. })
            if id == connect_id =>
        {
            match outcome {
                ConnectOutcome::Connected { conn_id } => println!("connected: {conn_id:?}"),
                other => println!("not connected: {other:?}"),
            }
            break;
        }
        EndpointWaitOutcome::Event(other) => println!("{other:?}"), // dispatch as usual
        EndpointWaitOutcome::Deadline => {} // the clock check above gives up
        _ => {} // a WaitHandle woke us; service commands
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Every dial goes through `connect` and its attempt policy, on the std and the portable endpoint alike.

`set_external_addresses` replaces the externally validated addresses advertised through Identify alongside the bound ones; NAT and relay-server contributions are kept and merged after them.

## Portable endpoint

There are two endpoint types over one engine: the std `Endpoint` above, and `PortableEndpoint<T, E>`, which runs over any `Transport` with no clock, sockets, or executor. Both drive the same batches and emit the same event stream in the same order (see the event loop section below). Disable default features for `no_std + alloc`, then provide identity, entropy, and a transport explicitly:

```rust,ignore
let mut endpoint = minip2p::Endpoint::portable(&identity, entropy)
    .agent_version("my-device/0.1.0")
    .protocol("/myapp/1.0.0")
    .build(transport)?;

let events = endpoint.poll(now)?;
let deadline = endpoint.next_deadline(now);
```

The portable endpoint supports listening, Connection attempts, ping, Identify inspection, custom streams (`add_protocol` registers one after build), state statistics, and consuming `shutdown(now)` (mDNS goodbyes are best effort there: one that could not be sent is an `EndpointEvent::MdnsFailed` among the returned events). Build failures are a `PortableBuildError` naming the part that failed (`ListenAddress`, `NatConfig`, `Gossipsub`, `MdnsConfig`, ...). Every operation that advances protocol work uses a caller-provided `Now`, so the host controls time consistently. There is no access to the raw swarm: every dial goes through `connect`.

### Capabilities

`PortableEndpointBuilder` configures each capability behind its own Cargo feature, over any transport; none of them needs smoltcp:

| Feature | Builder setters |
| --- | --- |
| `pubsub` | `.gossipsub()`, `.gossipsub_config(..)`; with `portable-mdns` also signed `.discovery()` and `.beacon_config(..)` |
| `portable-mdns` | `.mdns(io, config)` over any caller-owned `MdnsIo`, `.peer_discovery_config(..)` |
| `portable-autonat` | `.autonat(server)`, `.nat_config(..)` |
| `portable-relay` | `.relay(addr)`; includes `portable-autonat` |

`.mdns(io, config)` takes the carrier by value and stores it as a `Box<dyn MdnsIo>`, so it must be `'static`; keep a handle to whatever it runs on to reconfigure it later. The mDNS seed comes from the builder's entropy. The endpoint polls the transport again after each mDNS tick, since a carrier may share the transport's stack.

Relay paths turn a relay bridge into a connection, which takes circuit operations from the transport. `build(transport)` works over any transport and rejects relay configuration with `PortableBuildError::NatConfig(PortableNatConfigError::RelayWithoutCircuits)`; wrap the transport in a `CircuitTransport` and call `build_with_circuits(transport)` to run relays. AutoNAT alone needs nothing from the transport. Portable relay configurations must set `force_relay`: portable endpoints do not run DCUtR.

### smoltcp

For an embedded TCP endpoint, enable `smoltcp` with default features disabled. The host owns the smoltcp device and interface; minip2p owns the TCP, Noise XX, Yamux, Identify, Ping, and application-protocol state above them:

```bash
cargo add minip2p-rs --no-default-features --features smoltcp,pubsub
```

`.smoltcp(stack)` turns the builder into a `SmoltcpEndpointBuilder` that installs TCP (and mDNS, when asked) on one shared `SmoltcpStack` and builds an ordinary `PortableEndpoint` over a `SmoltcpTransport`. TCP and mDNS on the stack come with `smoltcp`; `pubsub` adds `.gossipsub()` and signed `.discovery()`:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack.clone())
    .listen("/ip4/0.0.0.0/tcp/4001")
    .mdns()
    .discovery()
    .protocol("/myapp/1.0.0")
    .build()?;
```

Use `tcp_config`, `smoltcp_config`, `mdns_config`, `mdns_carrier_config`, `gossipsub_config`, `beacon_config`, and `peer_discovery_config` only when overriding defaults. Keep a cloned `SmoltcpStack` to reconfigure the interface later: a wildcard listener follows the interface's addresses, and Identify advertises a changed address without another `listen`. `poll(now)` advances every enabled service and `next_deadline(now)` folds their timelines.

Portable AutoNAT is opt-in, and does not pull circuit transport state into an AutoNAT-only binary. Enable `portable-autonat`, configure trusted servers, and read the latest verdict from the same caller-driven endpoint. A verdict needs a quorum of distinct servers (3 of the last 5 by default), and a public one reports only addresses that quorum confirms, so with fewer than three reachable servers reachability stays Unknown:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack)
    .listen("/ip4/0.0.0.0/tcp/4001")
    .autonat(server_a)
    .autonat(server_b)
    .autonat(server_c)
    .build()?;

for event in endpoint.poll(now)? {
    // ReachabilityChanged is emitted once enough distinct servers agree.
    // Handle that and ordinary endpoint events here.
}
let reachability = endpoint.reachability();
```

Once at least one TCP listen address exists, the first due `poll(now)` starts a probe by dialing the configured server. Successful exchanges emit `EndpointEvent::Nat(NatEvent::ReachabilityChanged { .. })` after the configured confidence threshold is met; `reachability()` then returns that same settled verdict. Until a server exchange succeeds, it remains `Unknown`.

With `smoltcp` and `portable-relay`, the smoltcp builder wraps its TCP transport in a `CircuitTransport` itself, so a relay just works:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack)
    .relay(relay_addr)
    .build()?;

let connect = endpoint.connect(&remote_peer, now)?;
while endpoint.path(&remote_peer).is_none() {
    for event in endpoint.poll(now)? {
        // Handle EndpointEvent::Nat and ordinary endpoint events.
    }
}
```

`.relay()` selects a relay-only path and does not reserve inbound capacity. Use `.nat_config(...)` to combine AutoNAT servers with relay policy, and `ReservationPolicy::Always` for a device that must remain reachable through the relay.

## Transports

QUIC comes with the default `std + quic` features. TCP is opt-in via the `tcp` Cargo feature, so a QUIC-only app does not pull in the TCP stack. Enable it with `cargo add minip2p-rs --features tcp`.

An endpoint brings up whatever you asked it to listen on, then routes by address. Prefer complete multiaddresses:

```rust
let mut endpoint = minip2p::Endpoint::builder()
    .listen_on("/ip4/0.0.0.0/udp/4001/quic-v1")?
    .bind()?;
# Ok::<(), minip2p::BindError>(())
```

With the `tcp` feature, chain a `/tcp` listen address the same way. Connect to a `/udp/<port>/quic-v1` candidate and it is dialed over QUIC; a `/tcp` candidate goes over TCP. The address decides — nothing above the endpoint cares that there are two transports. `listen_default` is dual-stack QUIC. An endpoint with nothing to bind is refused rather than built empty.

The IP family is chosen by the address too: an `/ip4` or `/ip6` candidate is dialed as written, and a `/dns*` candidate is resolved and dialed once per family it answers with (`/dns4` / `/dns6` keep to one). The endpoint owns name resolution and never blocks on it: `connect` returns at once, each distinct name is looked up on a background thread, and the answer joins the attempt's race on a later `wait`/`poll` while `/ip4`/`/ip6` candidates and the relay leg are already running. A failed lookup is a failed candidate whose reason names the host; the attempt deadline covers the lookup, and a late answer is dropped. At most 32 distinct names are looked up at once; past that a candidate fails with a reason saying so. Configured relay and AutoNAT server addresses may name a host too and are resolved the same way. The transports themselves accept only `/ip4` and `/ip6` and reject `/dns*`, so direct transport users resolve names themselves. A finished lookup wakes a blocked `wait` through the swarm's wake-only handle, so it is applied at once and never reported as `Interrupted`.

Dropping a std `Endpoint` (or `Endpoint::close`) disconnects established peers. `close` drains for up to 500 ms and `close_within(timeout)` picks the deadline (`Duration::ZERO` tears down at once); the deadline bounds teardown time, not delivery of accepted writes. The returned `CloseReport` says how the drain ended (`CloseOutcome::Drained`, `DeadlineExpired`, or `Failed`) and lists, in `unfinished`, each connection still tracked with its peer when known. That does not cover `kill -9` or a hard partition; those still wait for the QUIC idle timeout. Portable endpoints use explicit `shutdown(now)`.

With the `nat` feature, an endpoint holding a QUIC relay reservation sends a ping every `NatConfig::reservation_keep_alive_interval_ms` to stop an idle relay connection from reaching that timeout. The default is 15 seconds. Keep the interval below `QuicLimits::idle_timeout_ms`; setting it to `0` disables the automatic pings. TCP reservations do not send them. Each successful automatic ping emits the ordinary `EndpointEvent::PingRttMeasured` event.

`minip2p::Error` is the runtime error of `poll`, `wait`, and every operation on a running endpoint. It preserves transport failures (platform I/O as `TransportError::Io` with an `IoErrorKind`), Sans-I/O state rejections, and driver-invariant failures as separate variants, and never carries a configuration or mDNS error: a capability that fails while running reports a capability failure event instead (`EndpointEvent::MdnsFailed`, `RelayServerEvent::AddrsRejected`) and the rest of the endpoint keeps going. Resource limits are configurable through `EndpointBuilder::quic_limits`, `EndpointBuilder::tcp_config` and, with the `nat` feature, `EndpointBuilder::circuit_limits` (the relay circuits' Yamux limits and circuit memory budget); each transport's memory budget caps what its connections and streams can retain (ADR 0019, ADR 0021), and limits that cannot work fail `bind` with `EndpointOptionsError::InvalidLimit`. The portable smoltcp builder takes `tcp_config` and, with `portable-relay`, `circuit_limits` the same way.

Prefer `Endpoint::wait` for the ordered Endpoint event stream: it returns an event, deadline, or interruption without swallowing interrupts. `EndpointEvent` is `#[non_exhaustive]` and carries enabled capability output — `Nat`, `Gossipsub`, `Discovery`, `RelayServer` — so one `wait` loop sees every event exactly once for every feature combination. `poll()` is the non-blocking drain of the same stream. Both endpoint types work in drive batches: one bounded batch of swarm events, one capability pass, then Connection-attempt terminals. `wait` runs one batch and hands its events out one per call; `poll` returns the whole batch. Within a batch the batch's swarm events come first, then capability events in relay-server, NAT, Gossipsub, Discovery, mDNS order, then Connection-attempt terminals (`ConnectSettled`). A `ConnectSettled` follows the `ConnectionEstablished` it reports, but other lifecycle events from the same batch (`PeerReady`, `ConnectionReplaced`, `ConnectionClosed`) may come before it too. No order is promised between concurrently racing Transport candidates. NAT attempt terminals (`ConnectFailed`, `FellBackToRelay`) never appear: the outcome is `ConnectSettled`. A `PathUpgraded` can still follow its attempt's `ConnectSettled` when the attempt settled on a provisional Relayed path. No `HolePunchFailed` names an attempt after its `ConnectSettled`. `InboundPathEstablished`, `PathUpgraded`, and `InboundDirectUpgrade` carry the connection ids they concern. `ConnectionClosed` carries the connection's `ConnectionCloseReason` (`Local`, `Remote { code }`, `TimedOut`, `Stalled`, or `Error(message)`); a failure that ended the connection is that reason, never also an `EndpointEvent::Error`.

```rust,ignore
use std::time::Duration;
use minip2p::{EndpointEvent, EndpointWaitOutcome, GossipsubEvent, NatEvent};

loop {
    match endpoint.wait(Duration::from_millis(250))? {
        EndpointWaitOutcome::Event(EndpointEvent::Gossipsub(GossipsubEvent::Message { data, .. })) => { /* ... */ }
        EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) => { /* ... */ }
        EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled { connect_id, outcome, .. }) => { /* ... */ }
        EndpointWaitOutcome::Event(_) => {} // EndpointEvent is non-exhaustive
        _ => {}
    }
}
```

State snapshot getters (`path`, `connected_peers`, `is_peer_ready`, `peer_readiness`, `peer_info`, `connection_id`, `connection_remote_addr`, `bound_addresses`, `reachability`, `active_reservation`, `known_peers`) expose durable state without driving the endpoint; they are not one cross-getter atomic snapshot and may be ahead of the event stream, never behind their own emitted transition. Prefer `connect` plus `ConnectSettled` for a Connection attempt. `wait` and `poll` use transport readiness when supported. Each call drives only its own endpoint, so blocking on one endpoint can delay others sharing the same thread. Deadlines accept an `Instant` (absolute), a `Duration` (relative), or `minip2p::WaitDeadline::NEVER`. A deadline that has already passed, whether a stale `Instant` or `Duration::ZERO`, makes `wait` return a queued event or drive the endpoint once without sleeping, so a stale timer never stalls it. The deadline bounds blocking, not delivery: with a strict operation timeout, check the clock before each `wait`, as in the loop above.

Background drivers can clone `Endpoint::wait_handle()` — the `WaitHandle` of its readiness poll — and interrupt a blocked `wait` from another thread. The wake is reported as `EndpointWaitOutcome::Interrupted`; interrupts sent before one is reported coalesce into one, and a pending one is reported even by a `wait` whose deadline has passed. Every transport and mDNS socket is registered with the endpoint's one readiness poll, so an idle `wait` sleeps until input or a real timer, with no fixed cadence.

`open_stream` is allowed once the peer is connected. Identify (`PeerReady`) supplies advertised protocols and enables early `RemoteDoesNotSupport` rejects; waiting for it before opening a known application protocol is optional policy, not a stack requirement. Every open ends in exactly one terminal: `StreamReady`, or an `Error` event naming the stream (a `SwarmErrorKind`) when negotiation fails, the peer closes the stream first, or `OUTBOUND_NEGOTIATION_TIMEOUT_MS` passes; a closed or replaced connection ends it with its own event.

The swarm keeps one connection per peer. Two direct connections to one peer that register within `SIMULTANEOUS_DIAL_WINDOW_MS` (5 s; `EndpointBuilder::simultaneous_dial_window` overrides it, and both peers should use the same value) race, and both peers keep the same one whatever order each sees them in: the one the lower peer ID dialed when the peers `connect` to each other at once, and the one with the lower connection token (shared by both ends: QUIC derives it from the connection IDs, TCP from the Noise handshake hash) when both are one peer's candidate dials. A transport without a token falls back to newest-wins for that case, so its peers can still end up on different connections. Past that window the newest connection wins. Within it, a winner arriving second replaces the other (`ConnectionReplaced`, below), while a loser arriving second closes unannounced; a losing dial of our own completes as `DialFailed` (a `connect` the winner already settled absorbs it), and `connect` settles on the connection the swarm kept. Because the peers agree only once each has seen both, a settled `connect` keeps its other candidate dials open until the window ends whenever one of them could still win; a higher-ID peer settled by the lower peer's dial aborts them at once, as they lose on both sides. Over TCP the listener sees both first; if it closes the dialer's only connection before the winning dial lands there, the dialer sees `ConnectionClosed` and then `ConnectionEstablished` on the winner. When a newer connection takes over, the stream carries a single `ConnectionReplaced { peer_id, old, new }` instead of a close and a second establishment, and the peer stays connected throughout. Streams and pending opens on `old` end with it without their own terminal events, so release whatever you keyed by `old`. Stream ids are unique only per connection, so `open_stream` returns `(ConnectionId, StreamId)` and every stream operation takes both; one aimed at `old` fails (`Error::is_stream_gone`) rather than reaching a stream on `new` that reuses its id. Readiness belongs to a connection: `PeerReady { conn_id, .. }` fires again for `new` once it is identified, and a ready wait should check `peer_readiness(peer)` (current connection plus Identify info, one snapshot) and then accept only a `PeerReady` whose `conn_id` is the current connection.

## Hosting a relay server

The std-only `relay-server` feature is independent of `nat`. The default hosting path is three lines:

```rust,no_run
let mut endpoint = minip2p::Endpoint::builder()
    .relay_server()
    .listen_on("/ip4/0.0.0.0/udp/4001/quic-v1")?
    .bind()?;
# Ok::<(), minip2p::BindError>(())
```

Use `relay_server_config` for validated capacity, duration, byte, control, and rate limits, including the per-IP caps (8 reservations and 8 circuits per IPv4 address or IPv6 /64 by default). `relay_server_announce_addrs` supplies explicit public TCP/QUIC addresses; it does not enable the service, and invalid shapes fail `bind` with `BindError::RelayServerAnnounce` (an invalid `relay_server_config` is `BindError::RelayServer`). Runtime replacement is atomic, with an empty list returning to AutoNAT-confirmed addresses and then concrete listeners. Raw Identify-observed addresses are never promoted. When a listener or AutoNAT-confirmed address refresh is rejected, the relay keeps advertising that source's previous addresses and reports `RelayServerEvent::AddrsRejected { source, error }`, then `AddrsRestored { source }` once a refresh is accepted again.

`set_relay_server_accepting(false)` pauses only new reservations and circuits; HOP stays advertised and existing lifecycles remain active. Typed output arrives as `EndpointEvent::RelayServer` from `wait`. Synchronous controls return `RelayServerControlError`; failed asynchronous open/send/close/reset operations arrive as `RelayServerEvent::Error`.

Relay-only endpoints accept and advertise inbound HOP and can open outbound STOP. NAT-only endpoints open outbound HOP and accept/advertise trusted STOP, without advertising HOP. Combined endpoints install both role sets. The Swarm keeps one live connection per peer; exact connection targeting by the relay driver relies on that invariant.

Reading is backpressured too (ADR 0012): each stream delivers at most one receive window that has not been acknowledged. The Endpoint acknowledges `EndpointEvent::StreamData` when the application pulls it from `poll` or `wait`, so a reader that stops pulling slows its sender. A protocol registered with `EndpointBuilder::manual_ack_protocol` or `Endpoint::add_manual_ack_protocol` is acknowledged by the application instead, with `Endpoint::stream_consumed`, for readers whose bytes outlive the event. Over-acknowledging is `TransportError::AckExceedsDelivered`, naming the stream and both counts.

Stream operations (`send_stream`, `close_stream_write`, `reset_stream`, `abandon_stream`, `stream_consumed`) take the connection and stream ids that `open_stream` or `StreamReady` gave; the peer is the connection's. The exact connection is still checked, so an id from a closed or replaced connection fails instead of reaching a same-numbered stream on its replacement. Two calls still work after the connection ended, because its delivered bytes keep the ended connection's transport slot until they settle (ADR 0012): `stream_consumed` releases them, and `abandon_stream` gives them up. A reader that does neither while peers churn eventually has the transport refuse new connections.

`send_stream` takes anything that converts into `Bytes` and accepts as much as the stream can queue. When not every byte fit it returns `Error::Full`: **a prefix may already have been accepted, and only the `unsent` tail is yours.** Hold it and send it again on `EndpointEvent::StreamWritable` for that stream. Full is backpressure, never a fault, and a slow reader slows the writer instead of tearing the connection down. A relay server forwards the same way: a full destination pauses the circuit's sender instead of closing it. `Ok(())` means accepted locally, never delivered.

A `?` on `send_stream` drops the tail:

```rust,ignore
endpoint.send_stream(conn_id, stream_id, chunk)?; // a Full here loses `unsent`
```

On the std `Endpoint`, `StreamWriter` does the holding for you (`PortableEndpoint` callers hold the tail themselves): one pending write per stream within an explicit byte budget, the tail resent on `StreamWritable`, and a `close_write` that sends the FIN only once the tail is accepted. Feed it every event; it drops its state when the stream ends or the connection closes or is replaced. Its `WriteAccepted` means the whole payload was accepted locally, never delivered.

```rust,ignore
use minip2p::{StreamWriter, WriteProgress};

let mut writer = StreamWriter::new(8 * 1024 * 1024);
if writer.write(&mut endpoint, conn_id, stream_id, payload)? == WriteProgress::Pending {
    // A WriteAccepted for this stream follows from `observe`.
}
// After the last chunk only: later writes are refused. The FIN follows the tail.
writer.close_write(&mut endpoint, conn_id, stream_id)?;

// In the event loop:
if let Some(done) = writer.observe(&mut endpoint, &event) { /* done.stream_id's write was accepted */ }
```

`Error::is_retryable()` is true for `Full`, and `Error::is_stream_gone()` for a stream or connection that no longer exists (`SwarmError::StreamNotFound`, `NotConnected`, or the transport's stream or connection not found). Neither covers a write side that is closing, or a stream still negotiating (`SwarmError::StreamNotReady`, usable once its `StreamReady` arrives).

When an application permanently relinquishes a stream, `Endpoint::abandon_stream` resets it, purges its already-buffered events (matched by connection as well as stream id), and suppresses later stream events. Once the stream's connection has ended it needs no queued event to do so: the Endpoint and swarm drop what they hold and the transport settles the stream outright. Use `Endpoint::reset_stream` when those terminal events should remain visible.

Relay bridges are promoted through end-to-end Noise and Yamux before `NatEvent::PathEstablished` reports `Path::Relayed`, so application protocols use ordinary streams on direct and relayed paths alike. `Endpoint::path(peer)` returns the path origin of the peer's current connection independently of whether the corresponding event was delivered. It is updated before path events are queued for both outbound connects and accepted inbound circuits. A `ConnectionReplaced` moves it to the new connection's origin (leaving a relay for a direct connection is reported once, as `PathUpgraded` or `InboundDirectUpgrade`), and it is gone once the peer disconnects.

With the `discovery` feature, `.discovery()` enables signed pubsub presence beacons, a bounded TTL address book, and caller-driven automatic NAT connects. It implies the `nat` and `pubsub` features. Applications can inspect `known_peers`, handle `EndpointEvent::Discovery` from `wait`, pass a validated `BeaconConfig` to select a room-scoped topic, and use `PeerDiscoveryConfig` for shared book and dial policy. Unsigned discovery beacons are always rejected even if unsigned application pubsub messages are allowed.

With the `mdns` feature, `.mdns()` enables zero-configuration local-link discovery on `_p2p._udp.local` without enabling pubsub. It implies `nat`, uses the same bounded peer book and dial state as signed discovery when both are enabled, and exposes per-address provenance through `KnownPeer`. Use `.mdns_config(...)` for mDNS timing and packet policy, and `.peer_discovery_config(...)` for the shared book and dial policy. Applications can inspect `known_peers` and handle the same `EndpointEvent::Discovery` events used by signed discovery. Because mDNS claims are unauthenticated, their automatic dials are direct-only and never activate configured relays. An mDNS socket failure while running is `EndpointEvent::MdnsFailed { error }`, reported once per change in failure state: mDNS keeps retrying (every `MDNS_FAILURE_RETRY`, 100 ms) and emits `EndpointEvent::MdnsRecovered` once a retry succeeds. Call `Endpoint::shutdown()` to send TTL-zero goodbyes and stop mDNS while keeping QUIC usable; it returns the first goodbye that could not be sent (also queued as a final `MdnsFailed`). `close`/`close_within` and drop send the same goodbyes best-effort; `close` reports a failed one only as an `MdnsFailed` in its `CloseReport`'s events.

Discovery source timestamps use a driver-private monotonic epoch. Compute their ages from `Endpoint::discovery_now_ms()`; an independently created `Instant` does not share that origin.

With the `pubsub` feature, `.gossipsub()` enables gossipsub and advertises `/meshsub/1.1.0` plus `/meshsub/1.0.0`. Pass a `GossipsubConfig` to `.gossipsub_config(...)` to tune mesh policy; an invalid configuration fails `bind()` with `BindError::Gossipsub` before any socket is allocated.

Built-in protocol ids (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` -- see `minip2p::RESERVED_PROTOCOL_IDS`) belong to the endpoint's own handlers; registering one via `EndpointBuilder::protocol` fails `bind()` with `BindError::Swarm(SwarmError::ReservedProtocol { .. })`, and `Endpoint::add_protocol` rejects it with `SwarmError::ReservedProtocol`.

## Benchmarks

`benches/endpoint_e2e.rs` times connection setup, ping, echo, and transfer over QUIC and TCP. `benches/endpoint_idle.rs` measures what an idle endpoint with no peers costs: blocking waits on the endpoint's shared poll per second and process CPU milliseconds per second, for QUIC alone, for QUIC + TCP with the relay server, Gossipsub, and mDNS started, and for the same without mDNS. It needs the `bench` feature, which compiles in the wait counters from `minip2p_transport::bench` and is off by default:

```bash
cargo bench -p minip2p-rs --features tcp,relay-server,pubsub,mdns,bench --bench endpoint_idle
```

`benches/endpoint_throughput.rs` measures one-way sustained throughput (256 MiB in 64 KiB writes, up to 32 MiB ahead of the receiver) over TCP, QUIC, and a forced relayed circuit through a third Endpoint, plus allocations per MB in a separate pass. It installs `stats_alloc` as its global allocator, so it counts every allocation made through the Rust allocator, QUIC's rustls TLS included. For the QUIC-carried cases it also reports each Endpoint's UDP datagrams per MB and average datagram size in each direction, from the `diagnostics` counters of `minip2p-quic` that the `bench` feature enables:

```bash
cargo bench -p minip2p-rs --features tcp,nat,relay-server,bench --bench endpoint_throughput
```

`benches/endpoint_rtt.rs` measures the same one-way goodput over an emulated link: a userspace proxy (`benches/support/delay.rs`) caps each direction at 100 Mbit/s and adds a 100 ms round trip, with no loss, so flow-control windows are measured at a real RTT where `tc netem` is unavailable. It reports the median of 3 warm transfers over QUIC and over TCP + Yamux with default limits. The TCP case measures Yamux credit at the RTT, not kernel TCP, because the proxy terminates TCP on both sides. With `MINIP2P_RTT_SWEEP` set it runs one of #361's window sweeps instead; `scripts/rtt-sweep.sh` runs them all in order and records the picks:

```bash
cargo bench -p minip2p-rs --features tcp,nat,relay-server,bench --bench endpoint_rtt
scripts/rtt-sweep.sh                    # every sweep, ~20 minutes
scripts/rtt-sweep.sh quic-stream yamux  # just these
```

`benches/endpoint_ping_load.rs` measures application-observed ping latency (`Instant` around `ping()` until the matching `PingRttMeasured` event, p50 and p99 over 200 samples) from an Endpoint with QUIC and TCP bound to a probe peer over each transport, while that Endpoint is idle, relays an unbounded transfer over a forced circuit, or forwards 500 1 KiB gossipsub messages per second between two peers. Each loaded case asserts the load advanced across the whole sampling window, and a sample slower than 2 s fails the run:

```bash
cargo bench -p minip2p-rs --features tcp,nat,relay-server,pubsub --bench endpoint_ping_load
```
