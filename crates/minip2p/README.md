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
# Ok::<(), minip2p::Error>(())
```

Listening is address-shaped: pass complete multiaddresses to `EndpointBuilder::listen_on` (or `listen_on_multiaddr`), or use `listen_default` for dual-stack QUIC wildcards. The transport is inferred from each address.

## Connecting and the event loop

`Endpoint::connect` is the one Connection-attempt entry point. It takes a `PeerId`, one complete peer address, or a list of complete addresses naming the same peer, and returns a `ConnectId` immediately. Candidate racing, DNS expansion, relay fallback, and direct-path upgrade all belong to that attempt, which ends with exactly one `EndpointEvent::ConnectSettled` (connected, failed, or cancelled). `cancel_connect` is the explicit cancellation; giving up a local wait never cancels anything.

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
        EndpointWaitOutcome::Interrupted => {} // a WaitHandle woke us; service commands
        EndpointWaitOutcome::Deadline => {
            endpoint.cancel_connect(connect_id); // explicit: the deadline is only local
            break;
        }
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Raw Transport dials bypass attempt policy and live on the lower-level swarm (`endpoint.swarm_mut().dial(..)`, or `SwarmRuntime::dial` for portable endpoints).

## Portable endpoint

Disable default features for `no_std + alloc`, then provide identity, entropy, and a concrete transport explicitly:

```rust,ignore
let mut endpoint = minip2p::Endpoint::portable(&identity, entropy)
    .agent_version("my-device/0.1.0")
    .protocol("/myapp/1.0.0")
    .build(transport)?;

let events = endpoint.poll(now)?;
let deadline = endpoint.next_deadline(now);
```

The portable endpoint supports listening, Connection attempts, ping, Identify inspection, custom streams, state statistics, and consuming `shutdown(now)`. Every operation that advances protocol work uses a caller-provided `Now`, so the host controls time consistently.

For an embedded TCP endpoint, enable `smoltcp` with default features disabled and build the endpoint over a `TcpTransport<SmoltcpTcpProvider<_>, _>`. The host owns the smoltcp device and interface; minip2p owns the TCP, Noise XX, Yamux, Identify, Ping, and application-protocol state above them:

```bash
cargo add minip2p-rs --no-default-features --features smoltcp,pubsub
```

The portable smoltcp builder can compose TCP, pubsub, signed-beacon discovery, and mDNS into one endpoint. Build one `SmoltcpStack` from the device and configured interface, then select the services needed by the application. TCP and portable mDNS are supplied by `smoltcp`; the separate `pubsub` feature enables `.gossipsub()` and signed `.discovery()`, which itself implies pubsub at runtime:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack)
    .listen("/ip4/0.0.0.0/tcp/4001")
    .mdns()
    .discovery()
    .protocol("/myapp/1.0.0")
    .build()?;
```

Use `tcp_config`, `smoltcp_config`, `mdns_config`, `mdns_carrier_config`, `gossipsub_config`, `beacon_config`, and `discovery_config` only when overriding defaults. The endpoint installs every adapter on the same stack, returns TCP, NAT, pubsub, and discovery progress as `EndpointEvent` values (`EndpointEvent::Nat`, `EndpointEvent::Gossipsub`, `EndpointEvent::Discovery`), and automatically dials newly observed peers. `poll(now)` advances all enabled services and `next_deadline(now)` folds their timelines. Manual provider composition remains available through `build(transport)`.

Portable AutoNAT is opt-in, and does not pull circuit transport state into an AutoNAT-only binary. Enable `portable-autonat`, configure one or more trusted servers, and read the latest verdict from the same caller-driven endpoint:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack)
    .listen("/ip4/0.0.0.0/tcp/4001")
    .autonat(autonat_server)
    .build()?;

for event in endpoint.poll(now)? {
    // ReachabilityChanged is emitted after enough server verdicts agree.
    // Handle that and ordinary endpoint events here.
}
let reachability = endpoint.reachability();
```

Once at least one TCP listen address exists, the first due `poll(now)` starts a probe by dialing the configured server. Successful exchanges emit `EndpointEvent::Nat(NatEvent::ReachabilityChanged { .. })` after the configured confidence threshold is met; `reachability()` then returns that same settled verdict. Until a server exchange succeeds, it remains `Unknown`.

Portable relay circuits remain a separate opt-in. Enable `portable-relay` (which includes `portable-autonat` and `smoltcp`), configure a relay, and drive connection progress through the same endpoint:

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

`.relay()` selects a relay-only path and does not reserve inbound capacity. Use `.nat_config(...)` to combine AutoNAT servers with relay policy, and `ReservationPolicy::Always` for a device that must remain reachable through the relay. Raw-UDP DCUtR actions are not run by the TCP-only portable endpoint.

## Transports

QUIC comes with the default `std + quic` features. TCP is opt-in via the `tcp` Cargo feature, so a QUIC-only app does not pull in the TCP stack. Enable it with `cargo add minip2p-rs --features tcp`.

An endpoint brings up whatever you asked it to listen on, then routes by address. Prefer complete multiaddresses:

```rust
let mut endpoint = minip2p::Endpoint::builder()
    .listen_on("/ip4/0.0.0.0/udp/4001/quic-v1")?
    .bind()?;
# Ok::<(), minip2p::Error>(())
```

With the `tcp` feature, chain a `/tcp` listen address the same way. Connect to a `/udp/<port>/quic-v1` candidate and it is dialed over QUIC; a `/tcp` candidate goes over TCP. The address decides — nothing above the endpoint cares that there are two transports. `listen_default` is dual-stack QUIC. An endpoint with nothing to bind is refused rather than built empty.

The IP family is chosen by the address too: an `/ip4` or `/ip6` candidate is dialed as written, and a `/dns*` candidate is resolved and dialed once per family it answers with (`/dns4` / `/dns6` keep to one).

Dropping a std `Endpoint` (or `Endpoint::close`) disconnects established peers. That does not cover `kill -9` or a hard partition; those still wait for the QUIC idle timeout. Portable endpoints use explicit `shutdown(now)`.

With the `nat` feature, an endpoint holding a QUIC relay reservation sends a ping every `NatConfig::reservation_keep_alive_interval_ms` to stop an idle relay connection from reaching that timeout. The default is 15 seconds. Keep the interval below `QuicLimits::idle_timeout_ms`; setting it to `0` disables the automatic pings. TCP reservations do not send them. Each successful automatic ping emits the ordinary `EndpointEvent::PingRttMeasured` event.

`minip2p::Error` preserves transport failures, Sans-I/O state rejections, and driver-invariant failures as separate variants. Resource limits are configurable through `EndpointBuilder::quic_limits` and `EndpointBuilder::tcp_config`.

Prefer `Endpoint::wait` for the ordered Endpoint event stream: it returns an event, deadline, or interruption without swallowing interrupts. `EndpointEvent` is `#[non_exhaustive]` and carries enabled capability output — `Nat`, `Gossipsub`, `Discovery`, `RelayServer` — so one `wait` loop sees every event exactly once for every feature combination. `poll()` is the non-blocking drain of the same stream. Within one Endpoint step, swarm events come first, then capability events in relay-server, NAT, Gossipsub, Discovery order, then Connection-attempt terminals (`ConnectSettled`); no order is promised between concurrently racing Transport candidates. NAT attempt terminals (`ConnectFailed`, `FellBackToRelay`) never appear: the outcome is `ConnectSettled`. A `PathUpgraded` can still follow its attempt's `ConnectSettled` when the attempt settled on a provisional Relayed path.

```rust,ignore
use std::time::Duration;
use minip2p::{EndpointEvent, EndpointWaitOutcome, GossipsubEvent, NatEvent};

loop {
    match endpoint.wait(Duration::from_millis(250))? {
        EndpointWaitOutcome::Event(EndpointEvent::Gossipsub(GossipsubEvent::Message { data, .. })) => { /* ... */ }
        EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) => { /* ... */ }
        EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled { connect_id, outcome, .. }) => { /* ... */ }
        EndpointWaitOutcome::Event(_) => {} // EndpointEvent is non-exhaustive
        EndpointWaitOutcome::Deadline | EndpointWaitOutcome::Interrupted => {}
    }
}
```

State snapshot getters (`path`, `connected_peers`, `is_peer_ready`, `peer_info`, `connection_id`, `connection_remote_addr`, `bound_addresses`, `reachability`, `active_reservation`, `known_peers`) expose durable state without driving the endpoint; they are not one cross-getter atomic snapshot and may be ahead of the event stream, never behind their own emitted transition. Prefer `connect` plus `ConnectSettled` for a Connection attempt. `wait` and `poll` use transport readiness when supported. Each call drives only its own endpoint, so blocking on one endpoint can delay others sharing the same thread. Deadlines accept an `Instant` (absolute), a `Duration` (relative), or `minip2p::Deadline::NEVER`. For `wait`, an already-passed absolute Instant returns `Deadline` before delivering another queued event; relative `Duration::ZERO` still drains / polls once.

Background drivers can clone `Endpoint::wait_handle()` — a transport-neutral `WaitHandle` — and interrupt a blocked `wait` from another thread. The wake is reported as `EndpointWaitOutcome::Interrupted`.

`open_stream` is allowed once the peer is connected. Identify (`PeerReady`) supplies advertised protocols and enables early `RemoteDoesNotSupport` rejects; waiting for it before opening a known application protocol is optional policy, not a stack requirement.

## Hosting a relay server

The std-only `relay-server` feature is independent of `nat`. The default hosting path is three lines:

```rust,no_run
let mut endpoint = minip2p::Endpoint::builder()
    .relay_server()
    .listen_on("/ip4/0.0.0.0/udp/4001/quic-v1")?
    .bind()?;
# Ok::<(), minip2p::Error>(())
```

Use `relay_server_config` for validated capacity, duration, byte, control, and rate limits. `relay_server_announce_addrs` supplies explicit public TCP/QUIC addresses; it does not enable the service, and invalid shapes fail before binding. Runtime replacement is atomic, with an empty list returning to AutoNAT-confirmed addresses and then concrete listeners. Raw Identify-observed addresses are never promoted.

`set_relay_server_accepting(false)` pauses only new reservations and circuits; HOP stays advertised and existing lifecycles remain active. Typed output arrives as `EndpointEvent::RelayServer` from `wait`. Synchronous controls return `RelayServerControlError`; failed asynchronous open/send/close/reset operations arrive as `RelayServerEvent::Error`.

Relay-only endpoints accept and advertise inbound HOP and can open outbound STOP. NAT-only endpoints open outbound HOP and accept/advertise trusted STOP, without advertising HOP. Combined endpoints install both role sets. The Swarm keeps one live connection per peer; exact connection targeting by the relay driver relies on that invariant.

When an application permanently relinquishes a stream, `Endpoint::abandon_stream` resets it, purges already-buffered events, and suppresses later stream events. Use `Endpoint::reset_stream` when those terminal events should remain visible.

`EndpointTransport` is the `TransportSet` holding whatever was bound — with the `nat` feature, a `CircuitTransport<TransportSet, StdEntropy>` wrapping it — and `EndpointSwarm` names the resulting concrete swarm type. Relay bridges are promoted through end-to-end Noise and Yamux before `NatEvent::PathEstablished` reports `Path::Relayed`, so application protocols use ordinary streams on direct and relayed paths alike. `Endpoint::path(peer)` returns the current NAT-orchestrated path independently of whether the corresponding event was delivered. It is updated before path events are queued for both outbound connects and accepted inbound circuits, and cleared only after the peer's final usable connection closes.

With the `discovery` feature, `.discovery()` enables signed pubsub presence beacons, a bounded TTL address book, and caller-driven automatic NAT connects. It implies the `nat` and `pubsub` features. Applications can inspect `known_peers`, handle `EndpointEvent::Discovery` from `wait`, pass a validated `BeaconConfig` to select a room-scoped topic, and use `PeerDiscoveryConfig` for shared book and dial policy. Unsigned discovery beacons are always rejected even if unsigned application pubsub messages are allowed.

With the `mdns` feature, `.mdns()` enables zero-configuration local-link discovery on `_p2p._udp.local` without enabling pubsub. It implies `nat`, uses the same bounded peer book and dial state as signed discovery when both are enabled, and exposes per-address provenance through `KnownPeer`. Use `.mdns_config(...)` for mDNS timing and packet policy, and `.peer_discovery_config(...)` for the shared book and dial policy. Applications can inspect `known_peers` and handle the same `EndpointEvent::Discovery` events used by signed discovery. Because mDNS claims are unauthenticated, their automatic dials are direct-only and never activate configured relays. Call `Endpoint::shutdown()` to send TTL-zero goodbyes and stop mDNS while keeping QUIC usable; drop performs the same sends best-effort.

Discovery source timestamps use a driver-private monotonic epoch. Compute their ages from `Endpoint::discovery_now_ms()`; an independently created `Instant` does not share that origin.

With the `pubsub` feature, `.gossipsub()` enables gossipsub and advertises `/meshsub/1.1.0` plus `/meshsub/1.0.0`. Pass a `GossipsubConfig` to `.gossipsub_config(...)` to tune mesh policy; an invalid configuration fails `bind()` before any socket is allocated.

Built-in protocol ids (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` -- see `minip2p::RESERVED_PROTOCOL_IDS`) belong to the endpoint's own handlers; registering one via `EndpointBuilder::protocol` makes the bind step fail, and `Endpoint::add_protocol` rejects it with `SwarmError::ReservedProtocol`.
