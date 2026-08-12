# minip2p-rs

Application-facing `Endpoint` API for minip2p.

```toml
[dependencies]
minip2p = { package = "minip2p-rs", version = "0.4.0" }
```

The package is named `minip2p-rs` on crates.io and its library target remains
`minip2p`, so application imports stay concise:

This crate provides the existing batteries-included std `Endpoint` and a
caller-driven portable endpoint behind the same entry point.

```rust
let mut endpoint = minip2p::Endpoint::builder()
    .agent_version("my-app/0.1.0")
    .protocol("/myapp/1.0.0")
    .bind_quic_dual_stack()?;

for address in endpoint.listen_all()? {
    println!("{address}");
}
# Ok::<(), minip2p::Error>(())
```

## Portable endpoint

Disable default features for `no_std + alloc`, then provide identity, entropy,
and a concrete transport explicitly:

```rust,ignore
let mut endpoint = minip2p::Endpoint::portable(&identity, entropy)
    .agent_version("my-device/0.1.0")
    .protocol("/myapp/1.0.0")
    .build(transport)?;

let events = endpoint.poll(now)?;
let deadline = endpoint.next_deadline(now);
```

The portable endpoint supports listening, dialing, ping, Identify inspection,
custom streams, state statistics, and consuming `shutdown(now)`. Every
operation that advances protocol work uses a caller-provided `Now`, so the
host controls time consistently.

For an embedded TCP endpoint, enable `smoltcp` with default features disabled
and build the endpoint over a `TcpTransport<SmoltcpTcpProvider<_>, _>`. The
host owns the smoltcp device and interface; minip2p owns the TCP, Noise XX,
Yamux, Identify, Ping, and application-protocol state above them:

```toml
minip2p = { package = "minip2p-rs", version = "0.4.0", default-features = false, features = ["smoltcp", "pubsub"] }
```

The portable smoltcp builder can compose TCP, pubsub, signed-beacon discovery,
and mDNS into one endpoint. Build one `SmoltcpStack` from the device and
configured interface, then select the services needed by the application.
TCP and portable mDNS are supplied by `smoltcp`; the separate `pubsub`
feature enables `.pubsub()` and signed `.discovery()`, which itself implies
pubsub at runtime:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack)
    .listen("/ip4/0.0.0.0/tcp/4001")
    .mdns()
    .discovery()
    .protocol("/myapp/1.0.0")
    .build()?;
```

Use `tcp_config`, `smoltcp_config`, `mdns_config`,
`mdns_carrier_config`, `pubsub_config`, `beacon_config`, and
`discovery_config` only when overriding defaults. The endpoint installs every
adapter on the same stack, returns TCP, pubsub, and discovery progress through
one `SmoltcpEvent` enum, and automatically dials newly observed peers.
`poll(now)` advances all enabled services and `next_deadline(now)` folds their
timelines. Manual provider composition remains available through
`build(transport)`.

Portable AutoNAT is opt-in, and does not pull circuit transport state into an
AutoNAT-only binary. Enable `portable-autonat`, configure one or more trusted
servers, and read the latest verdict from the same caller-driven endpoint:

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

Once at least one TCP listen address exists, the first due `poll(now)` starts a
probe by dialing the configured server. Successful exchanges emit
`SmoltcpEvent::Nat(NatEvent::ReachabilityChanged { .. })` after the configured
confidence threshold is met; `reachability()` then returns that same settled
verdict. Until a server exchange succeeds, it remains `Unknown`.

Portable relay circuits remain a separate opt-in. Enable `portable-relay`
(which includes `portable-autonat` and `smoltcp`), configure a relay, and drive
connection progress through the same endpoint:

```rust,ignore
let mut endpoint = Endpoint::portable(&identity, entropy)
    .smoltcp(stack)
    .relay(relay_addr)
    .build()?;

let connect = endpoint.connect_relay(&remote_peer, now)?;
while endpoint.path(&remote_peer).is_none() {
    for event in endpoint.poll(now)? {
        // Handle SmoltcpEvent::Nat and ordinary endpoint events.
    }
}
```

`.relay()` selects a relay-only path and does not reserve inbound capacity.
Use `.portable_nat_config(...)` (or its `.relay_config(...)` alias) to combine
AutoNAT servers with relay policy, and `ReservationPolicy::Always` for a device
that must remain reachable through the relay. Raw-UDP DCUtR actions are not run
by the TCP-only portable endpoint.

## Transports

QUIC comes with the default `std + quic` features. TCP is opt-in via the `tcp`
Cargo feature, so a QUIC-only app does not pull in the TCP stack. Enable it
with `minip2p-rs = { version = "0.4.0", features = ["tcp"] }`.

An endpoint brings up whatever you asked it to bind, then routes by address.
`quic`, `quic_dual_stack`, and `tcp` add sockets; `bind` brings them all up:

```rust
let mut endpoint = minip2p::Endpoint::builder()
    .quic("0.0.0.0:4001")
    .tcp("0.0.0.0:4001")
    .bind()?;
# Ok::<(), minip2p::Error>(())
```

Dial `/udp/<port>/quic-v1` and you get QUIC; dial a `/tcp` address and you get
TCP. The address decides — nothing above the endpoint cares that there are
two transports. `bind_quic`, `bind_quic_multiaddr`, `bind_quic_dual_stack`,
and `bind_tcp` are the one-transport shortcuts. An endpoint with nothing to
bind is refused rather than built empty.

`dial` resolves a `/dns*` target and dials one address per family, so a
dual-stack peer is tried both ways; `dial_ip4` and `dial_ip6` force one.

Dropping a std `Endpoint` (or calling `Endpoint::close`) disconnects
established peers so a long-lived listener is not left waiting on the QUIC
idle timeout (30s by default). That covers the common "dial, talk, drop the
dialer" pattern. It does **not** replace `kill -9` or a hard network
partition — those still wait for idle timeout. Portable endpoints keep
explicit `shutdown(now)` because they cannot poll without a caller-supplied
`Now`.

`minip2p::Error` preserves transport failures, Sans-I/O state rejections, and
driver-invariant failures as separate variants. Resource limits are
configurable through `EndpointBuilder::quic_limits` and
`EndpointBuilder::tcp_config`.

Event waits (`next_event`, `wait_peer_ready`, `wait_ping_rtt`) accept an
`Instant` (absolute deadline), a `Duration` (relative timeout), or
`minip2p::Deadline::NEVER` to block until the event arrives.
`next_wake` additionally returns on NAT, pubsub, or discovery queue progress,
including events already queued when the call begins. Its `Event` result
transfers ownership of one application event; `DriverProgress` leaves agent
events in their focused queues for the corresponding `take_*_events` method.
Progress is level-triggered across all active agents: drain every non-empty
agent queue before calling `next_wake` again, or it will immediately report
`DriverProgress` again.

Background drivers can clone `Endpoint::wait_handle()` — a transport-neutral `WaitHandle` — and interrupt a blocked
`next_wake` from another thread. The wake is reported as
`EndpointWake::Interrupted`; legacy event-specific waits consume interruptions
and continue waiting until their event or deadline.

When an application permanently relinquishes a stream, `Endpoint::abandon_stream`
resets it, purges already-buffered events, and suppresses later stream events.
Use `Endpoint::reset_stream` when those terminal events should remain visible.

`EndpointTransport` is the `TransportSet` holding whatever was bound — with the
`nat` feature, a `CircuitTransport<TransportSet, StdEntropy>` wrapping it — and
`EndpointSwarm` names the resulting concrete swarm type. Relay bridges are promoted through end-to-end
Noise and Yamux before `wait_path` returns `Path::Relayed`, so application
protocols use ordinary streams on direct and relayed paths alike.
`Endpoint::path(peer)` returns the current NAT-orchestrated path independently
of whether the corresponding event was drained. It is updated before path
events are queued for both outbound connects and accepted inbound circuits,
and cleared only after the peer's final usable connection closes.

With the `discovery` feature, `.discovery()` enables signed pubsub presence
beacons, a bounded TTL address book, and caller-driven automatic NAT connects.
It implies the `nat` and `pubsub` features. Applications can inspect
`known_peers`, drain `DiscoveryEvent`s, pass a validated `BeaconConfig` to
select a room-scoped topic, and use `PeerDiscoveryConfig` for shared book and
dial policy. Unsigned discovery beacons are always rejected even if unsigned
application pubsub messages are allowed.

With the `mdns` feature, `.mdns()` enables zero-configuration local-link
discovery on `_p2p._udp.local` without enabling pubsub. It implies `nat`, uses
the same bounded peer book and dial state as signed discovery when both are
enabled, and exposes per-address provenance through `KnownPeer`. Use
`.mdns_config(...)` for mDNS timing and packet policy, and
`.peer_discovery_config(...)` for the shared book and dial policy. Applications
can inspect `known_peers` and drain the same `DiscoveryEvent` queue used by
signed discovery. Because mDNS claims are unauthenticated, their automatic
dials are direct-only and never activate configured relays. Call
`Endpoint::shutdown()` to send TTL-zero goodbyes and stop mDNS while keeping
QUIC usable; drop performs the same sends best-effort.

Discovery source timestamps use a driver-private monotonic epoch. Compute
their ages from `Endpoint::discovery_now_ms()`; an independently created
`Instant` does not share that origin.

With the `pubsub` feature, `.pubsub()` enables gossipsub by default and
advertises `/meshsub/1.1.0` plus `/meshsub/1.0.0`. Pass a
`GossipsubConfig` to tune mesh policy, or
`.pubsub_config(FloodsubConfig::default())` to select the legacy floodsub
engine and advertise only `/floodsub/1.0.0`. This is a pre-1.0 API/default
change: `pubsub_config` now accepts either engine through `PubsubConfig`, and
gossipsub peers intentionally do not negotiate floodsub streams.

Built-in protocol ids (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` -- see
`minip2p::RESERVED_PROTOCOL_IDS`) belong to the endpoint's own handlers;
registering one via `EndpointBuilder::protocol` makes the `bind_quic*` step
fail, and `Endpoint::add_protocol` rejects it with
`SwarmError::ReservedProtocol`.
