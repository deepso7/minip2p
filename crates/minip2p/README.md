# minip2p-rs

App-facing facade for minip2p.

```toml
[dependencies]
minip2p = { package = "minip2p-rs", version = "0.1" }
```

The package is named `minip2p-rs` on crates.io and its library target remains
`minip2p`, so application imports stay concise:

This crate glues identity, QUIC transport, and the std swarm driver into a
small `Endpoint` API. Lower crates remain available directly for Sans-I/O and
`no_std + alloc` users.

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

`minip2p::Error` preserves transport failures, Sans-I/O state rejections, and
driver-invariant failures as separate variants. QUIC resource limits are
configurable through `EndpointBuilder::quic_limits`.

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

Background drivers can clone `Endpoint::wait_handle()` and interrupt a blocked
`next_wake` from another thread. The wake is reported as
`EndpointWake::Interrupted`; legacy event-specific waits consume interruptions
and continue waiting until their event or deadline.

When an application permanently relinquishes a stream, `Endpoint::abandon_stream`
resets it, purges already-buffered events, and suppresses later stream events.
Use `Endpoint::reset_stream` when those terminal events should remain visible.

With the `nat` feature, `EndpointTransport` is a
`CircuitTransport<QuicEndpoint, OsEntropy>` and `EndpointSwarm` names the
resulting concrete swarm type. Relay bridges are promoted through end-to-end
Noise and Yamux before `wait_path` returns `Path::Relayed`, so application
protocols use ordinary streams on direct and relayed paths alike.

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
