# minip2p

App-facing facade for minip2p.

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
`known_peers`, drain `DiscoveryEvent`s, or pass a validated `DiscoveryConfig`
to select a room-scoped topic and policy. Unsigned discovery beacons are always
rejected even if unsigned application pubsub messages are allowed.

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
