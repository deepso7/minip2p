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

With the `discovery` feature, `.discovery()` enables signed pubsub presence
beacons, a bounded TTL address book, and caller-driven automatic NAT connects.
It implies the `nat` and `pubsub` features. Applications can inspect
`known_peers`, drain `DiscoveryEvent`s, or pass a validated `DiscoveryConfig`
to select a room-scoped topic and policy. Unsigned discovery beacons are always
rejected even if unsigned application pubsub messages are allowed.

Built-in protocol ids (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` -- see
`minip2p::RESERVED_PROTOCOL_IDS`) belong to the endpoint's own handlers;
registering one via `EndpointBuilder::protocol` makes the `bind_quic*` step
fail, and `Endpoint::add_protocol` rejects it with
`SwarmError::ReservedProtocol`.
