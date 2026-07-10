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
