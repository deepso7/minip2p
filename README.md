<p align="center">
  <img src="docs/public/logo.svg" width="320" alt="minip2p logo">
</p>

# minip2p

A minimal [libp2p](https://libp2p.io/) implementation in Rust: small,
portable, understandable, and pleasant to use.

minip2p is built around a few deliberate constraints:

- Protocol and orchestration logic is Sans-I/O and deterministic.
- Core crates support `no_std + alloc`.
- There is no `async`/`.await`; callers choose the executor and drive progress.
- QUIC is the only transport adapter.
- `unsafe` is forbidden across the workspace.

The result is a set of reusable protocol state machines and a synchronous
`Endpoint` API for applications that want sensible defaults.

## Quick start

Install minip2p:

```toml
[dependencies]
minip2p-rs = "0.3.1"
```

Then create an endpoint:

```rust
use minip2p::{Deadline, Endpoint, Event};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut endpoint = Endpoint::builder()
        .agent_version("my-app/0.1.0")
        .bind_quic_dual_stack()?;

    for address in endpoint.listen_all()? {
        println!("listening on {address}");
    }

    while let Some(event) = endpoint.next_event(Deadline::NEVER)? {
        println!("{event:?}");
        if matches!(event, Event::ConnectionEstablished { .. }) {
            // Open streams, ping the peer, or continue polling for events.
        }
    }

    Ok(())
}
```

`Endpoint` is caller-driven: it owns sockets, but it does not start a runtime or
background task. Event waits accept an absolute `Instant`, a relative
`Duration`, or `Deadline::NEVER`.

For a complete application, run the gossipsub chat example:

```bash
cargo run -p minip2p-chat -- host --nick hostess
```

See [the chat guide](examples/chat/README.md) for NAT and cross-implementation
recipes. The [peer example](examples/peer/README.md) demonstrates relay
reservations and direct-path upgrades with DCUtR.

## Features

The base `Endpoint` includes QUIC, multistream-select, identify, ping, and
application protocols registered with `EndpointBuilder::protocol`.

| Feature | Adds |
| --- | --- |
| `nat` | Circuit Relay v2, AutoNAT, and DCUtR traversal policy |
| `pubsub` | StrictSign gossipsub by default, with explicit floodsub selection |
| `discovery` | Signed pubsub presence beacons and coordinated dialing; implies `nat` and `pubsub` |
| `mdns` | Local-link discovery and coordinated direct dialing; implies `nat` |

Features layer onto the same API. Lower-level users can instead drive
`SwarmCore` and individual protocol crates directly with explicit inputs,
outputs, timestamps, and deadlines.

## Architecture

The workspace has three strictly separated layers:

1. **Sans-I/O protocols** — identity, TLS, Noise, Yamux,
   multistream-select, ping, identify, relay, AutoNAT, DCUtR, pubsub, and mDNS.
   These crates contain state machines and wire codecs, not sockets or clocks.
2. **Sans-I/O orchestration** — `SwarmCore`, `NatAgent`, `BeaconAgent`, and
   `PeerDiscoveryAgent` compose protocols and policy while remaining
   deterministic and I/O-free.
3. **`std` adapters** — the quiche-based QUIC transport, mDNS socket driver,
   application-facing `Endpoint`, and UniFFI adapter own real I/O.

The default swarm intentionally includes only identify, ping, and registered
application protocols. Relay, traversal, pubsub, and discovery policy stay
opt-in so the base remains small and predictable.

TypeScript bindings live under `bindings/ts`: `@minip2p/core` defines the
platform-neutral API, and `@minip2p/react-native` provides its UniFFI-backed
React Native implementation. The Node adapter is currently a private scaffold.

Every crate has its own README with API-specific details.

## Development

[`just`](https://github.com/casey/just) commands mirror CI:

```bash
just test          # workspace tests and Endpoint feature matrix
just clippy        # warnings-as-errors, feature variants, and fuzz crate
just fmt           # format the workspace and fuzz crate
just check-nostd   # no_std crates on thumbv7em-none-eabi
just bench
just fuzz 30       # requires nightly and cargo-fuzz
```

Generate local API documentation with:

```bash
cargo doc --workspace --no-deps --open
```

All published Rust and TypeScript packages share one version. Releases also
include freshly built Android and iOS libraries for React Native.

## License

[MIT](LICENSE)
