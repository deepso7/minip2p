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
- QUIC and TCP sit side by side. The dial address picks the transport.
  QUIC is `std`-only; TCP is portable down to `no_std`.
- `unsafe` is forbidden across the workspace.

The result is a set of reusable protocol state machines and a synchronous
`Endpoint` API for applications that want sensible defaults.

## Quick start

Install minip2p:

```toml
[dependencies]
minip2p-rs = "0.4.9"
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

QUIC is the default. Turn on the `tcp` feature to listen on TCP as well, or
TCP only. The dial address picks the transport:

```toml
minip2p-rs = { version = "0.4.9", features = ["tcp"] }
```

```rust
let endpoint = minip2p::Endpoint::builder()
    .quic_dual_stack()
    .tcp("0.0.0.0:4001")
    .bind()?;
# Ok::<(), minip2p::Error>(())
```

On bare-metal or other `no_std` hosts, turn off default features and build with
`Endpoint::portable(...)`, supplying time samples, entropy, and a transport.
With `smoltcp`, you get TCP plus optional mDNS, discovery, pubsub, AutoNAT,
and relay on one embedded stack. See the
[`minip2p-rs` crate guide](crates/minip2p/README.md#portable-endpoint).

For a complete application, run the gossipsub chat example:

```bash
cargo run -p minip2p-chat -- host --nick hostess
```

See [the chat guide](examples/chat/README.md) for NAT and cross-implementation
recipes. The [peer example](examples/peer/README.md) demonstrates relay
reservations and direct-path upgrades with DCUtR.

## Features

The base `Endpoint` includes whatever you bind — QUIC, TCP, or both — plus
multistream-select, identify, ping, and any protocols registered with
`EndpointBuilder::protocol`.

| Feature | Adds |
| --- | --- |
| `nat` | Circuit Relay v2, AutoNAT, and DCUtR traversal policy |
| `relay-server` | std-only Circuit Relay v2 hosting, independent of `nat` |
| `pubsub` | StrictSign gossipsub by default, with explicit floodsub selection |
| `discovery` | Signed pubsub presence beacons and coordinated dialing; implies `nat` and `pubsub` |
| `mdns` | Local-link discovery and coordinated direct dialing; implies `nat` |

Features layer onto the same API. Lower-level users can instead drive
`SwarmCore` and individual protocol crates directly with explicit inputs,
outputs, timestamps, and deadlines.

Host a relay on QUIC and TCP with production defaults:

```bash
cargo run -p minip2p-relay-server-example
```

The [relay-server example](examples/relay-server/README.md) adds optional
persistent identity, explicit public announce addresses, pause/resume controls,
resource and rate limits, and readable typed lifecycle diagnostics while keeping
the default builder path small.

## Architecture

The workspace has four strictly separated layers:

1. **Sans-I/O protocols** — identity, TLS, Noise, Yamux,
   multistream-select, ping, identify, relay, AutoNAT, DCUtR, pubsub, and mDNS.
   These crates contain state machines and wire codecs, not sockets or clocks.
2. **Sans-I/O orchestration** — `SwarmCore`, `NatAgent`, `RelayServerAgent`,
   `BeaconAgent`, and `PeerDiscoveryAgent` compose protocols and policy while
   remaining deterministic and I/O-free.
3. **Transport adapters** — `minip2p-tcp` over a pluggable `TcpProvider`
   byte-stream seam (`no_std + alloc`), and the quiche-based `minip2p-quic`
   over UDP (`std`-only). `TransportSet` puts several behind one contract and
   routes by address.
4. **`std` adapters** — the mDNS socket driver, the application-facing
   `Endpoint`, and the UniFFI adapter: the hosted end of the I/O seams.

The seams below layer 3 — `TcpProvider` and `MdnsIo` — are what let TCP and
mDNS run on a device with no operating system. `StdTcpProvider` and
`MdnsSockets` are the hosted implementations; `SmoltcpTcpProvider` and
`SmoltcpMdnsIo` are the [smoltcp] ones. Everything above them is the same code
either way.

[smoltcp]: https://docs.rs/smoltcp

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
just test          # workspace tests, Endpoint feature matrix, and doctests
                   # requires cargo-nextest (https://get.nexte.st)
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
