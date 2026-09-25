<p align="center">
  <img src="docs/public/logo.svg" width="320" alt="minip2p logo">
</p>

# minip2p

A minimal [libp2p](https://libp2p.io/) implementation in Rust: small, portable, understandable, and pleasant to use.

minip2p is built around a few deliberate constraints:

- Protocol and orchestration logic is Sans-I/O and deterministic.
- Core crates support `no_std + alloc`.
- There is no `async`/`.await`; callers choose the executor and drive progress.
- QUIC and TCP sit side by side. The dial address picks the transport. QUIC is `std`-only; TCP is portable down to `no_std`.
- `unsafe` is forbidden across the workspace.

The result is a set of reusable protocol state machines and a synchronous `Endpoint` API for applications that want sensible defaults.

## Quick start

Install minip2p:

```bash
cargo add minip2p-rs
```

Then create an endpoint, connect to a peer by its complete address, and dispatch events until that one Connection attempt settles:

```rust
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut endpoint = Endpoint::builder()
        .agent_version("my-app/0.1.0")
        .listen_default()?
        .bind()?;

    for address in endpoint.listen_all()? {
        println!("listening on {address}");
    }

    // A complete peer address, copied from the remote's listen output.
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
                println!("attempt settled: {outcome:?}");
                break;
            }
            // Every other event is dispatched as usual while we wait.
            EndpointWaitOutcome::Event(event) => println!("{event:?}"),
            EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => {
                endpoint.cancel_connect(connect_id);
                break;
            }
        }
    }
    Ok(())
}
```

`Endpoint` is caller-driven: it owns sockets, but it does not start a runtime or background task. `connect` is the one Connection-attempt operation: it returns a `ConnectId` at once, and the attempt ends with exactly one `EndpointEvent::ConnectSettled`. `Endpoint::wait` is the one blocking wait over the one ordered Endpoint event stream: a loop sees every event exactly once, including enabled capability output such as `EndpointEvent::Nat`, `EndpointEvent::Gossipsub`, `EndpointEvent::Discovery`, and `EndpointEvent::RelayServer`, plus `Deadline` and `Interrupted` outcomes so it can service its own timers and commands. Each call drives only its own endpoint, so blocking on one endpoint can delay others sharing the same thread. Waits accept an absolute `Instant`, a relative `Duration`, or `Deadline::NEVER`.

QUIC is the default. Turn on the `tcp` feature to listen on TCP as well, or TCP only. Listen and peer addresses name their transport, so the address picks it:

```bash
cargo add minip2p-rs --features tcp
```

```rust
let endpoint = minip2p::Endpoint::builder()
    .listen_default()?
    .listen_on("/ip4/0.0.0.0/tcp/4001")?
    .bind()?;
# Ok::<(), minip2p::Error>(())
```

On bare-metal or other `no_std` hosts, turn off default features and build with `Endpoint::portable(...)`, supplying time samples, entropy, and a transport. With `smoltcp`, you get TCP plus optional mDNS, discovery, pubsub, AutoNAT, and relay on one embedded stack. See the [`minip2p-rs` crate guide](crates/minip2p/README.md#portable-endpoint).

For a complete application, run the gossipsub chat example:

```bash
cargo run -p minip2p-chat -- host --nick hostess
```

See [the chat guide](examples/chat/README.md) for NAT and cross-implementation recipes. The [peer example](examples/peer/README.md) demonstrates relay reservations and direct-path upgrades with DCUtR.

## Features

The base `Endpoint` includes whatever you bind — QUIC, TCP, or both — plus multistream-select, identify, ping, and any protocols registered with `EndpointBuilder::protocol`.

| Feature | Adds |
| --- | --- |
| `nat` | Circuit Relay v2, AutoNAT, and DCUtR traversal policy |
| `relay-server` | std-only Circuit Relay v2 hosting, independent of `nat` |
| `pubsub` | StrictSign gossipsub |
| `discovery` | Signed pubsub presence beacons and coordinated dialing; implies `nat` and `pubsub` |
| `mdns` | Local-link discovery and coordinated direct dialing; implies `nat` |

Features layer onto the same API. Lower-level users can instead drive `SwarmCore` and individual protocol crates directly with explicit inputs, outputs, timestamps, and deadlines.

Host a relay on QUIC and TCP with production defaults:

```bash
cargo run -p minip2p-relay-server-example
```

The [relay-server example](examples/relay-server/README.md) adds optional persistent identity, explicit public announce addresses, pause/resume controls, resource and rate limits, and readable typed lifecycle diagnostics while keeping the default builder path small.

## Architecture

The workspace has four strictly separated layers:

1. **Sans-I/O protocols** — identity, TLS, Noise, Yamux, multistream-select, ping, identify, relay, AutoNAT, DCUtR, pubsub, and mDNS. These crates contain state machines and wire codecs, not sockets or clocks.
2. **Sans-I/O orchestration** — `SwarmCore`, `NatAgent`, `RelayServerAgent`, `BeaconAgent`, and `PeerDiscoveryAgent` compose protocols and policy while remaining deterministic and I/O-free.
3. **Transport adapters** — `minip2p-tcp` over a pluggable `TcpProvider` byte-stream seam (`no_std + alloc`), and the quiche-based `minip2p-quic` over UDP (`std`-only). `TransportSet` puts several behind one contract and routes by address.
4. **`std` adapters** — the mDNS socket driver, the application-facing `Endpoint`, and the UniFFI adapter: the hosted end of the I/O seams.

The seams below layer 3 — `TcpProvider` and `MdnsIo` — are what let TCP and mDNS run on a device with no operating system. `StdTcpProvider` and `MdnsSockets` are the hosted implementations; `SmoltcpTcpProvider` and `SmoltcpMdnsIo` are the [smoltcp] ones. Everything above them is the same code either way.

[smoltcp]: https://docs.rs/smoltcp

The default swarm intentionally includes only identify, ping, and registered application protocols. Relay, traversal, pubsub, and discovery policy stay opt-in so the base remains small and predictable.

The TypeScript SDK runs on Node.js through `@minip2p/node` and on React Native through `@minip2p/react-native`. Both packages expose the same application interface.

Run the [Node.js ping example](examples/nodejs/README.md) to connect two local peers over QUIC or TCP.

Every crate has its own README with API-specific details.

## Development

[`just`](https://github.com/casey/just) commands mirror CI:

```bash
just test          # workspace tests, Endpoint feature matrix, and doctests
                   # requires cargo-nextest (https://get.nexte.st)
just clippy        # warnings-as-errors, feature variants, and fuzz crate
just fmt           # format the workspace and fuzz crate
just clean         # Cargo targets, node_modules, Turbo caches, docs output
just check-nostd   # no_std crates on thumbv7em-none-eabi
just bench
just fuzz 30       # requires nightly and cargo-fuzz
```

Docs and TypeScript bindings share a pnpm workspace at the repository root. Use the Node version in `.nvmrc`, then run:

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm --filter @minip2p/node native:build
pnpm test
pnpm lint
pnpm build:bindings
pnpm docs:check
```

Generate local API documentation with:

```bash
cargo doc --workspace --no-deps --open
```

All published Rust and TypeScript packages share one version. Releases also include freshly built Android and iOS libraries for React Native.

## License

[MIT](LICENSE)
