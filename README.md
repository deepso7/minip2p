# minip2p

A minimal [libp2p](https://libp2p.io/) implementation in Rust: small,
portable, understandable, and pleasant to use.

The project is built around five non-negotiables:

- **Sans-I/O architecture**: protocol and orchestration logic are
  deterministic state machines; sockets, clocks, and timers live only in
  adapters.
- **`no_std + alloc` core crates**, portable to embedded targets.
- **No `async`/`.await`**: everything is caller-driven and
  executor-independent.
- **QUIC only**: one great transport adapter; others are out of scope.
- **Top-notch DX** with clear defaults, actionable errors, and easy local
  bring-up.

`unsafe` is forbidden workspace-wide.

## Workspace status

Sans-I/O protocol crates (`no_std + alloc`):

- `crates/identity` (`minip2p-identity`): peer identity primitives, Ed25519 keys, varint helpers.
- `crates/core` (`minip2p-core`): transport-agnostic types (`Multiaddr`, `PeerAddr`, `Protocol`, `PeerId` re-export).
- `crates/transport` (`minip2p-transport`): transport contract, shared lifecycle types (trait + data types only).
- `crates/tls` (`minip2p-tls`): libp2p TLS certificate generation and peer verification.
- `crates/noise` (`minip2p-noise`): Sans-I/O libp2p Noise XX security handshake and transport cipher.
- `crates/yamux` (`minip2p-yamux`): bounded Sans-I/O libp2p Yamux stream multiplexer.
- `crates/multistream-select` (`minip2p-multistream-select`): `/multistream/1.0.0` negotiation state machine.
- `crates/ping` (`minip2p-ping`): `/ipfs/ping/1.0.0` state machine with RTT measurement.
- `crates/identify` (`minip2p-identify`): `/ipfs/id/1.0.0` state machine for protocol and address exchange.
- `crates/relay` (`minip2p-relay`): Circuit Relay v2 *client-side* state machines (`HopReservation`, `HopConnect`, `StopResponder`).
- `crates/autonat` (`minip2p-autonat`): AutoNAT reachability probe state machines.
- `crates/dcutr` (`minip2p-dcutr`): DCUtR hole-punch coordination state machines (`DcutrInitiator`, `DcutrResponder`).
- `crates/pubsub` (`minip2p-pubsub`): floodsub (`/floodsub/1.0.0`) — the libp2p pubsub RPC wire codec with StrictSign message signing, and the `FloodsubAgent` flooding router. Interops with go-libp2p and rust-libp2p.

Sans-I/O orchestrators (`no_std + alloc`):

- `crates/swarm` (`minip2p-swarm`): `SwarmCore` composes the protocol state machines, tracks connections and streams, drives multistream-select, and emits actions/events for the driver. Also ships a thin `std`-gated driver `Swarm<T: Transport>`.
- `crates/nat` (`minip2p-nat`): `NatAgent` NAT-traversal orchestrator — races direct dials against a relayed circuit, hole-punches with DCUtR over the bridge, and reports explicit path establish/upgrade/fallback events.
- `crates/discovery` (`minip2p-discovery`): signed pubsub presence-beacon codec and discovery agent — maintains a TTL address book, validates authenticated announcements, and emits deterministic dial and cancellation actions.

Runtime adapters (`std`):

- `crates/minip2p` (`minip2p`): app-facing facade that glues identity, QUIC, and the std swarm driver into an `Endpoint` API. Opt-in cargo features layer on without changing the base API:
  - `nat` wires the traversal agent into `Endpoint` (`connect`/`wait_path`/`take_nat_events`, relay reservations, AutoNAT probing).
  - `pubsub` adds floodsub (`subscribe`/`publish`/`take_pubsub_events`).
  - `discovery` composes `nat` and `pubsub` into signed peer discovery (`known_peers`/`next_discovery_event`), with coordinated dialing and bridge cleanup.
- `transports/quic` (`minip2p-quic`): QUIC transport adapter built on `quiche`, with libp2p TLS baked in. Owns UDP and DNS; exposes deadlines instead of running timers.

Examples:

- `examples/peer` (`minip2p-peer`): NAT-aware echo-ping demo — `listen` echoes pings (optionally holding a relay reservation), `dial` traverses NAT and shows the RTT drop when the hole punch upgrades the path mid-run.
- `examples/chat` (`minip2p-chat`): group chat over floodsub with NAT traversal — peers join a room by dialing one address, hole-punch direct paths where needed, and flood StrictSign-verified messages. Live-validated across real networks and against real go-libp2p and rust-libp2p peers.

Current validated behavior:

- Two local peers connect over QUIC in integration tests, with mutual libp2p TLS peer authentication.
- Bidirectional stream data exchange with half-close propagation.
- Multistream-select negotiation with spec-compliant varint framing.
- Ping round-trips with RTT measurement; identify exchange with observed-address plumbing.
- End-to-end stack via `minip2p::Endpoint`: QUIC + multistream-select + identify + ping + registered app protocols through one facade.
- NAT traversal live-validated end-to-end: relay reservation, circuit connect, DCUtR hole punch between two real NATs (home network ↔ mobile hotspot through a public relay), with explicit path events throughout.
- Floodsub live-validated: loopback and open-internet chat stars, star-forwarding, a NAT'd host punched into through a relay, and wire interop both ways with real go-libp2p (StrictSign) and rust-libp2p (unsigned, behind an explicit allow flag) peers.
- Pubsub peer discovery live-validated across a public host, home NAT, and mobile hotspot: automatic mesh formation, one-sided dial initiation, address updates, graceful punch-failure degradation, and leaf-to-leaf chat survival after host death.

## Architecture boundaries

Three layers, strictly separated:

1. Sans-I/O protocol crates — pure state machines, one per protocol. No sockets, no async runtimes, no wall clocks; callers pump inputs and timestamps in, actions and events come out.
2. Sans-I/O orchestrators (`swarm`, `nat`) — compose the protocol machines, still deterministic and I/O-free.
3. `std` adapters — the QUIC transport and the `Endpoint` facade own all real I/O.

The minimal default swarm intentionally composes only identify, ping, and
registered application protocols. Relay, AutoNAT, and DCUtR remain independent
Sans-I/O machines driven over generic streams; their dialing, retry, and
fallback policy belongs to the host. This keeps the base library small and
avoids hiding network policy in a monolithic swarm while still allowing
declarative protocol registration through `SwarmBuilder::protocol` and
`EndpointBuilder::protocol`. The `nat`, `pubsub`, and `discovery` facade
features are pre-packaged policy for the common case, built on the same public
hooks.

## Quick start

Build and run tests:

```bash
cargo test
```

Build an app endpoint with the top-level facade:

```rust
use minip2p::{Deadline, Endpoint, Event};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut node = Endpoint::builder()
        .agent_version("my-app/0.1.0")
        .bind_quic_dual_stack()?;

    let addrs = node.listen_all()?;
    println!("listening on {addrs:?}");

    // `next_event` also accepts an `Instant` or a relative `Duration`
    // when a wait needs a timeout.
    while let Some(event) = node.next_event(Deadline::NEVER)? {
        println!("{event:?}");
        if matches!(event, Event::ConnectionEstablished { .. }) {
            // The endpoint remains entirely caller-driven: keep polling,
            // or integrate `poll()` and transport deadlines in your host loop.
        }
    }
    Ok(())
}
```

`Endpoint` is the batteries-included synchronous facade. Custom runtimes can
drive `SwarmCore` and the protocol crates directly with inputs, outputs, and
explicit timestamps; none of those layers performs I/O, reads a clock, blocks,
or requires an async executor.

For the full stack in action, run the chat example (see
`examples/chat/README.md` for NAT'd and cross-implementation recipes):

```bash
cargo run -p minip2p-chat -- host --nick hostess
```

Common contributor workflows are available through `just` (mirrors CI):

```bash
just test          # cargo test + the minip2p feature matrix (nat, pubsub, nat+pubsub, discovery)
just clippy        # -D warnings, includes the separate fuzz/ workspace
just check-nostd   # no_std check on thumbv7em-none-eabi
just bench
just fuzz 30       # needs nightly + cargo-fuzz
```

## Documentation

Every crate has a README and rustdoc on all public APIs. Internal methods and types are commented for contributor onboarding.

Generate the full API docs with:

```bash
cargo doc --workspace --no-deps --open
```

## Roadmap focus

- [x] Local QUIC connectivity and integration coverage.
- [x] Multistream-select, ping, identify.
- [x] libp2p TLS peer authentication (mutual: both sides learn the PeerId at handshake time).
- [x] Swarm / connection management layer with builder DX.
- [x] Top-level `minip2p::Endpoint` facade for app authors.
- [x] Circuit Relay v2 client, DCUtR, and AutoNAT state machines.
- [x] NAT-traversal orchestration (`nat` feature), live-validated between two real NATs.
- [x] Floodsub pubsub (`pubsub` feature) with libp2p wire interop, plus the chat example.
- [x] Signed pubsub peer discovery (`discovery` feature), including automatic mesh dialing and host-death survival.
- [ ] Gossipsub, on the same pubsub API surface.
- [ ] A circuit transport, so relayed paths look like normal connections (today the relay bridge is a raw stream: chat requires a successful hole punch).
