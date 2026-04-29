# Hole-punch CLI plan (`examples/peer`)

Living plan for the remaining work on the `holepunch` branch. Covers the
runnable `minip2p-peer` CLI that exercises the full stack (QUIC + Swarm +
relay + DCUtR) against a real relay server. This file is scoped to the CLI
and its testing story; the overall project roadmap stays in `plan.md`.

## Goal

Two peers, both behind NAT, pinging each other over a direct QUIC connection
established via a relay-coordinated hole punch. If the hole punch fails, the
peers fall back to pinging over the relay circuit.

## Assumptions

- Local rust-libp2p relay for the first iteration (see the manual
  testing section for the exact `cargo run` invocation). A public
  VM-hosted relay is the next step for cross-network testing.
- Both peers are minip2p. We skip Noise and Yamux on the bridged stream --
  DCUtR frames flow directly over the relay bridge with length-prefixed
  framing.
- No interop with third-party libp2p peers over relay (documented
  limitation).

## Non-goals

- Running the relay itself from minip2p. We only implement the client side
  of HOP and the responder side of STOP.
- Interop with non-minip2p peers over the relay bridge.
- Automatic relay discovery (DHT, bootstrap nodes). The user supplies the
  relay multiaddr.

## Usage

```
# Direct mode (no relay -- validates the basic stack works locally)
minip2p-peer listen
minip2p-peer dial <multiaddr>/p2p/<peer-id>

# Relay mode (the full hole-punch flow)
minip2p-peer listen --relay <relay-multiaddr>/p2p/<relay-peer-id>
minip2p-peer dial  --relay <relay-multiaddr>/p2p/<relay-peer-id> \
                   --target <peer-b-id>
```

Planned internet-ready usage:

```
minip2p-peer listen \
  --relay /ip4/<relay-ip>/udp/4001/quic-v1/p2p/<relay-peer-id> \
  --autonat /ip4/<autonat-ip>/udp/4002/quic-v1/p2p/<autonat-peer-id> \
  --key ./peer-b.key \
  --listen /ip4/0.0.0.0/udp/0/quic-v1

minip2p-peer dial \
  --relay /ip4/<relay-ip>/udp/4001/quic-v1/p2p/<relay-peer-id> \
  --target <peer-b-id> \
  --autonat /ip4/<autonat-ip>/udp/4002/quic-v1/p2p/<autonat-peer-id> \
  --key ./peer-a.key \
  --listen /ip4/0.0.0.0/udp/0/quic-v1
```

`minip2p-peer autonat` runs a public AutoNAT service. Relay modes can pass
`--autonat <peer-addr>` to ask that service to dial their advertised candidates
before exchanging DCUtR addresses. The AutoNAT wire logic lives in
`minip2p-autonat`, a `no_std + alloc` Sans-I/O crate; the CLI owns stream I/O,
dial-back attempts, and deadlines. Repeatable `--external-addr` remains
available for known public addresses and port-forwards.

Output format is plain text, one event per line, prefixed with a role tag:

```
[listen] bound=/ip4/127.0.0.1/udp/52134/quic-v1 peer=12D3KooW...
[listen] reserved-on-relay addrs=[...]
[listen] incoming-circuit from=12D3KooW...
[listen] dcutr-sync-received remote-addrs=[...]
[listen] direct-connected rtt=42ms
[listen] ping 12D3KooW... 12ms
```

## File layout

```
examples/peer/
  Cargo.toml        # to be created; must be added to the workspace
                    # [workspace].members array in the root Cargo.toml
  src/
    main.rs         # argv parsing + dispatch to mode
    direct.rs       # mode 1 (listen / dial) -- pure Swarm usage
    relay.rs        # mode 2 (listen / dial) -- orchestrates relay + dcutr
    holepunch.rs    # shared hole-punch attempt logic + timing
    cli.rs          # multiaddr parsing, event printing helpers
```

Target budget: ~500 lines total.

## Step 0: Scaffold the crate (prerequisite)

Before any of the mode implementations, create `examples/peer/` with a
minimal `Cargo.toml` and `src/main.rs`, and register it under
`[workspace].members` in the root `Cargo.toml`. Confirm with
`cargo check -p minip2p-peer` before moving on.

## Mode 1: Direct (no relay)

Straightforward Swarm usage. Serves two purposes: proves the basic stack
works, and gives us a smoke-test we can run without any relay setup.

```rust
// Listener
let mut swarm = SwarmBuilder::new(&keypair).agent_version(...).build(transport);
swarm.transport_mut().listen_on_bound_addr()?;
println!("[listen] bound={}", swarm.transport().local_peer_addr()?);
loop {
    for event in swarm.poll()? { print_event(event); }
    sleep(5ms);
}

// Dialer
let mut swarm = SwarmBuilder::new(&keypair)...;
let _ = swarm.dial(&peer_addr)?;
loop {
    for event in swarm.poll()? {
        match event {
            SwarmEvent::IdentifyReceived { peer_id, .. } => { swarm.ping(&peer_id)?; }
            SwarmEvent::PingRttMeasured { peer_id, rtt_ms } => {
                println!("[dial] ping {peer_id} {rtt_ms}ms");
                return Ok(());
            }
            _ => print_event(event),
        }
    }
    sleep(5ms);
}
```

No new Swarm APIs needed.

## Mode 2: Relay listener (Peer B, the NATed target)

State machine driven off `SwarmEvent::UserStream*` events for the user
protocols `HOP_PROTOCOL_ID`, `STOP_PROTOCOL_ID`, `DCUTR_PROTOCOL_ID`.

```
States:
  ConnectingToRelay
    -> (ConnectionEstablished to relay) Reserving
  Reserving { hop_stream, flow: HopReservation }
    -> (flow.outcome = Accepted) WaitingForCircuit
  WaitingForCircuit
    -> (UserStreamReady(STOP_PROTOCOL, !initiated_locally)) StopAccepting
  StopAccepting { stop_stream, flow: StopResponder }
    -> (flow.request populated) -> accept, emit StopResponderBridged
    -> (on_bridge_data) DcutrExchange
  DcutrExchange { stop_stream, flow: DcutrResponder, remote_addrs }
    -> (poll_events = ConnectReceived) capture remote_addrs
    -> (poll_events = SyncReceived) HolePunching
  HolePunching { remote_addrs, deadline: now + 10s }
    -> (swarm emits ConnectionEstablished for non-relay peer) PingingDirect
    -> (deadline expired) PingingRelay (fallback)
  PingingDirect { peer }
  PingingRelay { bridge_stream }
```

Startup:

```rust
let mut swarm = SwarmBuilder::new(&keypair)...build(transport);
swarm.add_user_protocol(HOP_PROTOCOL_ID);
swarm.add_user_protocol(STOP_PROTOCOL_ID);
swarm.add_user_protocol(DCUTR_PROTOCOL_ID);

// Listen on the same UDP socket so we can accept direct connections
// during the hole punch without rebinding.
swarm.transport_mut().listen_on_bound_addr()?;
swarm.dial(&relay_addr)?;
```

Bridging details:

- When `StopResponder::accept()` returns, we're "on the bridge". Drain
  `take_bridge_bytes()` and hand those bytes to a fresh `DcutrResponder`.
  Subsequent `UserStreamData` events on the same `stream_id` go straight
  to `DcutrResponder::on_data()`.
- When `DcutrResponder` emits `ConnectReceived`, flush its outbound via
  `swarm.send_user_stream()`.
- When `DcutrResponder` emits `SyncReceived`, kick off hole punch.

Hole-punch specifics (responder side, per the DCUtR spec):

1. Wait `rtt / 2` before starting UDP bombardment. For now we approximate
   `rtt` as a small constant (say 100 ms) because the responder never
   measured it -- the initiator did. A future refinement will piggy-back
   the measured RTT on the DCUtR message sequence.
2. Send random UDP packets (32 random bytes) every 10-200 ms to each
   address in `remote_addrs` via `swarm.transport().send_raw_udp()`. Stop
   when we see `SwarmEvent::ConnectionEstablished` from a non-relay peer,
   or when the 10-second deadline expires.
3. On direct-connection success: run ping on the direct connection (normal
   `swarm.ping()` path).
4. On timeout: fall back to sending a 32-byte payload on the relay
   bridge stream and timing the echo manually; print the result as
   `via-relay rtt=...`. Bridge ping is not a real libp2p protocol here --
   just a simple echo to prove the bridge works end-to-end.

## Mode 2: Relay dialer (Peer A, the NATed initiator)

```
States:
  ConnectingToRelay
    -> (ConnectionEstablished to relay) Connecting
  Connecting { hop_stream, flow: HopConnect(target) }
    -> (flow.outcome = Bridged) DcutrExchange
  DcutrExchange { hop_stream, flow: DcutrInitiator, send_time }
    -> (flow.outcome = DialNow { remote_addrs, rtt_ms }) HolePunching
    -- also: flow.send_sync() + flush outbound
  HolePunching { target_peer, target_addrs, deadline }
    -- issue swarm.dial() to each addr in target_addrs immediately
    -> (ConnectionEstablished for target_peer on non-relay conn) PingingDirect
    -> (deadline expired) PingingRelay (fallback)
```

Identical bridging plumbing as the listener, with `HopConnect` in place of
`HopReservation` / `StopResponder`, and `DcutrInitiator` in place of
`DcutrResponder`.

The dialer's hole-punch behavior (per the DCUtR spec) is simpler than the
responder's: on receiving B's CONNECT reply, A immediately dials each of
B's observed addresses via `swarm.dial(&addr)`. No random UDP packets --
that's only on the responder side.

## Bridged-stream plumbing (shared)

After HOP CONNECT or STOP CONNECT completes, the same `stream_id` hosts
DCUtR frames. The state-machine state stores the stream id; the event loop
routes `UserStreamData` events for that id into the DCUtR state machine
and flushes `DcutrXxx::take_outbound()` via `send_user_stream`.

The relay crate's `HopConnect::take_bridge_bytes()` and
`StopResponder::take_bridge_bytes()` capture any bytes pipelined in the
same packet as the STATUS:OK reply; those drive the initial DCUtR CONNECT
frame delivery without needing a separate poll round.

## Open design questions to resolve during implementation

- **RTT for the responder's SYNC timing.** The DCUtR spec says the
  responder waits `rtt / 2` after `SyncReceived` before blasting UDP. We
  don't currently carry the measured RTT from the initiator to the
  responder -- the spec expects the responder to compute its own by
  measuring the round trip of CONNECT / CONNECT. For v1 use a fixed
  100 ms approximation; revisit once the flow is working.
- **Bridge ping fallback protocol id.** The fallback "ping over the
  relay" is a bespoke echo, not `/ipfs/ping/1.0.0`, because we can't run
  multistream-select inside the already-bridged stream (we'd have to stop
  the bridge, run MSS, and resume -- not worth it). Document this as
  `/minip2p/relay-ping/1.0.0` (dummy id, only meaningful between two
  minip2p peers) and make the payload format obvious (32 random bytes,
  echoed).
- **Multiple direct-dial candidates.** If B advertises multiple observed
  addresses (home + carrier), A dials all of them and keeps the first
  that establishes. On timeout, cancel the others.
- **Connection id tracking across modes.** We dial the relay first, then
  later dial the target peer directly. Swarm's `ConnectionEstablished`
  event gives us the peer id but not which dial call it corresponds to.
  The hole-punch success criterion is specifically "a new
  `ConnectionEstablished` for `target_peer_id` (the peer we're punching
  to)" -- not "any peer other than the relay". Using the negative
  formulation (`peer_id != relay_peer_id`) would misclassify any
  unrelated inbound connection as a hole-punch success. The initiator
  carries `target_peer_id` from the CLI args; the responder learns it
  from the STOP `CONNECT` message's `source_peer_id` field.

## Testing strategy

### Automated (CI-safe)

1. Direct-mode loopback test: spawn listener + dialer in two threads,
   assert the dialer prints a ping RTT within 5 seconds. Scripted with
   `std::process::Command`. Lives in `examples/peer/tests/direct.rs`.

2. Relay-mode loopback test with a **minimal in-process fake relay**.
   Rather than spinning up rust-libp2p, write a test-only fake relay
   (reuses the pattern from `crates/swarm/tests/relay_holepunch_flow.rs`
   but over real QUIC). Estimated cost is ~300 lines and gives us a CI
   signal that the full stack works. Defer if it balloons.

### Manual

1. Start a rust-libp2p relay server. From a checked-out `rust-libp2p`
   tree, run `cargo run --example relay-server-example` (the example
   lives at `examples/relay-server/`; verify the exact binary name
   against the repo state at time of use, as it has historically
   drifted). Note the `PeerAddr` it prints -- used as `<relay-addr>`
   below.
2. Terminal 1: `cargo run -p minip2p-peer -- listen --relay <relay-addr>`
3. Terminal 2: `cargo run -p minip2p-peer -- dial --relay <relay-addr> --target <B-peer-id>`
4. Both terminals should eventually print `direct-connected` or
   `via-relay` followed by a ping RTT.

## Deliverable checklist

- [x] Scaffold `examples/peer/` (Cargo.toml + main.rs) and register in
      root `Cargo.toml` workspace members (~20 LOC)
- [x] `examples/peer/src/main.rs` argv parsing (~50 LOC)
- [x] `examples/peer/src/direct.rs` direct mode listener + dialer (~80 LOC)
- [x] `examples/peer/src/relay.rs` relay mode state machines (~250 LOC)
- [x] Shared hole-punch dial/UDP logic (implemented inline in
      `examples/peer/src/relay.rs` rather than a separate `holepunch.rs`)
- [x] `examples/peer/src/cli.rs` multiaddr parsing, event printing (~60 LOC)
- [x] Automated direct-mode E2E test
- [ ] Automated relay-mode test with fake relay (optional, defer if
      oversized)
- [ ] Manual verification against rust-libp2p `relay-server-example`
- [x] Brief README at `examples/peer/README.md` with run instructions
      (this is the one README we should actually write because users will
      run the binary)

## Internet-Ready Follow-Ups

1. Persistent identity files -- DONE
   - [x] Add `--key <path>` to direct and relay modes.
   - [x] Generate an Ed25519 key if the file does not exist; reuse it if present.
   - [x] Print the stable peer id on startup so remote peers can use it as `--target`.
   - [x] Keep storage deliberately simple and application-owned; use raw secret import/export from `minip2p-identity`.

2. Configurable bind/listen address -- DONE
   - [x] Keep `127.0.0.1:0` as the no-flag default for fast local DX.
   - [x] Add `--listen <quic-multiaddr>` for real-network runs.
   - [x] Support `/ip4/0.0.0.0/udp/0/quic-v1` and `/ip6/::/udp/0/quic-v1` as bind forms.

3. Manual external address candidates -- DONE
   - [x] Add repeatable `--external-addr <quic-multiaddr>`.
   - [x] Include these addresses in DCUtR candidate payloads alongside observed/listen addresses.
   - [x] Prefer explicit external addresses over loopback/private listen addresses for cross-network hole punching.

4. Public relay walkthrough and diagnostics -- DONE (manual verification still pending)
   - [x] Document rust-libp2p relay startup with public UDP/TCP ports open.
   - [x] Show exact listener and dialer commands.
   - [x] Log observed relay address, DCUtR candidates, direct dial attempts, direct timeout/failure reason, and relay fallback reason.

5. AutoNAT reachability validation -- DONE
   - [x] Add `minip2p-autonat` (`no_std + alloc`, Sans-I/O) for AutoNAT request/response state machines.
   - [x] Add `minip2p-peer autonat` service mode for public dial-back checks.
   - [x] Add relay-mode `--autonat <peer-addr>` to validate advertised DCUtR candidates before relay/DCUtR exchange.
   - [x] Keep manual `--external-addr` as an override/debug path.

## Future follow-ups (not on this branch)

- Relay + DCUtR integration directly into `Swarm` (today the CLI
  orchestrates the state machines manually over the user-protocol API).
  Move the orchestration into Swarm once we have enough experience from
  the CLI to know the right abstraction.
- Noise + Yamux over the relay bridge for interop with third-party
  libp2p peers.
- Relay discovery (e.g. through DHT or a bootstrap list) instead of
  requiring the user to supply the relay multiaddr.
