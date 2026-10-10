# minip2p-nat

Sans-I/O NAT-traversal orchestrator for minip2p. The protocol machines (Circuit Relay v2, DCUtR, AutoNAT) live in their own crates; `NatAgent` is the relay-leg provider for a Connection attempt: it dials the relay, runs HOP CONNECT, promotes the circuit through Noise and Yamux, then runs DCUtR on that Relayed path. Direct candidate racing and the attempt's terminal outcome belong to the Connection-attempt engine.

`no_std + alloc`, no I/O, no clocks, no async.

## Connection model

Parallel racing with convergence — not sequential fallback:

```text
t0      caller races direct candidates (ConnectEngine)
t0+δ    relay leg (stagger δ when direct_racing, else now):
          for each eligible relay, within its share of the leg deadline:
            ensure relay session → HOP CONNECT(target)
            relay fails (unreachable, refused, share elapsed) ⇒ next relay
          → Bridged ⇒ promote bridge through Noise + Yamux
          → circuit Connected ⇒ PathEstablished(Relayed)  (provisional)
          → reserved peer opens /libp2p/dcutr on the Relayed path
inbound STOP circuit Connected ⇒ InboundPathEstablished(Relayed)
a better path later  ⇒ PathUpgraded { from, to }  (+ the circuit closes)
punch exhausted      ⇒ FellBackToRelay            (engine settles Connected)
relay leg dead       ⇒ ConnectFailed { error }    (engine decides the attempt)
```

Ranking: `DirectDialed` ≈ `DirectPunched` > `Relayed`.

HOP CONNECT only works at a relay where the _target_ holds a reservation, so the relay leg tries the configured relays one at a time. Relays that `ConnectLegs::target_addrs` name in a circuit address (`.../p2p/<relay>/p2p-circuit`) go first, the rest follow in `NatConfig::relays` order; relays that are not configured are never used. A relay listed under several addresses is tried at the next address when the previous one could not reach it; once it is reached, its other addresses are skipped. A bridge that fails to promote, or a circuit that closes before it carries a path, counts as that relay failing. Each relay gets `remaining / relays left` of `relay_leg_deadline_ms`, split across its addresses, so a relay that fails fast leaves its time to the rest and one stalled relay cannot use up the leg. The leg fails only after every relay has failed, with the last relay's error (`NatError::Timeout` when the last one ran out the leg deadline).

## Relayed paths are normal connections

`Path::Relayed { relay }` is metadata describing how the peer was reached. The bridge itself is promoted through end-to-end Noise XX and Yamux before `PathEstablished` (outbound) or `InboundPathEstablished` (inbound) is emitted. Identify, ping, pubsub, and application protocols can therefore use the ordinary swarm stream APIs without knowing whether the selected connection is direct or relayed.

Set `NatConfig::force_relay` to skip direct candidates and DCUtR entirely. This is useful for deterministic relay-only deployments and tests. Stalled outbound promotions are bounded by `relay_leg_deadline_ms`; inbound promotions are bounded by `circuit_handshake_timeout_ms`. The Connection-attempt engine owns the overall 30 s deadline.

## Driving the agent

```rust,ignore
use minip2p_core::ConnectId;
use minip2p_nat::{ConnectLegs, NatAgent, NatConfig};

let mut agent = NatAgent::new(local_peer_id, NatConfig {
    relays: vec![relay_peer_addr],
    ..NatConfig::default()
});
agent.set_listen_addrs(&validated_external_addrs);

let id = ConnectId::from_u64(1);
let legs = ConnectLegs {
    direct_racing: true,
    allow_relay: true,
    target_addrs: known_addrs_for_target, // circuit addresses steer relay choice
    deadline_ms: Some(attempt_expires_mono_ms), // relays split the time left
};
// `swarm` is any `NatSwarm`; `SwarmCore` implements it. It is passed into
// each call, never stored, and the agent issues dials, stream opens,
// writes, resets, and pings on it directly.
agent.connect(&mut swarm, id, target_peer, legs, now());

loop {
    // 1. Feed swarm events by reference, with the transport's circuit
    //    classification of the connection they bring up. The disposition
    //    stays true even when handling claims or releases a control-plane
    //    stream, so only forward events for which it returns false.
    let is_circuit = transport.is_circuit_connection(swarm_event.connection_id());
    let consumed = agent.handle_event(&mut swarm, &swarm_event, is_circuit, now());
    if !consumed { /* forward swarm_event to the application */ }
    // 2. Execute what needs the transport under the swarm.
    while let Some(action) = agent.poll_action() {
        match action {
            NatAction::PromoteBridge { token, .. } => {
                let result = promote_bridge(/* ... */);
                agent.promote_result(&mut swarm, token, result, now());
            }
            NatAction::SendRandomUdp { .. } | NatAction::CloseCircuit { .. } => { /* ... */ }
        }
    }
    // 3. Surface events to the application.
    while let Some(event) = agent.poll_event() { /* ... */ }
    // 4. Sleep at most `agent.next_timeout(now_ms)`, then tick.
    agent.handle_tick(&mut swarm, now());
}
```

### Reading the swarm

The agent keeps no copy of connections or readiness; it reads both from the `NatSwarm` each call. That state may be ahead of the event being handled (a host hands over a batch the swarm already applied), so the agent follows two rules: what it owns (dials, streams, reservations, path origins) is keyed by the exact connection id an event carries, and live swarm state only decides whether new work may start. Cleanup for a closed or replaced connection ends only the work bound to that connection, never work already started on its replacement. Readiness-triggered work starts only when the `PeerReady` connection is still the peer's ready one.

A dial to a concrete `/ip4`/`/ip6` address starts synchronously (`DialStart::Started`); its outcome arrives as `ConnectionEstablished` or `DialFailed`. The bare `SwarmCore` implementation rejects `/dns*` addresses with `NatSwarmError::NamedAddress`. A host that resolves names wraps the swarm in a small adapter that parks such a dial and returns `DialStart::Deferred`, keeping the token the agent passed in: the agent allocates and registers that token before the dial reaches the host, so the result can come back at any later point. Before dialing and reporting the parked dial through `agent.dial_result(&mut swarm, token, result, now)`, the host calls `agent.deferred_dial_wanted(token, now)` and drops the dial when that returns `false`: the owning flight has moved on, and a late result must not land on a newer one.

The `minip2p` crate (cargo feature `nat`) wires exactly this loop into `Endpoint` so applications get `connect(target)`, `ConnectSettled`, and `EndpointEvent::Nat(..)` from `Endpoint::wait` without touching the pump. Attempt terminals (`ConnectFailed`, `FellBackToRelay`) are consumed by the Endpoint's Connection-attempt engine and surface only as `ConnectSettled`:

```rust,ignore
use minip2p::{EndpointEvent, EndpointWaitOutcome, NatEvent};

let mut node = minip2p::Endpoint::builder()
    .relay(relay_peer_addr)
    .listen_default()?
    .bind()?;
node.listen_all()?;
let id = node.connect(vec_of_peer_addrs)?;
let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
loop {
    match node.wait(deadline)? {
        EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::PathEstablished {
            connect_id,
            path,
            ..
        })) if connect_id == id => println!("reached peer via {path:?}"),
        EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled { connect_id, outcome, .. })
            if connect_id == id =>
        {
            println!("settled: {outcome:?}");
            break;
        }
        EndpointWaitOutcome::Event(other) => { /* dispatch unrelated events */ }
        EndpointWaitOutcome::Interrupted => {}
        EndpointWaitOutcome::Deadline => {
            node.cancel_connect(id); // the deadline is local; cancel explicitly
            break;
        }
    }
}
```

## Own-side housekeeping

Independent of connect attempts, the agent also runs:

- **Reachability probing** (`NatConfig::autonat_servers`): single-shot AutoNAT probes aggregated through an M-sample window — the verdict flips only when N of the last M probes agree (defaults N=3, M=5), so one flaky probe never flaps `ReachabilityChanged`.
- **Relay reservations** (`NatConfig::reservation_policy`): held per policy (`Always` / `WhenPrivate` / `Never`), renewed at half the relay-reported lifetime, capped at `reservation_default_ttl_secs` (which is also the fallback when the relay omits `expire`, reports one already past, or the host has no wall clock), so renewal still lands before the actual expiry while the relay's clock runs less than half the reported lifetime ahead of ours, rotating relays with backoff on refusal, and reacquiring after a lost relay session. When the swarm replaces the connection carrying the reservation (`SwarmEvent::ConnectionReplaced`), the agent reports the reservation lost at once (withdrawing its circuit address), cancels any exchange on the old connection, and reserves again on the new one once it is ready: rust-libp2p relays drop a reservation with the connection that made it, so a reservation is bound to that exact connection. While a QUIC reservation is held, the agent pings the relay every `reservation_keep_alive_interval_ms` (15 seconds by default) so an otherwise idle connection does not reach QUIC's idle timeout. Set it below the configured QUIC idle timeout; `0` disables these pings. TCP reservations do not schedule them. In the `minip2p` endpoint, successful automatic pings emit the same `EndpointEvent::PingRttMeasured` event as a caller-requested ping. `WhenPrivate` reserves while reachability is Unknown or Private and releases once probes settle on Public.

## Responder side

A NAT'd listener holding a reservation handles inbound circuits automatically: the relay's STOP CONNECT is auto-accepted and the bridge is promoted into a normal circuit connection. The agent announces that Relayed path, opens `/libp2p/dcutr`, and sends CONNECT followed by SYNC. It emits `SendRandomUdp` blasts at the original circuit dialer's observed addresses to open its own NAT mapping (first after half the measured relay RTT, then every `blast_interval_ms` until `punch_deadline_ms`). The original circuit dialer makes the QUIC simultaneous-open dial. A landed punch is announced with `InboundDirectUpgrade` and replaces the circuit.

## Connection replacement and paths

The swarm keeps one connection per peer. When a newer connection takes the slot (`SwarmEvent::ConnectionReplaced { peer_id, old, new }`), the agent applies `new` before retiring `old`, so the peer never counts as disconnected and no relay leg or inbound flow fails just because `old` went away. Everything bound to `old` ends: its streams, its observed address, and the peer's readiness (`PeerReady` for `new` restarts what waits on it). A connection-level disconnect (`ConnectionClosed`) is acted on immediately.

Each connection records the path origin a NAT machine announced for it: Direct (dialed or punched) or Relayed through a relay, plus the Connect ID of the attempt that created it. `NatAgent::path` reports the origin of the peer's current connection. On a replacement the path becomes `new`'s origin; leaving a relay for a direct connection is reported exactly once, as `PathUpgraded` against the attempt that created the relayed path, or as `InboundDirectUpgrade` when it came from an inbound circuit. Other changes, such as relay A to relay B, only update the path.

## Status

- Dialer-side race (direct dials × relay leg × DCUtR punch): implemented, covered by scripted no-I/O tests in `tests/arbitration.rs`; relay rotation within one attempt in `tests/relay_rotation.rs`.
- Housekeeping (AutoNAT confidence aggregation, relay reservation renewal): implemented, covered by `tests/housekeeping.rs`.
- Responder side (inbound STOP circuits, punch-window UDP blasts): implemented, covered by `tests/inbound.rs` plus a two-agent end-to-end exchange over an in-memory relay emulator (`tests/two_agents.rs`).
- Scripted tests run against one shared fake `NatSwarm` (`tests/common`); `tests/real_swarm.rs` checks command results and event ordering against a real `SwarmCore`.
