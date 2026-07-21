# minip2p-nat

Sans-I/O NAT-traversal orchestrator for minip2p. The protocol machines
(Circuit Relay v2, DCUtR, AutoNAT) live in their own crates; `NatAgent` is
the missing conductor: it races direct dials against a relayed circuit,
starts a DCUtR hole punch over the bridge the moment it exists, and reports
every path decision explicitly.

`no_std + alloc`, no I/O, no clocks, no async.

## Connection model

Parallel racing with convergence — not sequential fallback:

```text
t0      direct leg: dial every validated candidate address
t0+δ    relay leg (stagger δ, default 200 ms; 0 = fully parallel):
          ensure relay session → HOP CONNECT(target)
          → Bridged ⇒ DCUtR punch starts over the bridge
          → after SYNC, promote bridge through Noise + Yamux
          → circuit Connected ⇒ PathEstablished(Relayed)
first usable path wins
a better path later  ⇒ PathUpgraded { from, to }  (+ the circuit closes)
punch exhausted      ⇒ FellBackToRelay            (the circuit stays usable)
nothing worked       ⇒ ConnectFailed { error }
```

Ranking: `DirectDialed` ≈ `DirectPunched` > `Relayed`.

## Relayed paths are normal connections

`Path::Relayed { relay }` is metadata describing how the peer was reached.
The bridge itself is promoted through end-to-end Noise XX and Yamux before
`PathEstablished` is emitted. Identify, ping, pubsub, and application
protocols can therefore use the ordinary swarm stream APIs without knowing
whether the selected connection is direct or relayed.

Set `NatConfig::force_relay` to skip direct candidates and DCUtR entirely.
This is useful for deterministic relay-only deployments and tests. Stalled
outbound promotions are bounded by `connect_deadline_ms`; inbound promotions
are bounded by `circuit_handshake_timeout_ms`.

## Driving the agent

```rust,ignore
let mut agent = NatAgent::new(local_peer_id, NatConfig {
    relays: vec![relay_peer_addr],
    ..NatConfig::default()
});
agent.set_listen_addrs(&validated_external_addrs);

let id = agent.connect(target_peer, candidate_addrs, now());

loop {
    // 1. Feed swarm events by reference. The disposition stays true even
    //    when handling claims or releases a control-plane stream, so only
    //    forward events for which it returns false to the application.
    let is_circuit = transport.is_circuit_connection(swarm_event.connection_id());
    let consumed = agent.handle_event_with_disposition_classified(
        &swarm_event,
        is_circuit,
        now(),
    );
    if !consumed { /* forward swarm_event to the application */ }
    // 2. Execute actions, echoing synchronous results back.
    while let Some(action) = agent.poll_action() {
        match action {
            NatAction::Dial { token, addr } =>
                agent.dial_result(token, swarm.dial(&addr).map_err(|e| e.to_string()), now()),
            NatAction::OpenStream { token, peer, protocol_id } =>
                agent.stream_open_result(
                    token,
                    swarm.open_stream(&peer, &protocol_id).map_err(|e| e.to_string()),
                    now(),
                ),
            NatAction::PromoteBridge { token, .. } =>
                agent.promote_result(token, promote_bridge(/* ... */), now()),
            // SendStream / ResetStream / ... map 1:1 onto Swarm methods.
            _ => { /* ... */ }
        }
    }
    // 3. Surface events to the application.
    while let Some(event) = agent.poll_event() { /* ... */ }
    // 4. Sleep at most `agent.next_timeout(now_ms)`, then tick.
    agent.handle_tick(now());
}
```

The `minip2p` facade (cargo feature `nat`) wires exactly this loop into
`Endpoint` so applications get `connect(&peer)` / `wait_path(...)` /
`take_nat_events()` without touching the pump:

```rust,ignore
let mut node = minip2p::Endpoint::builder()
    .relay(relay_peer_addr)
    .bind_quic("0.0.0.0:0")?;
node.listen_all()?;
let id = node.connect_with_addrs(peer, candidate_addrs)?;
if let Some(path) = node.wait_path(id, std::time::Duration::from_secs(30))? {
    println!("reached peer via {path:?}");
}
```

## Own-side housekeeping

Independent of connect attempts, the agent also runs:

- **Reachability probing** (`NatConfig::autonat_servers`): single-shot
  AutoNAT probes aggregated through an M-sample window — the verdict flips
  only when N of the last M probes agree (defaults N=3, M=5), so one flaky
  probe never flaps `ReachabilityChanged`.
- **Relay reservations** (`NatConfig::reservation_policy`): held per policy
  (`Always` / `WhenPrivate` / `Never`), renewed
  `reservation_renewal_margin_secs` before the relay-reported `expire`
  (default-TTL fallback when the relay omits it or the host has no wall
  clock), rotating relays with backoff on refusal, and reacquiring after a
  lost relay session. `WhenPrivate` reserves while reachability is Unknown
  or Private and releases once probes settle on Public.

## Responder side

A NAT'd listener holding a reservation handles inbound circuits
automatically: the relay's STOP CONNECT is auto-accepted, the initiator's
DCUtR exchange is answered with our validated addresses, and on SYNC the
agent emits `SendRandomUdp` blasts at the initiator's observed addresses
to open its own NAT mapping (first after `responder_sync_delay_ms`, then
every `blast_interval_ms` until `punch_deadline_ms`). Per DCUtR for QUIC
only the initiator dials — the blasts make that dial land. The bridge is
promoted into a normal circuit connection; a landed punch is announced with
`InboundDirectUpgrade` and supersedes that circuit.

## Status

- Dialer-side race (direct dials × relay leg × DCUtR punch): implemented,
  covered by scripted no-I/O tests in `tests/arbitration.rs`.
- Housekeeping (AutoNAT confidence aggregation, relay reservation renewal):
  implemented, covered by `tests/housekeeping.rs`.
- Responder side (inbound STOP circuits, punch-window UDP blasts):
  implemented, covered by `tests/inbound.rs` plus a two-agent end-to-end
  exchange over an in-memory relay emulator (`tests/two_agents.rs`).
