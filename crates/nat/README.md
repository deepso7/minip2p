# minip2p-nat

Sans-I/O NAT-traversal orchestrator for minip2p. The protocol machines (Circuit Relay v2, DCUtR, AutoNAT) live in their own crates; `NatAgent` is the relay-leg provider for a Connection attempt: it dials the relay, runs HOP CONNECT, promotes the circuit through Noise and Yamux, then runs DCUtR on that Relayed path. Direct candidate racing and the attempt's terminal outcome belong to the Connection-attempt engine.

`no_std + alloc`, no I/O, no clocks, no async.

## Connection model

Parallel racing with convergence — not sequential fallback:

```text
t0      caller races direct candidates (ConnectEngine)
t0+δ    relay leg (stagger δ when direct_racing, else now):
          ensure relay session → HOP CONNECT(target)
          → Bridged ⇒ promote bridge through Noise + Yamux
          → circuit Connected ⇒ PathEstablished(Relayed)  (provisional)
          → reserved peer opens /libp2p/dcutr on the Relayed path
inbound STOP circuit Connected ⇒ InboundPathEstablished(Relayed)
a better path later  ⇒ PathUpgraded { from, to }  (+ the circuit closes)
punch exhausted      ⇒ FellBackToRelay            (engine settles Connected)
relay leg dead       ⇒ ConnectFailed { error }    (engine decides the attempt)
```

Ranking: `DirectDialed` ≈ `DirectPunched` > `Relayed`.

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
agent.connect(id, target_peer, ConnectLegs { direct_racing: true, allow_relay: true }, now());

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

The `minip2p` crate (cargo feature `nat`) wires exactly this loop into `Endpoint` so applications get `connect(&peer)` / `nat_wait_path(...)` / `take_nat_events()` without touching the pump:

```rust,ignore
let mut node = minip2p::Endpoint::builder()
    .relay(relay_peer_addr)
    .bind_quic("0.0.0.0:0")?;
node.listen_all()?;
let id = node.connect(vec_of_peer_addrs)?;
if let Some(path) = node.nat_wait_path(id, std::time::Duration::from_secs(30))? {
    println!("reached peer via {path:?}");
}
```

## Own-side housekeeping

Independent of connect attempts, the agent also runs:

- **Reachability probing** (`NatConfig::autonat_servers`): single-shot AutoNAT probes aggregated through an M-sample window — the verdict flips only when N of the last M probes agree (defaults N=3, M=5), so one flaky probe never flaps `ReachabilityChanged`.
- **Relay reservations** (`NatConfig::reservation_policy`): held per policy (`Always` / `WhenPrivate` / `Never`), renewed `reservation_renewal_margin_secs` before the relay-reported `expire` (default-TTL fallback when the relay omits it or the host has no wall clock), rotating relays with backoff on refusal, and reacquiring after a lost relay session. While a QUIC reservation is held, the agent requests a ping every `reservation_keep_alive_interval_ms` (15 seconds by default) so an otherwise idle connection does not reach QUIC's idle timeout. Set it below the configured QUIC idle timeout; `0` disables these pings. TCP reservations do not schedule them. In the `minip2p` endpoint, successful automatic pings emit the same `Event::PingRttMeasured` event as a caller-requested ping. `WhenPrivate` reserves while reachability is Unknown or Private and releases once probes settle on Public.

## Responder side

A NAT'd listener holding a reservation handles inbound circuits automatically: the relay's STOP CONNECT is auto-accepted and the bridge is promoted into a normal circuit connection. The agent announces that Relayed path, opens `/libp2p/dcutr`, and sends CONNECT followed by SYNC. It emits `SendRandomUdp` blasts at the original circuit dialer's observed addresses to open its own NAT mapping (first after half the measured relay RTT, then every `blast_interval_ms` until `punch_deadline_ms`). The original circuit dialer makes the QUIC simultaneous-open dial. A landed punch is announced with `InboundDirectUpgrade` and supersedes the circuit.

## Status

- Dialer-side race (direct dials × relay leg × DCUtR punch): implemented, covered by scripted no-I/O tests in `tests/arbitration.rs`.
- Housekeeping (AutoNAT confidence aggregation, relay reservation renewal): implemented, covered by `tests/housekeeping.rs`.
- Responder side (inbound STOP circuits, punch-window UDP blasts): implemented, covered by `tests/inbound.rs` plus a two-agent end-to-end exchange over an in-memory relay emulator (`tests/two_agents.rs`).
