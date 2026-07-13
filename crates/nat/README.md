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
          → after SYNC, release bridge ⇒ PathEstablished(Relayed)
first usable path wins
a better path later  ⇒ PathUpgraded { from, to }  (+ the old bridge is reset)
punch exhausted      ⇒ FellBackToRelay            (the bridge stays yours)
nothing worked       ⇒ ConnectFailed { error }
```

Ranking: `DirectDialed` ≈ `DirectPunched` > `Relayed`.

## The relayed path is a raw bridge stream

`Path::Relayed { relay, stream_id, pending_data, remote_write_closed }` is
**not** a full swarm connection: no identify, ping, or multistream-select runs
over the circuit. Exchange raw bytes on `stream_id` (addressed to the relay
peer) with `Swarm::send_stream` and receive later bytes as ordinary
`StreamData` events.

At handoff, consume `pending_data` before waiting for `StreamData`; it contains
application bytes that arrived in the same transport read as the final DCUtR
frame and is surfaced exactly once on the original `PathEstablished` event.
When `remote_write_closed` is true, treat the remote read side as EOF after
draining `pending_data`: the NAT agent already consumed that stream event, so
the application will not receive it again. A circuit transport that makes
relayed paths look like normal connections is future work.

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
    let consumed = agent.handle_event_with_disposition(&swarm_event, now());
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
agent punches back — dialing the initiator's observed addresses and
emitting `SendRandomUdp` blasts (first after `responder_sync_delay_ms`,
then every `blast_interval_ms` until `punch_deadline_ms`). The bridge
stream is handed to the application via `InboundRelayCircuit`; a landed
punch is announced with `InboundDirectUpgrade`.

## Status

- Dialer-side race (direct dials × relay leg × DCUtR punch): implemented,
  covered by scripted no-I/O tests in `tests/arbitration.rs`.
- Housekeeping (AutoNAT confidence aggregation, relay reservation renewal):
  implemented, covered by `tests/housekeeping.rs`.
- Responder side (inbound STOP circuits, punch-back, UDP blasts):
  implemented, covered by `tests/inbound.rs` plus a two-agent end-to-end
  exchange over an in-memory relay emulator (`tests/two_agents.rs`).
