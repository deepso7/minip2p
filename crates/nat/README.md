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
          → Bridged ⇒ PathEstablished(Relayed)   (usable immediately)
          → DCUtR punch starts over the bridge, in parallel
first usable path wins
a better path later  ⇒ PathUpgraded { from, to }  (+ the old bridge is reset)
punch exhausted      ⇒ FellBackToRelay            (the bridge stays yours)
nothing worked       ⇒ ConnectFailed { error }
```

Ranking: `DirectDialed` ≈ `DirectPunched` > `Relayed`.

## The relayed path is a raw bridge stream

`Path::Relayed { relay, stream_id }` is **not** a full swarm connection: no
identify, ping, or multistream-select runs over the circuit. Exchange raw
bytes on `stream_id` (addressed to the relay peer) with `Swarm::send_stream`
and receive them as ordinary `StreamData` events. A circuit transport that
makes relayed paths look like normal connections is future work.

## Driving the agent

```rust,ignore
let mut agent = NatAgent::new(local_peer_id, NatConfig {
    relays: vec![relay_peer_addr],
    ..NatConfig::default()
});
agent.set_listen_addrs(&validated_external_addrs);

let id = agent.connect(target_peer, candidate_addrs, now());

loop {
    // 1. Feed swarm events by reference; consume stream events the agent
    //    owns (agent.owns_stream) instead of forwarding them to the app.
    agent.handle_event(&swarm_event, now());
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

The `minip2p` facade (feature `nat`, upcoming) wires exactly this loop into
`Endpoint` so applications get `connect(&peer)` / `wait_path(...)` without
touching the pump.

## Status

- Dialer-side race (direct dials × relay leg × DCUtR punch): implemented,
  covered by scripted no-I/O tests in `tests/arbitration.rs`.
- Housekeeping (AutoNAT confidence aggregation, relay reservation renewal):
  planned — knobs already exist on `NatConfig`.
- Responder side (inbound STOP circuits, punch-back, UDP blasts): planned.
