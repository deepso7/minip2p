# minip2p-peer

CLI demo that exercises the full minip2p stack end-to-end.

Two modes:

- **Direct** — two peers on the same host dial each other directly over
  QUIC and run ping. No relay. Validates the whole base stack
  (QUIC + multistream-select + identify + ping + swarm) in one command.
- **Relay** — two NATed peers rendezvous via a Circuit Relay v2 server,
  coordinate DCUtR, attempt a UDP hole-punch, and fall back to a
  relay-bridged RTT measurement if direct connection fails.

## Usage

```text
minip2p-peer listen
minip2p-peer dial   <peer-addr>
minip2p-peer listen --relay <relay-peer-addr>
minip2p-peer dial   --relay <relay-peer-addr> --target <peer-id>
```

Where:

- `<peer-addr>` is a full libp2p-style address ending in `/p2p/<peer-id>`,
  e.g. `/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooW...`
- `<relay-peer-addr>` is the same format, pointing at the relay server.
- `<peer-id>` is a bare libp2p PeerId (`12D3KooW...` or `Qm...`).

## Direct mode (5-minute quickstart)

Terminal 1:

```bash
cargo run -p minip2p-peer -- listen
# [listen] bound=/ip4/127.0.0.1/udp/53121/quic-v1/p2p/12D3KooW...
# [listen] waiting for dialers (Ctrl-C to stop)
```

Terminal 2, with the `bound=` peer-addr from above:

```bash
cargo run -p minip2p-peer -- dial /ip4/127.0.0.1/udp/53121/quic-v1/p2p/12D3KooW...
# [dial] dialing .../p2p/12D3KooW...
# [dial] connected peer=12D3KooW...
# [dial] identify peer=12D3KooW... agent=minip2p-peer/0.1.0 protocols=2
# [dial] ping peer=12D3KooW... rtt=6ms
```

Run the automated direct-mode E2E test:

```bash
cargo test -p minip2p-peer --test direct
```

## Relay mode (requires an external relay server)

Relay mode expects a Circuit Relay v2 server listening somewhere
reachable. The plan of record is to validate against the
`rust-libp2p` `relay-server-example` on the same host; once that's
working, swap in a VM-hosted relay.

Start a rust-libp2p relay server (rough steps; verify the exact binary
name against the `rust-libp2p` repo at time of use):

```bash
# from a checked-out rust-libp2p tree
cargo run --example relay-server-example
# note the peer-addr it prints -- that's <relay-peer-addr>
```

Peer B (listener, the NATed target):

```bash
cargo run -p minip2p-peer -- listen --relay <relay-peer-addr>
# [relay-listen] bound=/ip4/127.0.0.1/udp/52134/quic-v1/p2p/12D3KooW... (A)
# [relay-listen] us=12D3KooW... (A)
# [relay-listen] dialing-relay /ip4/.../p2p/12D3KooW... (relay)
# [relay-listen] connected peer=12D3KooW... (relay)
# [relay-listen] reserved-on-relay
# [relay-listen] incoming-circuit via-relay stream=...
# [relay-listen] stop-connect-from peer=12D3KooW... (B)
# [relay-listen] dcutr-connect-received addrs=1
# [relay-listen] dcutr-sync-received -> holepunching
# [relay-listen] direct-connected peer=12D3KooW... (B) (hole-punch success)
# [relay-listen] ping-direct peer=12D3KooW... (B) rtt=12ms -- done
```

Peer A (dialer), run while B is still alive:

```bash
cargo run -p minip2p-peer -- dial \
    --relay <relay-peer-addr> \
    --target <B-peer-id>
# [relay-dial] bound=...
# [relay-dial] us=...
# [relay-dial] target=...
# [relay-dial] dialing-relay ...
# [relay-dial] bridge-established via-relay
# [relay-dial] dcutr-dialnow addrs=1 rtt=N ms
# [relay-dial] dialing-direct /ip4/.../p2p/12D3KooW... (A)
# [relay-dial] direct-connected peer=... (hole-punch success)
# [relay-dial] ping-direct peer=... rtt=Nms -- done
```

### Fallback output (when hole-punch fails)

If the 10-second hole-punch deadline expires (e.g. symmetric NAT
between A and B), the dialer switches to a bridged echo:

```
[relay-dial] hole-punch-timeout -> relay-ping fallback
[relay-dial] ping-via-relay peer=... rtt=Nms -- done
```

The listener mirrors with:

```
[relay-listen] hole-punch-timeout -> relay-ping fallback
```

and echoes any payload bytes it receives on the bridge so the dialer
can measure an RTT.

## Output format

Each line is tagged with the role prefix (`[listen]`, `[dial]`,
`[relay-listen]`, `[relay-dial]`) and an event name, followed by
space-separated `key=value` fields. Designed to be both human-readable
and easy to grep/awk from tests.

## Architecture

This binary is deliberately procedural: each role is a linear script
built on `Swarm::run_until(deadline, predicate)`, so the sequence of
steps is visible top-to-bottom.

- `src/main.rs` — dispatch on parsed mode.
- `src/cli.rs` — hand-rolled argv parser; shared `print_event` helper.
- `src/direct.rs` — direct-mode listen/dial; zero relay machinery.
- `src/relay.rs` — relay-mode scripts for both Peer B (listener) and
  Peer A (dialer), driving the HOP/STOP/DCUtR state machines inline
  and running the hole-punch + relay-ping fallback at the bottom.

See `holepunch-plan.md` at the repo root for the design rationale and
open questions (RTT approximation on the responder side, relay-ping
protocol id, etc).

## Known limitations

- **No interop with third-party libp2p peers over the relay bridge.**
  The bridge skips Noise + Yamux to keep the demo small; DCUtR frames
  flow directly over the STOP stream with length-prefixed framing.
  Two minip2p peers work; a rust-libp2p peer on the other end of the
  bridge will not.

- **Loopback only.** Both modes bind `127.0.0.1:0` and make no
  attempt to discover public addresses. A STUN client (or real
  network deployment) is a future follow-up.

- **No relay server.** This binary implements the client side of HOP
  and the responder side of STOP; it does not run a relay. Use the
  `rust-libp2p` `relay-server-example` or equivalent.

- **Fresh identity per run.** Every invocation generates a new Ed25519
  keypair. A `--key-file` flag is on the DX roadmap.
