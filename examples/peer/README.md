# minip2p-peer

CLI demo that exercises the full minip2p stack end-to-end.

Two modes:

- **Direct** — two peers on the same host dial each other directly over
  QUIC, verify each other with libp2p mTLS, and run ping. No relay.
  Validates the whole base stack (QUIC + mTLS + multistream-select +
  identify + ping + swarm) in one command.
- **Relay** — two NATed peers rendezvous via a Circuit Relay v2 server,
  coordinate DCUtR, attempt a UDP hole-punch, verify direct QUIC identities
  with mTLS, and fall back to a relay-bridged RTT measurement if direct
  connection fails.

## Usage

```text
minip2p-peer listen [--key <path>] [--listen <quic-multiaddr>]
minip2p-peer dial   <peer-addr> [--key <path>] [--listen <quic-multiaddr>]
minip2p-peer autonat [--key <path>] [--listen <quic-multiaddr>]
minip2p-peer listen --relay <relay-peer-addr> [--autonat <peer-addr>] [--key <path>] [--listen <quic-multiaddr>] [--external-addr <quic-multiaddr>]...
minip2p-peer dial   --relay <relay-peer-addr> --target <peer-id> [--autonat <peer-addr>] [--key <path>] [--listen <quic-multiaddr>] [--external-addr <quic-multiaddr>]...
```

Where:

- `<peer-addr>` is a full libp2p-style address ending in `/p2p/<peer-id>`,
  e.g. `/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooW...`
- `<relay-peer-addr>` is the same format, pointing at the relay server.
- `<peer-id>` is a bare libp2p PeerId (`12D3KooW...` or `Qm...`).
- `--key <path>` stores a raw Ed25519 secret as hex and reuses it on later runs.
- `--listen <quic-multiaddr>` changes the UDP bind address; default is loopback
  (`127.0.0.1:0`). Use `/ip4/0.0.0.0/udp/0/quic-v1` or
  `/ip6/::/udp/0/quic-v1` for real-network tests.
- `autonat` runs a public AutoNAT service that accepts probes and dials the
  requester's candidates back.
- `--autonat <peer-addr>` asks a public AutoNAT service to validate relay-mode
  candidate dialability before DCUtR.
- `--external-addr <quic-multiaddr>` is repeatable in relay mode and adds manual
  DCUtR candidates when you have a known public address or port-forward.

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
# [dial] identify peer=12D3KooW... agent=minip2p-peer/0.1.0 protocols=2 observed=/ip4/127.0.0.1/udp/53122/quic-v1
# [dial] peer-ready peer=12D3KooW... protocols=2
# [dial] ping peer=12D3KooW... rtt=6ms
```

Both sides authenticate during the QUIC TLS handshake. The listener learns the
dialer's `PeerId` from the client certificate; no post-hoc manual binding is
needed.

Run the automated direct-mode E2E test:

```bash
cargo test -p minip2p-peer --test direct
```

## Relay mode (requires an external relay server)

Relay mode expects a Circuit Relay v2 server listening somewhere reachable. For
reachability validation, run an AutoNAT service on a public host too. For a
single VPS demo, the relay and AutoNAT service can be separate processes on the
same machine using different UDP ports.

Start a rust-libp2p relay server (rough steps; verify the exact binary
name against the `rust-libp2p` repo at time of use):

```bash
# from a checked-out rust-libp2p tree
cargo run --example relay-server-example
# note the peer-addr it prints -- that's <relay-peer-addr>
```

Start an AutoNAT service peer on a public host:

```bash
cargo run -p minip2p-peer -- autonat \
    --key ./autonat.key \
    --listen /ip4/0.0.0.0/udp/4002/quic-v1
# [autonat] bound=/ip4/0.0.0.0/udp/4002/quic-v1/p2p/12D3KooW...
```

Peer B (listener, the NATed target):

```bash
cargo run -p minip2p-peer -- listen \
    --relay <relay-peer-addr> \
    --autonat <autonat-peer-addr> \
    --key ./peer-b.key
# [relay-listen] bound=/ip4/127.0.0.1/udp/52134/quic-v1/p2p/12D3KooW... (A)
# [relay-listen] us=12D3KooW... (A)
# [relay-listen] autonat-dialing /ip4/.../p2p/12D3KooW...
# [relay-listen] autonat-public addrs=1
# [relay-listen] dcutr-candidates [/ip4/.../udp/.../quic-v1,/ip4/127.0.0.1/udp/52134/quic-v1]
# [relay-listen] dialing-relay /ip4/.../p2p/12D3KooW... (relay)
# [relay-listen] connected peer=12D3KooW... (relay)
# [relay-listen] reserved-on-relay
# [relay-listen] incoming-circuit via-relay stream=...
# [relay-listen] stop-connect-from peer=12D3KooW... (B)
# [relay-listen] dcutr-connect-received addrs=1
# [relay-listen] dcutr-sync-received -> holepunching
# [relay-listen] remote-dcutr-candidates [/ip4/.../udp/.../quic-v1]
# [relay-listen] direct-connected peer=12D3KooW... (B) (hole-punch success)
# [relay-listen] ping-direct peer=12D3KooW... (B) rtt=12ms -- done
```

Peer A (dialer), run while B is still alive:

```bash
cargo run -p minip2p-peer -- dial \
    --relay <relay-peer-addr> \
    --target <B-peer-id> \
    --autonat <autonat-peer-addr> \
    --key ./peer-a.key
# [relay-dial] bound=...
# [relay-dial] us=...
# [relay-dial] target=...
# [relay-dial] autonat-public addrs=1
# [relay-dial] dcutr-candidates [...]
# [relay-dial] dialing-relay ...
# [relay-dial] bridge-established via-relay
# [relay-dial] dcutr-dialnow addrs=1 rtt=N ms
# [relay-dial] remote-dcutr-candidates [...]
# [relay-dial] direct-dial-attempt /ip4/.../p2p/12D3KooW... (A)
# [relay-dial] direct-connected peer=... (hole-punch success)
# [relay-dial] ping-direct peer=... rtt=Nms -- done
```

### Public relay shape

For cross-network tests, run with public relay and AutoNAT service addresses,
stable keys, and non-loopback binds. AutoNAT validates whether your advertised
candidates are actually dialable by another libp2p peer:

```bash
cargo run -p minip2p-peer -- listen \
    --relay /ip4/<relay-ip>/udp/4001/quic-v1/p2p/<relay-peer-id> \
    --autonat /ip4/<autonat-ip>/udp/4002/quic-v1/p2p/<autonat-peer-id> \
    --key ./peer-b.key \
    --listen /ip4/0.0.0.0/udp/0/quic-v1

cargo run -p minip2p-peer -- dial \
    --relay /ip4/<relay-ip>/udp/4001/quic-v1/p2p/<relay-peer-id> \
    --target <peer-b-id> \
    --autonat /ip4/<autonat-ip>/udp/4002/quic-v1/p2p/<autonat-peer-id> \
    --key ./peer-a.key \
    --listen /ip4/0.0.0.0/udp/0/quic-v1
```

If you have a known UDP port-forward, add one or more manual
`--external-addr /ip4/<public-ip>/udp/<port>/quic-v1` candidates. Manual
candidates are advertised before the bound-socket candidate and validated by
AutoNAT when `--autonat` is present.

Expected terminal result is either `ping-direct` after a successful direct
QUIC+mTLS connection, or `ping-via-relay` after a bounded hole-punch timeout.

### Fallback output (when hole-punch fails)

If the bounded hole-punch deadline expires (e.g. symmetric NAT
between A and B), the dialer switches to a bridged echo:

```
[relay-dial] hole-punch-timeout reason=deadline elapsed -> relay-ping fallback
[relay-dial] ping-via-relay peer=... rtt=Nms -- done
```

The listener mirrors with:

```
[relay-listen] hole-punch-timeout reason=deadline elapsed -> relay-ping fallback
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
  and running mTLS-verified hole-punch + relay-ping fallback at the bottom.

See `holepunch-plan.md` at the repo root for the design rationale and
open questions (RTT approximation on the responder side, relay-ping
protocol id, etc).

## Known limitations

- **No interop with third-party libp2p peers over the relay bridge.**
  The bridge skips Noise + Yamux to keep the demo small; DCUtR frames
  flow directly over the STOP stream with length-prefixed framing.
  Two minip2p peers work; a rust-libp2p peer on the other end of the
  bridge will not.

- **AutoNAT is validation, not magic address discovery.** If you do not have a
  useful public candidate or port-forward, AutoNAT will report private/unknown
  and the demo should still fall back to relay ping with diagnostics.

- **No relay server.** This binary implements the client side of HOP
  and the responder side of STOP; it does not run a relay. Use the
  `rust-libp2p` `relay-server-example` or equivalent.

- **Unencrypted demo key files.** `--key` stores the raw Ed25519 secret as hex
  with `0600` permissions on Unix. Production applications should use an
  application-specific encrypted store, OS keychain, or KMS.

## Internet-Ready Flow

Implemented flags:

```text
--key <path>                         persist/reuse this peer's Ed25519 identity
--listen <quic-multiaddr>            bind address, e.g. /ip4/0.0.0.0/udp/0/quic-v1
--autonat <peer-addr>                validate candidates with a public AutoNAT service
--external-addr <quic-multiaddr>     additional public UDP candidate for DCUtR
```

Public relay workflow:

```bash
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
