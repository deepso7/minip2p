# minip2p-peer

A NAT-aware echo-ping demo for the full minip2p stack, built entirely on the
`minip2p` facade (`features = ["nat"]`). Two subcommands:

- **`listen`** — bind QUIC, echo every inbound ping stream byte for byte.
  With `--relay`, hold a Circuit Relay v2 reservation and print a
  paste-ready circuit address.
- **`dial`** — connect to a target through the NAT traversal agent and ping
  once per second, tagging every RTT with the path it travelled. When a
  DCUtR hole punch upgrades the path mid-run, the seq sequence continues
  unbroken and the RTT visibly drops.

The same two commands work on loopback, across the open internet, and
between two NATed hosts via a relay — the agent adapts; nothing is
configured per environment.

```text
USAGE:
    minip2p-peer listen [--relay <relay-peer-addr>] [--autonat <peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
    minip2p-peer dial   <target> [--relay <peer-addr>] [--autonat <peer-addr>] [--count <n>] [--key <path>] [--listen <quic-multiaddr>]
```

`<target>` accepts two shapes:

- a **circuit address** copied from the listener's `circuit=` line —
  `/ip4/…/udp/…/quic-v1/p2p/<relay>/p2p-circuit/p2p/<peer>`. The dialer
  derives the relay and the target peer from it; nothing else is needed.
- a **plain peer-addr** — `/ip4/…/udp/…/quic-v1/p2p/<peer-id>` — for a
  directly reachable peer. `--relay` optionally adds a relay leg to race
  against the direct dial.

`--count n` (dial only) stops after `n` pings, prints a summary, and exits
`0`. Without it the dialer pings until interrupted; a running summary is
printed every tenth pong as a periodic checkpoint (Ctrl-C itself prints
nothing further).

## Quickstart: loopback

Terminal 1:

```console
$ cargo run -p minip2p-peer -- listen
[listen] peer=12D3KooWDEW8… identity=ephemeral
[listen] bound=/ip4/127.0.0.1/udp/64294/quic-v1/p2p/12D3KooWDEW8…
[listen] echoing on /minip2p/echo/1 (Ctrl-C to stop)
```

Terminal 2 (paste the `bound=` value):

```console
$ cargo run -p minip2p-peer -- dial /ip4/127.0.0.1/udp/64294/quic-v1/p2p/12D3KooWDEW8… --count 3
[dial] path-established path=direct-dialed elapsed=10ms
[dial] ping seq=1 path=direct
[dial] pong seq=1 rtt=0ms path=direct
…
[dial] summary sent=3 received=3 relayed-count=0 relayed-avg-rtt=0ms direct-count=3 direct-avg-rtt=1ms
```

This is exactly what the CI E2E test (`tests/ping.rs`) runs.

## The real payoff: two peers behind NATs

You need one publicly reachable Circuit Relay v2 server. rust-libp2p's
[relay server example](https://github.com/libp2p/rust-libp2p/tree/master/examples/relay-server)
works:

```console
$ cargo run -p relay-server-example -- --port 4001 --secret-key-seed 42
```

**Peer B (listener), behind its NAT** — reserve a slot and publish the
circuit address:

```console
$ minip2p-peer listen --relay /ip4/<relay-host>/udp/4001/quic-v1/p2p/<relay-id>
[listen] us=12D3KooWB…
[listen] nat-relay-reserved relay=12D3KooWRelay… expires-unix=…
[listen] circuit=/ip4/<relay-host>/udp/4001/quic-v1/p2p/<relay-id>/p2p-circuit/p2p/12D3KooWB…
[listen] echoing on /minip2p/echo/1 (Ctrl-C to stop)
```

**Peer A (dialer), behind a different NAT** — paste the circuit address:

```console
$ minip2p-peer dial /ip4/<relay-host>/…/p2p-circuit/p2p/12D3KooWB…
[dial] path-established path=relayed elapsed=350ms
[dial] ping seq=1 path=relayed
[dial] pong seq=1 rtt=180ms path=relayed
[dial] pong seq=2 rtt=176ms path=relayed
[dial] nat-path-upgraded peer=12D3KooWB… from=relayed to=direct-punched
[dial] channel-switched path=direct outstanding-resent=1
[dial] ping seq=4 path=direct
[dial] pong seq=3 rtt=41ms path=direct
[dial] pong seq=4 rtt=38ms path=direct
…
[dial] summary sent=20 received=20 relayed-count=2 relayed-avg-rtt=178ms direct-count=18 direct-avg-rtt=39ms
```

What to look for:

- the first pongs travel `path=relayed` through the relay bridge;
- `nat-path-upgraded … to=direct-punched` marks the DCUtR hole punch
  landing, and `channel-switched` shows any in-flight seqs being resent on
  the new stream — **the seq sequence never breaks**;
- subsequent pongs are `path=direct` with a clearly lower RTT;
- the summary splits the RTT accounting per path.

If the punch cannot land (e.g. UDP blocked between the peers), you'll see
`nat-holepunch-failed` for each retry window and finally
`nat-fell-back-to-relay`; pings simply continue on `path=relayed`.

## Options

| flag | meaning |
| --- | --- |
| `--relay <peer-addr>` | relay for reservations (listen) or an extra relay leg (dial) |
| `--autonat <peer-addr>` | AutoNAT server for reachability probes; optional — with none configured the agent reserves whenever a relay is available |
| `--count <n>` | dial only: stop after `n` pings with a summary and exit code 0 |
| `--key <path>` | persistent Ed25519 secret (hex); created on first use. Keep the listener's key stable so its circuit address survives restarts |
| `--listen <multiaddr>` | explicit QUIC bind (`/ip4/0.0.0.0/udp/4001/quic-v1`); default is dual-stack UDP/0 |

## Notes

- The echo protocol (`/minip2p/echo/1`) frames are 16 bytes: an 8-byte
  big-endian seq followed by an 8-byte send timestamp. The listener never
  parses them — it echoes raw bytes, which also exercises frame
  fragmentation/coalescing on the dialer's reassembly path.
- A relayed path is an end-to-end Noise connection multiplexed with Yamux.
  Identify, ping, and the echo protocol use the same negotiated stream APIs
  as a direct connection.
- Exit paths: `--count` is the graceful shutdown (half-close, 3 s drain,
  summary); Ctrl-C is the blunt one. The listener runs until interrupted.
- The previous `direct`/`relay`/`autonat` modes (hand-rolled protocol
  drivers) live in git history; the machine-level reference for the
  traversal flows is `crates/nat/tests`.
