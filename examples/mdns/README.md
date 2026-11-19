# minip2p-mdns

Local-link peer discovery over mDNS. Two copies on one machine, or on one LAN, find each other with **no bootstrap address, no relay and nothing configured per environment** — the one part of the stack you can try without a second host or a public address.

```text
USAGE:
    minip2p-mdns [--no-dial] [--for <seconds>] [--key <path>] [--listen <transport-multiaddr>]
```

## Quickstart

Two terminals, no arguments, nothing copied between them:

```console
$ cargo run -p minip2p-mdns-demo
[mdns] us=12D3KooWDk1pjAev…
[mdns] listen-addr=/ip4/0.0.0.0/udp/38649/quic-v1/p2p/12D3KooWDk1pjAev…
[mdns] announcing, dial=on (Ctrl-C to stop)
[mdns] discovered peer=12D3KooWGuEXke7Y… source=mdns addrs=[/ip4/172.17.0.1/udp/45965/quic-v1] t=+0.0s
[mdns] connected peer=12D3KooWGuEXke7Y… t=+0.0s
[mdns] ready peer=12D3KooWGuEXke7Y… protocols=2 list=[/ipfs/id/1.0.0,/ipfs/ping/1.0.0] t=+0.1s
[mdns] updated peer=12D3KooWGuEXke7Y… source=mdns addrs=[/ip4/172.17.0.1/udp/45965/quic-v1,/ip4/127.0.0.1/udp/45965/quic-v1] t=+0.1s
```

Discovery is usually sub-second: mDNS probes exponentially at startup before settling into its steady-state query interval.

The `updated` lines are the address book filling in. One host usually has several interfaces, and each announcement burst carries what it knows at the time, so a peer's address list grows over the first moments rather than arriving complete.

## Watching a peer leave

Stop one side and the other notices straight away, because shutdown sends mDNS goodbyes rather than letting the record age out:

```console
[mdns] expired peer=12D3KooWKHx987jM… t=+6.1s
[mdns] disconnected peer=12D3KooWKHx987jM… reason=closed by the peer (code 0) t=+6.2s
```

Without the goodbye that `expired` would wait out the record's TTL — two minutes by default. `--for <seconds>` runs for a bounded time and then shuts down the same way, which is what makes the demo scriptable.

## Options

| flag | meaning |
| --- | --- |
| `--no-dial` | only watch the address book; do not dial what mDNS finds. Without it, discovery dials, which is the stack's own default (`PeerDiscoveryConfig::auto_dial`) |
| `--for <seconds>` | run for this long, send goodbyes, exit 0. Without it, runs until interrupted |
| `--key <path>` | persistent Ed25519 secret (hex), created on first use, so a restart keeps its peer id |
| `--listen <multiaddr>` | explicit QUIC or TCP bind; default is dual-stack QUIC on UDP/0 |

## A note on trust

**mDNS claims are unauthenticated.** The addresses in a `discovered` line are what some host on the link said about itself, and nothing more — anyone on the same network can make such a claim. They become trustworthy only once a connection to that peer completes the Noise handshake and proves possession of the peer id's key, which is what `connected` reports.

That is why `--no-dial` exists: on a network you do not control, you may want to watch the book without acting on it. The defaults bound the damage either way — `PeerDiscoveryConfig` caps mDNS-triggered dials per peer and globally per window, and the book itself is bounded.

## Test

```bash
just mdns-discovery
```

Spawns two instances, waits for both to exit, and asserts each discovered the *other's* peer id. It is `#[ignore]`d by default because it needs real multicast delivery on UDP 5353, which CI containers and many VPN configurations do not provide — the same reason `crates/minip2p/tests/mdns.rs` is ignored.
