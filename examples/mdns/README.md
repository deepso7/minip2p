# minip2p-mdns

Local-link peer discovery over mDNS. Two copies on one machine or LAN find each other with no bootstrap address, no relay and no configuration.

```text
usage: minip2p-mdns [--no-dial] [--for <seconds>]
```

## Quickstart

Run this in two terminals:

```console
$ cargo run -p minip2p-mdns-demo
[mdns] us=12D3KooWDk1pjAev…
[mdns] listen-addr=/ip4/0.0.0.0/udp/38649/quic-v1/p2p/12D3KooWDk1pjAev…
[mdns] discovered peer=12D3KooWGuEXke7Y… addrs=[/ip4/172.17.0.1/udp/45965/quic-v1] t=+0.0s
[mdns] connected peer=12D3KooWGuEXke7Y… t=+0.0s
[mdns] ready peer=12D3KooWGuEXke7Y… protocols=[/ipfs/id/1.0.0,/ipfs/ping/1.0.0] t=+0.1s
[mdns] updated peer=12D3KooWGuEXke7Y… addrs=[…,/ip4/127.0.0.1/udp/45965/quic-v1] t=+0.1s
```

`updated` lines are the address book filling in as announcements arrive from each of the peer's interfaces.

## Watching a peer leave

`--for <seconds>` runs for a bounded time, then shuts down and sends mDNS goodbyes, so the other side notices straight away instead of waiting out the record's TTL (two minutes by default):

```console
[mdns] expired peer=12D3KooWKHx987jM… t=+6.1s
[mdns] disconnected peer=12D3KooWKHx987jM… reason=closed by the peer (code 0) t=+6.2s
```

Ctrl-C skips the goodbyes.

If the mDNS socket fails while running (no multicast route, a VPN capturing UDP 5353), the run prints `mdns-failed`, and `mdns-recovered` if a retry succeeds, so a broken network looks different from an empty one.

## Trust

mDNS claims are unauthenticated: a `discovered` line is only what some host on the link said about itself. `connected` means the peer proved its peer id over TLS 1.3. Discovery dials what it finds by default (`PeerDiscoveryConfig::auto_dial`, rate-limited); pass `--no-dial` to stop outbound dials (peers can still dial in).
