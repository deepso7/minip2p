# Relay admission limits and AutoNAT trust

The relay server limited by peer and by exact IP address, with no cap on concurrent reservations or circuits per address and an IPv6 key of the full /128 — one host with a /64 is effectively unlimited. AutoNAT let one server cast every vote in its 3-of-5 window, counted `DialRefused` as a Private vote, and accepted whatever addresses the server returned, which the relay server then advertised (#327 finding 18 and the AutoNAT item). We decided:

- **Relay admission is keyed per IPv4 address or IPv6 /64.** Rate buckets use that key, and by default each key may hold 8 concurrent reservations (pending and committed) and take part in 8 concurrent circuits (counting either end, once when both share a key). The existing global and per-peer limits and token rates stay. Each limiter map holds at most 1,024 entries; when full it refuses new keys rather than evicting depleted ones, which would hand back their burst. Every value is configurable; ASN-based limits are left to host policy.
- **AutoNAT trusts a quorum of distinct servers.** The client rotates servers after every exchange, keeps only the latest vote per server PeerId, expires votes after 15 minutes, and needs the same quorum for each address it confirms. A returned address counts only if it is one we asked about; empty, malformed or unrelated replies, and `DialRefused`, are inconclusive. Because servers dial back the requested port at the IP they observe, we also ask about each listen address at every public IP our trusted relays and AutoNAT servers observe.

The trade-offs are deliberate: users behind CGNAT or sharing a /64 compete for the same 8 slots, and confirmation is slower and stays Unknown with fewer than three reachable servers. Both are preferable to one host exhausting a relay or one server deciding what we advertise.

## Amendments: implementation details

Relay admission (`minip2p-relay-server`):

- **An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is keyed as its IPv4 address** (`ip_key` in the agent), not as part of the `::ffff:0:0/64` prefix, so every IPv4 client reaching a dual-stack listener does not share one /64 bucket, and a dual-stack listener cannot be used to dodge the per-IPv4 limit.

AutoNAT quorum client (`minip2p-nat`'s reachability prober in `housekeeping`, and its `autonat` module):

- **A Public vote needs a dialable address.** A successful dial-back counts only if `select_direct_addrs` leaves at least one address; counting an empty selection could release a `WhenPrivate` reservation while providing no direct replacement path.
- **The threshold is clamped to the window.** A `confidence_threshold` above the vote window could never be reached, so it is treated as unanimity for the window instead of leaving reachability Unknown forever.
- **Confirmed addresses are sticky.** An address already confirmed stays advertised until a quorum leaves it out; newly confirmed ones are appended.
- **A settled verdict lapses when its votes expire**, even between probes: `next_deadline` includes the oldest vote's expiry. Back to Unknown, the next probe is pulled in to the unsettled cadence.
- **No phantom timeouts.** Without configured servers nothing is scheduled; with no listen address yet, the prober checks again at the unsettled cadence.
- **One response per exchange.** The client ignores anything pipelined behind the first response.
- **Address matching.** A returned address matches what we asked about even with a `/p2p` suffix naming us. An IPv4-compatible IPv6 address (`::a.b.c.d`, deprecated) is not an IPv4 host.
