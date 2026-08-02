# minip2p-mdns

Sans-I/O libp2p mDNS discovery for `_p2p._udp.local`, with a driver and an
optional `std` socket adapter. All of it is `no_std + alloc`; callers supply
time.

```text
MdnsDriver          budgets, interface refresh, the on-link check
  -> MdnsAgent      DNS scheduling and validation
  -> MdnsIo         interfaces, datagrams in, datagrams out
```

`MdnsAgent` is the deterministic core: it decides what to say and when, and
callers hand it time, interface snapshots, and incoming datagrams, then drain
outgoing actions and observations.

`MdnsDriver` runs that agent against an `MdnsIo`. It owns the decisions about
*how much*: how many datagrams to read and send per turn, when to re-enumerate
interfaces, what to do when the I/O fails, and which datagrams to drop before
the agent ever sees them. None of that is platform work, so it is the same code
wherever the datagrams come from.

## Writing an `MdnsIo`

Three operations: which interfaces exist and what addresses they hold, one
waiting datagram, and one datagram out of a chosen interface. `MdnsSockets` is
the hosted implementation — per-interface multicast sockets over `socket2`,
with interface enumeration — and needs the `std` feature, on by default. A host
without an operating system implements the trait over its own stack; nothing
above the seam changes.

Two details matter. `InterfaceId`s must be stable while an interface is up and
must never be reused for a different one, because the agent tracks
per-interface state against them. And `receive` never blocks: returning `None`
means nothing is waiting, so an implementation with several sockets should
rotate between them rather than drain one first, or a busy interface will spend
the whole budget while a quiet one waits.

mDNS claims are unauthenticated. A successful QUIC/TLS handshake verifies the
remote peer identity later, while the shared discovery book bounds retained
claims and automatic dial traffic. Endpoint automatic dials from mDNS are
direct-only: an unauthenticated claim never authorizes a configured relay or
HOP CONNECT.

This is a libp2p wire-interoperable mDNS subset, not complete RFC 6762 support.
Known-answer suppression, probing/conflict resolution, and receive-side
hop-limit verification are not implemented. IPv6 link-local addresses are not
advertised because minip2p multiaddrs do not yet support `/ip6zone`. SRV, A, and
AAAA records are ignored. On macOS, BSD, and Android, wildcard-bound receive
sockets cannot expose exact ingress-interface attribution without ancillary
packet information; the driver therefore rejects sources outside the
interface's on-link prefix as a safe approximation. That check is the driver's
rather than an `MdnsIo`'s, so every implementation gets it.
