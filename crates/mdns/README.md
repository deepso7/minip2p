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

## Implementations

`MdnsSockets` is the hosted one: per-interface multicast sockets over
`socket2`, with interface enumeration. It needs the `std` feature, on by
default.

`SmoltcpMdnsIo` is the embedded one, over [smoltcp] — a TCP/IP stack, not an
operating system. It needs the `smoltcp` feature and nothing else: the host
builds the `Interface` and supplies the link, and this owns the mDNS sockets on
it and the group memberships they need. smoltcp has one interface, so mDNS sees
one per family, and `refresh` re-reads its addresses — which is how an address
arriving by DHCP or SLAAC reaches the agent.

Nothing moves in a stack like that except when it is driven, so `next_deadline`
matters more here than it does with sockets: honouring it is what lets a device
sleep between packets instead of polling to find out nothing happened.

Hosts with neither implement `MdnsIo` over their own stack. Nothing above the
seam changes: the agent, the driver, the budgets, and the on-link check are the
same code either way, and each implementation is covered by its own suite — a
loopback pair for `MdnsSockets`, a shared frame bus for `SmoltcpMdnsIo`.

[smoltcp]: https://docs.rs/smoltcp

## Writing an `MdnsIo`

Four operations, of which two have defaults: which interfaces exist and what
addresses they hold, one waiting datagram, one datagram out of a chosen
interface, and — for a stack that runs in this process — `poll` and
`next_deadline`.

Three details matter:

- **`InterfaceId`s must be stable** while an interface is up, and must never be
  reused for a different one: the agent tracks per-interface state against them.
- **`receive` never blocks.** Returning `None` means nothing is waiting, so an
  implementation with several sockets should rotate between them rather than
  drain one first, or a busy interface will spend the whole budget while a quiet
  one waits.
- **Report what you wrote, never more.** The driver's buffer is one byte longer
  than the largest datagram mDNS will act on, so filling it is how truncation is
  recognised; capping a read at some smaller length of your own would hand over
  a truncated claim wearing a plausible length.

`poll` defaults to doing nothing, which is right for a socket an operating
system services. A stack running in this process needs it: the driver calls it
before reading, after writing, and once more before releasing the carrier at
shutdown — that last one is what gets the goodbyes onto the wire.

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
