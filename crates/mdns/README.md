# minip2p-mdns

Sans-I/O libp2p mDNS discovery for `_p2p._udp.local`, with an optional
synchronous `std` socket driver. The codec and agent build with `no_std +
alloc`; callers supply time, interface snapshots, incoming datagrams, and drain
outgoing actions and observations.

mDNS claims are unauthenticated. A successful QUIC/TLS handshake verifies the
remote peer identity later, while the shared discovery book bounds retained
claims and automatic dial traffic.

This is a libp2p wire-interoperable mDNS subset, not complete RFC 6762 support.
Known-answer suppression, probing/conflict resolution, and receive-side
hop-limit verification are not implemented. IPv6 link-local addresses are not
advertised because minip2p multiaddrs do not yet support `/ip6zone`. SRV, A, and
AAAA records are ignored. On macOS, BSD, and Android, wildcard-bound receive
sockets cannot expose exact ingress-interface attribution without ancillary
packet information; the driver therefore rejects sources outside the
interface's on-link prefix as a safe approximation.
