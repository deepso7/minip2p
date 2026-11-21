# mDNS stays link-local, and the smoltcp carrier maps onto one interface

mDNS is link-local by definition. Acting on a datagram from anywhere else would let a remote host put addresses into a local peer book. In crate `minip2p-mdns` we decided:

- **Only on-link sources are accepted.** `MdnsDriver::receive_batch` drops any datagram whose source is not inside one of the receiving interface's networks (`io::source_is_on_link`). A source of the other address family is never on-link: comparing a v6 address against a v4 network by its bits would make every one look local.
- **Hop limit 255 on send.** `SmoltcpMdnsIo` sets the UDP hop limit to 255, which is how link-local scope is signalled on the wire.
- **One socket per family, bound to the port, not an address.** It serves the multicast group and any unicast reply, whichever address of that family was targeted. Because both sockets wildcard-bind 5353, smoltcp may deliver a packet to either, so the receiving socket is not a family marker; the family (and so the `InterfaceId`) comes from the source address.
- **A family with no address is not an interface.** `SmoltcpMdnsIo::read_snapshots` omits it: it has no source to claim and nothing on-link to accept. This is where a host waiting for DHCP or SLAAC starts. The single smoltcp interface uses index 0: there is nothing to tell apart and no IPv6 scope to pick.
- **Default smoltcp buffers are 4 KiB each way with 4 packet slots** (`SmoltcpMdnsConfig::default`): two ordinary claims' worth, enough that a peer's burst does not drop what a poll has not read yet, deliberately far short of the 9000-byte datagrams mDNS allows.
- **smoltcp time is capped at `i64::MAX / 1000` ms** (`smoltcp_io::instant`): smoltcp stores microseconds in an `i64`, so saturating at `i64::MAX` milliseconds would overflow its internal multiplication. smoltcp's own TCP timers overflow near the end of the caller's clock, so saturation is covered by the carrier's unit tests, not the link tests. The smoltcp TCP provider caps time the same way (ADR 0043).
- **A hosted `MdnsSockets::attach` failure keeps the platform's `io::ErrorKind`,** so a host can tell a refused registration from running out of room.
- **A hosted interface refresh is all or nothing.** `MdnsSockets::refresh_interfaces` assigns ids on a copy of the `InterfaceRegistry`, and `replace` builds and registers every new socket before swapping anything, so a failure (a socket that cannot be built, a registration that runs out of tokens) hands out no ids, rolls back registrations already made, and leaves mDNS running on the old sockets rather than on half a set. An unchanged interface keeps its socket and so its multicast membership.

## On the wire

- **The TXT cache-flush bit is set only when the whole RRset fits in one datagram** (`dns.rs`: `txt_cache_flush && groups.len() == 1`). Cache-flush applies to a complete unique RRset; set on every fragment of a split set, it makes compliant caches discard the values learned from earlier fragments.
- **Test links never loop a host's own frames back,** like a real link: an agent that heard itself would answer its own queries.
