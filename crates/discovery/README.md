# minip2p-discovery

Sans-I/O peer discovery using signed pubsub presence beacons. The beacon protobuf
and default topic are wire-compatible with js-libp2p `pubsub-peer-discovery`:
`Peer { bytes publicKey = 1; repeated bytes addrs = 2; }` on
`_peer-discovery._p2p._pubsub`. Policy is intentionally different: minip2p keeps
a TTL address book and can emit automatic dial actions.
Address-less beacons still refresh peer presence, but never trigger a dial until
a later beacon supplies at least one normalized address.

The agent owns no clock, socket, stream, async task, or executor. Callers supply
`now_ms`, drain actions/events, and report connection outcomes. Beacons must be
carried by verified signed pubsub messages and their embedded public key must
derive the publisher peer id.

Current limitations: the facade NAT policy uses only its first configured relay;
wildcard IP listen addresses are not announced unless Identify/AutoNAT supplies a
usable external or circuit address. At the default 10-second cadence and the
pubsub 120-second seen TTL, the 4096-entry seen cache supports roughly 340 peers
(about 12 entries per peer).
