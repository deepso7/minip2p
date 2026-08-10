# minip2p-discovery

Sans-I/O discovery policy shared by signed pubsub beacons and local-link mDNS.
`PeerDiscoveryAgent` owns one bounded address book, expiry policy, dial state,
backoff, rate limits, provenance, and coalesced application events.
`BeaconAgent` separately validates and schedules wire-compatible
js-libp2p `pubsub-peer-discovery` beacons on
`_peer-discovery._p2p._pubsub`.

The split keeps the book independent of pubsub and DNS. Callers feed validated
signed `Observation`s through `observe_beacon` and unauthenticated address/TTL
claims through `observe_mdns`, then execute `Dial` and `CancelDial` actions.
Neither agent owns sockets, clocks, streams, tasks, or an executor.

Signed-beacon addresses are authenticated by the embedded public key and rank
ahead of mDNS candidates. A valid address-less beacon is still represented as
authenticated presence: it refreshes the beacon TTL and may produce a
provenance update, but does not itself trigger a dial.

mDNS records are unauthenticated claims. The transport's own handshake detects
a peer-id mismatch only after packets reach the claimed address, so the book
bounds retained addresses and peer identities, applies per-peer and global mDNS
dial budgets, and prevents mDNS-only observations from evicting beacon-backed
entries.
`KnownPeer` exposes the merged dial order and both source-specific subsets and
timestamps so applications do not have to guess provenance.

Pending state is structurally bounded. Peer transitions and dial failures
coalesce by peer in causal FIFO order, while protocol violations occupy a fixed
number of slots and count suppressed overflow. The bound depends only on
`PeerDiscoveryConfig`, not traffic volume or elapsed time.
