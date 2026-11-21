# Relay mesh: backbone link accounting, directory decoding and claim order

Details of the relay mesh (ADR 0027, ADR 0028), in the Endpoint's `Links` (`crates/minip2p/src/relay_mesh.rs`) and in `RelayServerAgent`'s mesh node and `mesh::directory` (`minip2p-relay-server`).

## What counts as a failed backbone link attempt

`Links` keeps a backbone link to every listed member, redialing with backoff from 1 s doubling to 30 s (ADR 0027). `Links::observe` decides which events grow the backoff:

- **A verified link that drops redials from the reset backoff.** Once the agent verified a member's proof (`Links::verified`), the backoff starts over, so a link that was up and closes is scheduled at the base delay, not counted as a failure.
- **A connection that closes unverified is a failed attempt.** Rejected by either side, timed out, or dropped before its proof checked out (ADR 0028), it grows the backoff, so a peer that keeps refusing us is not redialed at the base rate. A verification for a connection that is no longer current is ignored.
- **With our own dial still out, that dial's outcome decides.** If the member dialed us and its connection closes unverified while our dial is still handshaking, nothing is scheduled: our dial either establishes (and is judged on its proof) or fails.
- **The losing dial of a simultaneous pair is not a failure.** When our dial reports `DialFailed` while the member's connection is current and mid-proof, the winner is left to its proof; counting the loser would schedule a redial that races a link about to come up.

## Backbone and directory in the relay server

- **A failed member open or proof send is left to the proof deadline,** not handled inline: `MEMBER_PROOF_TIMEOUT_MS` closes the pending connection, so there is one failure path.
- **`verified` keeps only each member's latest link,** so a host that never drains it holds at most one entry per member.
- **A verified backbone link is inserted into `connections` like any other,** so circuits and workers on it end with it through the ordinary teardown path.
- **Directory backoff resets once the snapshot is in the transport.** When a `Present`/snapshot send leaves nothing queued, the next lost directory stream reopens from the shortest backoff.
- **Snapshots decode in linear time.** `Directory::stream_data` decodes frames with a cursor and drops the consumed bytes once at the end, so a snapshot read in one go is not quadratic in its size.
- **Equal-expiry claims keep the lower peer id first.** Members iterate in peer id order and the expiry sort is stable, which makes forward targets deterministic.
