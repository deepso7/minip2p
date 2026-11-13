# Plan: relay mesh — one relay address served from several regions

> **Status:** Proposed. Not implemented. Review history: reviewed with gpt-6.1-sol (high). Round 1: 8 findings (1 blocker: clients don't retry a refused CONNECT, so the relay must settle transient directory states itself). Round 2: that blocker still open (a stale holding node at capacity blocked fallback), plus 1 nit. Round 3: approved. Every finding was checked against the code and fixed.

## Goal

Run the public relay in several regions behind one address, with no client changes:

```
/dns/relay.minip2p.com/udp/19876/quic-v1/p2p/12D3KooWNAHhp6rp11SvCDA84zua3hhEYTLNjgKmEDmt1BddtLdf
```

Geo DNS sends each client to the nearest region. Every region runs with the same identity key, so the peer ID in the address is valid wherever a client lands. The regions form a **relay mesh**: each node tells the others which peers hold reservations on it, and a node that gets a CONNECT for a peer reserved elsewhere forwards the circuit to the node that holds the reservation.

```
Bob ──HOP CONNECT──▶ Frankfurt ══ backbone ══▶ Mumbai ──STOP──▶ Alice
                     (entry node)              (holding node)
```

Why forwarding is required: a reservation lives in one relay process (`crates/relay-server/src/agent.rs`, `reservations`), and clients can't steer to it. A client sends every RESERVE and CONNECT over whatever connection it already has to the relay's peer ID: minip2p (`crates/nat/src/acquire.rs:42-62`), rust-libp2p (`directly_connected_peers[relay].first()`, [priv_client.rs](https://github.com/libp2p/rust-libp2p/blob/master/protocols/relay/src/priv_client.rs)) and go-libp2p (`bestConnToPeer`, [swarm.go](https://github.com/libp2p/go-libp2p/blob/master/p2p/net/swarm/swarm.go)) alike. Circuit addresses are never dial targets in minip2p (`crates/core/src/peer_addr.rs:58-80`), and every region shares the relay peer ID, so nothing in a client can choose a region. Without forwarding, Bob in Europe reaches Frankfurt, which has no reservation for Alice, and gets `NO_RESERVATION`.

Circuit Relay v2 allows this. A reservation is tied to the relay's peer ID, not to a host ([circuit-v2.md](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md)). STOP CONNECT carries only the initiator's peer ID and the limit (`crates/relay/src/server.rs:392-401`), so any node can open it on behalf of a dialer connected elsewhere. Vouchers stay `None` (`agent.rs:2041`), so no signed state has to be shared.

The closest prior art is Tailscale's DERP mesh ([derpserver.go](https://github.com/tailscale/tailscale/blob/main/derp/derpserver/derpserver.go), [mesh.go](https://github.com/tailscale/tailscale/blob/main/cmd/derper/mesh.go)): a static full-mesh member list, each node pushing its local presence to every other node, single-hop forwarding to the node where the peer is connected, and no central store. This plan follows it, with one difference: DERP nodes keep their own keys and clients learn each peer's home region, while here all nodes share one public identity so that clients don't need to know about regions.

Non-goals:

- **No mesh-wide quotas.** Each node enforces its own admission limits on the circuits it sees (Decision 7). Mesh-wide rate limits would need shared counters.
- **No multi-hop forwarding.** A holding node only checks its local reservations and never forwards again (Decision 5).
- **No dynamic membership.** The member list is static config; changing it means restarting nodes with the new list.
- **No shared reservation store.** The directory is pushed between nodes; there is no database.
- **No client changes.** minip2p, rust-libp2p and go-libp2p clients work as they do against one relay.
- **No vouchers.** Unchanged.

## Terms

- **Mesh node:** one relay process in the mesh. Every node runs with the shared **public identity** (the relay peer ID clients see) and its own **backbone identity**.
- **Backbone:** QUIC connections between mesh nodes, authenticated with backbone identities.
- **Directory:** each node's view of which peers hold reservations on which other node.
- **Entry node:** the node a dialer's CONNECT reaches. **Holding node:** the node holding the destination's reservation.

## Decisions

### 1. Two identities per node

All nodes load the same public `identity.key`. The existing Mumbai key becomes the mesh's key, so today's published addresses stay valid.

Backbone links can't use the public identity. The swarm keeps one live connection per peer ID ("last connection wins", `crates/swarm/src/state.rs:2440-2450`), so links between nodes that all share one peer ID would replace each other. Each node therefore also has a backbone key and talks to the other nodes as a distinct peer. The member list names each member's backbone peer ID, which is also the backbone's authentication: a backbone connection from a peer ID not on the list is closed when it is established, and mesh protocols are refused from anyone but members.

The public identity is never used on the backbone, and the relay runs no Kademlia or gossipsub under it. Running one peer ID on several hosts confuses stateful protocols that key on peer ID ([kubo#6851](https://github.com/ipfs/kubo/issues/6851)), and the relay doesn't need any of them.

### 2. Backbone runs on a second swarm in the same Endpoint

The backbone needs its own identity, and a swarm has one. The Endpoint engine therefore owns a second `SwarmCore` for the backbone, with its own QUIC transport bound to a separate port (default UDP `19877`).

- **One wait loop.** The backbone transport attaches to the Endpoint's existing `SharedPoll` in a host token space, as mDNS does ([ADR 0013](../adr/0013-swarm-owned-shared-poll.md)). Readiness there ends a wait as `Woken`, and the engine drives the backbone core alongside the public one. No second thread or poll.
- **Disjoint connection IDs.** A `StreamKey` is `(ConnectionId, StreamId)` (`crates/relay-server/src/types.rs:11`), and the agent must tell the two swarms' connections apart. QUIC allocates ids in the `QUIC_IPV4`/`QUIC_IPV6` namespaces (`transports/quic/src/lib.rs:1668-1675`), which the public transport also uses. Register two new namespaces, `MESH_IPV4` (6) and `MESH_IPV6` (7), in `crates/transport/src/connection_id.rs`, and let `QuicNodeConfig` override the namespaces a transport allocates in.
- **One agent, two swarms.** The agent takes one `RelaySwarm` per call (`crates/relay-server/src/swarm.rs:26-78`). A `MeshSwarm` adapter in `crates/relay-server` holds both swarms and implements `RelaySwarm` by routing: `open_stream` by peer (backbone members go to the backbone swarm), everything else by the `ConnectionId`'s namespace. Backbone swarm events go to the same `agent.handle_event`, with `is_circuit = false`.
- **Link upkeep is the engine's job,** not the agent's: dial every member at start, and redial a lost member with backoff (1 s doubling to 30 s). Both ends of a pair dial; the swarm's simultaneous-dial tiebreak keeps one connection (`state.rs:2181-2206`).
- **Backbone timers are scheduled.** Sharing readiness covers socket input only. The Endpoint's wait budget today comes from the public core and the current drivers (`crates/minip2p/src/std/mod.rs:892`, `engine.rs:927`); it must also include the backbone core's `next_deadline` and the redial and directory-reopen deadlines, on every blocking and non-blocking drive path. Otherwise QUIC handshakes, retransmissions and reconnects on an idle backbone stall until unrelated public traffic arrives.

Rejected: one swarm with the backbone transport holding its own key. The swarm's Identify would advertise the public key on connections authenticated as a backbone key, and other code assumes one local identity per swarm. Two processes per region (relay plus a backbone sidecar): it would need IPC for every forwarded byte.

### 3. The directory is pushed, one ordered stream per link

Each node opens one directory stream (`/minip2p/relay-mesh/directory/1.0.0`) to every member it has a backbone connection to, and pushes its own local reservations on it:

- `Present { peer, expires_unix }`, when a reservation is committed or renewed, or moves to a replacement connection.
- `Gone { peer }`, when a reservation expires or its connection closes.

On a new directory stream the sender first sends a `Present` for every current reservation, then `Synced`. Because the stream is ordered and starts with a full snapshot, no sequence numbers are needed. Snapshots are small (default capacity is 128 reservations, `agent.rs:2066`).

**One live stream per member.** The receiver tracks the member's current inbound directory stream. A newer stream from the same member supersedes it: the receiver clears that member's entries, marks the member unsynced, and from then on applies messages, and runs cleanup, only for the newer stream. Data or a late close or reset on a superseded stream is ignored, so it can't erase the newer stream's snapshot. The member counts as synced once its current stream delivers `Synced`.

**Loss and recovery.** When a member's current directory stream ends, or its backbone connection closes, the receiver drops every entry from that member right away. The spec says a reservation stops being valid when its peer disconnects, so a stale entry must not outlive the link that vouched for it. A sender whose directory stream ends while the backbone connection is still up reopens it with the same backoff as redials (1 s doubling to 30 s), reset once a stream reaches `Synced`. A lost connection is redialed as in Decision 2, and the sender opens a fresh stream on the new connection.

Each frame is length-prefixed protobuf using `minip2p-core`'s field vocabulary, capped at 8 KiB like relay control frames. A receiver holds at most `max_directory_entries_per_member` entries per member (default 4096). A member that exceeds the cap, or sends a malformed frame, has its stream reset and its entries dropped, and resends a snapshot on its next stream.

The agent needs a hook at each change. Today `ReservationAccepted` and `ReservationClosed` fire on commit and close (`agent.rs:2003-2015`, `985-991`, `1261-1271`), but a move to a replacement connection (`on_connection_replaced`, `agent.rs:1188`) fires nothing. The agent publishes directory updates itself from `insert_reservation` and `remove_reservation` (`agent.rs:2341`, `2359`), plus the move. That covers every path in one place without new public events.

### 4. Resolving a CONNECT: the relay settles it, clients don't retry

Clients can't be relied on to retry. When a connected relay refuses a HOP CONNECT, minip2p's connect attempt retires every remaining address for that relay peer ID and fails if no other relay is configured (`crates/nat/src/attempt.rs:1289-1338`). Every region shares one peer ID, so to the client the whole mesh is one relay: any `NO_RESERVATION` the mesh gets wrong fails a connection that could have worked. The entry node therefore settles transient states itself, within the CONNECT's existing control deadline (`control_stream_timeout_ms`):

1. **Local reservation:** use it. It is known to be live.
2. **Remote claims:** order them by latest `expires_unix` (a new reservation gets now + the reservation lifetime, so the newest commit comes first), ties by lower backbone peer ID. Forward to the first. If it answers `NO_RESERVATION` or `CONNECTION_FAILED`, or the backbone link fails, try the next claim.
3. **No claim left, but some member is connected and not yet synced:** hold the CONNECT until that member's `Synced` arrives or its link drops, then look again from step 1.
4. **Otherwise,** or when the control deadline passes, answer the last status seen, or `NO_RESERVATION` if no claim was ever found.

`RESOURCE_LIMIT_EXCEEDED` and `PERMISSION_DENIED` from a holding node are passed to the dialer without trying other claims, since the holding node made a real decision about a live reservation. That only holds if the holding node checks the reservation first: today `decide_connect` runs pause and capacity checks before it looks for the reservation (`agent.rs:2113-2143`), so a stale node at capacity would answer `RESOURCE_LIMIT_EXCEEDED` and block the fallback. For a forwarded CONNECT the holding node therefore answers `NO_RESERVATION` before any other check when it has no live local reservation for the destination (Decision 7). Local CONNECTs keep today's order.

A peer normally has one reservation in the mesh: clients hold one reservation slot and keep one connection per relay peer ID (`crates/nat/src/housekeeping.rs:806-808`), and a replaced connection closes the old reservation with it (`housekeeping.rs:1047-1078`). Two nodes can still claim a peer briefly, for example when a client's re-dial resolves DNS to another region before the old node has seen the old connection close. Step 2 handles that: the newer claim is tried first, and a stale one that answers `NO_RESERVATION` falls through.

One window remains: a peer that has just reserved on node B, before B's `Present` reaches the entry node. A dialer learns a circuit address out of band (signaling, discovery) after the reservation exists, and backbone propagation takes one round trip between regions, so this needs the dialer to beat the backbone. It is accepted and listed under Risks.

Nodes need synced clocks (NTP) for this, and for derived WebTransport certhashes to match across nodes (`crates/tls/src/webtransport.rs:10-19`). A mesh node requires `Now::unix_seconds`.

### 5. Forwarding protocol

When `decide_connect` finds no local reservation (`agent.rs:2136-2143`), it looks in the directory. On a hit, the entry node opens a forward stream (`/minip2p/relay-mesh/forward/1.0.0`) on its backbone connection to the holding node and sends:

```
Forward { source: Bob's peer ID, destination: Alice's peer ID, limit }
```

The holding node treats this like a local CONNECT whose source leg is the forward stream. It checks its local reservations only, opens STOP to Alice on the reservation's connection with `source` and `limit` in STOP CONNECT, and replies with one `Status` using the Circuit Relay v2 codes: `OK`, `NO_RESERVATION`, `RESOURCE_LIMIT_EXCEEDED`, `PERMISSION_DENIED`, `CONNECTION_FAILED`. The entry node maps that status onto its HOP STATUS reply to Bob. After `OK`, both nodes splice raw bytes as they do for a local circuit.

- Alice sees a normal STOP from the relay peer ID with Bob as source. She already accepts STOP by relay peer ID (`crates/nat/src/agent.rs:830-836`).
- Bytes Bob pipelines after CONNECT are buffered at the entry node up to the existing 64 KiB cap (`agent.rs:1648`) until the forward is accepted, as they are while a local STOP is pending.
- A pending forward uses the same control deadline as a pending STOP (`control_stream_timeout_ms`), shared across every claim the entry node tries (Decision 4). At the deadline, the dialer gets `CONNECTION_FAILED` if the last forward was still pending.

### 6. Agent changes

The research for this plan found the committed forwarding path already generic: a `Circuit` is two `(PeerId, StreamKey)` legs plus two `Forward` queues (`agent.rs:208-251`), and `pump_forward`, `forward_accepted` and `close_circuit` only call `send_stream`/`ack_stream`/`close_stream_write`/`reset_stream` on the stored peer and stream. What assumes local STOP and HOP is the pending phase:

- `PendingCircuit` gets a destination-side enum, `Stop(StopInitiator)` or `Forward(ForwardInitiator)`, and a source-side enum, `Hop(HopResponder)` or `Forward(ForwardResponder)`. `on_stop_ready`, `accept_pending_circuit`, `fail_pending_connect` and `deny_connect` match on them. `stop_to_source` stays the index from the destination stream to its circuit.
- A leg's swarm peer is split from the logical peer. On the entry node, the destination leg's swarm peer is the holding node's backbone peer ID while `destination_peer_id` stays Alice. Today `target()` sends to `destination_peer_id` (`agent.rs:238`), which would be wrong for a forwarded leg.
- The `is_circuit` check that refuses CONNECT over relayed connections doesn't apply to backbone connections, which are direct.
- **Each circuit stores its effective limit.** Today `commit_circuit` schedules the duration deadline from the agent's config, and `forward_accepted` checks bytes against the same config (`agent.rs:1574`, `1791-1824`). A forwarded circuit on the holding node must enforce `Forward.limit` instead (Decision 7), so `PendingCircuit` and `Circuit` carry their `Limit`, set from config for local circuits and from the message for forwarded ones, and the duration deadline and byte check read it. Zero still means unlimited.
- A pending CONNECT can wait on a member's `Synced` or on the next claim (Decision 4), so it needs a state for "resolving" besides "STOP pending" and "forward pending", under the same control deadline.
- `CircuitOpened` and `CircuitClosed` gain `via: Option<PeerId>`, the other node's backbone peer ID, so logs show which circuits crossed the backbone.

The directory, the codec and the `MeshSwarm` adapter live in a new `mesh` module of `crates/relay-server`. They are `no_std + alloc` with caller-supplied time, like the rest of the crate.

### 7. Admission and limits

- **The entry node is authoritative for the dialer.** It runs every check it runs today (pause, rate limiter, source and destination per-peer caps, per-IP caps, global cap) and spends the rate token. Forwarded circuits count against the entry node's limits like local ones.
- **The holding node is authoritative for the destination.** It first checks that it holds a live reservation for the destination and answers `NO_RESERVATION` otherwise (Decision 4). Then it applies pause (`PERMISSION_DENIED`), the global circuit cap, the destination's per-peer and per-IP caps, and the pending-STOP cap for the reservation's connection. It counts the source as Bob, from `Forward.source`, with no IP key (the entry node already checked Bob's IP), and spends no rate token.
- **One limit.** The holding node puts `Forward.limit` in STOP CONNECT and enforces it through the circuit's stored limit (Decision 6), so both nodes close the circuit at the same byte count and duration even when their configs differ, and the entry node's config decides it.
- **No per-member cap.** Members are trusted operators' nodes. A forwarded circuit counts against the holding node's global and destination caps like a local one, which already bounds what the backbone can use.

### 8. Endpoint and relay binary

- **Endpoint:** `EndpointBuilder::relay_mesh(RelayMeshConfig { identity, listen, members })`, valid only with `relay_server`. `members` is a list of `PeerAddr`s (backbone addresses with backbone peer IDs). The node skips its own backbone peer ID if it appears, so every node can use the same list. New `EndpointEvent` variants report a member link coming up or going down.
- **Relay binary:** `--mesh-key <path>`, `--mesh-listen <addr>` (repeatable, default `0.0.0.0:19877` and `[::]:19877`), and `--mesh-member <peer addr>` (repeatable). The backbone key is created on first run like the public key, with the same permission checks. `service install` passes the flags through and stores the backbone key next to the identity (`/var/lib/minip2p-relay/mesh.key`). Logs: `[relay] mesh member=<id> up|down` and the directory size per member.

## Ops: `relay.minip2p.com` as a mesh

1. **Regions.** Keep Mumbai (`ap-south-1`) and add Frankfurt (`eu-central-1`) and a US region (`us-east-1`). Each node gets an Elastic IP. The current instance has none (see [infra/relay/README.md](../../infra/relay/README.md)), so attach one before the DNS change.
2. **Keys.** Mumbai keeps its `identity.key`; `service install` refuses to replace an existing identity, so it is never imported there. Copy that key once into SSM Parameter Store as a SecureString, readable only by the relay instances' role, and each new node runs `service install --import-key` with it. Each node creates its own backbone key, and its backbone peer ID goes into the shared member list.
3. **Security groups.** UDP `19877` opens only to the other members' Elastic IPs. The public ports don't change.
4. **DNS.** `minip2p.com` is on Cloudflare, whose geo steering needs its paid Load Balancing add-on. Delegate the `relay.minip2p.com` subdomain to a Route 53 hosted zone with NS records in Cloudflare instead, then create one latency-routed `A` and `AAAA` record per region holding that node's Elastic IP, each associated with a Route 53 health check on TCP `19876`, so a dead region drops out. These are plain records, not alias records, so the health check is attached to each record directly ([how Route 53 chooses records](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-how-route-53-chooses-records.html)). Route 53 health checks can't probe UDP, so TCP stands in for the node being up.
5. **Certificates.** Behind geo DNS, Let's Encrypt's HTTP-01 check reaches whichever region its vantage points resolve to ([challenge types](https://letsencrypt.org/docs/challenge-types/)), so switch to DNS-01 through the Route 53 zone (`certbot certonly --dns-route53`). Each node issues its own certificate with an instance role allowed to change only `_acme-challenge.relay.minip2p.com`. Three nodes stay under the limit of 5 duplicate certificates per week, but the forced-renewal test in the runbook counts against it, so run it on one node at a time. The deploy hook and live reload stay as they are.
6. **Rollout.**
   1. Deploy the mesh build to Mumbai alone, with a backbone key and no members; it behaves as today. Note its backbone peer ID.
   2. Bring up the new regions with the full member list, Mumbai included.
   3. Reinstall Mumbai's service with the full member list (`service uninstall` keeps the identity, then `service install` with the mesh flags). Until this step Mumbai has no members, so it closes the new nodes' backbone connections.
   4. Check `mesh member=… up` for every other member on every node, then switch DNS from the single `A` record to the latency records.

## PR stack

1. **`transport, quic: register mesh connection namespaces`.** `ConnectionNamespace::MESH_IPV4`/`MESH_IPV6` and the `QuicNodeConfig` namespace override.
2. **`relay-server: mesh directory and wire codec`.** The `mesh` module's directory (claims, selection, per-member caps) and the protobuf codec for both protocols, with unit tests and `wire_inputs` fuzz coverage.
3. **`relay-server: forward circuits across the mesh`.** The pending-circuit enums, the leg/logical peer split, directory publishing, the forward path on both sides, `MeshSwarm`, and the admission rules. Multi-node agent tests.
4. **`minip2p: relay_mesh on the Endpoint`.** The backbone swarm on the shared poll, link upkeep, `RelayMeshConfig`, events.
5. **`relay-server example: mesh flags`.** CLI, `service install`, logs, README, the hosting guide, the glossary, and an ADR recording Decisions 1, 2 and 5.
6. **Ops** (no code): the steps above and a runbook update in `infra/relay/README.md`.

PRs 1 and 2 are independent. Each later PR depends on the ones before it.

## Testing

- **Directory (PR 2):** a snapshot replaces a member's entries and ends synced; `Gone` and a stream close remove them; a newer stream supersedes an older one, and the older stream's late data, close or reset changes nothing; the per-member cap and a malformed frame reset the stream and drop the entries; claim ordering (local first, later expiry first, ties by backbone peer ID).
- **Agent (PR 3)**, with the `FakeSwarm`/`Node` fixtures (`crates/relay-server/tests/common/mod.rs`), running three nodes and carrying backbone bytes between them by hand:
  - Bob on node B reaches Alice reserved on node A; bytes flow both ways with backpressure, and a half-close and a reset propagate across the backbone.
  - Node A answers `NO_RESERVATION` after Alice left, and node B passes it on once no claim is left.
  - A peer that moves from A to B: during the overlap B's newer claim is tried first; when A's stale claim is tried first and answers `NO_RESERVATION`, the entry node falls through to B and the circuit opens, including when A is at its circuit capacity or paused.
  - A CONNECT that arrives while a member's snapshot is in flight waits for `Synced` and then opens; one that arrives while that member's link drops answers `NO_RESERVATION`.
  - A lost backbone link drops that member's entries, and CONNECTs to its peers get `NO_RESERVATION`. A directory stream reset on a live connection is reopened and resynced.
  - Admission: the entry node spends the rate token and applies Bob's limits; the holding node applies Alice's; pause on either node refuses.
  - Limits: nodes with different configs (including zero, unlimited) both close a forwarded circuit at the entry node's byte and duration limit.
  - A forward that times out answers `CONNECTION_FAILED` and leaves no state on either node.
- **Unchanged clients, no application retry (PR 3):** every case above where the circuit should open is also run with an unmodified `NatAgent` making one connect attempt, to show the relay settles it without client retries.
- **Agent acceptance (PR 3):** extend `tests/nat_pair.rs` to two mesh nodes, with Alice's `NatAgent` reserved on one and Bob's on the other. Like the existing test, it uses a fake swarm and injected circuit events, so it checks the agents' control flow, not a real handshake.
- **Endpoint (PR 4)**, real transports end to end: two relay `Endpoint`s on localhost meshed, a minip2p client reserved on each, a relayed stream that carries data both ways with hole punching disabled, and a run where DCUtR completes over the forwarded circuit. Also: an idle backbone reconnects and retransmits with no public traffic (the scheduling in Decision 2), and a backbone connection from a peer ID not on the member list is closed.
- **Interop (PR 5):** extend `just interop-relay-rust` (`tests/interop/rust-relay-client`, pinned rust-libp2p) to a two-node mesh, with its two foreign peers reserved on different nodes, so unchanged rust-libp2p clients complete CONNECT/STOP and exchange bytes across the backbone. The go-libp2p harness (`tests/interop/go-libp2p`) has no relay client today; add a go-libp2p relay-client mode to it and run the same two-node case.
- **Fuzz (PR 2):** both mesh frame decoders in `wire_inputs`.
- **Live (Ops):** a client in each region connects to a peer in another region through `relay.minip2p.com`, and the logs show `via=` on the forwarding node.

## Risks

- **One key on several hosts.** A breach of any node exposes the public identity for the whole mesh. Mitigations: SSM with a narrow instance role, no SSH open to the world, and an ADR noting that rotating the key changes every published address.
- **Peers seeing one peer ID at several IPs.** Kubo's maintainers report odd behaviour when two nodes share an ID ([kubo#6851](https://github.com/ipfs/kubo/issues/6851)). For a relay that runs only relay, Identify, Ping and AutoNAT this is contained: clients keep one connection to the relay at a time, observed addresses come from that connection, and all nodes announce the same `/dns` addresses. AutoNAT counts the whole mesh as one server (`crates/nat/src/housekeeping.rs:226`).
- **Roaming clients.** A client that changes networks can briefly hold connections to two nodes. Decision 4 tries the newer claim first and falls through a stale one.
- **Propagation window.** A CONNECT that reaches an entry node before a brand-new reservation's `Present` does gets `NO_RESERVATION`, and minip2p clients don't retry it (Decision 4). It needs the dialer to learn the circuit address faster than one backbone round trip.
- **Backbone partition.** Nodes that can't reach each other answer `NO_RESERVATION` for each other's peers. Health checks can't see this; the `mesh member … down` log can.
- **Extra hop.** A forwarded circuit adds the backbone round trip, which DCUtR's RTT measurement includes. Peers reserved in the same region as the dialer are unaffected.

## Follow-ups

- Mesh-wide rate limits, if per-node limits prove too loose.
- Metrics for forwarded circuits and directory size, once the relay has a metrics story.
