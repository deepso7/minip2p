# Relay mesh: the public identity vouches for each backbone key

Supersedes the authentication half of [ADR 0027](0027-relay-mesh-two-identities-and-single-hop-forwarding.md)'s first decision: members are no longer named by backbone peer ID on every node. Two identities per node, the backbone swarm and single-hop forwarding stand. Under the member list, a mesh took two installs per node (the backbone peer ID only appeared after first start) and adding a node meant editing and restarting every existing one, since each closed backbone connections from peers not on its own list ([plan](../plans/relay-config.md), Decisions 3 to 5). Every node already holds the public identity's secret key, so it can sign for its own backbone key and check the others'. We decided:

- **A signed proof replaces the allowlist.** At startup a node signs `"minip2p relay mesh member v1"` followed by its backbone peer ID's bytes with the public identity key (`mesh::sign_member_proof`), and `MeshConfig` carries the public key and that proof instead of a member list. A backbone peer is a member once its proof verifies against the public key and the connection's remote peer ID, which the QUIC handshake authenticated, so the proof can't be replayed by another key.
- **A new backbone connection is pending until both proofs check out.** Both sides open `/minip2p/relay-mesh/member/1.0.0`, send the 64-byte signature and half-close; the receiver answers one `0x01` byte and half-closes. Each message is judged only at its half-close, a reset before then is dropped, and the connection is closed on a bad, malformed or duplicate proof, or after 5 s without both. Only then does it join the directory, get a directory stream, and report `MeshMemberUp`. A pending connection is no directory member, so it can't hold up a CONNECT; its other mesh streams are reset.
- **Every backbone open is bound to its connection.** `open_stream` takes the peer's current connection, which may be a replacement the agent hasn't heard of yet. Member, directory and forward opens first check `RelaySwarm::connection_peer`, and so do promoting, expiring and rejecting a pending connection; a retired one is left to its queued lifecycle event. A link's replacement proves itself while the member stays in the directory unsynced, so replacement reports neither Down nor a second Up.
- **A link forms when either side lists the other.** The Endpoint dials the members it lists and accepts any verified peer that dials it, so a new node that lists every existing node joins with no change on them. Only the listing side redials a link that drops.

## Rejected alternatives

- **Keeping the allowlist beside the proof.** It would keep the reinstall rounds the proof removes, and it never protected against what matters (below).
- **Address-only member entries, gossiped membership, or join tokens.** Each changes dialing, the wire or the trust model for little over printing the backbone peer ID at install.

## Consequences

- A leaked public identity key already forced a new identity (ADR 0027); now it also lets the holder join the mesh. A backbone-ID allowlist never protected against that, since the key's holder can serve the relay address anyway.
- **A backbone key alone can't be revoked by editing a list.** A node is removed by stopping it; a node whose backbone key leaked, but not the identity, stays able to join until the identity is replaced. Keep backbone keys as protected as the identity.
- QUIC still allocates a connection before the proof, so the backbone port stays restricted to the members' IPs.
- `EndpointEvent::RelayMeshMemberUp`/`Down` are gone: members, listed or not, come from the agent's verified state as `RelayServerEvent::MeshMemberUp`/`MeshMemberDown`, and a refused peer as `MeshPeerRejected`.
