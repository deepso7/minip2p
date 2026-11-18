# Plan: relay config file and a simpler relay mesh setup

> **Status:** PR 1 (config file) implemented; PR 2 in progress. Council (gpt-6.2-sol high, claude-opus-5.5 high): round 1 6/10 and 6/10 (peer IDs stay in member entries); round 2 7/10 and 7.5/10 (replacement, redial backoff, pending cap, service key paths); round 3 8/10 and 8/10 (redial after a pre-verification close, replacement Up/Down, wire format); round 4 8/10 and 9/10 (connection binding during replacement, message boundaries, `DialFailed`); round 5 8/10 and 9/10 (cancelling a mismatched open, outbound dispatch, stale timeouts, how `Links` learns verification); round 6 9/10 and 9/10 (stale proof rejection, `RelaySwarm` methods, one Up/Down path); both satisfied with the fixes below. A later review by gemini-4-carbon (medium), 8/10, found that directory and forward opens weren't bound to a connection, that the key loader can't create a service-owned backbone key during install, and that the event plumbing was underspecified; fixed below.

## Goal

Make `minip2p-relay` simple to set up and change, for a single relay and for a relay mesh. Breaking changes to the binary's flags, `service install`, and the mesh agent/Endpoint API are fine (pre-1.0). The mesh isn't deployed anywhere yet, so there is no mixed-version mesh to keep working.

Today:

- **Every change reinstalls.** `service install` bakes every option into the unit's `ExecStart` (`examples/relay-server/src/service.rs:157-200`). Changing one option means rerunning `service install` with all the others, and a forgotten `--webtransport-cert` or `--mesh-listen` silently turns that feature off. About 30 relay flags (`examples/relay-server/src/cli.rs`) can only be set this way.
- **A mesh installs twice.** A member entry carries the member's backbone peer ID (ADR 0027 Decision 1), and the backbone key is only created on first start. So every node installs, the operator copies each `mesh listening=` log line, then reinstalls every node with the full list.
- **Adding a node edits every node.** A node closes backbone connections from peer IDs not on its own list (`crates/relay-server/src/agent/mesh_node.rs:112`), so every existing node needs the new entry.

After this plan:

```bash
# a single relay
sudo minip2p-relay service install --hostname relay.example.com
sudoedit /etc/minip2p-relay/relay.toml && sudo minip2p-relay service restart   # any later change

# the first mesh node: its relay.toml has a [mesh] section with no members
sudo minip2p-relay service install --config relay.toml
# → mesh_member_candidate=/ip4/<public ip>/udp/19877/quic-v1/p2p/12D3KooW…   (printed at install, before start)

# each later node: the shared key, and a relay.toml listing every existing node's mesh_member_candidate (as confirmed by its startup log)
sudo minip2p-relay service install --config relay.toml --import-key identity.key
```

One install per node. Adding a node needs no relay config edit or restart on existing nodes; their firewalls still need the new node's IP (UDP `19877` stays restricted).

Non-goals (possible follow-ups, each needs its own case):

- **Address-only member entries.** Dialing without a peer ID would change `Transport::dial`, the swarm's dial tracking and self-detection (`crates/transport/src/transport.rs:150`, `crates/swarm/src/core.rs:487`). Printing the peer ID at install removes the log-copying round without it.
- **DNS names as members.** Backbone addresses stay `/ip4`/`/ip6` (`crates/minip2p/src/std/mod.rs:1908-1928`).
- **Join tokens, member gossip, backbone on the relay port, certificate sharing.**
- **Opening the backbone port to everyone.** The proof (Decision 3) makes an open port safe from impersonation, but QUIC still allocates a connection before the proof. The runbook keeps UDP `19877` restricted to the members' IPs.
- **Live config reload, `config set`, and flags overriding the file.**

## Decisions

### 1. One TOML file holds every relay option

`minip2p-relay --config PATH` reads a TOML file whose fields mirror the flags:

```toml
hostname = "relay.example.com" # derives the /dns announcements, as service install does today
key = "/var/lib/minip2p-relay/identity.key"
# quic = ["0.0.0.0:19876"]        # default: automatic IPv4/IPv6, as today
# announce = ["/dns/…"]           # extra announcements

[webtransport] # present = on
cert = "/etc/minip2p-relay/tls/fullchain.pem"
key = "/etc/minip2p-relay/tls/privkey.pem"

[limits]
max_reservations = 1024
max_circuit_bytes = 1048576

[mesh] # present = on
key = "/var/lib/minip2p-relay/mesh.key"
members = ["/ip4/198.51.100.7/udp/19877/quic-v1/p2p/12D3KooW…"]
```

- `--config` excludes every other option flag: the service uses the file, and foreground runs, Docker and tests use flags as today. No precedence rules.
- The file lists only what the operator changed; omitted fields take the binary's defaults, so new releases' defaults still apply. Unknown fields are an error.
- A section's presence turns its feature on: `[webtransport]` (with `cert`/`key` for a CA certificate, empty for derived certificates) and `[mesh]`.
- `hostname` requires the default ports (no `quic`/`tcp` binds; use explicit `announce` entries with custom ports) and adds `/dns/<hostname>/tcp/19876` and `/dns/<hostname>/udp/19876/quic-v1`, plus the hashless `/dns/<hostname>/udp/19876/quic-v1/webtransport` only with a CA certificate, the same rule `service install` applies today (`service.rs:164-171`); the Endpoint rejects a hashless address with derived certificates (`crates/minip2p/src/std/mod.rs:2101`).
- `cli.rs` and the config loader share one test table, so every flag has a matching field.
- Parsing uses `serde` + `toml` in `examples/relay-server` only. No library crate gains a dependency.

### 2. `service install` writes the file once; the unit never changes

`service install (--hostname H | --config FILE) [--import-key K]`:

- `--hostname` writes a minimal `/etc/minip2p-relay/relay.toml` if no file exists, and errors if an existing file names a different hostname. `--config` validates `FILE` and installs it, replacing any existing file. Passing both is an error.
- The installed file always names the service key paths: install writes `key = "/var/lib/minip2p-relay/identity.key"` (and `[mesh] key = "/var/lib/minip2p-relay/mesh.key"`) when absent, and errors when they name anything else, so the identity stays persistent (the CLI's default is an ephemeral key) and a copied config can't bypass `--import-key`. Cert and key paths must be absolute, as today (`service.rs:217-221`). Install fills in the key paths before validating, so a bare `[mesh]` passes; a foreground `--config` with `[mesh]` and no `[mesh] key` is an error, so a backbone key is never ephemeral.
- With `[mesh]`, install creates the backbone key if missing (service-owned, 0600, never overwritten), staged and chowned the way `identity.key` is today (`service.rs:397-427`): `load_keypair` refuses files not owned by the running uid (`examples/common/src/lib.rs:131-142`), so root can't use it here, and a repeat install reads the existing key's peer ID after checking it is a regular `minip2p-relay`-owned 0600 file. It refuses a `[mesh] key` equal to `key`, rejects a mesh listen port of `0`, and prints `mesh_member_candidate=/ip4/<ip>/udp/<port>/quic-v1/p2p/<backbone id>` (`/ip6/…` for IPv6 binds) for each configured listen address, or for the default binds (`0.0.0.0:19877`, `[::]:19877`) when none are configured, with a note to replace a wildcard IP with the node's public IP and to confirm against the `mesh listening=` startup log, which shows what actually bound (automatic binds can fall back to one address family). Today that ID only appears in the log after first start.
- The unit's `ExecStart` is only `minip2p-relay --config /etc/minip2p-relay/relay.toml`. The file is root:minip2p-relay 0640.
- Drops `--webtransport*`, `--mesh`, `--mesh-listen` and `--mesh-member` from `service install`.

### 3. The public identity vouches for each backbone key

Replaces the authentication half of ADR 0027 Decision 1 (two identities per node stays). Every node holds the public identity's secret key, so it can sign for its own backbone key and check the others':

- At startup a node signs `"minip2p relay mesh member v1" || backbone peer ID bytes` with the public identity key. The Endpoint computes the proof and passes it, with the public key, in `MeshConfig`, which drops its `members` allowlist (`crates/relay-server/src/mesh/mod.rs:54`); `crates/relay-server` gains `minip2p-identity` (`default-features = false, features = ["ed25519"]`) to verify. `MeshSwarm::open_stream` routes the member protocol to the backbone (`mesh/swarm.rs:52`).
- **A new backbone connection starts pending,** keyed by `ConnectionId`. It is not in `links`, not in the directory, gets no directory stream, and emits no Up. Both sides open `/minip2p/relay-mesh/member/1.0.0` (registered beside the directory and forward protocols in `register_backbone_roles`, `crates/relay-server/src/mesh/mod.rs:94`, and dispatched before `on_stop_ready` claims locally initiated streams, `crates/relay-server/src/agent.rs:1008`, with `initiated_locally` telling the sending stream from the receiving one) on the connection and send their proof, then half-close: the message is exactly the 64-byte Ed25519 signature, checked at EOF, so a short or long message is a rejection; the receiver checks it against the public key and the connection's remote peer ID (authenticated by QUIC's TLS) and answers with one byte, `0x01`, then half-closes, checked the same way. Only a clean half-close is judged: a member stream reset before EOF, on either side, is dropped without rejecting the connection, and the 5 s deadline covers a proof that never comes. The decoder buffers split reads into a fixed 65-byte buffer (2 bytes for the accept), so an unverified peer can't make it grow, and goes into the `wire_inputs` fuzz target. A second inbound member stream on a pending connection rejects it. A connection becomes a member link only when its own proof was accepted **and** the remote's proof checked out; only then does `member_connected` run (directory entry, directory stream, and a new `RelayServerEvent::MeshMemberUp`, with `MeshMemberDown` when a verified link ends). One side can finish first and open its directory stream while the other is still pending and resets it; the existing directory reopen path (`mesh_node.rs:499`) retries it.
- Pending connections time out after 5 s, independent of `control_stream_timeout_ms`; with the port restricted, no separate cap is needed (a cap would also count this node's own dials to a large mesh); a failed or late proof closes the connection and logs `[relay] mesh peer=<id> rejected: <reason>`. Mesh streams other than the member protocol from a pending connection are reset, as non-members' are today (`mesh_node.rs:419`), but without that path's `not a mesh member` error, since it happens on routine link setup. The proof deadline is part of the agent's `next_deadline` (`agent.rs:1446`), so an idle pending connection expires on time.
- **Opens are bound to a connection.** `open_stream(peer)` picks the peer's current connection (`crates/swarm/src/core.rs:596`), and events reach the agent after the swarm handled the whole batch, so an open meant for one connection can land on its replacement. Today only `open_stop` checks this (`agent.rs:2670-2685`); `open_directory` and the forward open in `route` don't (`mesh_node.rs:201-213`, `575-578`), so a directory stream or a forwarded circuit could start on an unverified replacement. Every backbone open (member, directory, forward) goes through one helper that first checks the swarm's live `connection_peer(conn) == Some(peer)`; then `open_stream(peer)` lands on that connection. If the check fails, nothing is opened: the replacement runs its own exchange, and a forward treats it as a failed claim (Decision 4 of the relay mesh plan). An outbound member stream that fails to open arrives as `OpenStreamFailed` (`agent.rs:1407`) and is dropped.
- **Promotion, timeout and rejection check the live connection.** The agent sweeps deadlines before it dispatches a queued `ConnectionReplaced` (`agent.rs:983`), so its own view can be stale. Promoting a proof, expiring one, and rejecting a bad one (the retired connection's queued stream events still arrive, `crates/swarm/src/state.rs:2374`) all check the swarm's live `connection_peer` (`crates/swarm/src/core.rs:303`); a pending connection the swarm has already retired is skipped, and its queued lifecycle event moves or removes the directory entry. `RelaySwarm` (`crates/relay-server/src/swarm.rs:27-90`) gains `connection_peer`, implemented on `SwarmCore` and routed by connection in `MeshSwarm`.
- `RelayServerAgent::new` checks that the mesh public key's peer ID is its own, signs `PeerId::to_bytes()` through one helper shared with verification, and registers the member protocol only when the mesh is on.
- A pending connection is never a directory member, so it can't hold up CONNECTs waiting on `Synced` (`mesh_node.rs:590-597`). On `ConnectionReplaced` the swarm has already retired the old connection (`crates/swarm/src/state.rs:2374-2382`), so the old link ends as today (`mesh_node.rs:160-174`) and the new connection goes through the proof exchange; meanwhile the member stays in the directory as unsynced, so waiting CONNECTs keep waiting as they do today. If that proof fails, `member_disconnected` and `resolve_waiting(None)` run. A pending connection that is itself replaced (the simultaneous-dial tiebreak) is dropped, and its successor inherits the member's unsynced directory entry: whichever pending connection holds it runs `member_disconnected` and `resolve_waiting(None)` on any terminal failure (bad proof, timeout, remote close). Replacement emits neither `MeshMemberDown` nor a second `MeshMemberUp`; Down fires only when the member leaves the directory.
- The proof can't be replayed: it names the backbone peer ID, and only that key's holder completes the TLS handshake.

**Revocation.** A node is removed by stopping it. A node's compromise exposes the public identity key anyway (ADR 0027), which already forces a new identity; a backbone-ID allowlist never protected against that. The new cost: a leaked backbone key alone, without the identity, can't be revoked by editing a list. The ADR records this.

### 4. A link forms when either side lists the other

Members dial the entries they list and accept any verified inbound peer. A link is one connection used both ways, so a new node that lists every existing node links to all of them with no change on the existing nodes.

- `Links` stays keyed by peer ID and only drives redials of listed entries. Up/Down come from the agent's verified-link state, so unlisted members report Up/Down too. If a listed member is already linked through an inbound connection, `Links` doesn't dial it; when that link drops, the listing side redials (1 s doubling to 30 s, unchanged) and the other side waits. `Links` records each listed member's current `ConnectionId` on `ConnectionEstablished` or `ConnectionReplaced { new }` (clearing `up` and any scheduled redial, and the in-flight dial only if it is that connection, as today, `relay_mesh.rs:223-237`), and resets backoff and sets `up` only when the agent verifies that current connection. The agent records every verified connection, replacements included, in a queue that `collect_agent_events` (`crates/minip2p/src/relay_server.rs:187-191`) drains through a `#[doc(hidden)]` `RelayServerAgent::take_verified_links()` and passes to the backbone's `Links`. It isn't a `RelayServerEvent` variant: that enum is public and exhaustive, so every host's match would have to handle it. The public Up/Down are the agent's `MeshMemberUp`/`MeshMemberDown` (directory membership), reaching hosts as `EndpointEvent::RelayServer(..)` like `MeshMemberSynced`; `EndpointEvent::RelayMeshMemberUp`/`Down` are deleted and the example logs from the new events, so nothing reports twice and the log lines keep their order. A close of the current connection while not up (either side rejected the proof, the timeout fired, or the connection dropped) counts as a failed attempt (next address, backoff, once) only if no dial is in flight. Otherwise the dial's own outcome decides; this covers an inbound simultaneous-dial loser that is established and closed while this node's own dial is still handshaking. A `DialFailed` schedules a redial only when the member has no current connection, so the losing dial of a simultaneous pair (which reports `DialFailed`, `crates/swarm/src/state.rs:2208`) doesn't disturb a winner that is mid-proof; "awaiting redial" means no current connection and no dial. So a misconfigured member is redialed with backoff, and none is ever left undialed.
- A full mesh needs every pair covered by at least one side. The docs say: each new node lists every existing node. A node listing its own entry skips it by peer ID, as today (`crates/minip2p/src/std/mod.rs:2422-2427`); the filter moves into `Backbone::new` along with the list.

### 5. Logs

- `[relay] mesh member=<backbone id> up|down`, now for unlisted members too.
- `[relay] mesh member=<id> synced entries=<n>` unchanged.
- `[relay] mesh peer=<id> rejected: <reason>` new, from a new `RelayServerEvent::MeshPeerRejected { peer_id, reason }`, since the shared `Mesh` runtime error kind also covers dial failures and bad streams.

## PR stack

1. **`relay-server example: config file`.** Decisions 1 and 2, with `[mesh]` mapped onto today's mesh options, plus the install-time `mesh_member_candidate` lines. README, hosting guide, `webtransport-certificates.mdx`, `infra/relay/README.md` (the current relay migrates by `service install --config` with its WebTransport paths, then checks the `webtransport=` log line). Tests: the shared flag/field table, a hostname-only install keeps its peer ID across restarts, `hostname` with custom binds rejected, a different `--hostname` on an existing file rejected, unknown fields rejected, `--config` with other flags rejected, unit file, install keeps an existing file, `--import-key` with a conflicting `key` rejected, CA-only hashless announcement, mesh listen port `0` rejected, a repeat install with `[mesh]` reads the existing service-owned backbone key, foreground `--config` with `[mesh]` and no key rejected.
2. **`relay mesh: identity-signed membership`.** Decisions 3–5 in `crates/relay-server` and `crates/minip2p`. ADR 0028 superseding ADR 0027's member-list authentication; glossary; hosting guide and runbook drop the second install round and the edits on existing nodes.

PR 1 is useful alone. PR 2 depends on it for the docs only.

## Tests (PR 2)

- Agent: a pending peer gets no snapshot, its streams are reset without the non-member error, a proof with a short message, early EOF or trailing bytes is rejected, a member, directory or forward open meant for a connection that was replaced in the same poll (through the real swarm) isn't opened on the replacement, and the replacement verifies on its own; a second inbound member stream rejects the connection; a proof deadline that fires, or a malformed proof that arrives, for an already-replaced connection (same poll as the replacement) doesn't remove the member; an outbound proof stream is handled, not taken by the STOP path; it expires at the proof deadline with no other traffic, can't open directory or forward streams, and doesn't make a CONNECT wait; a bad proof and a missing one (after 5 s) close the connection; a valid proof makes it a member and emits Up; a directory stream opened before the other side verified is reset and reopened; a replacement that fails verification (or is itself replaced, then fails) ends the member and resolves waiting CONNECTs; a verified replacement emits no Down or second Up.
- Endpoint: A lists nobody, B lists A, C lists A and B. All three pairs reach `synced`, and circuits forward A↔B, A↔C and B↔C. A node with a different identity key is rejected. A dropped link is redialed only by the side that lists the other, a listed member that fails its proof, or whose connection closes before verification, is redialed with backoff, a replaced-then-failed connection is redialed, and a simultaneous-dial loser, whether it reports `DialFailed` or arrives inbound and closes, doesn't trigger an extra dial.
