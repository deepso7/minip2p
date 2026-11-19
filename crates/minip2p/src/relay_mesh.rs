//! The relay-mesh backbone: a second swarm beside the Endpoint's public one,
//! under the node's own backbone identity, over its own QUIC transport.
//!
//! The relay agent drives both swarms through one
//! [`MeshSwarm`](minip2p_relay_server::mesh::MeshSwarm) and decides who is a
//! member (ADR 0028); this module owns what the agent leaves to its host:
//! keeping a link to every member this node lists. A listed member is dialed
//! at start and, while it has no connection, redialed after a backoff of
//! 1 s doubling to 30 s, reset once the agent verifies its connection.
//! Members that dial in are accepted whether listed or not, so a link forms
//! when either side lists the other; a link that drops is redialed only by
//! a side that lists the other.

use std::collections::BTreeMap;

use minip2p_core::platform::{Deadline, Now, StdEntropy};
use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::QuicTransport;
use minip2p_swarm::{SwarmCore, SwarmEvent};
use minip2p_transport::ConnectionId;

use minip2p_relay_server::mesh::Backoff;
use minip2p_relay_server::{RelayServerRuntimeError, RelayServerRuntimeErrorKind};

/// The backbone's default UDP port, on every listen address of
/// [`RelayMeshConfig::new`].
pub const DEFAULT_RELAY_MESH_PORT: u16 = 19_877;

/// Makes a relay Endpoint one node of a relay mesh, through
/// [`EndpointBuilder::relay_mesh`](crate::EndpointBuilder::relay_mesh).
///
/// Every node serves the relay under the same public identity (the
/// Endpoint's), and links to the other members over a backbone under an
/// identity of its own, so the links between nodes that share a public peer
/// id don't replace each other. The public identity vouches for each
/// backbone identity, so membership needs no list (ADR 0028).
#[derive(Clone, Debug)]
pub struct RelayMeshConfig {
    /// This node's backbone identity: one per node, never the public one.
    pub identity: Ed25519Keypair,
    /// Backbone QUIC listen addresses, `/ip4|ip6/<ip>/udp/<port>/quic-v1`,
    /// at most one per IP family. Members dial these.
    pub listen: Vec<Multiaddr>,
    /// The members this node dials, each a backbone address
    /// `/ip4|ip6/<ip>/udp/<port>/quic-v1` with its backbone peer id. List
    /// every existing node when adding one; nodes need not list each other
    /// both ways. This node's own entry is skipped, so every node can take
    /// the same list. Members that dial in are accepted whether listed or
    /// not.
    pub members: Vec<PeerAddr>,
}

impl RelayMeshConfig {
    /// A backbone under `identity` listening on UDP
    /// [`DEFAULT_RELAY_MESH_PORT`] on every IPv4 and IPv6 interface.
    pub fn new(identity: Ed25519Keypair, members: impl IntoIterator<Item = PeerAddr>) -> Self {
        let listen = [Protocol::Ip4([0; 4]), Protocol::Ip6([0; 16])]
            .into_iter()
            .map(|ip| {
                Multiaddr::from_protocols(vec![
                    ip,
                    Protocol::Udp(DEFAULT_RELAY_MESH_PORT),
                    Protocol::QuicV1,
                ])
            })
            .collect();
        Self {
            identity,
            listen,
            members: members.into_iter().collect(),
        }
    }
}

/// The backbone swarm.
pub(crate) type BackboneSwarm = SwarmCore<QuicTransport, StdEntropy>;

/// The backbone swarm and its listed members' links.
pub(crate) struct Backbone {
    pub(crate) core: BackboneSwarm,
    links: Links,
}

impl Backbone {
    /// `core` is already listening. An entry for `core`'s own peer id is
    /// skipped.
    pub(crate) fn new(core: BackboneSwarm, members: impl IntoIterator<Item = PeerAddr>) -> Self {
        let links = Links::new(core.local_peer_id(), members);
        Self { core, links }
    }

    /// Dials every member whose redial is due, returning the dials the
    /// transport refused at once: no `DialFailed` follows for those.
    pub(crate) fn redial(&mut self, now: Now) -> Vec<RelayServerRuntimeError> {
        let mut refused = Vec::new();
        for addr in self.links.due(now) {
            let dialed = match self.core.dial(&addr) {
                Ok(conn_id) => Some(conn_id),
                Err(error) => {
                    refused.push(RelayServerRuntimeError {
                        kind: RelayServerRuntimeErrorKind::Mesh,
                        peer_id: Some(*addr.peer_id()),
                        detail: format!("dialing mesh member at {}: {error}", addr.transport()),
                    });
                    None
                }
            };
            self.links.dialed(addr.peer_id(), dialed, now);
        }
        refused
    }

    /// Follows listed members' connections through one backbone event.
    pub(crate) fn observe(&mut self, event: &SwarmEvent, now: Now) {
        self.links.observe(event, now);
    }

    /// The agent verified `peer`'s connection `conn_id`
    /// ([`take_verified_links`](minip2p_relay_server::RelayServerAgent::take_verified_links)).
    pub(crate) fn verified(&mut self, peer: &PeerId, conn_id: ConnectionId) {
        self.links.verified(peer, conn_id);
    }

    /// When the next redial is due; the swarm's own timers are
    /// `core.next_deadline`.
    pub(crate) fn redial_deadline(&self) -> Option<Deadline> {
        self.links.next_deadline()
    }

    /// The backbone's listen addresses, with its peer id.
    pub(crate) fn listen_addrs(&self) -> Vec<PeerAddr> {
        let own = self.core.local_peer_id();
        self.core
            .listened_addrs()
            .iter()
            .filter_map(|addr| PeerAddr::new(addr.clone(), *own).ok())
            .collect()
    }

    /// Stops redialing and disconnects every member: the endpoint is
    /// closing. Later polls carry the closes out.
    pub(crate) fn shutdown(&mut self, now: Now) {
        self.links.0.clear();
        for peer in self.core.connected_peers() {
            drop(self.core.disconnect(&peer, now.monotonic_ms));
        }
    }
}

/// Listed members' link bookkeeping, apart from the swarm so it can be
/// tested alone.
struct Links(BTreeMap<PeerId, Link>);

struct Link {
    /// The member's addresses, in the order given; dials rotate through
    /// them, moving on after each failure.
    addrs: Vec<PeerAddr>,
    next: usize,
    /// The member's current backbone connection, verified or not, whoever
    /// dialed it.
    conn: Option<ConnectionId>,
    /// The agent verified `conn`.
    up: bool,
    /// Our dial to it, until it establishes or fails.
    dial: Option<ConnectionId>,
    /// When to dial again, while it has no connection and no dial is out.
    redial_at: Option<Deadline>,
    /// Redial delay after a link is lost or an attempt fails.
    backoff: Backoff,
}

impl Links {
    /// Every member but `own` starts due, so the first batch dials them
    /// all. A member listed under several addresses gets one link over all
    /// of them.
    fn new(own: &PeerId, members: impl IntoIterator<Item = PeerAddr>) -> Self {
        let mut links = BTreeMap::new();
        for addr in members.into_iter().filter(|addr| addr.peer_id() != own) {
            links
                .entry(*addr.peer_id())
                .or_insert_with(|| Link {
                    addrs: Vec::new(),
                    next: 0,
                    conn: None,
                    up: false,
                    dial: None,
                    redial_at: Some(Deadline::IMMEDIATE),
                    backoff: Backoff::new(),
                })
                .addrs
                .push(addr);
        }
        Self(links)
    }

    fn awaiting_redial(link: &Link) -> bool {
        link.conn.is_none() && link.dial.is_none()
    }

    /// The members to dial now.
    fn due(&self, now: Now) -> Vec<PeerAddr> {
        self.0
            .values()
            .filter(|link| Self::awaiting_redial(link))
            .filter(|link| link.redial_at.is_some_and(|at| at.is_expired_at(now)))
            .filter_map(|link| link.addrs.get(link.next).cloned())
            .collect()
    }

    /// Records a dial to `peer`: its connection, or `None` when the
    /// transport refused it at once, which counts as a failed dial.
    fn dialed(&mut self, peer: &PeerId, dial: Option<ConnectionId>, now: Now) {
        if let Some(link) = self.0.get_mut(peer) {
            link.redial_at = None;
            link.dial = dial;
            if dial.is_none() {
                link.failed(now);
            }
        }
    }

    fn observe(&mut self, event: &SwarmEvent, now: Now) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id }
            | SwarmEvent::ConnectionReplaced {
                peer_id,
                new: conn_id,
                ..
            } => {
                let Some(link) = self.0.get_mut(peer_id) else {
                    return;
                };
                if link.dial == Some(*conn_id) {
                    link.dial = None;
                }
                link.conn = Some(*conn_id);
                link.up = false;
                link.redial_at = None;
            }
            SwarmEvent::ConnectionClosed {
                peer_id, conn_id, ..
            } => {
                let Some(link) = self.0.get_mut(peer_id) else {
                    return;
                };
                if link.conn != Some(*conn_id) {
                    return;
                }
                link.conn = None;
                if std::mem::replace(&mut link.up, false) {
                    // A link that was up: redial from the reset backoff.
                    link.schedule(now);
                } else if link.dial.is_none() {
                    // Rejected, timed out or dropped before it was
                    // verified: a failed attempt. With a dial out, its own
                    // outcome decides.
                    link.failed(now);
                }
            }
            SwarmEvent::DialFailed { conn_id, .. } => {
                let Some(link) = self.0.values_mut().find(|link| link.dial == Some(*conn_id))
                else {
                    return;
                };
                link.dial = None;
                // The losing dial of a simultaneous pair leaves the winner
                // to its proof.
                if link.conn.is_none() {
                    link.failed(now);
                }
            }
            _ => {}
        }
    }

    /// The agent verified `peer`'s connection `conn_id`: if it is still the
    /// current one, the link is up and the backoff starts over.
    fn verified(&mut self, peer: &PeerId, conn_id: ConnectionId) {
        if let Some(link) = self.0.get_mut(peer)
            && link.conn == Some(conn_id)
        {
            link.up = true;
            link.backoff.reset();
        }
    }

    fn next_deadline(&self) -> Option<Deadline> {
        self.0
            .values()
            .filter(|link| Self::awaiting_redial(link))
            .filter_map(|link| link.redial_at)
            .min()
    }
}

impl Link {
    /// An attempt failed: the next one tries the member's next address.
    fn failed(&mut self, now: Now) {
        self.next = (self.next + 1) % self.addrs.len().max(1);
        self.schedule(now);
    }

    /// Schedules the next dial after the current backoff, then doubles it.
    fn schedule(&mut self, now: Now) {
        self.redial_at = Some(now.deadline_after(self.backoff.next_delay_ms()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_transport::{ConnectionCloseReason, ConnectionNamespace};

    fn member() -> PeerAddr {
        PeerAddr::new(
            "/ip4/127.0.0.1/udp/19877/quic-v1".parse().expect("address"),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("peer address")
    }

    fn links(members: impl IntoIterator<Item = PeerAddr>) -> Links {
        Links::new(&Ed25519Keypair::generate().peer_id(), members)
    }

    fn conn(index: u64) -> ConnectionId {
        ConnectionId::namespaced(ConnectionNamespace::MESH_IPV4, index).expect("in range")
    }

    fn at(ms: u64) -> Now {
        Now::from_millis(ms)
    }

    fn established(peer: &PeerId, conn_id: ConnectionId) -> SwarmEvent {
        SwarmEvent::ConnectionEstablished {
            peer_id: *peer,
            conn_id,
        }
    }

    fn closed(peer: &PeerId, conn_id: ConnectionId) -> SwarmEvent {
        SwarmEvent::ConnectionClosed {
            peer_id: *peer,
            conn_id,
            reason: ConnectionCloseReason::TimedOut,
        }
    }

    fn dial_failed(addr: &PeerAddr, conn_id: ConnectionId) -> SwarmEvent {
        SwarmEvent::DialFailed {
            conn_id,
            addr: addr.clone(),
            reason: "unreachable".into(),
        }
    }

    /// How long after `now` the next redial is due.
    fn redial_in(links: &Links, now: Now) -> Option<u64> {
        links.next_deadline().map(|due| due.millis_until(now))
    }

    #[test]
    fn failed_dials_rotate_through_a_members_addresses() {
        let v4 = member();
        let v6 = PeerAddr::new(
            "/ip6/::1/udp/19877/quic-v1".parse().expect("address"),
            *v4.peer_id(),
        )
        .expect("peer address");
        let mut links = links([v4.clone(), v6.clone()]);
        assert_eq!(links.due(at(0)), vec![v4.clone()]);
        links.dialed(v4.peer_id(), None, at(0));
        assert_eq!(links.due(at(1_000)), vec![v6]);
        links.dialed(v4.peer_id(), None, at(1_000));
        assert_eq!(links.due(at(3_000)), vec![v4]);
    }

    #[test]
    fn failed_dials_back_off_from_one_second_doubling_to_thirty() {
        let addr = member();
        let mut links = links([addr.clone()]);
        assert_eq!(links.due(at(0)), vec![addr.clone()], "dialed at start");

        let mut now = 0;
        let mut delays = Vec::new();
        for index in 0..7 {
            links.dialed(addr.peer_id(), Some(conn(index)), at(now));
            assert_eq!(links.next_deadline(), None, "no redial while a dial is out");
            links.observe(&dial_failed(&addr, conn(index)), at(now));
            let delay = redial_in(&links, at(now)).expect("redial scheduled");
            assert!(links.due(at(now + delay - 1)).is_empty());
            now += delay;
            assert_eq!(links.due(at(now)), vec![addr.clone()]);
            delays.push(delay);
        }
        assert_eq!(delays, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
    }

    #[test]
    fn own_entry_and_unlisted_members_are_not_dialed() {
        let identity = Ed25519Keypair::generate();
        let own = PeerAddr::new(
            "/ip4/127.0.0.1/udp/1/quic-v1".parse().expect("address"),
            identity.peer_id(),
        )
        .expect("peer address");
        let other = member();
        let mut links = Links::new(&identity.peer_id(), [own, other.clone()]);
        assert_eq!(links.due(at(0)), vec![other]);

        // An unlisted member that dialed in and dropped is left to redial.
        let unlisted = Ed25519Keypair::generate().peer_id();
        links.observe(&established(&unlisted, conn(5)), at(0));
        links.verified(&unlisted, conn(5));
        links.observe(&closed(&unlisted, conn(5)), at(10));
        assert_eq!(links.0.len(), 1);
    }

    #[test]
    fn a_verified_link_that_drops_is_redialed_after_one_second() {
        let addr = member();
        let peer = *addr.peer_id();
        let mut links = links([addr.clone()]);
        // Two failures first, so the backoff has grown.
        for index in 0..2 {
            links.dialed(&peer, Some(conn(index)), at(0));
            links.observe(&dial_failed(&addr, conn(index)), at(0));
        }

        // The member dials us: no redial while it proves itself, and the
        // backoff resets once the agent verifies it.
        links.observe(&established(&peer, conn(9)), at(10));
        assert_eq!(links.next_deadline(), None);
        links.verified(&peer, conn(9));
        links.observe(&closed(&peer, conn(9)), at(20));
        assert_eq!(redial_in(&links, at(20)), Some(1_000));
        // A stale close changes nothing.
        links.observe(&closed(&peer, conn(9)), at(30));
        assert_eq!(redial_in(&links, at(20)), Some(1_000));
    }

    #[test]
    fn a_connection_that_closes_unverified_is_a_failed_attempt() {
        let addr = member();
        let peer = *addr.peer_id();
        let mut links = links([addr.clone()]);
        let mut now = 0;
        let mut delays = Vec::new();
        for index in 0..3 {
            links.dialed(&peer, Some(conn(index)), at(now));
            links.observe(&established(&peer, conn(index)), at(now));
            // Rejected by either side, or timed out: never verified.
            links.observe(&closed(&peer, conn(index)), at(now));
            let delay = redial_in(&links, at(now)).expect("redial scheduled");
            delays.push(delay);
            now += delay;
        }
        assert_eq!(delays, [1_000, 2_000, 4_000]);

        // A verification for a connection that is no longer current is
        // ignored.
        links.dialed(&peer, Some(conn(7)), at(now));
        links.observe(&established(&peer, conn(7)), at(now));
        links.observe(
            &SwarmEvent::ConnectionReplaced {
                peer_id: peer,
                old: conn(7),
                new: conn(8),
                old_path: minip2p_core::Path::Direct,
                new_path: minip2p_core::Path::Direct,
            },
            at(now),
        );
        links.verified(&peer, conn(7));
        links.observe(&closed(&peer, conn(8)), at(now));
        assert_eq!(
            redial_in(&links, at(now)),
            Some(8_000),
            "the replaced-then-failed connection counts as a failure"
        );
    }

    #[test]
    fn a_simultaneous_dial_loser_triggers_no_extra_dial() {
        let addr = member();
        let peer = *addr.peer_id();

        // Our dial loses to the member's: it reports `DialFailed` while the
        // winner is mid-proof.
        let mut links = links([addr.clone()]);
        links.dialed(&peer, Some(conn(1)), at(0));
        links.observe(&established(&peer, conn(2)), at(0));
        links.observe(&dial_failed(&addr, conn(1)), at(0));
        assert_eq!(links.next_deadline(), None);
        assert!(links.due(at(60_000)).is_empty());

        // The member's dial loses: established, then closed, while ours is
        // still handshaking. Ours decides.
        let mut links = self::links([addr.clone()]);
        links.dialed(&peer, Some(conn(1)), at(0));
        links.observe(&established(&peer, conn(2)), at(0));
        links.observe(&closed(&peer, conn(2)), at(0));
        assert_eq!(links.next_deadline(), None, "our dial is still out");
        links.observe(&established(&peer, conn(1)), at(5));
        links.verified(&peer, conn(1));
        links.observe(&closed(&peer, conn(1)), at(10));
        assert_eq!(
            redial_in(&links, at(10)),
            Some(1_000),
            "the loser did not grow the backoff"
        );
    }
}
