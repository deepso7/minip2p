//! The relay-mesh backbone: a second swarm beside the Endpoint's public one,
//! under the node's own backbone identity, over its own QUIC transport.
//!
//! The relay agent drives both swarms through one
//! [`MeshSwarm`](minip2p_relay_server::mesh::MeshSwarm); this module owns
//! what the agent leaves to its host: keeping a link to every member up.
//! Every member is dialed at start, and a member whose link is lost (or
//! whose dial failed) is redialed after a backoff of 1 s doubling to 30 s,
//! reset once the link is up. Both ends of a pair dial; the swarm's
//! simultaneous-dial tiebreak keeps one connection.

use std::collections::BTreeMap;

use minip2p_core::platform::{Deadline, Now, StdEntropy};
use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::QuicTransport;
use minip2p_swarm::{SwarmCore, SwarmEvent};
use minip2p_transport::ConnectionId;

use crate::EndpointEvent;
use minip2p_relay_server::{RelayServerRuntimeError, RelayServerRuntimeErrorKind};

/// The backbone's default UDP port, on every listen address of
/// [`RelayMeshConfig::new`].
pub const DEFAULT_RELAY_MESH_PORT: u16 = 19_877;

/// First redial delay after a member's link is lost or its dial fails.
const MIN_REDIAL_BACKOFF_MS: u64 = 1_000;
/// The redial delay doubles per failed dial up to this.
const MAX_REDIAL_BACKOFF_MS: u64 = 30_000;

/// Makes a relay Endpoint one node of a relay mesh, through
/// [`EndpointBuilder::relay_mesh`](crate::EndpointBuilder::relay_mesh).
///
/// Every node serves the relay under the same public identity (the
/// Endpoint's), and links to the other members over a backbone under an
/// identity of its own, so the links between nodes that share a public peer
/// id don't replace each other.
#[derive(Clone, Debug)]
pub struct RelayMeshConfig {
    /// This node's backbone identity: one per node, never the public one.
    pub identity: Ed25519Keypair,
    /// Backbone QUIC listen addresses, `/ip4|ip6/<ip>/udp/<port>/quic-v1`,
    /// at most one per IP family. Members dial these.
    pub listen: Vec<Multiaddr>,
    /// Every member's backbone address, `/ip4|ip6/<ip>/udp/<port>/quic-v1`
    /// with its backbone peer id. This node's own entry is skipped, so
    /// every node can take the same list. A backbone connection from any
    /// other peer is closed.
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

    /// The members' backbone peer ids, without this node's own.
    pub(crate) fn member_ids(&self) -> impl Iterator<Item = PeerId> + '_ {
        let own = self.identity.peer_id();
        self.members
            .iter()
            .map(PeerAddr::peer_id)
            .filter(move |peer| **peer != own)
            .cloned()
    }
}

/// The backbone swarm.
pub(crate) type BackboneSwarm = SwarmCore<QuicTransport, StdEntropy>;

/// The backbone swarm and its member links.
pub(crate) struct Backbone {
    pub(crate) core: BackboneSwarm,
    links: Links,
}

impl Backbone {
    /// `core` is already listening; `members` excludes this node.
    pub(crate) fn new(core: BackboneSwarm, members: impl IntoIterator<Item = PeerAddr>) -> Self {
        Self {
            core,
            links: Links::new(members),
        }
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
                        peer_id: Some(addr.peer_id().clone()),
                        detail: format!("dialing mesh member at {}: {error}", addr.transport()),
                    });
                    None
                }
            };
            self.links.dialed(addr.peer_id(), dialed, now);
        }
        refused
    }

    /// Follows member links through one backbone event, returning the
    /// change to report.
    pub(crate) fn observe(&mut self, event: &SwarmEvent, now: Now) -> Option<EndpointEvent> {
        self.links.observe(event, now)
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
            .filter_map(|addr| PeerAddr::new(addr.clone(), own.clone()).ok())
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

/// Member link bookkeeping, apart from the swarm so it can be tested alone.
struct Links(BTreeMap<PeerId, Link>);

struct Link {
    /// The member's addresses, in the order given; dials rotate through
    /// them, moving on after each failure.
    addrs: Vec<PeerAddr>,
    next: usize,
    /// The member's backbone connection is established.
    up: bool,
    /// Our dial to it, until it establishes or fails.
    dial: Option<ConnectionId>,
    /// When to dial again, while the link is down and no dial is out.
    redial_at: Option<Deadline>,
    backoff_ms: u64,
}

impl Links {
    /// Every member starts due, so the first batch dials them all. A
    /// member listed under several addresses gets one link over all of them.
    fn new(members: impl IntoIterator<Item = PeerAddr>) -> Self {
        let mut links = BTreeMap::new();
        for addr in members {
            links
                .entry(addr.peer_id().clone())
                .or_insert_with(|| Link {
                    addrs: Vec::new(),
                    next: 0,
                    up: false,
                    dial: None,
                    redial_at: Some(Deadline::IMMEDIATE),
                    backoff_ms: MIN_REDIAL_BACKOFF_MS,
                })
                .addrs
                .push(addr);
        }
        Self(links)
    }

    fn awaiting_redial(link: &Link) -> bool {
        !link.up && link.dial.is_none()
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

    fn observe(&mut self, event: &SwarmEvent, now: Now) -> Option<EndpointEvent> {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                let link = self.0.get_mut(peer_id)?;
                if link.dial == Some(*conn_id) {
                    link.dial = None;
                }
                link.redial_at = None;
                link.backoff_ms = MIN_REDIAL_BACKOFF_MS;
                let was_up = std::mem::replace(&mut link.up, true);
                (!was_up).then(|| EndpointEvent::RelayMeshMemberUp {
                    peer_id: peer_id.clone(),
                })
            }
            SwarmEvent::ConnectionReplaced { peer_id, new, .. } => {
                let link = self.0.get_mut(peer_id)?;
                if link.dial == Some(*new) {
                    link.dial = None;
                }
                None
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                let link = self.0.get_mut(peer_id)?;
                if !std::mem::replace(&mut link.up, false) {
                    return None;
                }
                link.schedule(now);
                Some(EndpointEvent::RelayMeshMemberDown {
                    peer_id: peer_id.clone(),
                })
            }
            SwarmEvent::DialFailed { conn_id, .. } => {
                let link = self
                    .0
                    .values_mut()
                    .find(|link| link.dial == Some(*conn_id))?;
                link.dial = None;
                if !link.up {
                    link.failed(now);
                }
                None
            }
            _ => None,
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
    /// A dial failed: the next one tries the member's next address.
    fn failed(&mut self, now: Now) {
        self.next = (self.next + 1) % self.addrs.len().max(1);
        self.schedule(now);
    }

    /// Schedules the next dial after the current backoff, then doubles it.
    fn schedule(&mut self, now: Now) {
        self.redial_at = Some(now.deadline_after(self.backoff_ms));
        self.backoff_ms = (self.backoff_ms * 2).min(MAX_REDIAL_BACKOFF_MS);
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

    fn conn(index: u64) -> ConnectionId {
        ConnectionId::namespaced(ConnectionNamespace::MESH_IPV4, index).expect("in range")
    }

    fn at(ms: u64) -> Now {
        Now::from_millis(ms)
    }

    #[test]
    fn failed_dials_rotate_through_a_members_addresses() {
        let v4 = member();
        let v6 = PeerAddr::new(
            "/ip6/::1/udp/19877/quic-v1".parse().expect("address"),
            v4.peer_id().clone(),
        )
        .expect("peer address");
        let mut links = Links::new([v4.clone(), v6.clone()]);
        assert_eq!(links.due(at(0)), vec![v4.clone()]);
        links.dialed(v4.peer_id(), None, at(0));
        assert_eq!(links.due(at(1_000)), vec![v6]);
        links.dialed(v4.peer_id(), None, at(1_000));
        assert_eq!(links.due(at(3_000)), vec![v4]);
    }

    #[test]
    fn failed_dials_back_off_from_one_second_doubling_to_thirty() {
        let addr = member();
        let mut links = Links::new([addr.clone()]);
        assert_eq!(links.due(at(0)), vec![addr.clone()], "dialed at start");

        let mut now = 0;
        let mut delays = Vec::new();
        for index in 0..7 {
            links.dialed(addr.peer_id(), Some(conn(index)), at(now));
            assert_eq!(links.next_deadline(), None, "no redial while a dial is out");
            let failed = SwarmEvent::DialFailed {
                conn_id: conn(index),
                addr: addr.clone(),
                reason: "unreachable".into(),
            };
            assert!(links.observe(&failed, at(now)).is_none());
            let due = links.next_deadline().expect("redial scheduled");
            let delay = due.millis_until(at(now));
            assert!(links.due(at(now + delay - 1)).is_empty());
            now += delay;
            assert_eq!(links.due(at(now)), vec![addr.clone()]);
            delays.push(delay);
        }
        assert_eq!(delays, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
    }

    #[test]
    fn a_lost_link_reports_down_and_redials_after_one_second() {
        let addr = member();
        let peer = addr.peer_id().clone();
        let mut links = Links::new([addr.clone()]);
        // Two failures first, so the backoff has grown.
        for index in 0..2 {
            links.dialed(&peer, Some(conn(index)), at(0));
            let failed = SwarmEvent::DialFailed {
                conn_id: conn(index),
                addr: addr.clone(),
                reason: "unreachable".into(),
            };
            links.observe(&failed, at(0));
        }

        // The member dials us: the link is up, and the backoff resets.
        let up = SwarmEvent::ConnectionEstablished {
            peer_id: peer.clone(),
            conn_id: conn(9),
        };
        assert!(matches!(
            links.observe(&up, at(10)),
            Some(EndpointEvent::RelayMeshMemberUp { peer_id }) if peer_id == peer
        ));
        assert_eq!(links.next_deadline(), None);

        let closed = SwarmEvent::ConnectionClosed {
            peer_id: peer.clone(),
            conn_id: conn(9),
            reason: ConnectionCloseReason::TimedOut,
        };
        assert!(matches!(
            links.observe(&closed, at(20)),
            Some(EndpointEvent::RelayMeshMemberDown { peer_id }) if peer_id == peer
        ));
        assert_eq!(links.next_deadline(), Some(at(20).deadline_after(1_000)));
        // A second close of a link already down reports nothing.
        assert!(links.observe(&closed, at(30)).is_none());
    }

    #[test]
    fn own_backbone_id_is_not_a_member() {
        let identity = Ed25519Keypair::generate();
        let own = PeerAddr::new(
            "/ip4/127.0.0.1/udp/1/quic-v1".parse().expect("address"),
            identity.peer_id(),
        )
        .expect("peer address");
        let other = member();
        let config = RelayMeshConfig::new(identity, [own, other.clone()]);
        assert_eq!(
            config.member_ids().collect::<Vec<_>>(),
            vec![other.peer_id().clone()]
        );
    }
}
