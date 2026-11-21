//! A scripted relay mesh: several [`Node`]s whose backbone links are fake
//! connections in the mesh namespace, with every backbone command one node
//! issues carried to the other by hand.
#![expect(
    clippy::indexing_slicing,
    reason = "node indices are the mesh's own, and a bad one should fail the test"
)]

use std::collections::{BTreeMap, BTreeSet};

use minip2p_core::PeerId;
use minip2p_core::platform::Now;
use minip2p_identity::Ed25519Keypair;
use minip2p_relay::{HopMessage, Status};
use minip2p_relay_server::mesh::{
    DIRECTORY_PROTOCOL_ID, MEMBER_ACCEPT, MEMBER_PROOF_LEN, MEMBER_PROTOCOL_ID, MeshConfig,
    is_backbone_connection, sign_member_proof,
};
use minip2p_relay_server::{RelayServerConfig, RelayServerEvent, StreamKey};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, ConnectionNamespace, StreamId};

use super::{Call, Node, at, connect_request, peer, reserve_request, sends_on};

/// The public identity every node of the mesh shares.
pub fn relay_identity() -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([7; 32])
}

/// The relay's peer id on every node.
pub fn relay_peer() -> PeerId {
    relay_identity().peer_id()
}

/// Node `i`'s backbone peer id.
pub fn member(i: usize) -> PeerId {
    peer(format!("mesh-member-{i}").as_bytes())
}

/// Node `i`'s member proof under the mesh's public identity.
pub fn proof(i: usize) -> [u8; MEMBER_PROOF_LEN] {
    sign_member_proof(&relay_identity(), &member(i))
}

/// Node `i` of a mesh: a relay under [`relay_identity`] whose backbone peer
/// id is [`member`]`(i)`.
pub fn mesh_node(i: usize, mut config: RelayServerConfig) -> Node {
    config.mesh = Some(MeshConfig::new(&relay_identity(), &member(i)));
    let mut node = Node::with_identity(relay_peer(), config);
    node.replace_announce_addrs(vec![super::direct_addr()])
        .expect("valid announce address");
    node
}

/// The member stream `node` opened on `conn_id`, in `calls`.
pub fn member_open(calls: &[Call], conn_id: ConnectionId) -> Option<StreamKey> {
    calls.iter().find_map(|call| match call {
        Call::Open {
            protocol_id,
            opened: Some(stream),
            ..
        } if protocol_id == MEMBER_PROTOCOL_ID && stream.conn_id == conn_id => Some(*stream),
        _ => None,
    })
}

/// Plays node `from`'s side of the member exchange on `node`'s pending
/// connection `conn_id`, from `node`'s `calls` since it came up: accepts
/// `node`'s proof and sends `from`'s own. Returns the commands `node`
/// issued.
pub fn verify_by_hand(
    node: &mut Node,
    from: usize,
    conn_id: ConnectionId,
    calls: &[Call],
    now: Now,
) -> Vec<Call> {
    let outbound = member_open(calls, conn_id).expect("a member open");
    node.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: member(from),
            conn_id,
            stream_id: outbound.stream_id,
            protocol_id: MEMBER_PROTOCOL_ID.into(),
            initiated_locally: true,
        },
        false,
        now,
    );
    node.data(&member(from), outbound, &[MEMBER_ACCEPT], now);
    node.half_close(&member(from), outbound, now);
    let inbound = StreamKey {
        conn_id,
        stream_id: StreamId::new(77),
    };
    send_member_stream(node, from, inbound, &proof(from), now);
    node.calls()
}

/// `from` opens a member stream `stream` on `node`, writes `message` and
/// half-closes it.
pub fn send_member_stream(
    node: &mut Node,
    from: usize,
    stream: StreamKey,
    message: &[u8],
    now: Now,
) {
    node.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: member(from),
            conn_id: stream.conn_id,
            stream_id: stream.stream_id,
            protocol_id: MEMBER_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        now,
    );
    if !message.is_empty() {
        node.data(&member(from), stream, message, now);
    }
    node.half_close(&member(from), stream, now);
}

/// The backbone connection, on any node, to node `to`.
pub fn link(to: usize) -> ConnectionId {
    ConnectionId::namespaced(ConnectionNamespace::MESH_IPV4, to as u64 + 1).expect("in range")
}

fn link_node(conn_id: ConnectionId) -> usize {
    conn_id.sequence() as usize - 1
}

/// Node `i`'s verified links to every other node, in node order.
fn others_links(i: usize, count: usize) -> Vec<(PeerId, ConnectionId)> {
    let mut links: Vec<_> = (0..count)
        .filter(|&j| j != i)
        .map(|j| (member(j), link(j)))
        .collect();
    links.sort();
    links
}

/// A mesh of nodes under one public identity, every pair linked.
pub struct Mesh {
    pub nodes: Vec<Node>,
    /// Client-facing commands each node issued, for the test to read.
    client_calls: Vec<Vec<Call>>,
    /// Backbone streams each node opened, with their protocol.
    opened: BTreeMap<(usize, StreamKey), String>,
    /// `(from, to)` pairs whose directory traffic waits for
    /// [`Mesh::release_directory`].
    held: BTreeSet<(usize, usize)>,
    held_calls: Vec<(usize, Call)>,
}

impl Mesh {
    /// One mesh node per config, every pair linked and synced at time 0.
    pub fn new(configs: Vec<RelayServerConfig>) -> Self {
        Self::with_held(configs, &[])
    }

    /// [`Mesh::new`], with the directory traffic of each `(from, to)` in
    /// `held` waiting from the start.
    pub fn with_held(configs: Vec<RelayServerConfig>, held: &[(usize, usize)]) -> Self {
        let count = configs.len();
        let nodes = configs
            .into_iter()
            .enumerate()
            .map(|(i, config)| {
                let mut node = mesh_node(i, config);
                node.swarm.next_stream = i as u64 * 100_000;
                node
            })
            .collect();
        let mut mesh = Self {
            nodes,
            client_calls: vec![Vec::new(); count],
            opened: BTreeMap::new(),
            held: held.iter().copied().collect(),
            held_calls: Vec::new(),
        };
        for (i, node) in mesh.nodes.iter_mut().enumerate() {
            for j in (0..count).filter(|&j| j != i) {
                node.establish(&member(j), link(j));
            }
        }
        mesh.pump(at(0));
        for (i, node) in mesh.nodes.iter_mut().enumerate() {
            let events = node.events();
            let others = (0..count).filter(|&j| j != i);
            let synced = others.clone().filter(|&j| !mesh.held.contains(&(j, i)));
            assert_eq!(
                events.len(),
                others.clone().count() + synced.clone().count(),
                "{events:?}"
            );
            for j in others {
                let up = RelayServerEvent::MeshMemberUp { member: member(j) };
                assert!(events.contains(&up), "{events:?}");
            }
            for j in synced {
                let event = RelayServerEvent::MeshMemberSynced {
                    member: member(j),
                    entries: 0,
                };
                assert!(events.contains(&event), "{events:?}");
            }
            let mut verified = node.take_verified_links();
            verified.sort();
            assert_eq!(verified, others_links(i, count));
        }
        mesh
    }

    /// Carries backbone commands between nodes at `now` until none is left,
    /// keeping the client-facing ones for [`Mesh::calls`].
    pub fn pump(&mut self, now: Now) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                for call in self.nodes[i].calls() {
                    moved |= self.route(i, call, now);
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// Node `i`.
    pub fn node(&mut self, i: usize) -> &mut Node {
        &mut self.nodes[i]
    }

    /// Holds directory traffic from `from` to `to` until
    /// [`Mesh::release_directory`].
    pub fn hold_directory(&mut self, from: usize, to: usize) {
        self.held.insert((from, to));
    }

    /// The streams node `i` opened to node `to` for `protocol_id`, oldest
    /// first, as node `i` names them.
    pub fn opened(&self, i: usize, to: usize, protocol_id: &str) -> Vec<StreamKey> {
        self.opened
            .iter()
            .filter(|((node, stream), protocol)| {
                *node == i && stream.conn_id == link(to) && *protocol == protocol_id
            })
            .map(|((_, stream), _)| *stream)
            .collect()
    }

    /// Node `to`'s name for a stream node `from` opened as `stream`.
    pub fn remote(from: usize, stream: StreamKey) -> StreamKey {
        StreamKey {
            conn_id: link(from),
            stream_id: stream.stream_id,
        }
    }

    /// The directory stream `from` publishes to `to` on closes on both ends,
    /// as when `to` resets it.
    pub fn reset_directory(&mut self, from: usize, to: usize, now: Now) {
        let stream = *self
            .opened(from, to, DIRECTORY_PROTOCOL_ID)
            .last()
            .expect("a directory stream");
        self.nodes[to].stream_closed(&member(from), Self::remote(from, stream), now);
        self.nodes[from].stream_closed(&member(to), stream, now);
        self.pump(now);
    }

    /// Delivers held directory traffic from `from` to `to`, then pumps.
    pub fn release_directory(&mut self, from: usize, to: usize, now: Now) {
        self.held.remove(&(from, to));
        let calls = core::mem::take(&mut self.held_calls);
        for (i, call) in calls {
            self.route(i, call, now);
        }
        self.pump(now);
    }

    /// Client-facing commands node `i` issued since the last call.
    pub fn calls(&mut self, i: usize) -> Vec<Call> {
        core::mem::take(&mut self.client_calls[i])
    }

    /// Routes one command node `i` issued; returns whether it was a
    /// backbone one.
    fn route(&mut self, i: usize, call: Call, now: Now) -> bool {
        let stream = match &call {
            Call::Open {
                opened: Some(stream),
                ..
            }
            | Call::Send { stream, .. }
            | Call::Close { stream, .. }
            | Call::Reset { stream, .. } => *stream,
            _ => {
                self.client_calls[i].push(call);
                return false;
            }
        };
        if !is_backbone_connection(stream.conn_id) {
            self.client_calls[i].push(call);
            return false;
        }
        let j = link_node(stream.conn_id);
        let directory = self
            .opened
            .get(&(i, stream))
            .is_some_and(|protocol| protocol == DIRECTORY_PROTOCOL_ID);
        if self.held.contains(&(i, j)) && directory {
            self.held_calls.push((i, call));
            return true;
        }
        let remote = Self::remote(i, stream);
        match call {
            Call::Open { protocol_id, .. } => {
                self.opened.insert((i, stream), protocol_id.clone());
                if protocol_id == DIRECTORY_PROTOCOL_ID && self.held.contains(&(i, j)) {
                    self.held_calls.push((
                        i,
                        Call::Open {
                            peer: member(j),
                            protocol_id,
                            opened: Some(stream),
                        },
                    ));
                    return true;
                }
                self.nodes[j].handle_event(
                    &SwarmEvent::StreamReady {
                        peer_id: member(i),
                        conn_id: remote.conn_id,
                        stream_id: remote.stream_id,
                        protocol_id: protocol_id.clone(),
                        initiated_locally: false,
                    },
                    false,
                    now,
                );
                self.nodes[i].handle_event(
                    &SwarmEvent::StreamReady {
                        peer_id: member(j),
                        conn_id: stream.conn_id,
                        stream_id: stream.stream_id,
                        protocol_id,
                        initiated_locally: true,
                    },
                    false,
                    now,
                );
            }
            Call::Send { data, accepted, .. } => {
                if accepted != 0 {
                    self.nodes[j].data(&member(i), remote, &data[..accepted], now);
                }
            }
            Call::Close { .. } => {
                self.nodes[j].half_close(&member(i), remote, now);
            }
            Call::Reset { .. } => {
                self.nodes[j].stream_closed(&member(i), remote, now);
                self.nodes[i].stream_closed(&member(j), stream, now);
            }
            _ => {}
        }
        true
    }

    /// Commits `client`'s reservation on node `i` over `stream`.
    pub fn reserve(&mut self, i: usize, client: &PeerId, stream: StreamKey, now: Now) {
        let node = &mut self.nodes[i];
        node.establish(client, stream.conn_id);
        node.hop_ready(client, stream, now);
        node.data(client, stream, &frame(reserve_request()), now);
        let events = node.events();
        assert!(
            matches!(
                events[..],
                [RelayServerEvent::ReservationAccepted { .. }, ..]
            ),
            "{events:?}"
        );
        self.pump(now);
        self.client_calls[i].retain(|call| match call {
            Call::Send { stream: on, .. }
            | Call::Close { stream: on, .. }
            | Call::Reset { stream: on, .. }
            | Call::Ack { stream: on, .. } => *on != stream,
            _ => true,
        });
    }

    /// `client`, connected to node `i` over `stream.conn_id`, sends CONNECT
    /// to `destination` on `stream`.
    pub fn connect(
        &mut self,
        i: usize,
        client: &PeerId,
        stream: StreamKey,
        destination: &PeerId,
        now: Now,
    ) {
        let node = &mut self.nodes[i];
        node.establish(client, stream.conn_id);
        node.hop_ready(client, stream, now);
        node.data(client, stream, &frame(connect_request(destination)), now);
        self.pump(now);
    }

    /// The STOP stream node `i` opened to its reserved client, answered
    /// with `status` at `now`. Node `i`'s client-facing commands until then
    /// are dropped.
    pub fn answer_stop(
        &mut self,
        i: usize,
        client: &PeerId,
        status: Status,
        now: Now,
    ) -> StreamKey {
        let calls = self.calls(i);
        let stop = super::opened(&calls).expect("a STOP open");
        self.nodes[i].stop_ready(client, stop, now);
        self.nodes[i].stop_status(client, stop, status, now);
        self.pump(now);
        self.calls(i);
        stop
    }

    /// The HOP STATUS node `i` wrote on `stream` since the last read, and
    /// every later write on it.
    pub fn hop_status(&mut self, i: usize, stream: StreamKey) -> (Option<Status>, Vec<Vec<u8>>) {
        let calls = self.calls(i);
        hop_status(&calls, stream)
    }
}

/// The HOP STATUS in the first write on `stream`, and the writes after it.
#[expect(
    clippy::panic,
    reason = "a write that is not a HOP reply fails the test"
)]
pub fn hop_status(calls: &[Call], stream: StreamKey) -> (Option<Status>, Vec<Vec<u8>>) {
    let mut sends = sends_on(calls, stream).into_iter();
    let status = sends.next().map(|reply| {
        let minip2p_relay::FrameDecode::Complete { payload, .. } =
            minip2p_relay::decode_frame(&reply)
        else {
            panic!("a framed HOP reply: {reply:?}");
        };
        HopMessage::decode(payload)
            .expect("a HOP message")
            .status
            .expect("a status")
    });
    (status, sends.collect())
}

fn frame(message: HopMessage) -> Vec<u8> {
    minip2p_relay::encode_frame(&message.encode())
}
