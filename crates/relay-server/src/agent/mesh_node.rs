//! The agent's relay-mesh side: backbone membership, directory publishing
//! and receiving, CONNECT resolution across members, and the forward
//! protocol on both the entry and the holding node.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identity::PublicKey;
use minip2p_relay::{Limit, Status};
use minip2p_swarm::DriverError;
use minip2p_transport::ConnectionId;

use super::{
    Connection, Deadlines, Held, HopWorker, Io, PendingCircuit, PendingDestination, PendingMesh,
    Resolution, Responder, Route, control_send_failure,
};
use crate::mesh::{
    Backoff, DIRECTORY_PROTOCOL_ID, Directory, DirectoryInput, DirectoryMessage,
    FORWARD_PROTOCOL_ID, ForwardMessage, MEMBER_ACCEPT, MEMBER_PROOF_LEN, MEMBER_PROOF_TIMEOUT_MS,
    MEMBER_PROTOCOL_ID, MemberReader, MeshConfig, decode_mesh_frame, is_backbone_connection,
    verify_member_proof,
};
use crate::{
    CircuitDirection, MeshRejectionReason, RelayServerAgent, RelayServerEvent,
    RelayServerRuntimeErrorKind, RelaySwarmError, StreamKey,
};

/// Most directory bytes queued behind a full stream. Past it the stream is
/// reset and reopened, so the member resyncs from a fresh snapshot.
const MAX_DIRECTORY_BACKLOG: usize = 1 << 20;

/// A mesh node's state beside the relay's own.
pub(super) struct MeshNode {
    /// The shared public identity, which members' proofs are checked
    /// against, and this node's own proof.
    public_key: PublicKey,
    proof: [u8; MEMBER_PROOF_LEN],
    directory: Directory<StreamKey>,
    /// Each verified member's backbone link.
    links: BTreeMap<PeerId, Link>,
    /// Backbone connections whose member proofs are still out (ADR 0028).
    /// Not in `links` or the directory, unless one holds the directory entry
    /// of a member whose link it replaced.
    pending: BTreeMap<ConnectionId, Pending>,
    /// Each pending connection's proof deadline.
    pub(super) proof_deadlines: Deadlines<ConnectionId>,
    /// Connections verified since the host last took them, replacements
    /// included: each member's latest.
    verified: Vec<(PeerId, ConnectionId)>,
    /// Directory streams this node opened, to their member, until they
    /// close. A link's current one is its `stream`.
    publishing: BTreeMap<StreamKey, PeerId>,
    /// Directory streams members opened to this node, until they close.
    receiving: BTreeMap<StreamKey, PeerId>,
    /// Members whose directory stream reopens at the deadline.
    pub(super) reopen: Deadlines<PeerId>,
}

impl MeshNode {
    pub(super) fn new(config: &MeshConfig) -> Self {
        Self {
            public_key: config.public_key.clone(),
            proof: config.proof,
            directory: Directory::new(config.max_directory_entries_per_member),
            links: BTreeMap::new(),
            pending: BTreeMap::new(),
            proof_deadlines: Deadlines::new(),
            verified: Vec::new(),
            publishing: BTreeMap::new(),
            receiving: BTreeMap::new(),
            reopen: Deadlines::new(),
        }
    }

    /// Forgets `peer`'s link if it is `conn_id`, dropping the member's
    /// directory entry. Returns whether it was.
    fn forget_link(&mut self, peer: &PeerId, conn_id: ConnectionId) -> bool {
        if self
            .links
            .get(peer)
            .is_none_or(|link| link.conn_id != conn_id)
        {
            return false;
        }
        self.links.remove(peer);
        self.reopen.remove(peer);
        self.verified.retain(|(_, verified)| *verified != conn_id);
        self.directory.member_disconnected(peer);
        self.publishing
            .retain(|stream, _| stream.conn_id != conn_id);
        self.receiving.retain(|stream, _| stream.conn_id != conn_id);
        true
    }

    /// Whether `stream` is one of a pending connection's member streams.
    fn is_member_stream(&self, stream: StreamKey) -> bool {
        self.pending
            .get(&stream.conn_id)
            .is_some_and(|pending| pending.side(stream).is_some())
    }

    pub(super) fn assert_consistent(&self) {
        assert!(
            self.proof_deadlines
                .by_key
                .keys()
                .all(|conn_id| self.pending.contains_key(conn_id)),
            "a proof deadline without a pending connection"
        );
        assert!(
            self.pending
                .values()
                .all(|pending| !self.links.contains_key(&pending.peer) || !pending.holds_entry),
            "a pending connection holds the entry of a member that has a link"
        );
    }
}

/// One member's backbone connection and the directory stream this node
/// publishes on.
struct Link {
    conn_id: ConnectionId,
    stream: Option<StreamKey>,
    /// The stream negotiated and its snapshot went out; updates follow it.
    live: bool,
    /// Bytes a full stream has not taken yet, resent on its writable.
    backlog: Vec<u8>,
    blocked: bool,
    /// Delay before a directory stream that ended on a live link reopens;
    /// reset once a snapshot is in the transport.
    backoff: Backoff,
}

/// A backbone connection running the member proof exchange.
struct Pending {
    peer: PeerId,
    /// This node's member stream, carrying its proof out and the answer
    /// back, until the answer's half-close.
    outbound: Option<(StreamKey, MemberReader)>,
    /// The peer's member stream, carrying its proof, until its half-close.
    inbound: Option<(StreamKey, MemberReader)>,
    /// The peer opened a member stream; a second one is a rejection.
    inbound_seen: bool,
    /// The peer accepted this node's proof.
    accepted: bool,
    /// The peer's proof checked out.
    verified: bool,
    /// The connection replaced the member's link (or a pending connection
    /// that held this), so the member stays in the directory, unsynced,
    /// until it is verified or fails.
    holds_entry: bool,
}

/// Which of a pending connection's member streams a stream is.
#[derive(Clone, Copy)]
enum Side {
    Outbound,
    Inbound,
}

impl Pending {
    fn side(&self, stream: StreamKey) -> Option<Side> {
        if self.outbound.as_ref().is_some_and(|(s, _)| *s == stream) {
            Some(Side::Outbound)
        } else if self.inbound.as_ref().is_some_and(|(s, _)| *s == stream) {
            Some(Side::Inbound)
        } else {
            None
        }
    }

    fn reader(&mut self, side: Side) -> Option<&mut MemberReader> {
        let slot = match side {
            Side::Outbound => &mut self.outbound,
            Side::Inbound => &mut self.inbound,
        };
        slot.as_mut().map(|(_, reader)| reader)
    }
}

impl RelayServerAgent {
    /// Whether `conn_id` is a backbone connection of this mesh node. Always
    /// false for a single relay, which treats every connection as today.
    pub(super) fn is_backbone(&self, conn_id: ConnectionId) -> bool {
        self.mesh.is_some() && is_backbone_connection(conn_id)
    }

    pub(super) fn owns_mesh_stream(&self, stream: StreamKey) -> bool {
        self.mesh.as_ref().is_some_and(|mesh| {
            mesh.publishing.contains_key(&stream)
                || mesh.receiving.contains_key(&stream)
                || mesh.is_member_stream(stream)
        })
    }

    /// The backbone connections verified since the last call, each with its
    /// peer, replacements included; only each member's latest is kept. The
    /// Endpoint's member redial bookkeeping reads it; it is not a
    /// [`RelayServerEvent`] so hosts' matches don't have to handle it.
    #[doc(hidden)]
    pub fn take_verified_links(&mut self) -> Vec<(PeerId, ConnectionId)> {
        self.mesh
            .as_mut()
            .map(|mesh| core::mem::take(&mut mesh.verified))
            .unwrap_or_default()
    }

    /// Whether `peer` is a member whose current link is `conn_id`.
    fn is_member_link(&self, peer: &PeerId, conn_id: ConnectionId) -> bool {
        self.mesh.as_ref().is_some_and(|mesh| {
            mesh.links
                .get(peer)
                .is_some_and(|link| link.conn_id == conn_id)
        })
    }

    /// Opens `protocol_id` on `peer`'s backbone connection `conn_id`, and
    /// only there. `open_stream` takes the peer's current connection, which
    /// may already be a replacement the agent has not heard of: then nothing
    /// is opened, and the replacement runs its own proof exchange.
    fn open_backbone(
        &mut self,
        io: &mut Io<'_>,
        peer: &PeerId,
        conn_id: ConnectionId,
        protocol_id: &str,
    ) -> Option<StreamKey> {
        if io.swarm.connection_peer(conn_id) != Some(peer) {
            return None;
        }
        match io.swarm.open_stream(peer, protocol_id, io.now_ms()) {
            Ok(stream) if stream.conn_id == conn_id => Some(stream),
            Ok(stream) => {
                self.reset(io, peer.clone(), stream);
                None
            }
            Err(error) => {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::OpenStream,
                    Some(peer.clone()),
                    error.to_string(),
                );
                None
            }
        }
    }

    /// A backbone connection came up. It stays pending, outside the
    /// directory, until both member proofs check out.
    ///
    /// Out of line: inlined into `dispatch`, it slowed every relay's events.
    #[inline(never)]
    pub(super) fn on_backbone_established(
        &mut self,
        io: &mut Io<'_>,
        peer: PeerId,
        conn_id: ConnectionId,
    ) {
        self.start_pending(io, peer, conn_id, false);
    }

    /// Starts `conn_id`'s proof exchange: arms its deadline and opens this
    /// node's member stream. `holds_entry` as in [`Pending::holds_entry`].
    fn start_pending(
        &mut self,
        io: &mut Io<'_>,
        peer: PeerId,
        conn_id: ConnectionId,
        holds_entry: bool,
    ) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        mesh.pending.insert(
            conn_id,
            Pending {
                peer: peer.clone(),
                outbound: None,
                inbound: None,
                inbound_seen: false,
                accepted: false,
                verified: false,
                holds_entry,
            },
        );
        mesh.proof_deadlines
            .set(conn_id, io.now_ms().saturating_add(MEMBER_PROOF_TIMEOUT_MS));
        // A failed open leaves the exchange to its deadline.
        if let Some(stream) = self.open_backbone(io, &peer, conn_id, MEMBER_PROTOCOL_ID)
            && let Some(pending) = self
                .mesh
                .as_mut()
                .and_then(|mesh| mesh.pending.get_mut(&conn_id))
        {
            pending.outbound = Some((stream, MemberReader::accept()));
        }
    }

    /// A member's link, or a pending connection, was replaced. The old one
    /// goes first and the new one starts its own proof exchange. A member
    /// whose link (or pending holder) was replaced stays in the directory,
    /// unsynced, so CONNECTs waiting on it, or falling back from a forward
    /// on the old link, keep waiting for the new link's snapshot instead of
    /// failing.
    ///
    /// Out of line: inlined into `dispatch`, it slowed every relay's events.
    #[inline(never)]
    pub(super) fn on_backbone_replaced(
        &mut self,
        io: &mut Io<'_>,
        peer: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
    ) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        let holds_entry = if let Some(pending) = mesh.pending.remove(&old) {
            mesh.proof_deadlines.remove(&old);
            pending.holds_entry
        } else if mesh.forget_link(peer, old) {
            mesh.directory.member_connected(peer.clone());
            true
        } else {
            false
        };
        self.on_connection_closed(io, peer, old);
        self.start_pending(io, peer.clone(), new, holds_entry);
    }

    /// Forgets the backbone connection `conn_id` to `peer`, link or pending.
    /// Returns whether the member left the directory with it; the caller
    /// then re-resolves the CONNECTs waiting on it.
    pub(super) fn on_backbone_closed(&mut self, peer: &PeerId, conn_id: ConnectionId) -> bool {
        let Some(mesh) = &mut self.mesh else {
            return false;
        };
        if let Some(pending) = mesh.pending.remove(&conn_id) {
            mesh.proof_deadlines.remove(&conn_id);
            if !pending.holds_entry {
                return false;
            }
            mesh.directory.member_disconnected(peer);
        } else if !mesh.forget_link(peer, conn_id) {
            return false;
        }
        self.events.push_back(RelayServerEvent::MeshMemberDown {
            member: peer.clone(),
        });
        true
    }

    // --- Member proofs ---

    /// This node's member stream finished negotiating: sends the proof and
    /// half-closes. One whose connection is gone is reset.
    pub(super) fn on_member_ready(&mut self, io: &mut Io<'_>, peer: &PeerId, stream: StreamKey) {
        let Some(mesh) = &self.mesh else {
            return;
        };
        if !mesh.is_member_stream(stream) {
            // Its connection was retired or rejected while it negotiated.
            self.rejected_hop_streams.insert(stream, peer.clone());
            self.reset(io, peer.clone(), stream);
            return;
        }
        let proof = mesh.proof;
        let sent = io
            .swarm
            .send_stream(peer, stream, proof.to_vec().into(), io.now_ms())
            .and_then(|()| io.swarm.close_stream_write(peer, stream, io.now_ms()));
        if let Err(error) = sent {
            // The exchange is left to its deadline.
            self.runtime_error(
                RelayServerRuntimeErrorKind::SendStream,
                Some(peer.clone()),
                control_send_failure(error),
            );
            self.drop_member_stream(stream);
            self.rejected_hop_streams.insert(stream, peer.clone());
            self.reset(io, peer.clone(), stream);
        }
    }

    /// The peer opened a member stream on `stream.conn_id`. A pending
    /// connection takes the first; a second rejects the connection.
    fn on_member_inbound(&mut self, io: &mut Io<'_>, peer: &PeerId, stream: StreamKey) {
        let pending = self
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.pending.get_mut(&stream.conn_id))
            .filter(|pending| pending.peer == *peer);
        match pending {
            Some(pending) if !pending.inbound_seen => {
                pending.inbound_seen = true;
                pending.inbound = Some((stream, MemberReader::proof()));
            }
            Some(_) => {
                self.rejected_hop_streams.insert(stream, peer.clone());
                self.reset(io, peer.clone(), stream);
                self.reject(io, stream.conn_id, MeshRejectionReason::DuplicateProof);
            }
            // A verified link proves itself once.
            None => {
                self.rejected_hop_streams.insert(stream, peer.clone());
                self.reset(io, peer.clone(), stream);
            }
        }
    }

    /// Bytes on a member stream, kept for the half-close. Returns whether
    /// the stream is one.
    pub(super) fn on_member_data(
        &mut self,
        io: &mut Io<'_>,
        stream: StreamKey,
        data: &[u8],
    ) -> bool {
        let Some(pending) = self
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.pending.get_mut(&stream.conn_id))
        else {
            return false;
        };
        let Some(reader) = pending.side(stream).and_then(|side| pending.reader(side)) else {
            return false;
        };
        reader.push(data);
        io.ack(stream, data.len());
        true
    }

    /// A member stream half-closed: its message is judged. A valid proof is
    /// answered with the accept byte. Returns whether the stream is one.
    pub(super) fn on_member_eof(&mut self, io: &mut Io<'_>, stream: StreamKey) -> bool {
        let Some(mesh) = &mut self.mesh else {
            return false;
        };
        let Some(pending) = mesh.pending.get_mut(&stream.conn_id) else {
            return false;
        };
        let peer = pending.peer.clone();
        match pending.side(stream) {
            None => return false,
            Some(Side::Outbound) => {
                let accepted = pending
                    .outbound
                    .take()
                    .is_some_and(|(_, reader)| reader.finish() == Ok(&[MEMBER_ACCEPT][..]));
                if !accepted {
                    self.reject(io, stream.conn_id, MeshRejectionReason::MalformedAccept);
                    return true;
                }
                pending.accepted = true;
            }
            Some(Side::Inbound) => {
                let proof = pending
                    .inbound
                    .take()
                    .map(|(_, reader)| reader.finish_proof());
                let Some(Ok(proof)) = proof else {
                    self.reject(io, stream.conn_id, MeshRejectionReason::MalformedProof);
                    return true;
                };
                if !verify_member_proof(&mesh.public_key, &peer, &proof) {
                    self.reject(io, stream.conn_id, MeshRejectionReason::InvalidProof);
                    return true;
                }
                let answered = io
                    .swarm
                    .send_stream(
                        &peer,
                        stream,
                        Vec::from([MEMBER_ACCEPT]).into(),
                        io.now_ms(),
                    )
                    .and_then(|()| io.swarm.close_stream_write(&peer, stream, io.now_ms()));
                if let Err(error) = answered {
                    // The peer's side is left to its deadline.
                    self.runtime_error(
                        RelayServerRuntimeErrorKind::SendStream,
                        Some(peer),
                        control_send_failure(error),
                    );
                    return true;
                }
                if let Some(pending) = self
                    .mesh
                    .as_mut()
                    .and_then(|mesh| mesh.pending.get_mut(&stream.conn_id))
                {
                    pending.verified = true;
                }
            }
        }
        self.try_promote(io, stream.conn_id);
        true
    }

    /// A member stream closed or failed to negotiate before its half-close:
    /// dropped, without rejecting the connection; the deadline covers a
    /// proof that never comes. Returns whether the stream is one.
    pub(super) fn drop_member_stream(&mut self, stream: StreamKey) -> bool {
        let Some(pending) = self
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.pending.get_mut(&stream.conn_id))
        else {
            return false;
        };
        match pending.side(stream) {
            Some(Side::Outbound) => pending.outbound = None,
            Some(Side::Inbound) => pending.inbound = None,
            None => return false,
        }
        true
    }

    /// Makes a pending connection a member link once both proofs checked
    /// out, unless the swarm already retired it (its queued lifecycle event
    /// settles it then).
    fn try_promote(&mut self, io: &mut Io<'_>, conn_id: ConnectionId) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        let Some(pending) = mesh.pending.get(&conn_id) else {
            return;
        };
        if !(pending.accepted && pending.verified)
            || io.swarm.connection_peer(conn_id) != Some(&pending.peer)
        {
            return;
        }
        let Some(pending) = mesh.pending.remove(&conn_id) else {
            return;
        };
        mesh.proof_deadlines.remove(&conn_id);
        self.member_connected(io, pending.peer, conn_id, pending.holds_entry);
    }

    /// Closes a pending connection whose proof exchange failed, unless the
    /// swarm already retired it. A member it held the directory entry of
    /// leaves the directory, and the CONNECTs waiting on it re-resolve.
    fn reject(&mut self, io: &mut Io<'_>, conn_id: ConnectionId, reason: MeshRejectionReason) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        let Some(peer) = mesh
            .pending
            .get(&conn_id)
            .map(|pending| pending.peer.clone())
        else {
            return;
        };
        if io.swarm.connection_peer(conn_id) != Some(&peer) {
            // Its queued `ConnectionReplaced` or `ConnectionClosed` moves or
            // removes the directory entry.
            return;
        }
        let holds_entry = mesh
            .pending
            .remove(&conn_id)
            .is_some_and(|pending| pending.holds_entry);
        mesh.proof_deadlines.remove(&conn_id);
        if holds_entry {
            mesh.directory.member_disconnected(&peer);
        }
        self.events.push_back(RelayServerEvent::MeshPeerRejected {
            peer_id: peer.clone(),
            reason,
        });
        if let Err(error) = io.swarm.close_connection(&peer, conn_id, io.now_ms()) {
            self.runtime_error(
                RelayServerRuntimeErrorKind::Mesh,
                Some(peer.clone()),
                error.to_string(),
            );
        }
        if holds_entry {
            self.events
                .push_back(RelayServerEvent::MeshMemberDown { member: peer });
            self.resolve_waiting(io, None);
        }
    }

    /// Rejects the pending connections whose proofs are due.
    pub(super) fn expire_proofs(&mut self, io: &mut Io<'_>) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        for conn_id in mesh.proof_deadlines.due(io.now_ms()) {
            if let Some(mesh) = &mut self.mesh {
                mesh.proof_deadlines.remove(&conn_id);
            }
            self.reject(io, conn_id, MeshRejectionReason::TimedOut);
        }
    }

    /// A verified connection becomes `peer`'s link: the member joins the
    /// directory (unless it never left it) and a directory sync starts.
    fn member_connected(
        &mut self,
        io: &mut Io<'_>,
        peer: PeerId,
        conn_id: ConnectionId,
        in_directory: bool,
    ) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        mesh.links.insert(
            peer.clone(),
            Link {
                conn_id,
                stream: None,
                live: false,
                backlog: Vec::new(),
                blocked: false,
                backoff: Backoff::new(),
            },
        );
        mesh.reopen.remove(&peer);
        mesh.directory.member_connected(peer.clone());
        // Only each member's latest counts, so a host that never takes
        // them holds one per member.
        mesh.verified.retain(|(member, _)| *member != peer);
        mesh.verified.push((peer.clone(), conn_id));
        if !in_directory {
            self.events.push_back(RelayServerEvent::MeshMemberUp {
                member: peer.clone(),
            });
        }
        // Kept like any connection, so circuits and workers on it end with it.
        self.connections.insert(
            conn_id,
            Connection {
                peer_id: peer.clone(),
                ip: None,
                is_circuit: false,
            },
        );
        self.open_directory(io, peer);
    }

    // --- Directory, sender side ---

    fn open_directory(&mut self, io: &mut Io<'_>, member: PeerId) {
        let Some(conn_id) = self
            .mesh
            .as_ref()
            .and_then(|mesh| mesh.links.get(&member))
            .map(|link| link.conn_id)
        else {
            return;
        };
        match self.open_backbone(io, &member, conn_id, DIRECTORY_PROTOCOL_ID) {
            Some(stream) => {
                if let Some(mesh) = &mut self.mesh
                    && let Some(link) = mesh.links.get_mut(&member)
                {
                    link.stream = Some(stream);
                    mesh.publishing.insert(stream, member);
                }
            }
            // A retired link goes with its queued lifecycle event.
            None => self.schedule_reopen(io, &member),
        }
    }

    /// Queues `member`'s directory stream to reopen after its backoff.
    fn schedule_reopen(&mut self, io: &Io<'_>, member: &PeerId) {
        if let Some(mesh) = &mut self.mesh
            && let Some(link) = mesh.links.get_mut(member)
        {
            let delay_ms = link.backoff.next_delay_ms();
            mesh.reopen
                .set(member.clone(), io.now_ms().saturating_add(delay_ms));
        }
    }

    pub(super) fn reopen_due_directories(&mut self, io: &mut Io<'_>) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        for member in mesh.reopen.due(io.now_ms()) {
            let Some(mesh) = &mut self.mesh else {
                return;
            };
            mesh.reopen.remove(&member);
            if mesh
                .links
                .get(&member)
                .is_some_and(|link| link.stream.is_none())
            {
                self.open_directory(io, member);
            }
        }
    }

    /// The link's current directory stream ended while the link is up:
    /// later events on it are still claimed, and a new one opens after the
    /// backoff.
    fn lose_directory(&mut self, io: &Io<'_>, member: &PeerId) {
        if let Some(mesh) = &mut self.mesh
            && let Some(link) = mesh.links.get_mut(member)
        {
            link.stream = None;
            link.live = false;
            link.blocked = false;
            link.backlog.clear();
        }
        self.schedule_reopen(io, member);
    }

    /// A directory stream this node opened finished negotiating: sends the
    /// snapshot, a `Present` per local reservation then `Synced`. Returns
    /// whether the stream is one.
    pub(super) fn on_directory_ready(&mut self, io: &mut Io<'_>, stream: StreamKey) -> bool {
        let Some(mesh) = &mut self.mesh else {
            return false;
        };
        let Some(member) = mesh.publishing.get(&stream).cloned() else {
            return false;
        };
        let Some(link) = mesh
            .links
            .get_mut(&member)
            .filter(|link| link.stream == Some(stream))
        else {
            // A stream given up while it negotiated.
            self.reset(io, member, stream);
            return true;
        };
        link.live = true;
        let mut snapshot = Vec::new();
        for (peer, record) in &self.reservations {
            snapshot.extend_from_slice(
                &DirectoryMessage::Present {
                    peer: peer.clone(),
                    expires_unix: record.expires_unix,
                }
                .encode_frame(),
            );
        }
        snapshot.extend_from_slice(&DirectoryMessage::Synced.encode_frame());
        self.send_directory(io, &member, snapshot);
        true
    }

    /// Sends the message `message` builds to every member whose directory
    /// stream is live. A relay outside a mesh pays one inline branch: the
    /// message is built only when there is a member to send it to, out of
    /// line.
    #[inline(always)]
    pub(super) fn publish(&mut self, io: &mut Io<'_>, message: impl FnOnce() -> DirectoryMessage) {
        if self.mesh.is_some() {
            self.publish_to_members(io, message);
        }
    }

    #[inline(never)]
    fn publish_to_members(&mut self, io: &mut Io<'_>, message: impl FnOnce() -> DirectoryMessage) {
        let Some(mesh) = &self.mesh else {
            return;
        };
        let members: Vec<PeerId> = mesh
            .links
            .iter()
            .filter(|(_, link)| link.live)
            .map(|(member, _)| member.clone())
            .collect();
        if members.is_empty() {
            return;
        }
        let frame = message().encode_frame();
        for member in members {
            self.send_directory(io, &member, frame.clone());
        }
    }

    /// Writes `data` on `member`'s directory stream behind any backlog. A
    /// Full queues the tail for the stream's writable; any other failure,
    /// or a backlog past its cap, resets the stream and reopens it later.
    fn send_directory(&mut self, io: &mut Io<'_>, member: &PeerId, data: Vec<u8>) {
        let Some(link) = self
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.links.get_mut(member))
        else {
            return;
        };
        let Some(stream) = link.stream else {
            return;
        };
        if link.blocked {
            link.backlog.extend_from_slice(&data);
            if link.backlog.len() > MAX_DIRECTORY_BACKLOG {
                self.reset(io, member.clone(), stream);
                self.lose_directory(io, member);
            }
            return;
        }
        match io
            .swarm
            .send_stream(member, stream, data.into(), io.now_ms())
        {
            // Nothing is left queued, so the snapshot is in the transport:
            // the next lost stream reopens from the shortest backoff.
            Ok(()) => link.backoff.reset(),
            Err(RelaySwarmError(DriverError::Full { unsent, .. })) => {
                link.blocked = true;
                link.backlog = unsent.to_vec();
            }
            Err(error) => {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::SendStream,
                    Some(member.clone()),
                    control_send_failure(error),
                );
                self.reset(io, member.clone(), stream);
                self.lose_directory(io, member);
            }
        }
    }

    /// Resends a blocked directory stream's backlog.
    pub(super) fn resume_directory(&mut self, io: &mut Io<'_>, stream: StreamKey) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        let Some(member) = mesh.publishing.get(&stream).cloned() else {
            return;
        };
        let Some(link) = mesh
            .links
            .get_mut(&member)
            .filter(|link| link.stream == Some(stream) && link.blocked)
        else {
            return;
        };
        link.blocked = false;
        let backlog = core::mem::take(&mut link.backlog);
        self.send_directory(io, &member, backlog);
    }

    // --- Directory, receiver side, and stream ends ---

    /// An inbound mesh stream finished negotiating. A member stream joins
    /// its pending connection's proof exchange. Directory and forward
    /// streams from a member's current link are taken; on a pending
    /// connection they are reset quietly (the peer may simply have verified
    /// first, and reopens its directory stream later), and from anyone else
    /// they are reset as an error. Returns whether the stream is the
    /// relay's.
    ///
    /// Out of line: inlined into `dispatch`, it slowed every relay's events.
    #[inline(never)]
    pub(super) fn on_mesh_stream_ready(
        &mut self,
        io: &mut Io<'_>,
        peer: &PeerId,
        stream: StreamKey,
        protocol_id: &str,
    ) -> bool {
        if protocol_id == MEMBER_PROTOCOL_ID {
            self.on_member_inbound(io, peer, stream);
            return true;
        }
        if protocol_id != DIRECTORY_PROTOCOL_ID && protocol_id != FORWARD_PROTOCOL_ID {
            return false;
        }
        if self
            .mesh
            .as_ref()
            .is_some_and(|mesh| mesh.pending.contains_key(&stream.conn_id))
        {
            self.rejected_hop_streams.insert(stream, peer.clone());
            self.reset(io, peer.clone(), stream);
            return true;
        }
        if !self.is_member_link(peer, stream.conn_id) {
            self.rejected_hop_streams.insert(stream, peer.clone());
            self.reset(io, peer.clone(), stream);
            self.runtime_error(
                RelayServerRuntimeErrorKind::Mesh,
                Some(peer.clone()),
                format!("refused {protocol_id} from a peer that is not a mesh member"),
            );
            return true;
        }
        if protocol_id == DIRECTORY_PROTOCOL_ID {
            if let Some(mesh) = &mut self.mesh {
                mesh.directory.stream_opened(peer.clone(), stream);
                mesh.receiving.insert(stream, peer.clone());
            }
        } else {
            self.hop_workers.insert(
                stream,
                HopWorker {
                    peer_id: peer.clone(),
                    responder: Responder::Forward {
                        request: Vec::new(),
                        source: None,
                    },
                    request_known: false,
                    is_circuit: false,
                },
            );
            self.hop_deadlines.set(
                stream,
                io.now_ms()
                    .saturating_add(self.config.control_stream_timeout_ms),
            );
        }
        true
    }

    /// Bytes on a directory stream: a member's directory, applied; or on one
    /// this node publishes on, ignored. Returns whether the stream is one.
    pub(super) fn on_directory_data(
        &mut self,
        io: &mut Io<'_>,
        stream: StreamKey,
        data: &[u8],
    ) -> bool {
        let Some(mesh) = &mut self.mesh else {
            return false;
        };
        if mesh.publishing.contains_key(&stream) {
            io.ack(stream, data.len());
            return true;
        }
        let Some(member) = mesh.receiving.get(&stream).cloned() else {
            return false;
        };
        io.ack(stream, data.len());
        match mesh.directory.stream_data(&member, &stream, data) {
            DirectoryInput::Ignored => {}
            // A new claim can serve a CONNECT waiting on another member.
            DirectoryInput::Applied => self.resolve_waiting(io, None),
            DirectoryInput::Synced => {
                let entries = mesh.directory.entry_count(&member);
                self.events
                    .push_back(RelayServerEvent::MeshMemberSynced { member, entries });
                self.resolve_waiting(io, None);
            }
            DirectoryInput::Reset(reason) => {
                mesh.receiving.remove(&stream);
                self.rejected_hop_streams.insert(stream, member.clone());
                self.reset(io, member.clone(), stream);
                self.runtime_error(
                    RelayServerRuntimeErrorKind::Mesh,
                    Some(member),
                    format!("reset a member's directory stream: {reason:?}"),
                );
            }
        }
        true
    }

    /// A directory stream half-closed (`closed` false) or closed. A member's
    /// current one drops its entries; this node's own one, once closed,
    /// reopens after the backoff. Returns whether the stream is one.
    pub(super) fn on_directory_ended(
        &mut self,
        io: &mut Io<'_>,
        stream: StreamKey,
        closed: bool,
    ) -> bool {
        let Some(mesh) = &mut self.mesh else {
            return false;
        };
        if let Some(member) = mesh.receiving.get(&stream).cloned() {
            mesh.directory.stream_ended(&member, &stream);
            if closed {
                mesh.receiving.remove(&stream);
            }
            return true;
        }
        let Some(member) = mesh.publishing.get(&stream).cloned() else {
            return false;
        };
        // The receiver never writes, so its half-close changes nothing.
        if closed {
            mesh.publishing.remove(&stream);
            if mesh
                .links
                .get(&member)
                .is_some_and(|link| link.stream == Some(stream))
            {
                self.lose_directory(io, &member);
            }
        }
        true
    }

    // --- CONNECT resolution, entry side ---

    /// Picks a CONNECT's destination leg (Decision 4): the local
    /// reservation, else the next untried remote claim (latest expiry
    /// first), else a wait while some member is unsynced. `Err` is the
    /// status to refuse it with: the last claim's refusal, or
    /// `NO_RESERVATION` when no claim was found.
    pub(super) fn route(
        &mut self,
        io: &mut Io<'_>,
        destination: &PeerId,
        resolution: &mut Resolution,
    ) -> Result<Route, Status> {
        if let Some(conn_id) = self.live_reservation(destination) {
            if self.pending_stop_count(conn_id)
                >= self.config.max_pending_stop_requests_per_connection
            {
                return Err(Status::ResourceLimitExceeded);
            }
            match self.open_stop(io, destination, conn_id) {
                Ok(stream) => return Ok(Route::Stop { conn_id, stream }),
                Err(status) => resolution.last_status = Some(status),
            }
        }
        let Some(mesh) = &self.mesh else {
            return Err(resolution.last_status.unwrap_or(Status::NoReservation));
        };
        let now_unix = io.now.unix_seconds.unwrap_or(0);
        let claims: Vec<(PeerId, Option<ConnectionId>)> = mesh
            .directory
            .claims(destination, now_unix)
            .into_iter()
            .map(|claim| {
                let link = mesh.links.get(claim.member).map(|link| link.conn_id);
                (claim.member.clone(), link)
            })
            .filter(|tried| !resolution.tried.contains(tried))
            .collect();
        for (member, link) in claims {
            resolution.tried.push((member.clone(), link));
            // A claim whose link is gone, or replaced under the agent, is a
            // failed one.
            let opened = link
                .and_then(|conn_id| self.open_backbone(io, &member, conn_id, FORWARD_PROTOCOL_ID));
            match opened {
                Some(stream) => return Ok(Route::Forward { member, stream }),
                None => resolution.last_status = Some(Status::ConnectionFailed),
            }
        }
        if self
            .mesh
            .as_ref()
            .is_some_and(|mesh| mesh.directory.has_unsynced_member())
        {
            Ok(Route::Wait)
        } else {
            Err(resolution.last_status.unwrap_or(Status::NoReservation))
        }
    }

    /// Routes a resolving CONNECT again, or answers it once nothing is
    /// left.
    fn resolve(&mut self, io: &mut Io<'_>, source_stream: StreamKey) {
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return;
        };
        let destination = circuit.destination_peer_id.clone();
        let source_ip = circuit.source_ip.clone();
        let held_ip = circuit.destination_ip.clone();
        // The destination may have reserved here since admission. Its IP
        // then joins the circuit's accounting, under the same cap.
        let local_ip = self
            .live_reservation(&destination)
            .and_then(|conn_id| self.connection_ip(conn_id));
        let ip_changes = local_ip.is_some() && local_ip != held_ip;
        if ip_changes
            && local_ip != source_ip
            && self.ip_tally.is_full(
                local_ip.as_ref(),
                Held::Circuits,
                self.config.max_circuits_per_ip,
            )
        {
            self.fail_pending_connect(io, source_stream, Status::ResourceLimitExceeded);
            return;
        }
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return;
        };
        // Only a mesh node resolves, and its CONNECTs carry mesh state.
        let mut resolution = circuit
            .mesh
            .as_mut()
            .map(|mesh| core::mem::take(&mut mesh.resolution))
            .unwrap_or_default();
        let routed = self.route(io, &destination, &mut resolution);
        if ip_changes && matches!(routed, Ok(Route::Stop { .. })) {
            self.release_circuit_ips(source_ip.as_ref(), held_ip.as_ref());
            self.hold_circuit_ips(source_ip.as_ref(), local_ip.as_ref());
        }
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return;
        };
        if let Some(mesh) = &mut circuit.mesh {
            mesh.resolution = resolution;
        }
        match routed {
            Ok(Route::Wait) => {}
            Ok(route) => {
                if ip_changes && matches!(route, Route::Stop { .. }) {
                    circuit.destination_ip = local_ip;
                }
                circuit.route(route);
                if let Some(conn_id) = circuit.destination_conn_id {
                    self.pending_by_destination.insert((conn_id, source_stream));
                }
                if let Some(stream) = circuit.destination_stream {
                    self.stop_to_source.insert(stream, source_stream);
                }
            }
            Err(status) => self.fail_pending_connect(io, source_stream, status),
        }
    }

    /// Re-routes the CONNECTs waiting on a member's directory, after a
    /// member synced or a link dropped (`None`: all of them), or after
    /// `Some(destination)` reserved here (only those to it).
    pub(super) fn resolve_waiting(&mut self, io: &mut Io<'_>, destination: Option<&PeerId>) {
        let waiting: Vec<StreamKey> = self
            .pending_circuits
            .iter()
            .filter(|(_, circuit)| {
                matches!(circuit.destination, PendingDestination::Resolving)
                    && destination.is_none_or(|peer| circuit.destination_peer_id == *peer)
            })
            .map(|(stream, _)| *stream)
            .collect();
        for source_stream in waiting {
            self.resolve(io, source_stream);
        }
    }

    pub(super) fn is_pending_forward(&self, source_stream: StreamKey) -> bool {
        self.pending_circuits
            .get(&source_stream)
            .is_some_and(|circuit| matches!(circuit.destination, PendingDestination::Forward(_)))
    }

    /// A forward did not open a circuit. `NO_RESERVATION` and
    /// `CONNECTION_FAILED` (including a failed link or stream) move on to
    /// the next claim; any other status is the holding node's decision on a
    /// live reservation and goes to the dialer.
    pub(super) fn forward_refused(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        status: Status,
    ) {
        if !matches!(status, Status::NoReservation | Status::ConnectionFailed) {
            self.fail_pending_connect(io, source_stream, status);
            return;
        }
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return;
        };
        if let Some(mesh) = &mut circuit.mesh {
            mesh.resolution.last_status = Some(status);
        }
        let member = circuit.destination_leg_peer().clone();
        let ready = circuit.destination_ready();
        let stream = circuit.destination_stream.take();
        let conn_id = circuit.destination_conn_id.take();
        circuit.destination = PendingDestination::Resolving;
        if let Some(conn_id) = conn_id {
            self.pending_by_destination
                .remove(&(conn_id, source_stream));
        }
        if let Some(stream) = stream {
            self.stop_to_source.remove(&stream);
            self.retire_stop(io, member, stream, ready);
        }
        self.resolve(io, source_stream);
    }

    /// Reads a forward's STATUS reply on the entry node. Returns how many
    /// of `data`'s bytes it kept as the holding node's pipelined payload;
    /// those stay unacknowledged until forwarded.
    pub(super) fn on_forward_reply(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        data: &[u8],
    ) -> usize {
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return 0;
        };
        let member = circuit.destination_leg_peer().clone();
        let PendingDestination::Forward(forward) = &mut circuit.destination else {
            return 0;
        };
        let Some(reply) = &mut forward.reply else {
            return 0;
        };
        reply.extend_from_slice(data);
        match decode_mesh_frame(reply, ForwardMessage::decode) {
            Ok(None) => 0,
            Ok(Some((ForwardMessage::Status(Status::Ok), consumed))) => {
                // Bytes past the STATUS can only be from this read: an
                // earlier one held no complete frame.
                let pipelined = reply.split_off(consumed);
                let kept = !pipelined.is_empty()
                    && self.append_pending_payload(
                        io,
                        source_stream,
                        CircuitDirection::DestinationToSource,
                        &pipelined,
                    );
                self.accept_pending_circuit(io, source_stream);
                if kept { pipelined.len() } else { 0 }
            }
            Ok(Some((ForwardMessage::Status(status), _))) => {
                self.forward_refused(io, source_stream, status);
                0
            }
            Ok(Some((ForwardMessage::Forward { .. }, _))) | Err(_) => {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::Mesh,
                    Some(member),
                    "malformed forward reply".into(),
                );
                self.forward_refused(io, source_stream, Status::ConnectionFailed);
                0
            }
        }
    }

    // --- Forward protocol, holding side ---

    /// Reads a member's forward request. Request bytes are consumed as
    /// read; payload pipelined behind it stays unacknowledged with the
    /// pending circuit.
    pub(super) fn on_forward_request_data(
        &mut self,
        io: &mut Io<'_>,
        stream: StreamKey,
        data: &[u8],
    ) {
        let Some(HopWorker {
            peer_id,
            responder: Responder::Forward { request, source },
            request_known,
            ..
        }) = self.hop_workers.get_mut(&stream)
        else {
            return;
        };
        if *request_known {
            // The request was refused; nothing after it matters.
            io.ack(stream, data.len());
            return;
        }
        request.extend_from_slice(data);
        match decode_mesh_frame(request, ForwardMessage::decode) {
            Ok(None) => io.ack(stream, data.len()),
            Ok(Some((
                ForwardMessage::Forward {
                    source: forwarded,
                    destination,
                    limit,
                },
                consumed,
            ))) => {
                *request_known = true;
                *source = Some(forwarded.clone());
                let pipelined = request.split_off(consumed);
                request.clear();
                io.ack(stream, data.len() - pipelined.len());
                self.decide_forward(io, stream, forwarded, destination, limit);
                let kept = !pipelined.is_empty()
                    && self.pending_circuits.contains_key(&stream)
                    && self.append_pending_payload(
                        io,
                        stream,
                        CircuitDirection::SourceToDestination,
                        &pipelined,
                    );
                if !kept {
                    io.ack(stream, pipelined.len());
                }
            }
            Ok(Some((ForwardMessage::Status(_), _))) | Err(_) => {
                let member = peer_id.clone();
                io.ack(stream, data.len());
                self.remove_hop_worker(stream);
                self.rejected_hop_streams.insert(stream, member.clone());
                self.reset(io, member.clone(), stream);
                self.runtime_error(
                    RelayServerRuntimeErrorKind::Mesh,
                    Some(member),
                    "malformed forward request".into(),
                );
            }
        }
    }

    /// Decides a forwarded CONNECT (Decision 7). Without a live local
    /// reservation for `destination` it answers `NO_RESERVATION` before any
    /// other check, so the entry node falls through to its next claim. Then
    /// pause, the global cap, the destination's peer and IP caps, and the
    /// reservation connection's pending-STOP cap. The source counts as
    /// `source`, with no IP key and no rate token.
    fn decide_forward(
        &mut self,
        io: &mut Io<'_>,
        stream: StreamKey,
        source: PeerId,
        destination: PeerId,
        limit: Limit,
    ) {
        let Some(member) = self
            .hop_workers
            .get(&stream)
            .map(|worker| worker.peer_id.clone())
        else {
            return;
        };
        let conn_id = self.live_reservation(&destination);
        let destination_ip = conn_id.and_then(|conn_id| self.connection_ip(conn_id));
        let checked = match conn_id {
            None => Err(Status::NoReservation),
            Some(_) if !self.accepting => Err(Status::PermissionDenied),
            Some(conn_id)
                if self.circuit_count() >= self.config.max_circuits
                    || self.peer_circuit_count(&destination)
                        >= self.config.max_circuits_per_peer
                    || self.ip_tally.is_full(
                        destination_ip.as_ref(),
                        Held::Circuits,
                        self.config.max_circuits_per_ip,
                    )
                    || self.pending_stop_count(conn_id)
                        >= self.config.max_pending_stop_requests_per_connection =>
            {
                Err(Status::ResourceLimitExceeded)
            }
            Some(conn_id) => Ok(conn_id),
        };
        let opened = checked.and_then(|conn_id| {
            self.open_stop(io, &destination, conn_id)
                .map(|stop| (conn_id, stop))
        });
        let (conn_id, stop) = match opened {
            Ok(opened) => opened,
            Err(status) => {
                self.deny_connect(io, stream, destination, status);
                return;
            }
        };
        let mesh = PendingMesh {
            forwarded_by: Some(member),
            limit,
            resolution: Resolution::default(),
        };
        let pending = PendingCircuit::new(
            source,
            destination,
            None,
            destination_ip,
            Route::Stop {
                conn_id,
                stream: stop,
            },
            Some(Box::new(mesh)),
        );
        self.insert_pending_circuit(
            stream,
            pending,
            io.now_ms()
                .saturating_add(self.config.control_stream_timeout_ms),
        );
    }
}
