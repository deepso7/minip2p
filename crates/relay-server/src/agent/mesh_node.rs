//! The agent's relay-mesh side: backbone membership, directory publishing
//! and receiving, CONNECT resolution across members, and the forward
//! protocol on both the entry and the holding node.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_relay::{Limit, Status};
use minip2p_swarm::DriverError;
use minip2p_transport::ConnectionId;

use super::{
    Connection, Deadlines, Held, HopWorker, Io, PendingCircuit, PendingDestination, Resolution,
    Responder, Route, control_send_failure,
};
use crate::mesh::{
    DIRECTORY_PROTOCOL_ID, Directory, DirectoryInput, DirectoryMessage, FORWARD_PROTOCOL_ID,
    ForwardMessage, MeshConfig, decode_mesh_frame, is_backbone_connection,
};
use crate::{
    CircuitDirection, RelayServerAgent, RelayServerRuntimeErrorKind, RelaySwarmError, StreamKey,
};

/// First delay before a directory stream that ended on a live link reopens;
/// it doubles per reopen up to [`MAX_REOPEN_BACKOFF_MS`], and resets once a
/// snapshot is out.
const MIN_REOPEN_BACKOFF_MS: u64 = 1_000;
const MAX_REOPEN_BACKOFF_MS: u64 = 30_000;

/// Most directory bytes queued behind a full stream. Past it the stream is
/// reset and reopened, so the member resyncs from a fresh snapshot.
const MAX_DIRECTORY_BACKLOG: usize = 1 << 20;

/// A mesh node's state beside the relay's own.
pub(super) struct MeshNode {
    members: BTreeSet<PeerId>,
    directory: Directory<StreamKey>,
    /// Each connected member's backbone link.
    links: BTreeMap<PeerId, Link>,
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
            members: config.members.clone(),
            directory: Directory::new(config.max_directory_entries_per_member),
            links: BTreeMap::new(),
            publishing: BTreeMap::new(),
            receiving: BTreeMap::new(),
            reopen: Deadlines::new(),
        }
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
    backoff_ms: u64,
}

impl RelayServerAgent {
    /// Whether `conn_id` is a backbone connection of this mesh node. Always
    /// false for a single relay, which treats every connection as today.
    pub(super) fn is_backbone(&self, conn_id: ConnectionId) -> bool {
        self.mesh.is_some() && is_backbone_connection(conn_id)
    }

    pub(super) fn owns_directory_stream(&self, stream: StreamKey) -> bool {
        self.mesh.as_ref().is_some_and(|mesh| {
            mesh.publishing.contains_key(&stream) || mesh.receiving.contains_key(&stream)
        })
    }

    /// Whether `peer` is a member whose current link is `conn_id`.
    fn is_member_link(&self, peer: &PeerId, conn_id: ConnectionId) -> bool {
        self.mesh.as_ref().is_some_and(|mesh| {
            mesh.links
                .get(peer)
                .is_some_and(|link| link.conn_id == conn_id)
        })
    }

    /// A backbone connection came up: a member's starts a directory sync,
    /// anyone else's is closed.
    pub(super) fn on_backbone_established(
        &mut self,
        io: &mut Io<'_>,
        peer: PeerId,
        conn_id: ConnectionId,
    ) {
        let Some(mesh) = &mut self.mesh else {
            return;
        };
        if !mesh.members.contains(&peer) {
            if let Err(error) = io.swarm.close_connection(&peer, conn_id, io.now_ms()) {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::Mesh,
                    Some(peer.clone()),
                    error.to_string(),
                );
            }
            self.runtime_error(
                RelayServerRuntimeErrorKind::Mesh,
                Some(peer),
                "closed a backbone connection from a peer that is not a mesh member".into(),
            );
            return;
        }
        mesh.links.insert(
            peer.clone(),
            Link {
                conn_id,
                stream: None,
                live: false,
                backlog: Vec::new(),
                blocked: false,
                backoff_ms: MIN_REOPEN_BACKOFF_MS,
            },
        );
        mesh.reopen.remove(&peer);
        mesh.directory.member_connected(peer.clone());
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

    /// A member's link was replaced. It holds no reservation to move, so
    /// the old link goes first and the new one starts a fresh sync. The
    /// member stays connected and unsynced throughout, so CONNECTs waiting
    /// on it, or falling back from a forward on the old link, keep waiting
    /// for the new link's snapshot instead of failing.
    pub(super) fn on_backbone_replaced(
        &mut self,
        io: &mut Io<'_>,
        peer: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
    ) {
        if self.on_backbone_closed(peer, old)
            && let Some(mesh) = &mut self.mesh
        {
            mesh.directory.member_connected(peer.clone());
        }
        self.on_connection_closed(io, peer, old);
        self.on_backbone_established(io, peer.clone(), new);
    }

    /// Forgets the link `conn_id` to `peer`, dropping the member's entries.
    /// Returns whether it was the member's current link; the caller then
    /// re-resolves the CONNECTs waiting on it.
    pub(super) fn on_backbone_closed(&mut self, peer: &PeerId, conn_id: ConnectionId) -> bool {
        let Some(mesh) = &mut self.mesh else {
            return false;
        };
        if mesh
            .links
            .get(peer)
            .is_none_or(|link| link.conn_id != conn_id)
        {
            return false;
        }
        mesh.links.remove(peer);
        mesh.reopen.remove(peer);
        mesh.directory.member_disconnected(peer);
        mesh.publishing
            .retain(|stream, _| stream.conn_id != conn_id);
        mesh.receiving.retain(|stream, _| stream.conn_id != conn_id);
        true
    }

    // --- Directory, sender side ---

    fn open_directory(&mut self, io: &mut Io<'_>, member: PeerId) {
        match io
            .swarm
            .open_stream(&member, DIRECTORY_PROTOCOL_ID, io.now_ms())
        {
            Ok(stream) => {
                if let Some(mesh) = &mut self.mesh
                    && let Some(link) = mesh.links.get_mut(&member)
                {
                    link.stream = Some(stream);
                    mesh.publishing.insert(stream, member);
                }
            }
            Err(error) => {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::OpenStream,
                    Some(member.clone()),
                    error.to_string(),
                );
                self.schedule_reopen(io, &member);
            }
        }
    }

    /// Queues `member`'s directory stream to reopen after its backoff.
    fn schedule_reopen(&mut self, io: &Io<'_>, member: &PeerId) {
        if let Some(mesh) = &mut self.mesh
            && let Some(link) = mesh.links.get_mut(member)
        {
            mesh.reopen
                .set(member.clone(), io.now_ms().saturating_add(link.backoff_ms));
            link.backoff_ms = link.backoff_ms.saturating_mul(2).min(MAX_REOPEN_BACKOFF_MS);
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
        link.backoff_ms = MIN_REOPEN_BACKOFF_MS;
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

    /// Sends `message` to every member whose directory stream is live.
    pub(super) fn publish(&mut self, io: &mut Io<'_>, message: &DirectoryMessage) {
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
        let frame = message.encode_frame();
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
            Ok(()) => {}
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

    /// An inbound mesh stream finished negotiating. Directory and forward
    /// streams from a member's current link are taken; from anyone else they
    /// are reset. Returns whether the stream is the relay's.
    pub(super) fn on_mesh_stream_ready(
        &mut self,
        io: &mut Io<'_>,
        peer: &PeerId,
        stream: StreamKey,
        protocol_id: &str,
    ) -> bool {
        if protocol_id != DIRECTORY_PROTOCOL_ID && protocol_id != FORWARD_PROTOCOL_ID {
            return false;
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
            DirectoryInput::Ignored | DirectoryInput::Applied => {}
            DirectoryInput::Synced => self.resolve_waiting(io),
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
            match io
                .swarm
                .open_stream(&member, FORWARD_PROTOCOL_ID, io.now_ms())
            {
                Ok(stream) => return Ok(Route::Forward { member, stream }),
                Err(error) => {
                    self.runtime_error(
                        RelayServerRuntimeErrorKind::OpenStream,
                        Some(member),
                        error.to_string(),
                    );
                    resolution.last_status = Some(Status::ConnectionFailed);
                }
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
        let mut resolution = core::mem::take(&mut circuit.resolution);
        let routed = self.route(io, &destination, &mut resolution);
        if ip_changes && matches!(routed, Ok(Route::Stop { .. })) {
            self.release_circuit_ips(source_ip.as_ref(), held_ip.as_ref());
            self.hold_circuit_ips(source_ip.as_ref(), local_ip.as_ref());
        }
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return;
        };
        circuit.resolution = resolution;
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

    /// Re-routes every CONNECT waiting on a member's directory, after a
    /// member synced or a link dropped.
    pub(super) fn resolve_waiting(&mut self, io: &mut Io<'_>) {
        let waiting: Vec<StreamKey> = self
            .pending_circuits
            .iter()
            .filter(|(_, circuit)| matches!(circuit.destination, PendingDestination::Resolving))
            .map(|(stream, _)| *stream)
            .collect();
        for source_stream in waiting {
            self.resolve(io, source_stream);
        }
    }

    pub(super) fn is_pending_forward(&self, source_stream: StreamKey) -> bool {
        self.pending_circuits
            .get(&source_stream)
            .is_some_and(|circuit| {
                matches!(circuit.destination, PendingDestination::Forward { .. })
            })
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
        circuit.resolution.last_status = Some(status);
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
        let PendingDestination::Forward {
            reply: Some(reply), ..
        } = &mut circuit.destination
        else {
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
        let mut pending = PendingCircuit {
            source_peer_id: source,
            destination_peer_id: destination,
            source_leg_peer: member,
            source_ip: None,
            destination_ip,
            destination_conn_id: None,
            destination_stream: None,
            destination: PendingDestination::Resolving,
            limit,
            resolution: Resolution::default(),
            source_pipelined: Vec::new(),
            destination_pipelined: Vec::new(),
            source_eof: false,
        };
        pending.route(Route::Stop {
            conn_id,
            stream: stop,
        });
        self.insert_pending_circuit(
            stream,
            pending,
            io.now_ms()
                .saturating_add(self.config.control_stream_timeout_ms),
        );
    }
}
