//! Sans-I/O core of the swarm.
//!
//! [`SwarmCore`] is a pure state machine: it consumes [`TransportEvent`]
//! values (plus a caller-supplied wall-clock timestamp) and emits
//! [`SwarmAction`] commands for a driver to execute against a concrete
//! transport. No sockets, no async runtime, no clock reads.
//!
//! `no_std + alloc` compatible. The std [`crate::Swarm`] driver is a thin
//! wrapper that owns a transport, reads the clock via [`std::time::Instant`],
//! and shuttles events and actions between the transport and the core.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identify::{
    IdentifyAction, IdentifyConfig, IdentifyEvent, IdentifyProtocol, IDENTIFY_PROTOCOL_ID,
};
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_ping::{
    PingAction, PingConfig, PingEvent, PingProtocol, PING_PAYLOAD_LEN, PING_PROTOCOL_ID,
};
use minip2p_transport::{ConnectionId, StreamId, TransportEvent};

use crate::events::{OpenStreamToken, SwarmAction, SwarmError, SwarmEvent};

// ---------------------------------------------------------------------------
// Protocol identification
// ---------------------------------------------------------------------------

/// Identifies which protocol owns a negotiated stream.
///
/// Kept private; callers refer to protocols by their string ids via
/// [`SwarmCore::open_user_stream`] and the `protocol_id` fields of
/// [`SwarmEvent::UserStreamReady`] / [`SwarmEvent::UserStreamData`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum ProtocolKind {
    Ping,
    /// Identify responder: we send our info.
    IdentifyResponder,
    /// Identify initiator: we receive their info.
    IdentifyInitiator,
    /// A user-registered protocol, with its string ID retained so events
    /// can surface it back to the application.
    User(String),
}

/// Tracks a pending outbound stream that is still negotiating multistream-select.
struct PendingOutbound {
    negotiator: MultistreamSelect,
    target: ProtocolKind,
}

/// Metadata associated with an outstanding OpenStream request waiting for
/// the driver to report back the allocated stream id.
struct PendingOpen {
    conn_id: ConnectionId,
    protocol: String,
    target: ProtocolKind,
}

// ---------------------------------------------------------------------------
// SwarmCore
// ---------------------------------------------------------------------------

/// Pure Sans-I/O swarm state machine.
///
/// See the module-level docs for the interaction model.
pub struct SwarmCore {
    // --- Protocol handlers ---
    ping: PingProtocol,
    identify: IdentifyProtocol,

    // --- Connection tracking ---
    /// Maps connection ids to peer ids (verified or synthetic).
    conn_to_peer: BTreeMap<ConnectionId, PeerId>,
    /// Maps peer ids to their primary connection id.
    peer_to_conn: BTreeMap<PeerId, ConnectionId>,
    /// Connections that have been established (with or without peer identity).
    active_connections: BTreeMap<ConnectionId, bool>,

    // --- Stream tracking ---
    /// Inbound streams being negotiated (server-side multistream-select).
    inbound_negotiators: BTreeMap<(ConnectionId, StreamId), MultistreamSelect>,
    /// Outbound streams being negotiated (client-side multistream-select).
    outbound_negotiators: BTreeMap<(ConnectionId, StreamId), PendingOutbound>,
    /// Streams that completed negotiation: maps to the owning protocol.
    stream_owner: BTreeMap<(ConnectionId, StreamId), ProtocolKind>,
    /// Outstanding OpenStream requests keyed by token; populated when the
    /// core emits `SwarmAction::OpenStream` and drained when the driver
    /// reports the allocated stream id back via `on_stream_opened`.
    pending_opens: BTreeMap<OpenStreamToken, PendingOpen>,
    /// Auto-incrementing source for [`OpenStreamToken`]s.
    next_open_token: u64,

    // --- Configuration ---
    /// Protocol IDs we advertise for inbound multistream-select negotiation.
    supported_protocols: Vec<String>,
    /// Application-registered protocol IDs (subset of `supported_protocols`).
    user_protocols: Vec<String>,

    // --- Bookkeeping ---
    /// Peers with a pending `.ping(peer)` call: once the ping stream
    /// negotiates, the queued 32-byte payload is sent automatically.
    pending_pings: BTreeMap<PeerId, [u8; PING_PAYLOAD_LEN]>,

    // --- Output queues ---
    events: Vec<SwarmEvent>,
    actions: Vec<SwarmAction>,
}

impl SwarmCore {
    /// Creates a new core with the given identify and ping configs.
    pub fn new(identify_config: IdentifyConfig, ping_config: PingConfig) -> Self {
        let supported_protocols = vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
        ];

        Self {
            ping: PingProtocol::new(ping_config),
            identify: IdentifyProtocol::new(identify_config),
            conn_to_peer: BTreeMap::new(),
            peer_to_conn: BTreeMap::new(),
            active_connections: BTreeMap::new(),
            inbound_negotiators: BTreeMap::new(),
            outbound_negotiators: BTreeMap::new(),
            stream_owner: BTreeMap::new(),
            pending_opens: BTreeMap::new(),
            next_open_token: 1,
            supported_protocols,
            user_protocols: Vec::new(),
            pending_pings: BTreeMap::new(),
            events: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Registers a user protocol id that this swarm will accept on inbound
    /// streams and allow for outbound opens via [`Self::open_user_stream`].
    pub fn add_user_protocol(&mut self, protocol_id: impl Into<String>) {
        let id = protocol_id.into();
        if !self.user_protocols.iter().any(|p| p == &id) {
            self.user_protocols.push(id.clone());
        }
        if !self.supported_protocols.iter().any(|p| p == &id) {
            self.supported_protocols.push(id);
        }
    }

    // -----------------------------------------------------------------------
    // Egress (driver drains these)
    // -----------------------------------------------------------------------

    /// Drains all buffered actions for the driver to execute.
    pub fn take_actions(&mut self) -> Vec<SwarmAction> {
        core::mem::take(&mut self.actions)
    }

    /// Drains all buffered application-visible events.
    pub fn poll_events(&mut self) -> Vec<SwarmEvent> {
        core::mem::take(&mut self.events)
    }

    /// Records a non-fatal error observed by the driver while executing a
    /// queued action (e.g. a [`SwarmAction::SendStream`] call on the
    /// transport failed).
    ///
    /// Surfaces as a [`SwarmEvent::Error`] on the next
    /// [`Self::poll_events`]. Used by the driver so transport-level
    /// failures are never silently dropped.
    pub fn record_error(&mut self, message: String) {
        self.events.push(SwarmEvent::Error { message });
    }

    // -----------------------------------------------------------------------
    // Application-facing intents
    // -----------------------------------------------------------------------

    /// Queues a ping to `peer_id` with the supplied random payload at
    /// `now_ms`.
    ///
    /// If a ping stream is already negotiated for this peer, the ping fires
    /// immediately (emits a `SendStream` action). If a ping stream is still
    /// negotiating, the payload is buffered and fires when the stream
    /// becomes ready. Otherwise a new ping stream is opened and the payload
    /// is buffered.
    ///
    /// The payload should come from a cryptographic RNG. The driver
    /// generates it in the std wrapper so the core stays free of
    /// randomness-dependencies.
    pub fn ping(
        &mut self,
        peer_id: &PeerId,
        payload: [u8; PING_PAYLOAD_LEN],
        now_ms: u64,
    ) -> Result<(), SwarmError> {
        if !self.peer_to_conn.contains_key(peer_id) {
            return Err(SwarmError::NotConnected {
                peer_id: peer_id.clone(),
            });
        }

        // Case 1: a ping stream is already negotiated -- fire now.
        if self.find_negotiated_ping_stream(peer_id).is_some() {
            let action = self
                .ping
                .send_ping(peer_id, &payload, now_ms)
                .map_err(|e| SwarmError::PingError {
                    reason: format!("{e}"),
                })?;
            self.execute_ping_action(action);
            return Ok(());
        }

        // Case 2: a ping stream is negotiating -- update the queued payload.
        if self.has_pending_ping_stream(peer_id) {
            self.pending_pings.insert(peer_id.clone(), payload);
            return Ok(());
        }

        // Case 3: no stream yet -- open one and queue the payload.
        self.pending_pings.insert(peer_id.clone(), payload);
        self.queue_open_protocol_stream(peer_id, PING_PROTOCOL_ID, ProtocolKind::Ping)?;
        Ok(())
    }

    /// Opens a new outbound stream and starts multistream-select negotiation
    /// for `protocol_id`. The actual stream id is not known until the driver
    /// reports back via [`Self::on_stream_opened`].
    pub fn open_user_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<(), SwarmError> {
        if !self.user_protocols.iter().any(|p| p == protocol_id) {
            return Err(SwarmError::ProtocolNotRegistered {
                protocol_id: protocol_id.to_string(),
            });
        }
        if !self.peer_to_conn.contains_key(peer_id) {
            return Err(SwarmError::NotConnected {
                peer_id: peer_id.clone(),
            });
        }

        self.queue_open_protocol_stream(
            peer_id,
            protocol_id,
            ProtocolKind::User(protocol_id.to_string()),
        )
    }

    /// Sends raw bytes on a negotiated user stream.
    ///
    /// Emits a `SendStream` action; the driver executes it.
    pub fn send_user_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        self.actions.push(SwarmAction::SendStream {
            conn_id,
            stream_id,
            data,
        });
        Ok(())
    }

    /// Half-closes our write side of a user stream.
    pub fn close_user_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        self.actions
            .push(SwarmAction::CloseStreamWrite { conn_id, stream_id });
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_user_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        self.actions
            .push(SwarmAction::ResetStream { conn_id, stream_id });
        Ok(())
    }

    /// Closes the connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        self.actions
            .push(SwarmAction::CloseConnection { conn_id });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Connection / peer lookup helpers (driver uses these)
    // -----------------------------------------------------------------------

    /// Returns the primary connection id currently mapped to `peer_id`.
    pub fn conn_for(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.peer_to_conn.get(peer_id).copied()
    }

    /// Returns the peer id currently mapped to `conn_id`, if any.
    pub fn peer_for(&self, conn_id: ConnectionId) -> Option<&PeerId> {
        self.conn_to_peer.get(&conn_id)
    }

    // -----------------------------------------------------------------------
    // Ingress
    // -----------------------------------------------------------------------

    /// Feeds a transport event into the core.
    pub fn on_transport_event(&mut self, event: TransportEvent, now_ms: u64) {
        match event {
            TransportEvent::Connected { id, endpoint } => {
                self.active_connections.insert(id, true);
                if let Some(peer_id) = endpoint.peer_id() {
                    self.register_connection(id, peer_id.clone());
                } else {
                    // Peer identity is not yet known (e.g. server side with
                    // verify_peer(false)). Synthesize a placeholder PeerId
                    // for internal bookkeeping so protocol handlers can still
                    // operate. No ConnectionEstablished event yet -- we emit
                    // one when the real identity arrives via
                    // PeerIdentityVerified.
                    let _ = self.ensure_peer_id_for_conn(id);
                }
            }
            TransportEvent::PeerIdentityVerified { id, endpoint, .. } => {
                if let Some(peer_id) = endpoint.peer_id() {
                    self.upgrade_connection_identity(id, peer_id.clone());
                }
            }
            TransportEvent::IncomingConnection { id, .. } => {
                self.active_connections.insert(id, false);
            }
            TransportEvent::IncomingStream { id, stream_id } => {
                self.handle_incoming_stream(id, stream_id);
            }
            TransportEvent::StreamOpened { .. } => {
                // Outbound stream id allocation is driver-synchronous; the
                // core tracks opens via `on_stream_opened` rather than this
                // event. No-op here.
            }
            TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } => {
                self.handle_stream_data(id, stream_id, data, now_ms);
            }
            TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                self.handle_stream_remote_write_closed(id, stream_id);
            }
            TransportEvent::StreamClosed { id, stream_id } => {
                self.handle_stream_closed(id, stream_id);
            }
            TransportEvent::Closed { id } => {
                self.handle_connection_closed(id);
            }
            TransportEvent::Listening { .. } => {}
            TransportEvent::Error { id, message } => {
                self.events.push(SwarmEvent::Error {
                    message: format!("transport error on connection {id}: {message}"),
                });
            }
        }
    }

    /// Advances time-based protocol state (e.g. ping timeouts).
    pub fn on_tick(&mut self, now_ms: u64) {
        let tick_actions = self.ping.on_tick(now_ms);
        for action in tick_actions {
            self.execute_ping_action(action);
        }
        self.collect_protocol_events();
    }

    /// Reports the result of an [`SwarmAction::OpenStream`] back to the core.
    ///
    /// The driver calls this after `transport.open_stream(conn_id)`
    /// succeeds. The core starts multistream-select on the stream and emits
    /// the outbound handshake as `SendStream` actions.
    pub fn on_stream_opened(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        token: OpenStreamToken,
        _now_ms: u64,
    ) {
        let Some(pending) = self.pending_opens.remove(&token) else {
            self.events.push(SwarmEvent::Error {
                message: format!(
                    "unknown OpenStream token {} reported by driver",
                    token.0
                ),
            });
            return;
        };

        // Guard against the driver reporting a different connection id than
        // the one we asked to open on.
        if pending.conn_id != conn_id {
            self.events.push(SwarmEvent::Error {
                message: format!(
                    "driver opened stream on connection {} but core requested {}",
                    conn_id, pending.conn_id
                ),
            });
            return;
        }

        let mut negotiator = MultistreamSelect::dialer(pending.protocol.as_str());
        for output in negotiator.start() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.actions.push(SwarmAction::SendStream {
                    conn_id,
                    stream_id,
                    data: bytes,
                });
            }
        }

        self.outbound_negotiators.insert(
            (conn_id, stream_id),
            PendingOutbound {
                negotiator,
                target: pending.target,
            },
        );
    }

    /// Reports that an [`SwarmAction::OpenStream`] failed at the driver.
    pub fn on_open_stream_failed(
        &mut self,
        token: OpenStreamToken,
        reason: String,
        _now_ms: u64,
    ) {
        let pending = self.pending_opens.remove(&token);
        self.events.push(SwarmEvent::Error {
            message: match pending {
                Some(p) => format!(
                    "open_stream for protocol '{}' on connection {} failed: {reason}",
                    p.protocol, p.conn_id
                ),
                None => format!("open_stream failed (unknown token): {reason}"),
            },
        });
    }

    /// Records that the driver just dialed `conn_id`. Currently a no-op
    /// -- the core begins tracking once `TransportEvent::Connected` or
    /// `TransportEvent::IncomingConnection` arrives -- but kept as an
    /// extension point.
    pub fn on_dialed(&mut self, _conn_id: ConnectionId) {}

    // -----------------------------------------------------------------------
    // Internal: state helpers
    // -----------------------------------------------------------------------

    fn require_conn(&self, peer_id: &PeerId) -> Result<ConnectionId, SwarmError> {
        self.peer_to_conn
            .get(peer_id)
            .copied()
            .ok_or_else(|| SwarmError::NotConnected {
                peer_id: peer_id.clone(),
            })
    }

    fn find_negotiated_ping_stream(&self, peer_id: &PeerId) -> Option<StreamId> {
        let conn = *self.peer_to_conn.get(peer_id)?;
        self.stream_owner.iter().find_map(|((c, s), owner)| {
            if *c == conn && matches!(owner, ProtocolKind::Ping) {
                Some(*s)
            } else {
                None
            }
        })
    }

    fn has_pending_ping_stream(&self, peer_id: &PeerId) -> bool {
        let Some(&conn) = self.peer_to_conn.get(peer_id) else {
            return false;
        };
        let negotiating = self
            .outbound_negotiators
            .iter()
            .any(|((c, _), pending)| *c == conn && matches!(pending.target, ProtocolKind::Ping));
        if negotiating {
            return true;
        }
        // Also check `pending_opens` for Ping opens that haven't yet been
        // ack'd by the driver (common shortly after calling ping()).
        self.pending_opens.values().any(|open| {
            open.conn_id == conn && matches!(open.target, ProtocolKind::Ping)
        })
    }

    fn queue_open_protocol_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        target: ProtocolKind,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        let token = self.next_open_token();
        self.pending_opens.insert(
            token,
            PendingOpen {
                conn_id,
                protocol: protocol_id.to_string(),
                target,
            },
        );
        self.actions
            .push(SwarmAction::OpenStream { conn_id, token });
        Ok(())
    }

    fn next_open_token(&mut self) -> OpenStreamToken {
        loop {
            let raw = self.next_open_token;
            self.next_open_token = self.next_open_token.wrapping_add(1);
            if raw != 0 {
                return OpenStreamToken(raw);
            }
        }
    }

    /// Returns the PeerId for a connection, creating a synthetic one if
    /// needed. Synthetic PeerIds are only ever seen internally -- the
    /// application does not see a `ConnectionEstablished` event for them.
    fn ensure_peer_id_for_conn(&mut self, conn_id: ConnectionId) -> PeerId {
        if let Some(peer_id) = self.conn_to_peer.get(&conn_id) {
            return peer_id.clone();
        }

        let synthetic_key = format!("minip2p-synthetic-conn-{}", conn_id.as_u64());
        let peer_id = PeerId::from_public_key_protobuf(synthetic_key.as_bytes());
        self.conn_to_peer.insert(conn_id, peer_id.clone());
        self.peer_to_conn.insert(peer_id.clone(), conn_id);
        peer_id
    }

    fn register_connection(&mut self, id: ConnectionId, peer_id: PeerId) {
        let is_new = !self.conn_to_peer.contains_key(&id);

        // If a different connection to the same peer already exists, close
        // it so it doesn't orphan in conn_to_peer. Last connection wins.
        if let Some(&existing_id) = self.peer_to_conn.get(&peer_id) {
            if existing_id != id {
                self.supersede_connection(existing_id);
            }
        }

        self.conn_to_peer.insert(id, peer_id.clone());
        self.peer_to_conn.insert(peer_id.clone(), id);

        if is_new {
            self.events.push(SwarmEvent::ConnectionEstablished {
                peer_id: peer_id.clone(),
            });

            // Auto-open identify.
            if let Err(e) = self.queue_open_protocol_stream(
                &peer_id,
                IDENTIFY_PROTOCOL_ID,
                ProtocolKind::IdentifyInitiator,
            ) {
                self.events.push(SwarmEvent::Error {
                    message: format!("failed to queue identify stream to {peer_id}: {e}"),
                });
            }
        }
    }

    fn supersede_connection(&mut self, old_id: ConnectionId) {
        self.conn_to_peer.remove(&old_id);
        self.active_connections.remove(&old_id);
        self.stream_owner.retain(|(cid, _), _| *cid != old_id);
        self.inbound_negotiators
            .retain(|(cid, _), _| *cid != old_id);
        self.outbound_negotiators
            .retain(|(cid, _), _| *cid != old_id);
        self.pending_opens.retain(|_, p| p.conn_id != old_id);
        self.actions
            .push(SwarmAction::CloseConnection { conn_id: old_id });
    }

    fn upgrade_connection_identity(&mut self, conn_id: ConnectionId, new_peer_id: PeerId) {
        let existing = self.conn_to_peer.get(&conn_id).cloned();

        match existing {
            Some(ref current) if *current == new_peer_id => return,
            Some(ref stale) => {
                self.peer_to_conn.remove(stale);
                self.ping.migrate_peer(stale, &new_peer_id);
                self.identify.migrate_peer(stale, &new_peer_id);
                if let Some(payload) = self.pending_pings.remove(stale) {
                    self.pending_pings.insert(new_peer_id.clone(), payload);
                }
                self.migrate_buffered_events(stale, &new_peer_id);
            }
            None => {}
        }

        self.conn_to_peer.insert(conn_id, new_peer_id.clone());
        self.peer_to_conn.insert(new_peer_id.clone(), conn_id);

        self.events.push(SwarmEvent::ConnectionEstablished {
            peer_id: new_peer_id.clone(),
        });

        if let Err(e) = self.queue_open_protocol_stream(
            &new_peer_id,
            IDENTIFY_PROTOCOL_ID,
            ProtocolKind::IdentifyInitiator,
        ) {
            self.events.push(SwarmEvent::Error {
                message: format!(
                    "failed to queue identify stream to {new_peer_id} after identity upgrade: {e}"
                ),
            });
        }
    }

    fn migrate_buffered_events(&mut self, old: &PeerId, new: &PeerId) {
        for event in &mut self.events {
            match event {
                SwarmEvent::ConnectionEstablished { peer_id }
                | SwarmEvent::ConnectionClosed { peer_id }
                | SwarmEvent::PingTimeout { peer_id } => {
                    if peer_id == old {
                        *peer_id = new.clone();
                    }
                }
                SwarmEvent::IdentifyReceived { peer_id, .. }
                | SwarmEvent::PingRttMeasured { peer_id, .. }
                | SwarmEvent::UserStreamReady { peer_id, .. }
                | SwarmEvent::UserStreamData { peer_id, .. }
                | SwarmEvent::UserStreamRemoteWriteClosed { peer_id, .. }
                | SwarmEvent::UserStreamClosed { peer_id, .. } => {
                    if peer_id == old {
                        *peer_id = new.clone();
                    }
                }
                SwarmEvent::Error { .. } => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: stream event handling
    // -----------------------------------------------------------------------

    fn handle_incoming_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let mut listener = MultistreamSelect::listener(self.supported_protocols.clone());
        let outputs = listener.start();
        self.inbound_negotiators
            .insert((conn_id, stream_id), listener);

        for output in outputs {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.actions.push(SwarmAction::SendStream {
                    conn_id,
                    stream_id,
                    data: bytes,
                });
            }
        }
    }

    fn handle_stream_data(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
        now_ms: u64,
    ) {
        let key = (conn_id, stream_id);

        if self.inbound_negotiators.contains_key(&key) {
            self.feed_inbound_negotiator(conn_id, stream_id, &data, now_ms);
            return;
        }

        if self.outbound_negotiators.contains_key(&key) {
            self.feed_outbound_negotiator(conn_id, stream_id, &data, now_ms);
            return;
        }

        self.dispatch_protocol_data(conn_id, stream_id, data, now_ms);
    }

    fn dispatch_protocol_data(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
        now_ms: u64,
    ) {
        let key = (conn_id, stream_id);
        let Some(protocol) = self.stream_owner.get(&key).cloned() else {
            return;
        };
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        match protocol {
            ProtocolKind::Ping => {
                let actions = self.ping.on_stream_data(&peer_id, stream_id, &data, now_ms);
                for action in actions {
                    self.execute_ping_action(action);
                }
            }
            ProtocolKind::IdentifyInitiator => {
                let actions = self.identify.on_stream_data(peer_id, stream_id, data);
                self.execute_identify_actions(actions);
            }
            ProtocolKind::IdentifyResponder => {
                // Responder doesn't expect data; ignore.
            }
            ProtocolKind::User(_) => {
                self.events.push(SwarmEvent::UserStreamData {
                    peer_id,
                    stream_id,
                    data,
                });
            }
        }
    }

    fn handle_stream_remote_write_closed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);
        let Some(protocol) = self.stream_owner.get(&key).cloned() else {
            return;
        };
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        match protocol {
            ProtocolKind::Ping => {
                let actions = self
                    .ping
                    .on_stream_remote_write_closed(&peer_id, stream_id);
                for action in actions {
                    self.execute_ping_action(action);
                }
            }
            ProtocolKind::IdentifyInitiator => {
                let actions = self
                    .identify
                    .on_stream_remote_write_closed(peer_id, stream_id);
                self.execute_identify_actions(actions);
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(_) => {
                self.events.push(SwarmEvent::UserStreamRemoteWriteClosed {
                    peer_id,
                    stream_id,
                });
            }
        }
    }

    fn handle_stream_closed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);

        if let Some(protocol) = self.stream_owner.remove(&key) {
            if let Some(peer_id) = self.conn_to_peer.get(&conn_id).cloned() {
                match protocol {
                    ProtocolKind::Ping => {
                        self.ping.on_stream_closed(&peer_id, stream_id);
                    }
                    ProtocolKind::IdentifyInitiator | ProtocolKind::IdentifyResponder => {
                        self.identify.on_stream_closed(peer_id, stream_id);
                    }
                    ProtocolKind::User(_) => {
                        self.events.push(SwarmEvent::UserStreamClosed {
                            peer_id,
                            stream_id,
                        });
                    }
                }
            }
        }

        self.inbound_negotiators.remove(&key);
        self.outbound_negotiators.remove(&key);
    }

    fn handle_connection_closed(&mut self, conn_id: ConnectionId) {
        self.active_connections.remove(&conn_id);

        if let Some(peer_id) = self.conn_to_peer.remove(&conn_id) {
            let was_active = self.peer_to_conn.get(&peer_id) == Some(&conn_id);
            if was_active {
                self.peer_to_conn.remove(&peer_id);
                self.ping.remove_peer(&peer_id);
                self.identify.remove_peer(&peer_id);
                self.pending_pings.remove(&peer_id);
                self.events
                    .push(SwarmEvent::ConnectionClosed { peer_id });
            }
        }

        self.stream_owner.retain(|(cid, _), _| *cid != conn_id);
        self.inbound_negotiators
            .retain(|(cid, _), _| *cid != conn_id);
        self.outbound_negotiators
            .retain(|(cid, _), _| *cid != conn_id);
        self.pending_opens.retain(|_, p| p.conn_id != conn_id);
    }

    // -----------------------------------------------------------------------
    // Internal: multistream-select negotiation
    // -----------------------------------------------------------------------

    fn feed_inbound_negotiator(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: &[u8],
        now_ms: u64,
    ) {
        let key = (conn_id, stream_id);
        let negotiator = match self.inbound_negotiators.get_mut(&key) {
            Some(n) => n,
            None => return,
        };

        let outputs = negotiator.receive(data);
        let mut negotiated_protocol = None;

        for output in outputs {
            match output {
                MultistreamOutput::OutboundData(bytes) => {
                    self.actions.push(SwarmAction::SendStream {
                        conn_id,
                        stream_id,
                        data: bytes,
                    });
                }
                MultistreamOutput::Negotiated { protocol } => {
                    negotiated_protocol = Some(protocol);
                }
                MultistreamOutput::NotAvailable => {
                    self.inbound_negotiators.remove(&key);
                    self.actions.push(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }
                MultistreamOutput::ProtocolError { reason } => {
                    self.events.push(SwarmEvent::Error {
                        message: format!(
                            "multistream error on inbound stream {stream_id}: {reason}"
                        ),
                    });
                    self.inbound_negotiators.remove(&key);
                    self.actions.push(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }
            }
        }

        if let Some(protocol) = negotiated_protocol {
            let remaining = self
                .inbound_negotiators
                .get_mut(&key)
                .map(|n| n.take_remaining_buffer())
                .unwrap_or_default();

            self.inbound_negotiators.remove(&key);
            self.on_inbound_negotiated(conn_id, stream_id, &protocol);

            if !remaining.is_empty() {
                self.dispatch_protocol_data(conn_id, stream_id, remaining, now_ms);
            }
        }
    }

    fn feed_outbound_negotiator(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: &[u8],
        now_ms: u64,
    ) {
        let key = (conn_id, stream_id);
        let pending = match self.outbound_negotiators.get_mut(&key) {
            Some(p) => p,
            None => return,
        };

        let outputs = pending.negotiator.receive(data);
        let target = pending.target.clone();
        let mut negotiated = false;

        for output in outputs {
            match output {
                MultistreamOutput::OutboundData(bytes) => {
                    self.actions.push(SwarmAction::SendStream {
                        conn_id,
                        stream_id,
                        data: bytes,
                    });
                }
                MultistreamOutput::Negotiated { .. } => {
                    negotiated = true;
                }
                MultistreamOutput::NotAvailable => {
                    self.events.push(SwarmEvent::Error {
                        message: format!(
                            "remote peer does not support protocol for stream {stream_id}"
                        ),
                    });
                    self.outbound_negotiators.remove(&key);
                    self.actions.push(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }
                MultistreamOutput::ProtocolError { reason } => {
                    self.events.push(SwarmEvent::Error {
                        message: format!(
                            "multistream error on outbound stream {stream_id}: {reason}"
                        ),
                    });
                    self.outbound_negotiators.remove(&key);
                    self.actions.push(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }
            }
        }

        if negotiated {
            let remaining = self
                .outbound_negotiators
                .get_mut(&key)
                .map(|p| p.negotiator.take_remaining_buffer())
                .unwrap_or_default();

            self.outbound_negotiators.remove(&key);
            self.on_outbound_negotiated(conn_id, stream_id, target, now_ms);

            if !remaining.is_empty() {
                self.dispatch_protocol_data(conn_id, stream_id, remaining, now_ms);
            }
        }
    }

    fn on_inbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol: &str,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        if protocol == PING_PROTOCOL_ID {
            self.stream_owner
                .insert((conn_id, stream_id), ProtocolKind::Ping);
            let actions = self.ping.register_inbound_stream(peer_id, stream_id);
            for action in actions {
                self.execute_ping_action(action);
            }
            return;
        }

        if protocol == IDENTIFY_PROTOCOL_ID {
            // TODO: surface the remote's source address so observed-addr can be filled.
            let observed_addr = Vec::new();
            match self
                .identify
                .register_outbound_stream(peer_id, stream_id, observed_addr)
            {
                Ok(actions) => {
                    // Only record ownership on success, so a rejected
                    // registration doesn't leave the stream tracked here
                    // with no owning handler.
                    self.stream_owner
                        .insert((conn_id, stream_id), ProtocolKind::IdentifyResponder);
                    self.execute_identify_actions(actions);
                }
                Err(e) => {
                    // Registration refused (e.g. identify already has a
                    // responder stream for this peer). Don't leak the
                    // underlying transport stream -- reset it so the
                    // remote knows we're not going to respond.
                    self.events.push(SwarmEvent::Error {
                        message: format!("identify responder error: {e}"),
                    });
                    self.actions
                        .push(SwarmAction::ResetStream { conn_id, stream_id });
                }
            }
            return;
        }

        if self.user_protocols.iter().any(|p| p == protocol) {
            self.stream_owner.insert(
                (conn_id, stream_id),
                ProtocolKind::User(protocol.to_string()),
            );
            self.events.push(SwarmEvent::UserStreamReady {
                peer_id,
                stream_id,
                protocol_id: protocol.to_string(),
                initiated_locally: false,
            });
        }
    }

    fn on_outbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        target: ProtocolKind,
        now_ms: u64,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);
        self.stream_owner
            .insert((conn_id, stream_id), target.clone());

        match target {
            ProtocolKind::Ping => {
                if let Err(e) = self
                    .ping
                    .register_outbound_stream(peer_id.clone(), stream_id)
                {
                    self.events.push(SwarmEvent::Error {
                        message: format!("ping register error: {e}"),
                    });
                    self.stream_owner.remove(&(conn_id, stream_id));
                    self.actions
                        .push(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }

                if let Some(payload) = self.pending_pings.remove(&peer_id) {
                    match self.ping.send_ping(&peer_id, &payload, now_ms) {
                        Ok(action) => self.execute_ping_action(action),
                        Err(e) => self.events.push(SwarmEvent::Error {
                            message: format!("deferred ping send failed: {e}"),
                        }),
                    }
                }
            }
            ProtocolKind::IdentifyInitiator => {
                self.identify.register_inbound_stream(peer_id, stream_id);
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(protocol_id) => {
                self.events.push(SwarmEvent::UserStreamReady {
                    peer_id,
                    stream_id,
                    protocol_id,
                    initiated_locally: true,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: execute protocol-handler actions
    // -----------------------------------------------------------------------

    fn execute_ping_action(&mut self, action: PingAction) {
        match action {
            PingAction::Send {
                ref peer_id,
                stream_id,
                data,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    self.actions.push(SwarmAction::SendStream {
                        conn_id,
                        stream_id,
                        data: data.to_vec(),
                    });
                }
            }
            PingAction::CloseStreamWrite {
                ref peer_id,
                stream_id,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    self.actions
                        .push(SwarmAction::CloseStreamWrite { conn_id, stream_id });
                }
            }
            PingAction::ResetStream {
                ref peer_id,
                stream_id,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    self.actions
                        .push(SwarmAction::ResetStream { conn_id, stream_id });
                }
            }
        }
    }

    fn execute_identify_actions(&mut self, actions: Vec<IdentifyAction>) {
        for action in actions {
            match action {
                IdentifyAction::Send {
                    ref peer_id,
                    stream_id,
                    ref data,
                } => {
                    if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                        self.actions.push(SwarmAction::SendStream {
                            conn_id,
                            stream_id,
                            data: data.clone(),
                        });
                    }
                }
                IdentifyAction::CloseStreamWrite {
                    ref peer_id,
                    stream_id,
                } => {
                    if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                        self.actions
                            .push(SwarmAction::CloseStreamWrite { conn_id, stream_id });
                    }
                }
            }
        }
    }

    fn collect_protocol_events(&mut self) {
        for event in self.ping.poll_events() {
            match event {
                PingEvent::RttMeasured {
                    peer_id, rtt_ms, ..
                } => {
                    self.events
                        .push(SwarmEvent::PingRttMeasured { peer_id, rtt_ms });
                }
                PingEvent::Timeout { peer_id, .. } => {
                    self.events.push(SwarmEvent::PingTimeout { peer_id });
                }
                PingEvent::ProtocolViolation {
                    peer_id, reason, ..
                } => {
                    self.events.push(SwarmEvent::Error {
                        message: format!("ping protocol violation from {peer_id}: {reason}"),
                    });
                }
                _ => {}
            }
        }

        for event in self.identify.poll_events() {
            match event {
                IdentifyEvent::Received { peer_id, info } => {
                    self.events
                        .push(SwarmEvent::IdentifyReceived { peer_id, info });
                }
                IdentifyEvent::Error { error, .. } => {
                    self.events.push(SwarmEvent::Error {
                        message: format!("identify error: {error}"),
                    });
                }
            }
        }
    }
}
