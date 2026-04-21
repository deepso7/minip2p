//! Connection and protocol orchestration layer for minip2p.
//!
//! The [`Swarm`] owns a [`Transport`], manages connections by [`PeerId`],
//! auto-negotiates protocols via multistream-select, and dispatches stream
//! events to the appropriate protocol handler.
//!
//! Currently supports:
//! - [`PingProtocol`] -- `/ipfs/ping/1.0.0`
//! - [`IdentifyProtocol`] -- `/ipfs/id/1.0.0`

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_identify::{
    IdentifyAction, IdentifyConfig, IdentifyEvent, IdentifyMessage, IdentifyProtocol,
    IDENTIFY_PROTOCOL_ID,
};
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_ping::{
    PingAction, PingConfig, PingEvent, PingProtocol, PING_PAYLOAD_LEN, PING_PROTOCOL_ID,
};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

mod builder;
pub use builder::SwarmBuilder;

// ---------------------------------------------------------------------------
// Protocol identification
// ---------------------------------------------------------------------------

/// Identifies which protocol owns a negotiated stream.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum ProtocolId {
    Ping,
    /// Identify responder: we send our info.
    IdentifyResponder,
    /// Identify initiator: we receive their info.
    IdentifyInitiator,
    /// A user-registered protocol, with its string ID retained so events can
    /// surface it back to the application.
    User(String),
}

/// Tracks a pending outbound stream that is still negotiating multistream-select.
struct PendingOutbound {
    negotiator: MultistreamSelect,
    target_protocol: ProtocolId,
}

// ---------------------------------------------------------------------------
// Swarm events
// ---------------------------------------------------------------------------

/// Events emitted by the swarm to the application.
#[derive(Clone, Debug)]
pub enum SwarmEvent {
    /// A new connection was established and identity verified.
    ConnectionEstablished { peer_id: PeerId },
    /// A connection was closed.
    ConnectionClosed { peer_id: PeerId },
    /// Identify information received from a remote peer.
    IdentifyReceived {
        peer_id: PeerId,
        info: IdentifyMessage,
    },
    /// A ping RTT measurement completed.
    PingRttMeasured {
        peer_id: PeerId,
        rtt_ms: u64,
    },
    /// A ping timed out.
    PingTimeout { peer_id: PeerId },
    /// A user-registered protocol was successfully negotiated on a stream,
    /// either because we opened it via [`Swarm::open_user_stream`] or because
    /// a remote opened a stream for a protocol we accepted via
    /// [`Swarm::add_user_protocol`].
    UserStreamReady {
        peer_id: PeerId,
        stream_id: StreamId,
        protocol_id: String,
        /// True if we opened this stream; false if the remote opened it.
        initiated_locally: bool,
    },
    /// Raw data arrived on a negotiated user stream.
    UserStreamData {
        peer_id: PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// The remote closed its write side on a user stream.
    UserStreamRemoteWriteClosed {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// A user stream was fully closed.
    UserStreamClosed {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// A non-fatal error occurred.
    Error { message: String },
}

// ---------------------------------------------------------------------------
// Swarm
// ---------------------------------------------------------------------------

/// Orchestrates connections, protocol negotiation, and stream dispatch.
///
/// The caller drives the swarm by calling [`poll`](Swarm::poll) in a loop.
/// Each poll iteration:
/// 1. Drives the underlying transport (reads/writes UDP).
/// 2. Processes transport events (connections, streams, data).
/// 3. Runs multistream-select negotiation for new streams.
/// 4. Dispatches data to the correct protocol handler.
/// 5. Executes protocol actions (send, close, reset) on the transport.
/// 6. Returns [`SwarmEvent`]s to the application.
pub struct Swarm<T: Transport> {
    transport: T,

    // --- Protocol handlers ---
    ping: PingProtocol,
    identify: IdentifyProtocol,

    // --- Connection tracking ---
    /// Maps connection ids to peer ids (verified or synthetic).
    conn_to_peer: HashMap<ConnectionId, PeerId>,
    /// Maps peer ids to their primary connection id.
    peer_to_conn: BTreeMap<PeerId, ConnectionId>,
    /// Connections that have been established (with or without peer identity).
    active_connections: HashMap<ConnectionId, bool>,

    // --- Stream tracking ---
    /// Inbound streams being negotiated (server-side multistream-select).
    inbound_negotiators: HashMap<(ConnectionId, StreamId), MultistreamSelect>,
    /// Outbound streams being negotiated (client-side multistream-select).
    outbound_negotiators: HashMap<(ConnectionId, StreamId), PendingOutbound>,
    /// Streams that completed negotiation: maps to the owning protocol.
    stream_owner: HashMap<(ConnectionId, StreamId), ProtocolId>,

    // --- Configuration ---
    /// Protocol IDs we advertise for inbound negotiation.
    ///
    /// Always contains the built-in protocols (`/ipfs/id/1.0.0`,
    /// `/ipfs/ping/1.0.0`) plus any user protocols registered via
    /// [`Swarm::add_user_protocol`].
    supported_protocols: Vec<String>,
    /// Application-registered protocol IDs (subset of `supported_protocols`).
    user_protocols: Vec<String>,

    // --- Bookkeeping ---
    /// Auto-incrementing connection id counter. Used by [`Swarm::dial`] so
    /// callers don't have to invent connection ids themselves.
    next_connection_id: u64,
    /// Peers with a pending `.ping(peer)` call: once the ping stream
    /// negotiates, a 32-byte payload is sent automatically.
    pending_pings: HashMap<PeerId, [u8; PING_PAYLOAD_LEN]>,
    /// Start of the logical clock. Swarm tracks wall time itself so callers
    /// don't have to thread `now_ms` through every method.
    start: Instant,

    // --- Output ---
    /// Buffered events for the application.
    events: Vec<SwarmEvent>,
}

impl<T: Transport> Swarm<T> {
    /// Creates a new swarm wrapping the given transport.
    pub fn new(
        transport: T,
        identify_config: IdentifyConfig,
        ping_config: PingConfig,
    ) -> Self {
        let supported_protocols = vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
        ];

        Self {
            transport,
            ping: PingProtocol::new(ping_config),
            identify: IdentifyProtocol::new(identify_config),
            conn_to_peer: HashMap::new(),
            peer_to_conn: BTreeMap::new(),
            active_connections: HashMap::new(),
            inbound_negotiators: HashMap::new(),
            outbound_negotiators: HashMap::new(),
            stream_owner: HashMap::new(),
            supported_protocols,
            user_protocols: Vec::new(),
            next_connection_id: 1,
            pending_pings: HashMap::new(),
            start: Instant::now(),
            events: Vec::new(),
        }
    }

    /// Returns the number of milliseconds elapsed since this swarm was
    /// constructed.
    ///
    /// Swarm uses this internal clock for ping timeouts, RTT measurement,
    /// and any other time-dependent protocol logic so callers don't have to
    /// thread a timestamp through every method.
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Allocates the next unused connection id, skipping 0.
    fn allocate_connection_id(&mut self) -> ConnectionId {
        loop {
            let raw = self.next_connection_id;
            self.next_connection_id = self.next_connection_id.wrapping_add(1);
            if raw != 0 {
                return ConnectionId::new(raw);
            }
        }
    }

    /// Registers a user protocol id that this swarm will accept on inbound streams.
    ///
    /// When a remote peer negotiates this protocol on a stream we observe,
    /// a [`SwarmEvent::UserStreamReady`] is emitted and subsequent stream
    /// data is surfaced via [`SwarmEvent::UserStreamData`]. The application
    /// is responsible for all protocol state; the swarm only handles
    /// multistream-select negotiation and stream lifecycle.
    pub fn add_user_protocol(&mut self, protocol_id: impl Into<String>) {
        let id = protocol_id.into();
        if !self.user_protocols.iter().any(|p| p == &id) {
            self.user_protocols.push(id.clone());
        }
        if !self.supported_protocols.iter().any(|p| p == &id) {
            self.supported_protocols.push(id);
        }
    }

    /// Returns a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    // --- Public API ---

    /// Start listening on the given multiaddr.
    pub fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError> {
        self.transport.listen(addr)
    }

    /// Dial a remote peer.
    ///
    /// Swarm allocates a connection id internally and returns it, so callers
    /// don't have to invent ids themselves. The returned id can be used with
    /// [`Swarm::disconnect_by_id`] but is otherwise optional to retain --
    /// all higher-level APIs take [`PeerId`].
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.allocate_connection_id();
        self.transport.dial(id, addr)?;
        Ok(id)
    }

    /// Pings a peer, sending a random 32-byte payload and measuring RTT.
    ///
    /// If no ping stream exists yet, one is opened and the ping is queued
    /// to fire as soon as multistream-select completes. The resulting RTT
    /// is delivered via [`SwarmEvent::PingRttMeasured`].
    ///
    /// Returns an error if the peer is not currently connected.
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), TransportError> {
        let payload: [u8; PING_PAYLOAD_LEN] = rand_ping_payload();

        // If a ping stream is already negotiated, send right away.
        if let Some(stream_id) = self.find_negotiated_ping_stream(peer_id) {
            let now = self.now_ms();
            let action = self.ping.send_ping(peer_id, &payload, now).map_err(|e| {
                TransportError::PollError {
                    reason: format!("ping error: {e}"),
                }
            })?;
            self.execute_ping_action(action);
            let _ = stream_id;
            return Ok(());
        }

        // Otherwise open a ping stream and remember to send the payload once
        // the stream is ready.
        self.pending_pings.insert(peer_id.clone(), payload);
        let _ = self.open_protocol_stream(peer_id, PING_PROTOCOL_ID, ProtocolId::Ping)?;
        Ok(())
    }

    /// Finds a ping stream that has already completed multistream-select for
    /// the given peer, if any.
    fn find_negotiated_ping_stream(&self, peer_id: &PeerId) -> Option<StreamId> {
        let conn = *self.peer_to_conn.get(peer_id)?;
        self.stream_owner
            .iter()
            .find_map(|((c, s), owner)| {
                if *c == conn && matches!(owner, ProtocolId::Ping) {
                    Some(*s)
                } else {
                    None
                }
            })
    }

    /// Close the connection to a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), TransportError> {
        let conn_id = self
            .peer_to_conn
            .get(peer_id)
            .copied()
            .ok_or_else(|| TransportError::PollError {
                reason: format!("no connection for peer {peer_id}"),
            })?;
        self.transport.close(conn_id)
    }

    /// Opens a new outbound stream and negotiates `protocol_id` via
    /// multistream-select.
    ///
    /// The protocol must have been registered with
    /// [`Swarm::add_user_protocol`] first. When negotiation completes, a
    /// [`SwarmEvent::UserStreamReady`] is emitted; subsequent stream data
    /// arrives as [`SwarmEvent::UserStreamData`].
    pub fn open_user_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<StreamId, TransportError> {
        if !self.user_protocols.iter().any(|p| p == protocol_id) {
            return Err(TransportError::InvalidConfig {
                reason: format!(
                    "protocol '{protocol_id}' is not registered; call add_user_protocol first"
                ),
            });
        }

        self.open_protocol_stream(
            peer_id,
            protocol_id,
            ProtocolId::User(protocol_id.to_string()),
        )
    }

    /// Sends raw bytes on a previously-negotiated user stream.
    pub fn send_user_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        let conn_id = self.require_conn(peer_id)?;
        self.transport.send_stream(conn_id, stream_id, data)
    }

    /// Half-closes the write side of a user stream.
    pub fn close_user_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let conn_id = self.require_conn(peer_id)?;
        self.transport.close_stream_write(conn_id, stream_id)
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_user_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let conn_id = self.require_conn(peer_id)?;
        self.transport.reset_stream(conn_id, stream_id)
    }

    /// Looks up the connection id for a peer, or returns an error.
    fn require_conn(&self, peer_id: &PeerId) -> Result<ConnectionId, TransportError> {
        self.peer_to_conn
            .get(peer_id)
            .copied()
            .ok_or_else(|| TransportError::PollError {
                reason: format!("no connection for peer {peer_id}"),
            })
    }

    /// Drive the swarm: poll transport, dispatch events, run protocols.
    ///
    /// Returns application-visible events. Must be called repeatedly in an
    /// event loop. Swarm tracks wall time internally, so no timestamp
    /// argument is needed.
    pub fn poll(&mut self) -> Result<Vec<SwarmEvent>, TransportError> {
        let now_ms = self.now_ms();

        // 1. Poll the transport for raw events.
        let transport_events = self.transport.poll()?;

        // 2. Process each transport event.
        for event in transport_events {
            self.handle_transport_event(event, now_ms);
        }

        // 3. Tick protocol timers.
        let tick_actions = self.ping.on_tick(now_ms);
        for action in tick_actions {
            self.execute_ping_action(action);
        }

        // 4. Collect protocol events into swarm events.
        self.collect_protocol_events();

        // 5. Return buffered swarm events.
        Ok(std::mem::take(&mut self.events))
    }

    // --- Internal: transport event handling ---

    /// Returns the PeerId for a connection, creating a synthetic one if needed.
    ///
    /// Synthetic PeerIds allow protocol handlers to operate on connections
    /// where the remote peer's identity is unknown (e.g. server side with
    /// one-way TLS).
    fn ensure_peer_id_for_conn(&mut self, conn_id: ConnectionId) -> PeerId {
        if let Some(peer_id) = self.conn_to_peer.get(&conn_id) {
            return peer_id.clone();
        }

        // Create a synthetic PeerId from the connection id. This uses a
        // fake public key protobuf so the resulting PeerId is well-formed.
        // It will be replaced if the real peer identity is later discovered.
        let synthetic_key = format!("minip2p-synthetic-conn-{}", conn_id.as_u64());
        let peer_id = PeerId::from_public_key_protobuf(synthetic_key.as_bytes());
        self.conn_to_peer.insert(conn_id, peer_id.clone());
        self.peer_to_conn.insert(peer_id.clone(), conn_id);
        peer_id
    }

    fn handle_transport_event(&mut self, event: TransportEvent, now_ms: u64) {
        match event {
            TransportEvent::Connected { id, endpoint } => {
                self.active_connections.insert(id, true);
                if let Some(peer_id) = endpoint.peer_id() {
                    self.register_connection(id, peer_id.clone());
                } else {
                    // Connection established but peer identity unknown (e.g. server
                    // side with verify_peer(false)). Create a synthetic PeerId so
                    // protocol handlers can still operate.
                    let peer_id = self.ensure_peer_id_for_conn(id);
                    self.events
                        .push(SwarmEvent::ConnectionEstablished { peer_id });
                }
            }
            TransportEvent::PeerIdentityVerified { id, endpoint, .. } => {
                if let Some(peer_id) = endpoint.peer_id() {
                    self.register_connection(id, peer_id.clone());
                }
            }
            TransportEvent::IncomingConnection { id, .. } => {
                self.active_connections.insert(id, false);
            }
            TransportEvent::IncomingStream { id, stream_id } => {
                self.handle_incoming_stream(id, stream_id);
            }
            TransportEvent::StreamOpened { id, stream_id } => {
                // An outbound stream we opened is now ready. Multistream-select
                // negotiation was already started in open_protocol_stream, so
                // we just wait for data.
                let _ = (id, stream_id);
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

    fn register_connection(&mut self, id: ConnectionId, peer_id: PeerId) {
        let is_new = !self.conn_to_peer.contains_key(&id);
        self.conn_to_peer.insert(id, peer_id.clone());
        self.peer_to_conn.insert(peer_id.clone(), id);

        if is_new {
            self.events
                .push(SwarmEvent::ConnectionEstablished { peer_id: peer_id.clone() });

            // Auto-open identify: we open a stream to read their info.
            if let Err(e) = self.open_protocol_stream(
                &peer_id,
                IDENTIFY_PROTOCOL_ID,
                ProtocolId::IdentifyInitiator,
            ) {
                self.events.push(SwarmEvent::Error {
                    message: format!("failed to open identify stream to {peer_id}: {e}"),
                });
            }
        }
    }

    fn handle_incoming_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        // Start server-side multistream-select negotiation.
        let mut listener = MultistreamSelect::listener(self.supported_protocols.clone());
        let outputs = listener.start();
        self.inbound_negotiators
            .insert((conn_id, stream_id), listener);

        for output in outputs {
            if let MultistreamOutput::OutboundData(bytes) = output {
                let _ = self.transport.send_stream(conn_id, stream_id, bytes);
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

        // Case 1: inbound stream still negotiating.
        if self.inbound_negotiators.contains_key(&key) {
            self.feed_inbound_negotiator(conn_id, stream_id, &data, now_ms);
            return;
        }

        // Case 2: outbound stream still negotiating.
        if self.outbound_negotiators.contains_key(&key) {
            self.feed_outbound_negotiator(conn_id, stream_id, &data, now_ms);
            return;
        }

        // Case 3: negotiated stream — dispatch to protocol.
        self.dispatch_protocol_data(conn_id, stream_id, data, now_ms);
    }

    /// Dispatches data to the protocol handler that owns a negotiated stream.
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
            ProtocolId::Ping => {
                let actions = self
                    .ping
                    .on_stream_data(&peer_id, stream_id, &data, now_ms);
                for action in actions {
                    self.execute_ping_action(action);
                }
            }
            ProtocolId::IdentifyInitiator => {
                let actions = self
                    .identify
                    .on_stream_data(peer_id, stream_id, data);
                self.execute_identify_actions(actions);
            }
            ProtocolId::IdentifyResponder => {
                // Responder doesn't expect data; ignore.
            }
            ProtocolId::User(_) => {
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
            ProtocolId::Ping => {
                let actions = self
                    .ping
                    .on_stream_remote_write_closed(&peer_id, stream_id);
                for action in actions {
                    self.execute_ping_action(action);
                }
            }
            ProtocolId::IdentifyInitiator => {
                let actions = self
                    .identify
                    .on_stream_remote_write_closed(peer_id, stream_id);
                self.execute_identify_actions(actions);
            }
            ProtocolId::IdentifyResponder => {}
            ProtocolId::User(_) => {
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
                    ProtocolId::Ping => {
                        self.ping.on_stream_closed(&peer_id, stream_id);
                    }
                    ProtocolId::IdentifyInitiator | ProtocolId::IdentifyResponder => {
                        self.identify.on_stream_closed(peer_id, stream_id);
                    }
                    ProtocolId::User(_) => {
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
            self.peer_to_conn.remove(&peer_id);
            self.ping.remove_peer(&peer_id);
            self.identify.remove_peer(&peer_id);
            self.pending_pings.remove(&peer_id);
            self.events
                .push(SwarmEvent::ConnectionClosed { peer_id });
        }

        // Clean up all stream state for this connection.
        self.stream_owner.retain(|(cid, _), _| *cid != conn_id);
        self.inbound_negotiators
            .retain(|(cid, _), _| *cid != conn_id);
        self.outbound_negotiators
            .retain(|(cid, _), _| *cid != conn_id);
    }

    // --- Internal: multistream-select negotiation ---

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
                    let _ = self.transport.send_stream(conn_id, stream_id, bytes);
                }
                MultistreamOutput::Negotiated { protocol } => {
                    negotiated_protocol = Some(protocol);
                }
                MultistreamOutput::NotAvailable => {
                    self.inbound_negotiators.remove(&key);
                    return;
                }
                MultistreamOutput::ProtocolError { reason } => {
                    self.events.push(SwarmEvent::Error {
                        message: format!(
                            "multistream error on inbound stream {stream_id}: {reason}"
                        ),
                    });
                    self.inbound_negotiators.remove(&key);
                    return;
                }
            }
        }

        if let Some(protocol) = negotiated_protocol {
            // Drain any bytes pipelined after the negotiation handshake —
            // these belong to the negotiated protocol.
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
        let target = pending.target_protocol.clone();
        let mut negotiated = false;

        for output in outputs {
            match output {
                MultistreamOutput::OutboundData(bytes) => {
                    let _ = self.transport.send_stream(conn_id, stream_id, bytes);
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
                    return;
                }
                MultistreamOutput::ProtocolError { reason } => {
                    self.events.push(SwarmEvent::Error {
                        message: format!(
                            "multistream error on outbound stream {stream_id}: {reason}"
                        ),
                    });
                    self.outbound_negotiators.remove(&key);
                    return;
                }
            }
        }

        if negotiated {
            // Drain any bytes pipelined after the negotiation handshake.
            let remaining = self
                .outbound_negotiators
                .get_mut(&key)
                .map(|p| p.negotiator.take_remaining_buffer())
                .unwrap_or_default();

            self.outbound_negotiators.remove(&key);
            self.on_outbound_negotiated(conn_id, stream_id, target);

            if !remaining.is_empty() {
                self.dispatch_protocol_data(conn_id, stream_id, remaining, now_ms);
            }
        }
    }

    /// Called when an inbound stream finishes multistream-select negotiation.
    fn on_inbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol: &str,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        if protocol == PING_PROTOCOL_ID {
            self.stream_owner
                .insert((conn_id, stream_id), ProtocolId::Ping);
            let actions = self.ping.register_inbound_stream(peer_id, stream_id);
            for action in actions {
                self.execute_ping_action(action);
            }
            return;
        }

        if protocol == IDENTIFY_PROTOCOL_ID {
            // Inbound identify: the remote wants our info. We are the responder.
            self.stream_owner
                .insert((conn_id, stream_id), ProtocolId::IdentifyResponder);

            // Build observed_addr from the connection's endpoint.
            // TODO: surface the remote's source address through the swarm
            // so the observed-addr field can be filled in.
            let observed_addr = Vec::new();

            match self
                .identify
                .register_outbound_stream(peer_id, stream_id, observed_addr)
            {
                Ok(actions) => {
                    self.execute_identify_actions(actions);
                }
                Err(e) => {
                    self.events.push(SwarmEvent::Error {
                        message: format!("identify responder error: {e}"),
                    });
                }
            }
            return;
        }

        if self.user_protocols.iter().any(|p| p == protocol) {
            self.stream_owner.insert(
                (conn_id, stream_id),
                ProtocolId::User(protocol.to_string()),
            );
            self.events.push(SwarmEvent::UserStreamReady {
                peer_id,
                stream_id,
                protocol_id: protocol.to_string(),
                initiated_locally: false,
            });
            return;
        }

        // Unknown protocol — should not happen since we only advertise known ones.
    }

    /// Called when an outbound stream finishes multistream-select negotiation.
    fn on_outbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        target: ProtocolId,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        self.stream_owner
            .insert((conn_id, stream_id), target.clone());

        match target {
            ProtocolId::Ping => {
                if let Err(e) = self
                    .ping
                    .register_outbound_stream(peer_id.clone(), stream_id)
                {
                    self.events.push(SwarmEvent::Error {
                        message: format!("ping register error: {e}"),
                    });
                }

                // If the app called `swarm.ping(&peer)` before the stream
                // was negotiated, flush the queued payload now.
                if let Some(payload) = self.pending_pings.remove(&peer_id) {
                    let now = self.now_ms();
                    match self.ping.send_ping(&peer_id, &payload, now) {
                        Ok(action) => self.execute_ping_action(action),
                        Err(e) => self.events.push(SwarmEvent::Error {
                            message: format!("deferred ping send failed: {e}"),
                        }),
                    }
                }
            }
            ProtocolId::IdentifyInitiator => {
                // We opened a stream to read their info. Just register it;
                // data will arrive via on_stream_data.
                self.identify.register_inbound_stream(peer_id, stream_id);
            }
            ProtocolId::IdentifyResponder => {
                // Shouldn't happen for outbound.
            }
            ProtocolId::User(protocol_id) => {
                self.events.push(SwarmEvent::UserStreamReady {
                    peer_id,
                    stream_id,
                    protocol_id,
                    initiated_locally: true,
                });
            }
        }
    }

    // --- Internal: open outbound protocol stream ---

    fn open_protocol_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        target: ProtocolId,
    ) -> Result<StreamId, TransportError> {
        let conn_id = self
            .peer_to_conn
            .get(peer_id)
            .copied()
            .ok_or_else(|| TransportError::PollError {
                reason: format!("no connection for peer {peer_id}"),
            })?;

        let stream_id = self.transport.open_stream(conn_id)?;

        // Start client-side multistream-select.
        let mut negotiator = MultistreamSelect::dialer(protocol_id);
        let outputs = negotiator.start();

        for output in outputs {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.transport.send_stream(conn_id, stream_id, bytes)?;
            }
        }

        self.outbound_negotiators.insert(
            (conn_id, stream_id),
            PendingOutbound {
                negotiator,
                target_protocol: target,
            },
        );

        Ok(stream_id)
    }

    // --- Internal: execute protocol actions ---

    fn execute_ping_action(&mut self, action: PingAction) {
        match action {
            PingAction::Send {
                ref peer_id,
                stream_id,
                data,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    let _ = self.transport.send_stream(conn_id, stream_id, data.to_vec());
                }
            }
            PingAction::CloseStreamWrite {
                ref peer_id,
                stream_id,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    let _ = self.transport.close_stream_write(conn_id, stream_id);
                }
            }
            PingAction::ResetStream {
                ref peer_id,
                stream_id,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    let _ = self.transport.reset_stream(conn_id, stream_id);
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
                        if let Err(e) = self.transport.send_stream(conn_id, stream_id, data.clone()) {
                            self.events.push(SwarmEvent::Error {
                                message: format!("identify send failed: {e}"),
                            });
                        }
                    } else {
                        self.events.push(SwarmEvent::Error {
                            message: format!("identify send: no connection for peer {peer_id}"),
                        });
                    }
                }
                IdentifyAction::CloseStreamWrite {
                    ref peer_id,
                    stream_id,
                } => {
                    if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                        if let Err(e) = self.transport.close_stream_write(conn_id, stream_id) {
                            self.events.push(SwarmEvent::Error {
                                message: format!("identify close-write failed: {e}"),
                            });
                        }
                    }
                }
            }
        }
    }

    // --- Internal: collect protocol events ---

    fn collect_protocol_events(&mut self) {
        // Ping events.
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

        // Identify events.
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

/// Generates a random 32-byte ping payload using OS randomness.
///
/// Falls back to a deterministic-but-non-repeating pattern if randomness is
/// unavailable, which should only happen in very constrained environments.
fn rand_ping_payload() -> [u8; PING_PAYLOAD_LEN] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut payload = [0u8; PING_PAYLOAD_LEN];
    if getrandom::fill(&mut payload).is_ok() {
        return payload;
    }

    // Fallback: mix the wall clock into a simple pattern so payloads differ
    // from ping to ping even when randomness is not available.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = ((seed >> (i % 8)) as u8) ^ (i as u8);
    }
    payload
}
