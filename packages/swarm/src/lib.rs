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

use minip2p_core::{PeerAddr, PeerId};
use minip2p_identify::{
    IdentifyAction, IdentifyConfig, IdentifyEvent, IdentifyMessage, IdentifyProtocol,
    IDENTIFY_PROTOCOL_ID,
};
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_ping::{
    PingAction, PingConfig, PingEvent, PingProtocol, PING_PAYLOAD_LEN, PING_PROTOCOL_ID,
};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

// ---------------------------------------------------------------------------
// Protocol identification
// ---------------------------------------------------------------------------

/// Identifies which protocol owns a negotiated stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum ProtocolId {
    Ping,
    /// Identify responder: we send our info.
    IdentifyResponder,
    /// Identify initiator: we receive their info.
    IdentifyInitiator,
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
    supported_protocols: Vec<String>,

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
            events: Vec::new(),
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

    /// Start listening on the given address.
    pub fn listen(&mut self, addr: &minip2p_core::Multiaddr) -> Result<(), TransportError> {
        self.transport.listen(addr)
    }

    /// Dial a remote peer.
    pub fn dial(
        &mut self,
        id: ConnectionId,
        addr: &PeerAddr,
    ) -> Result<(), TransportError> {
        self.transport.dial(id, addr)
    }

    /// Open a ping stream to a connected peer.
    ///
    /// The swarm handles multistream-select negotiation. Once negotiated, the
    /// stream is registered with the ping protocol.
    pub fn open_ping(&mut self, peer_id: &PeerId) -> Result<StreamId, TransportError> {
        self.open_protocol_stream(peer_id, PING_PROTOCOL_ID, ProtocolId::Ping)
    }

    /// Send a ping to a connected peer (must have an open ping stream).
    pub fn send_ping(
        &mut self,
        peer_id: &PeerId,
        payload: &[u8; PING_PAYLOAD_LEN],
        now_ms: u64,
    ) -> Result<(), TransportError> {
        let action = self
            .ping
            .send_ping(peer_id, payload, now_ms)
            .map_err(|e| TransportError::PollError {
                reason: format!("ping error: {e}"),
            })?;
        self.execute_ping_action(action);
        Ok(())
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

    /// Drive the swarm: poll transport, dispatch events, run protocols.
    ///
    /// Returns application-visible events. Must be called repeatedly.
    pub fn poll(&mut self, now_ms: u64) -> Result<Vec<SwarmEvent>, TransportError> {
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
        let Some(&protocol) = self.stream_owner.get(&key) else {
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
        }
    }

    fn handle_stream_remote_write_closed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);

        if let Some(&protocol) = self.stream_owner.get(&key) {
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
            }
        }
    }

    fn handle_stream_closed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);

        if let Some(protocol) = self.stream_owner.remove(&key) {
            if let Some(peer_id) = self.conn_to_peer.get(&conn_id) {
                match protocol {
                    ProtocolId::Ping => {
                        self.ping.on_stream_closed(peer_id, stream_id);
                    }
                    ProtocolId::IdentifyInitiator | ProtocolId::IdentifyResponder => {
                        self.identify
                            .on_stream_closed(peer_id.clone(), stream_id);
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
        let target = pending.target_protocol;
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

        match protocol {
            p if p == PING_PROTOCOL_ID => {
                self.stream_owner
                    .insert((conn_id, stream_id), ProtocolId::Ping);
                let actions = self
                    .ping
                    .register_inbound_stream(peer_id, stream_id);
                for action in actions {
                    self.execute_ping_action(action);
                }
            }
            p if p == IDENTIFY_PROTOCOL_ID => {
                // Inbound identify: the remote wants our info. We are the responder.
                self.stream_owner
                    .insert((conn_id, stream_id), ProtocolId::IdentifyResponder);

                // Build observed_addr from the connection's endpoint.
                // For now, use an empty observed address; the Swarm doesn't
                // have the remote's source address readily available in this
                // context. A proper implementation would pass it through.
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
            }
            _ => {
                // Unknown protocol — should not happen since we only advertise known ones.
            }
        }
    }

    /// Called when an outbound stream finishes multistream-select negotiation.
    fn on_outbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        target: ProtocolId,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        self.stream_owner.insert((conn_id, stream_id), target);

        match target {
            ProtocolId::Ping => {
                if let Err(e) = self
                    .ping
                    .register_outbound_stream(peer_id, stream_id)
                {
                    self.events.push(SwarmEvent::Error {
                        message: format!("ping register error: {e}"),
                    });
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
