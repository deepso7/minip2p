//! Relay-circuit transport built from an existing ordered bridge stream.
//!
//! Each adopted bridge drives a [`SecureMuxSession`], which runs
//! multistream-select, Noise XX, and Yamux over it without owning sockets,
//! clocks, or an executor. This crate supplies what that session leaves to its
//! host: bridge lifecycle, arbitration against direct connections, and the
//! mapping onto [`TransportEvent`]s.
//!
//! Wrapped transport connection IDs pass through unchanged; circuit IDs are
//! allocated in [`ConnectionNamespace::CIRCUIT`], which keeps them disjoint
//! from every base transport's ids.
//!
//! Fresh Noise key material comes from a [`minip2p_platform::EntropySource`]
//! the host injects — the same seam every other minip2p transport draws from,
//! so one adapter over a board's RNG serves a circuit transport and a TCP
//! transport at once.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, Protocol};
use minip2p_identity::{Ed25519Keypair, PeerId};
#[cfg(feature = "std")]
use minip2p_platform::StdEntropy;
use minip2p_platform::{Deadline, EntropyError, EntropySource, Now};
use minip2p_secure_mux::{
    SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole, YamuxConfig,
};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionIdAllocator, ConnectionNamespace, ConnectionState,
    StreamId, Transport, TransportError, TransportEvent,
};
use thiserror::Error;

// A retired bridge suppresses late inner-transport events after the circuit's
// public `Closed`. Keep this finite because a peer may never finish closing
// its half of a gracefully closed bridge.
const MAX_RETIRED_BRIDGES: usize = 1024;

/// Which endpoint initiated the relayed connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitRole {
    /// Sent the relay HOP CONNECT request.
    Initiator,
    /// Accepted the relay STOP CONNECT request.
    Responder,
}

/// Description of a relay stream that has become a transparent byte bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeAdoption {
    /// Wrapped transport connection to the relay.
    pub inner_conn: ConnectionId,
    /// Stream carrying the relayed byte bridge.
    pub bridge_stream: StreamId,
    /// Relay peer used to form the circuit endpoint address.
    pub relay: PeerId,
    /// Expected peer at the other end of the bridge.
    pub remote_peer: PeerId,
    /// Local role in the end-to-end circuit handshake.
    pub role: CircuitRole,
    /// Bytes already read beyond the relay CONNECT response.
    pub pending_data: Vec<u8>,
    /// Whether the bridge's remote write side was already closed.
    pub remote_write_closed: bool,
}

/// Synchronous errors from adopting a relay bridge.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdoptError {
    /// The bridge is already adopted with different immutable metadata.
    #[error("bridge is already adopted with conflicting parameters")]
    ConflictingAdoption,
    /// A verified direct connection to the peer already exists.
    #[error("peer already has a direct connection")]
    PeerAlreadyDirect,
    /// The bridge cannot carry a handshake because its remote write side closed.
    #[error("bridge remote write side is closed")]
    RemoteWriteClosed,
    /// The wrapped relay connection is not active.
    #[error("wrapped relay connection is unknown")]
    UnknownConnection,
    /// Fresh Noise key material could not be generated.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    /// All circuit connection identifiers have been allocated.
    #[error("circuit connection IDs exhausted")]
    IdsExhausted,
}

/// Why a circuit is being torn down.
struct Teardown {
    /// Text for the public [`TransportEvent::Error`], if one is emitted.
    message: String,
    /// The remote ended an established session cleanly rather than failing.
    graceful: bool,
}

impl Teardown {
    fn fault(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            graceful: false,
        }
    }
}

impl From<SessionError> for Teardown {
    fn from(error: SessionError) -> Self {
        Self {
            graceful: matches!(error, SessionError::GoAway { code: 0 }),
            message: error.to_string(),
        }
    }
}

struct Circuit {
    id: ConnectionId,
    inner_conn: ConnectionId,
    bridge_stream: StreamId,
    relay: PeerId,
    remote_peer: PeerId,
    role: CircuitRole,
    session: SecureMuxSession,
}

impl Circuit {
    fn bridge_key(&self) -> (ConnectionId, StreamId) {
        (self.inner_conn, self.bridge_stream)
    }

    fn endpoint(&self, peer: Option<PeerId>) -> ConnectionEndpoint {
        let address = Multiaddr::from_protocols(vec![
            Protocol::P2p(self.relay.clone()),
            Protocol::P2pCircuit,
        ]);
        match peer {
            Some(peer) => ConnectionEndpoint::with_peer_id(address, peer),
            None => ConnectionEndpoint::new(address),
        }
    }

    fn is_ready(&self) -> bool {
        self.session.is_established()
    }
}

/// A transport wrapper that promotes relay bridge streams into connections.
pub struct CircuitTransport<T, E> {
    inner: T,
    entropy: E,
    identity: Ed25519Keypair,
    yamux_config: YamuxConfig,
    circuits: BTreeMap<ConnectionId, Circuit>,
    bridge_index: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    retired_bridges: BTreeSet<(ConnectionId, StreamId)>,
    retired_bridge_order: VecDeque<(ConnectionId, StreamId)>,
    active_inner: BTreeSet<ConnectionId>,
    direct_by_peer: BTreeMap<PeerId, BTreeSet<ConnectionId>>,
    direct_by_conn: BTreeMap<ConnectionId, PeerId>,
    pending: VecDeque<TransportEvent>,
    circuit_id_allocator: ConnectionIdAllocator,
}

impl<T, E> CircuitTransport<T, E> {
    /// Wraps a transport with an explicit entropy source and local identity.
    pub fn new(inner: T, identity: Ed25519Keypair, entropy: E) -> Self {
        Self {
            inner,
            entropy,
            identity,
            yamux_config: YamuxConfig::default(),
            circuits: BTreeMap::new(),
            bridge_index: BTreeMap::new(),
            retired_bridges: BTreeSet::new(),
            retired_bridge_order: VecDeque::new(),
            active_inner: BTreeSet::new(),
            direct_by_peer: BTreeMap::new(),
            direct_by_conn: BTreeMap::new(),
            pending: VecDeque::new(),
            circuit_id_allocator: ConnectionIdAllocator::new(ConnectionNamespace::CIRCUIT),
        }
    }

    /// Replaces the Yamux limits used by subsequently adopted circuits.
    #[cfg(test)]
    pub fn set_yamux_config(&mut self, config: YamuxConfig) {
        self.yamux_config = config;
    }

    /// Returns whether an identifier belongs to a circuit connection.
    pub fn is_circuit(id: ConnectionId) -> bool {
        id.is_circuit()
    }

    /// Returns the active circuit connection identifiers.
    pub fn circuit_ids(&self) -> Vec<ConnectionId> {
        self.circuits.keys().copied().collect()
    }

    /// Borrows the wrapped transport.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably borrows the wrapped transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Transport, E: EntropySource> CircuitTransport<T, E> {
    /// Promotes an already-negotiated relay bridge into a circuit connection.
    ///
    /// Repeating the same `(inner_conn, bridge_stream)` adoption is
    /// idempotent and returns the existing circuit identifier when its relay,
    /// remote peer, role, and remote-write state agree. Conflicting immutable
    /// metadata returns [`AdoptError::ConflictingAdoption`].
    pub fn adopt_bridge(&mut self, adoption: BridgeAdoption) -> Result<ConnectionId, AdoptError> {
        let key = (adoption.inner_conn, adoption.bridge_stream);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            let circuit = self
                .circuits
                .get(&id)
                .expect("bridge index must reference an active circuit");
            if adoption.remote_write_closed
                || adoption.relay != circuit.relay
                || adoption.remote_peer != circuit.remote_peer
                || adoption.role != circuit.role
            {
                return Err(AdoptError::ConflictingAdoption);
            }
            return Ok(id);
        }
        if adoption.remote_write_closed {
            return Err(AdoptError::RemoteWriteClosed);
        }
        if !self.active_inner.contains(&adoption.inner_conn) {
            return Err(AdoptError::UnknownConnection);
        }
        if self
            .direct_by_peer
            .get(&adoption.remote_peer)
            .is_some_and(|connections| !connections.is_empty())
        {
            return Err(AdoptError::PeerAlreadyDirect);
        }

        let id = self
            .circuit_id_allocator
            .peek()
            .ok_or(AdoptError::IdsExhausted)?;

        let mut static_secret = [0u8; 32];
        let mut ephemeral_secret = [0u8; 32];
        self.entropy.fill_bytes(&mut static_secret)?;
        self.entropy.fill_bytes(&mut ephemeral_secret)?;

        let session = SecureMuxSession::new(SessionConfig {
            role: match adoption.role {
                CircuitRole::Initiator => SessionRole::Initiator,
                CircuitRole::Responder => SessionRole::Responder,
            },
            identity: self.identity.clone(),
            static_secret,
            ephemeral_secret,
            expected_peer: Some(adoption.remote_peer.clone()),
            yamux: self.yamux_config.clone(),
        });
        let circuit = Circuit {
            id,
            inner_conn: adoption.inner_conn,
            bridge_stream: adoption.bridge_stream,
            relay: adoption.relay,
            remote_peer: adoption.remote_peer,
            role: adoption.role,
            session,
        };

        // Consume the sequence only here: an adoption that failed above
        // (entropy, validation) must leave the id space untouched.
        let consumed = self.circuit_id_allocator.allocate();
        debug_assert_eq!(consumed, Ok(id), "peeked id must match the allocated one");

        self.bridge_index.insert(key, id);
        if adoption.role == CircuitRole::Responder {
            self.pending.push_back(TransportEvent::IncomingConnection {
                id,
                endpoint: circuit.endpoint(None),
            });
        }
        self.circuits.insert(id, circuit);

        let start_result = self.with_circuit(id, |this, circuit| {
            circuit.session.start()?;
            this.pump(circuit)
        });
        if let Err(teardown) = start_result {
            self.fail_circuit(id, teardown.message, true);
            return Ok(id);
        }
        if !adoption.pending_data.is_empty() {
            self.inject_bridge_data(
                adoption.inner_conn,
                adoption.bridge_stream,
                adoption.pending_data,
            );
        }
        Ok(id)
    }

    /// Injects bytes read from a bridge outside the wrapped transport poll.
    pub fn inject_bridge_data(
        &mut self,
        inner_conn: ConnectionId,
        bridge_stream: StreamId,
        data: Vec<u8>,
    ) {
        let key = (inner_conn, bridge_stream);
        let Some(id) = self.bridge_index.get(&key).copied() else {
            return;
        };
        // A failed session is unusable, so `is_ready` reads false afterwards:
        // capture readiness before feeding it. In particular, a normal Yamux
        // GoAway from an established circuit must close without being
        // misclassified as a pre-handshake protocol failure.
        let pre_ready = self.circuits.get(&id).is_some_and(|c| !c.is_ready());
        let result = self.with_circuit(id, |this, circuit| {
            let fed = circuit.session.handle_input(data);
            // Pump either way: bytes the session queued before failing, and
            // events it already produced, are the caller's regardless.
            let pumped = this.pump(circuit);
            fed.map_err(Teardown::from).and(pumped)
        });
        if let Err(teardown) = result {
            self.fail_circuit(id, teardown.message, pre_ready || !teardown.graceful);
        }
    }

    /// Reports that a bridge received its remote FIN.
    pub fn inject_bridge_remote_write_closed(
        &mut self,
        inner_conn: ConnectionId,
        bridge_stream: StreamId,
    ) {
        let key = (inner_conn, bridge_stream);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            let pre_ready = self.circuits.get(&id).is_some_and(|c| !c.is_ready());
            self.fail_circuit(
                id,
                "relay bridge remote write side closed".to_string(),
                pre_ready,
            );
        }
    }

    /// Reports that a bridge stream fully closed or reset.
    pub fn inject_bridge_closed(&mut self, inner_conn: ConnectionId, bridge_stream: StreamId) {
        let key = (inner_conn, bridge_stream);
        self.release_retired_bridge(key);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            let pre_ready = self.circuits.get(&id).is_some_and(|c| !c.is_ready());
            self.fail_circuit(id, "relay bridge closed".to_string(), pre_ready);
        }
    }

    fn with_circuit<R>(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut Self, &mut Circuit) -> Result<R, Teardown>,
    ) -> Result<R, Teardown> {
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or_else(|| Teardown::fault(format!("circuit {id} is unknown")))?;
        let result = operation(self, &mut circuit);
        self.circuits.insert(id, circuit);
        result
    }

    fn retire_bridge(&mut self, key: (ConnectionId, StreamId)) {
        if !self.retired_bridges.insert(key) {
            return;
        }
        self.retired_bridge_order.push_back(key);
        if self.retired_bridge_order.len() > MAX_RETIRED_BRIDGES
            && let Some(expired) = self.retired_bridge_order.pop_front()
        {
            self.retired_bridges.remove(&expired);
        }
    }

    fn release_retired_bridge(&mut self, key: (ConnectionId, StreamId)) {
        if self.retired_bridges.remove(&key) {
            self.retired_bridge_order
                .retain(|candidate| *candidate != key);
        }
    }

    fn release_retired_bridges_for_connection(&mut self, id: ConnectionId) {
        self.retired_bridges.retain(|(conn, _)| *conn != id);
        self.retired_bridge_order.retain(|(conn, _)| *conn != id);
    }

    /// Drains session outputs, writing bytes to the bridge and turning
    /// everything else into public transport events.
    ///
    /// The session queues both in one ordered stream, so a single pass keeps
    /// the wire and the event feed in step.
    fn pump(&mut self, circuit: &mut Circuit) -> Result<(), Teardown> {
        while let Some(output) = circuit.session.poll_output() {
            match output {
                SessionOutput::Write(bytes) => {
                    self.inner
                        .send_stream(circuit.inner_conn, circuit.bridge_stream, bytes)
                        .map_err(|error| {
                            Teardown::fault(format!("relay bridge send failed: {error}"))
                        })?;
                }
                SessionOutput::Established { peer } => {
                    // The session leaves this policy to its host, and here the
                    // host is this wrapper: a verified direct connection
                    // outranks a relayed one, so the circuit loses.
                    if self
                        .direct_by_peer
                        .get(&peer)
                        .is_some_and(|connections| !connections.is_empty())
                    {
                        return Err(Teardown::fault("direct connection won circuit arbitration"));
                    }
                    self.pending.push_back(TransportEvent::Connected {
                        id: circuit.id,
                        endpoint: circuit.endpoint(Some(peer)),
                    });
                }
                SessionOutput::IncomingStream { stream } => {
                    self.pending.push_back(TransportEvent::IncomingStream {
                        id: circuit.id,
                        stream_id: stream,
                    });
                }
                SessionOutput::StreamData { stream, data } => {
                    self.pending.push_back(TransportEvent::StreamData {
                        id: circuit.id,
                        stream_id: stream,
                        data,
                    });
                }
                SessionOutput::StreamRemoteWriteClosed { stream } => {
                    self.pending
                        .push_back(TransportEvent::StreamRemoteWriteClosed {
                            id: circuit.id,
                            stream_id: stream,
                        });
                }
                SessionOutput::StreamClosed { stream } => {
                    self.pending.push_back(TransportEvent::StreamClosed {
                        id: circuit.id,
                        stream_id: stream,
                    });
                }
            }
        }
        Ok(())
    }

    fn fail_circuit(&mut self, id: ConnectionId, message: String, emit_error: bool) {
        let Some(circuit) = self.circuits.remove(&id) else {
            return;
        };
        let key = circuit.bridge_key();
        self.bridge_index.remove(&key);
        self.retire_bridge(key);
        let reset_result = self
            .inner
            .reset_stream(circuit.inner_conn, circuit.bridge_stream);
        // The circuit is already retired. A failed bridge reset cannot revive
        // it or replace the error/close transition below.
        match reset_result {
            Ok(()) | Err(_) => {}
        }
        if emit_error {
            self.pending
                .push_back(TransportEvent::Error { id, message });
        }
        self.pending.push_back(TransportEvent::Closed { id });
    }

    fn record_direct(&mut self, id: ConnectionId, peer: PeerId) {
        if let Some(previous) = self.direct_by_conn.insert(id, peer.clone())
            && previous != peer
            && let Some(ids) = self.direct_by_peer.get_mut(&previous)
        {
            ids.remove(&id);
            if ids.is_empty() {
                self.direct_by_peer.remove(&previous);
            }
        }
        self.direct_by_peer
            .entry(peer.clone())
            .or_default()
            .insert(id);
        let losers: Vec<_> = self
            .circuits
            .iter()
            .filter_map(|(circuit_id, circuit)| {
                (!circuit.is_ready() && circuit.remote_peer == peer).then_some(*circuit_id)
            })
            .collect();
        for circuit_id in losers {
            self.fail_circuit(
                circuit_id,
                "direct connection won circuit arbitration".to_string(),
                true,
            );
        }
    }

    fn remove_direct(&mut self, id: ConnectionId) {
        let Some(peer) = self.direct_by_conn.remove(&id) else {
            return;
        };
        if let Some(ids) = self.direct_by_peer.get_mut(&peer) {
            ids.remove(&id);
            if ids.is_empty() {
                self.direct_by_peer.remove(&peer);
            }
        }
    }

    fn reject_inner_collision(&mut self, id: ConnectionId) {
        self.active_inner.remove(&id);
        self.remove_direct(id);
        let close_result = self.inner.close(id);
        // The colliding connection is removed from circuit bookkeeping;
        // cleanup failure must not hide the namespace violation.
        match close_result {
            Ok(()) | Err(_) => {}
        }
        self.pending.push_back(TransportEvent::Error {
            id,
            message: "wrapped transport allocated in the circuit connection-ID namespace"
                .to_string(),
        });
    }

    fn handle_inner_event(&mut self, event: TransportEvent) {
        let event_id = match &event {
            TransportEvent::Connected { id, .. }
            | TransportEvent::StreamOpened { id, .. }
            | TransportEvent::IncomingStream { id, .. }
            | TransportEvent::StreamData { id, .. }
            | TransportEvent::StreamRemoteWriteClosed { id, .. }
            | TransportEvent::StreamClosed { id, .. }
            | TransportEvent::Closed { id }
            | TransportEvent::Error { id, .. }
            | TransportEvent::IncomingConnection { id, .. }
            | TransportEvent::PeerIdentityVerified { id, .. } => Some(*id),
            TransportEvent::Listening { .. } => None,
        };
        if event_id.is_some_and(ConnectionId::is_circuit) {
            self.reject_inner_collision(event_id.expect("checked above"));
            return;
        }

        match event {
            TransportEvent::IncomingConnection { id, endpoint } => {
                self.active_inner.insert(id);
                self.pending
                    .push_back(TransportEvent::IncomingConnection { id, endpoint });
            }
            TransportEvent::Connected { id, endpoint } => {
                self.active_inner.insert(id);
                if let Some(peer) = endpoint.peer_id().cloned() {
                    self.record_direct(id, peer);
                }
                self.pending
                    .push_back(TransportEvent::Connected { id, endpoint });
            }
            TransportEvent::PeerIdentityVerified {
                id,
                endpoint,
                previous_peer_id,
            } => {
                if let Some(peer) = endpoint.peer_id().cloned() {
                    self.record_direct(id, peer);
                }
                self.pending
                    .push_back(TransportEvent::PeerIdentityVerified {
                        id,
                        endpoint,
                        previous_peer_id,
                    });
            }
            TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) {
                    self.inject_bridge_data(id, stream_id, data);
                } else if !self.retired_bridges.contains(&key) {
                    self.pending.push_back(TransportEvent::StreamData {
                        id,
                        stream_id,
                        data,
                    });
                }
            }
            TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) {
                    self.inject_bridge_remote_write_closed(id, stream_id);
                } else if !self.retired_bridges.contains(&key) {
                    self.pending
                        .push_back(TransportEvent::StreamRemoteWriteClosed { id, stream_id });
                }
            }
            TransportEvent::StreamClosed { id, stream_id } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) || self.retired_bridges.contains(&key) {
                    self.inject_bridge_closed(id, stream_id);
                } else {
                    self.pending
                        .push_back(TransportEvent::StreamClosed { id, stream_id });
                }
            }
            TransportEvent::Closed { id } => {
                self.active_inner.remove(&id);
                self.remove_direct(id);
                let riding: Vec<_> = self
                    .circuits
                    .iter()
                    .filter_map(|(circuit_id, circuit)| {
                        (circuit.inner_conn == id).then_some(*circuit_id)
                    })
                    .collect();
                for circuit_id in riding {
                    let pre_ready = self
                        .circuits
                        .get(&circuit_id)
                        .is_some_and(|circuit| !circuit.is_ready());
                    self.fail_circuit(circuit_id, "relay connection closed".to_string(), pre_ready);
                }
                self.release_retired_bridges_for_connection(id);
                self.pending.push_back(TransportEvent::Closed { id });
            }
            other => self.pending.push_back(other),
        }
    }

    /// Runs one stream operation against a circuit's session and flushes
    /// whatever it queued.
    ///
    /// A failure that kills the session closes the circuit before returning.
    /// No `Error` event goes out: the caller already learns why from the
    /// returned error, exactly as for a locally requested [`Transport::close`].
    fn operate_session<R>(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut SecureMuxSession) -> Result<R, SessionError>,
    ) -> Result<R, TransportError> {
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let result = operation(&mut circuit.session);
        let pumped = self.pump(&mut circuit);
        self.circuits.insert(id, circuit);

        if let Err(teardown) = pumped {
            self.fail_circuit(id, teardown.message.clone(), false);
            return Err(TransportError::PollError {
                reason: teardown.message,
            });
        }
        match result {
            Ok(value) => Ok(value),
            Err(SessionError::NotEstablished) => Err(TransportError::InvalidState {
                id,
                state: ConnectionState::Connecting,
                expected: ConnectionState::Connected,
            }),
            Err(SessionError::UnknownStream { stream }) => Err(TransportError::StreamNotFound {
                id,
                stream_id: stream,
            }),
            // Yamux refused the operation — a full send buffer, an unknown
            // substream — but the session itself is still healthy.
            Err(SessionError::Yamux(error)) => Err(TransportError::PollError {
                reason: error.to_string(),
            }),
            // Defensive: today a session only fails fatally while handling
            // input, so a local operation cannot land here. Dropping the arm
            // would leave a dead session in the map if that ever changed.
            Err(fatal) => {
                let reason = fatal.to_string();
                self.fail_circuit(id, reason.clone(), false);
                Err(TransportError::PollError { reason })
            }
        }
    }

    fn drain_pending_events(&mut self) -> Vec<TransportEvent> {
        self.pending.drain(..).collect()
    }
}

impl<T: Transport, E: EntropySource> Transport for CircuitTransport<T, E> {
    fn dial(&mut self, address: &minip2p_core::PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.inner.dial(address)?;
        if id.is_circuit() {
            let close_result = self.inner.close(id);
            // The dial is rejected regardless of best-effort inner cleanup.
            match close_result {
                Ok(()) | Err(_) => {}
            }
            return Err(TransportError::DialFailed {
                id,
                reason: "wrapped transport allocated in the circuit connection-ID namespace"
                    .to_string(),
            });
        }
        Ok(id)
    }

    fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.inner.listen(address)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        if !id.is_circuit() {
            return self.inner.open_stream(id);
        }
        let stream_id = self.operate_session(id, SecureMuxSession::open_stream)?;
        self.pending
            .push_back(TransportEvent::StreamOpened { id, stream_id });
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.send_stream(id, stream_id, data);
        }
        self.operate_session(id, |session| session.send(stream_id, data))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamSendFailed {
                    id,
                    stream_id,
                    reason,
                })
            })
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.close_stream_write(id, stream_id);
        }
        self.operate_session(id, |session| session.close_stream_write(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamCloseWriteFailed {
                    id,
                    stream_id,
                    reason,
                })
            })
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.reset_stream(id, stream_id);
        }
        self.operate_session(id, |session| session.reset_stream(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamResetFailed {
                    id,
                    stream_id,
                    reason,
                })
            })
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.close(id);
        }
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let key = circuit.bridge_key();
        self.bridge_index.remove(&key);
        self.retire_bridge(key);
        // A circuit still negotiating has no Yamux session to shut down, so
        // `go_away` refuses and the bridge is reset instead.
        let announced = circuit.session.go_away(0).is_ok();
        let flushed = self.pump(&mut circuit).is_ok();
        let graceful = announced
            && flushed
            && self
                .inner
                .close_stream_write(circuit.inner_conn, circuit.bridge_stream)
                .is_ok();
        if !graceful {
            let reset_result = self
                .inner
                .reset_stream(circuit.inner_conn, circuit.bridge_stream);
            // The connection is closed even if best-effort bridge cleanup
            // fails, so preserve the single `Closed` event below.
            match reset_result {
                Ok(()) | Err(_) => {}
            }
        }
        self.pending.push_back(TransportEvent::Closed { id });
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        if !self.pending.is_empty() {
            return Ok(self.drain_pending_events());
        }
        for event in self.inner.poll(now)? {
            self.handle_inner_event(event);
        }
        for id in self.circuits.keys().copied().collect::<Vec<_>>() {
            if !self
                .circuits
                .get(&id)
                .is_some_and(|circuit| circuit.session.is_established())
            {
                continue;
            }
            let result = self.with_circuit(id, |this, circuit| {
                circuit.session.poll(now)?;
                this.pump(circuit)
            });
            if let Err(teardown) = result {
                self.fail_circuit(id, teardown.message, !teardown.graceful);
            }
        }
        Ok(self.drain_pending_events())
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() {
            // Buffered circuit events are due regardless of what the host's
            // clock reads, so this needs no retained time sample.
            return Some(Deadline::IMMEDIATE);
        }
        let mut deadline = self.inner.next_deadline();
        for circuit in self.circuits.values() {
            let session_deadline = circuit.session.next_deadline().or_else(|| {
                // An externally injected bridge read can complete the upgrade
                // while `Connected` is pending. The pending-event fast path
                // then returns before `session.poll` gets a time sample, so
                // keepalive is not armed yet. Wake once more immediately to
                // stamp the newly established Yamux session.
                circuit
                    .session
                    .is_established()
                    .then_some(Deadline::IMMEDIATE)
            });
            deadline = Deadline::earliest_opt(deadline, session_deadline);
        }
        deadline
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_addresses()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.inner.active_inbound_connection_sources()
    }

    /// Forwards to the wrapped transport, which owns the socket a hole punch
    /// has to leave from. A circuit has no datagram of its own to send.
    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        self.inner.send_datagram(target, payload)
    }
}

#[cfg(feature = "std")]
impl<T: minip2p_transport::BlockingTransport, E: EntropySource> minip2p_transport::BlockingTransport
    for CircuitTransport<T, E>
{
    fn wait_for_input(&mut self, timeout: core::time::Duration) -> minip2p_transport::WaitOutcome {
        if self.pending.is_empty() {
            self.inner.wait_for_input(timeout)
        } else {
            minip2p_transport::WaitOutcome::Ready
        }
    }

    /// Forwards to the wrapped transport, which owns the socket that
    /// `wait_for_input` actually blocks on.
    ///
    /// Inheriting the inert default would hand callers a handle that silently
    /// does nothing while the wait still blocks inside the inner transport.
    fn wait_handle(&self) -> minip2p_transport::WaitHandle {
        self.inner.wait_handle()
    }
}

/// Wraps a session failure as the stream error the transport contract expects.
///
/// Identifier and state errors pass through: they describe the request rather
/// than the stream operation, and callers match on them.
fn stream_error(
    error: TransportError,
    wrap: impl FnOnce(String) -> TransportError,
) -> TransportError {
    match error {
        error @ (TransportError::ConnectionNotFound { .. }
        | TransportError::StreamNotFound { .. }
        | TransportError::InvalidState { .. }) => error,
        error => wrap(error.to_string()),
    }
}

#[cfg(feature = "std")]
impl<T> CircuitTransport<T, StdEntropy> {
    /// Wraps a transport using operating-system entropy.
    pub fn new_os(inner: T, identity: Ed25519Keypair) -> Self {
        Self::new(inner, identity, StdEntropy::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_core::SansIoProtocol;
    use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
    use minip2p_noise::{
        NOISE_PROTOCOL_ID, NoiseConfig, NoiseInput, NoiseOutput, NoiseRole, NoiseSession,
    };
    use minip2p_secure_mux::KEEPALIVE_INTERVAL_MS;
    use minip2p_test_support::InMemoryTransport;

    #[derive(Clone, Debug)]
    struct CounterEntropy(u8);

    impl EntropySource for CounterEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            self.0 = self.0.wrapping_add(1);
            output.fill(self.0);
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::failed("injected failure"))
        }
    }

    struct CloseObservingTransport<T> {
        inner: T,
        fail_close_write: bool,
        fail_send: bool,
        send_calls: usize,
        close_write_calls: usize,
        reset_calls: usize,
    }

    /// Leaf transport whose wait handle records interrupts, so a test can
    /// prove one reached the bottom of a decorator stack.
    struct WakeableTransport {
        inner: InMemoryTransport,
        interrupts: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
    }

    impl Transport for WakeableTransport {
        fn dial(&mut self, addr: &minip2p_core::PeerAddr) -> Result<ConnectionId, TransportError> {
            self.inner.dial(addr)
        }

        fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
            self.inner.listen(addr)
        }

        fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
            self.inner.open_stream(id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Vec<u8>,
        ) -> Result<(), TransportError> {
            self.inner.send_stream(id, stream_id, data)
        }

        fn close_stream_write(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.inner.close_stream_write(id, stream_id)
        }

        fn reset_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.inner.reset_stream(id, stream_id)
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.inner.close(id)
        }

        fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            self.inner.poll(now)
        }
    }

    impl minip2p_transport::BlockingTransport for WakeableTransport {
        fn wait_handle(&self) -> minip2p_transport::WaitHandle {
            let interrupts = alloc::sync::Arc::clone(&self.interrupts);
            minip2p_transport::WaitHandle::new(move || {
                interrupts.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            })
        }
    }

    /// A decorator that forwards `wait_for_input` but inherits the inert
    /// default `wait_handle` hands callers a handle that does nothing while
    /// the wait still blocks in the transport underneath.
    #[test]
    fn wait_handle_reaches_through_the_circuit_wrapper() {
        use minip2p_transport::BlockingTransport;

        let local = identity(1);
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
        let interrupts = alloc::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let transport = CircuitTransport::new(
            WakeableTransport {
                inner,
                interrupts: alloc::sync::Arc::clone(&interrupts),
            },
            local,
            CounterEntropy(1),
        );

        let handle = BlockingTransport::wait_handle(&transport);
        assert!(
            !handle.is_noop(),
            "the wrapper must not report an inert handle over a wakeable transport"
        );

        handle.interrupt();
        assert_eq!(
            interrupts.load(core::sync::atomic::Ordering::SeqCst),
            1,
            "interrupt must reach the transport that owns the wait"
        );
    }

    impl<T> CloseObservingTransport<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                fail_close_write: false,
                fail_send: false,
                send_calls: 0,
                close_write_calls: 0,
                reset_calls: 0,
            }
        }
    }

    impl<T: Transport> Transport for CloseObservingTransport<T> {
        fn dial(
            &mut self,
            address: &minip2p_core::PeerAddr,
        ) -> Result<ConnectionId, TransportError> {
            self.inner.dial(address)
        }

        fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
            self.inner.listen(address)
        }

        fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
            self.inner.open_stream(id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Vec<u8>,
        ) -> Result<(), TransportError> {
            self.send_calls += 1;
            if self.fail_send {
                return Err(TransportError::StreamSendFailed {
                    id,
                    stream_id,
                    reason: "injected bridge send failure".to_string(),
                });
            }
            self.inner.send_stream(id, stream_id, data)
        }

        fn close_stream_write(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.close_write_calls += 1;
            if self.fail_close_write {
                return Err(TransportError::StreamCloseWriteFailed {
                    id,
                    stream_id,
                    reason: "injected FIN failure".to_string(),
                });
            }
            self.inner.close_stream_write(id, stream_id)
        }

        fn reset_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.reset_calls += 1;
            self.inner.reset_stream(id, stream_id)
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.inner.close(id)
        }

        fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            self.inner.poll(now)
        }

        fn next_deadline(&self) -> Option<Deadline> {
            self.inner.next_deadline()
        }

        fn local_addresses(&self) -> Vec<Multiaddr> {
            self.inner.local_addresses()
        }

        fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
            self.inner.active_inbound_connection_sources()
        }
    }

    type CloseObservedCircuit =
        CircuitTransport<CloseObservingTransport<InMemoryTransport>, CounterEntropy>;
    type TestCircuit = CircuitTransport<InMemoryTransport, CounterEntropy>;
    type CloseObservedPair = (
        CloseObservedCircuit,
        TestCircuit,
        ConnectionId,
        StreamId,
        PeerId,
        PeerId,
    );

    /// Whether a circuit has authenticated its peer but not finished the
    /// upgrade: the exact window in which a decrypted batch can straddle the
    /// Yamux selection boundary.
    fn selecting_yamux<T, E>(transport: &CircuitTransport<T, E>, id: ConnectionId) -> bool {
        transport.circuits.get(&id).is_some_and(|circuit| {
            circuit.session.peer().is_some() && !circuit.session.is_established()
        })
    }

    fn established<T, E>(transport: &CircuitTransport<T, E>, id: ConnectionId) -> bool {
        transport
            .circuits
            .get(&id)
            .is_some_and(|circuit| circuit.session.is_established())
    }

    fn identity(seed: u8) -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([seed; 32])
    }

    fn setup_pair_with_yamux_config(
        yamux_config: Option<YamuxConfig>,
    ) -> (
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        ConnectionId,
        StreamId,
        PeerId,
        PeerId,
    ) {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(inner_a, a_identity, CounterEntropy(10));
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        if let Some(config) = yamux_config {
            a.set_yamux_config(config.clone());
            b.set_yamux_config(config);
        }

        let _ = a.poll(Now::from_millis(0)).expect("initial A events");
        let _ = b.poll(Now::from_millis(0)).expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
        let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");

        let a_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("initiator adoption");
        let b_id = b
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay,
                remote_peer: a_peer.clone(),
                role: CircuitRole::Responder,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("responder adoption");
        // Circuit IDs are endpoint-local; synchronized test counters let the
        // pair helpers refer to both deterministic IDs with one value.
        assert_eq!(a_id, b_id);
        assert!(CircuitTransport::<InMemoryTransport, CounterEntropy>::is_circuit(a_id));
        let incoming = b.poll(Now::from_millis(0)).expect("responder incoming");
        assert!(matches!(
            incoming.as_slice(),
            [TransportEvent::IncomingConnection { id, endpoint }]
                if *id == b_id && endpoint.peer_id().is_none()
        ));
        (a, b, a_id, bridge, a_peer, b_peer)
    }

    fn setup_pair() -> (
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        ConnectionId,
        StreamId,
        PeerId,
        PeerId,
    ) {
        setup_pair_with_yamux_config(None)
    }

    fn setup_close_observed_pair() -> CloseObservedPair {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(
            CloseObservingTransport::new(inner_a),
            a_identity,
            CounterEntropy(10),
        );
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        let _ = a.poll(Now::from_millis(0)).expect("initial A events");
        let _ = b.poll(Now::from_millis(0)).expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
        let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");
        let a_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("initiator adoption");
        let b_id = b
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay,
                remote_peer: a_peer.clone(),
                role: CircuitRole::Responder,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("responder adoption");
        // Circuit IDs are endpoint-local; synchronized test counters let the
        // pair helpers refer to both deterministic IDs with one value.
        assert_eq!(a_id, b_id);
        assert!(matches!(
            b.poll(Now::from_millis(0)).expect("responder incoming").as_slice(),
            [TransportEvent::IncomingConnection { id, .. }] if *id == b_id
        ));
        (a, b, a_id, bridge, a_peer, b_peer)
    }

    fn complete_handshake<TA, EA, TB, EB>(
        a: &mut CircuitTransport<TA, EA>,
        b: &mut CircuitTransport<TB, EB>,
        circuit_id: ConnectionId,
        a_peer: &PeerId,
        b_peer: &PeerId,
    ) where
        TA: Transport,
        EA: EntropySource,
        TB: Transport,
        EB: EntropySource,
    {
        let mut a_connected = false;
        let mut b_connected = false;
        for _ in 0..32 {
            for event in a.poll(Now::from_millis(0)).expect("drive initiator") {
                if let TransportEvent::Connected { id, endpoint } = event
                    && id == circuit_id
                {
                    assert_eq!(endpoint.peer_id(), Some(b_peer));
                    a_connected = true;
                }
            }
            for event in b.poll(Now::from_millis(0)).expect("drive responder") {
                if let TransportEvent::Connected { id, endpoint } = event
                    && id == circuit_id
                {
                    assert_eq!(endpoint.peer_id(), Some(a_peer));
                    b_connected = true;
                }
            }
            if a_connected && b_connected {
                return;
            }
        }
        panic!("circuit handshake did not complete");
    }

    #[test]
    fn a_quiet_circuit_keeps_alive_without_opening_a_stream() {
        let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let inner_conn = a
            .circuits
            .get(&circuit_id)
            .expect("initiator circuit")
            .inner_conn;

        assert_eq!(
            a.next_deadline(),
            Some(Deadline::from_millis(KEEPALIVE_INTERVAL_MS)),
            "Connected must arm keepalive without another poll"
        );

        let a_sends = a.inner().send_calls;

        let ping = a
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .expect("initiator keepalive");
        assert!(
            ping.iter()
                .all(|event| !matches!(event, TransportEvent::StreamData { .. })),
            "a yamux ping is not stream data: {ping:?}"
        );
        assert_eq!(
            a.inner().send_calls,
            a_sends + 1,
            "the keepalive deadline must write a Yamux ping to the bridge"
        );

        let ping_wire = b
            .inner_mut()
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .expect("read ping from bridge");
        let ping_bytes = ping_wire
            .into_iter()
            .find_map(|event| match event {
                TransportEvent::StreamData {
                    stream_id, data, ..
                } if stream_id == bridge => Some(data),
                _ => None,
            })
            .expect("Yamux ping bytes crossed the bridge");
        b.inject_bridge_data(inner_conn, bridge, ping_bytes);

        let pong_wire = a
            .inner_mut()
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .expect("read pong from bridge");
        let pong_bytes = pong_wire
            .into_iter()
            .find_map(|event| match event {
                TransportEvent::StreamData {
                    stream_id, data, ..
                } if stream_id == bridge => Some(data),
                _ => None,
            })
            .expect("Yamux pong bytes crossed the bridge");
        a.inject_bridge_data(inner_conn, bridge, pong_bytes);

        let ack = a
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .expect("initiator sees the pong");
        assert!(
            ack.is_empty(),
            "a keepalive pong is session traffic: {ack:?}"
        );
        assert!(
            a.circuit_ids().contains(&circuit_id),
            "keepalive must not tear the circuit down"
        );
    }

    #[test]
    fn circuit_runs_noise_yamux_and_stream_contract() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

        let stream = a.open_stream(circuit_id).expect("open circuit stream");
        assert_eq!(stream.as_u64() % 2, 1, "initiator streams are odd");
        assert!(a
            .poll(Now::from_millis(0))
            .expect("opened")
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamOpened { id, stream_id } if *id == circuit_id && *stream_id == stream)));
        let incoming = b.poll(Now::from_millis(0)).expect("incoming stream");
        assert!(incoming.iter().any(|event| matches!(event,
            TransportEvent::IncomingStream { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));

        a.send_stream(circuit_id, stream, b"hello".to_vec())
            .expect("send");
        let data = b.poll(Now::from_millis(0)).expect("data");
        assert!(data.iter().any(|event| matches!(event,
            TransportEvent::StreamData { id, stream_id, data }
                if *id == circuit_id && *stream_id == stream && data == b"hello"
        )));

        a.close_stream_write(circuit_id, stream).expect("FIN");
        let eof = b.poll(Now::from_millis(0)).expect("remote FIN");
        assert!(eof.iter().any(|event| matches!(event,
            TransportEvent::StreamRemoteWriteClosed { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));
        b.send_stream(circuit_id, stream, b"reply".to_vec())
            .expect("reverse send remains open");
        let reply = a.poll(Now::from_millis(0)).expect("reply");
        assert!(reply.iter().any(|event| matches!(event,
            TransportEvent::StreamData { data, .. } if data == b"reply"
        )));

        b.reset_stream(circuit_id, stream).expect("reset");
        let local_closed = b.poll(Now::from_millis(0)).expect("local reset close");
        assert_eq!(
            local_closed
                .iter()
                .filter(|event| matches!(event, TransportEvent::StreamClosed { id, stream_id } if *id == circuit_id && *stream_id == stream))
                .count(),
            1
        );
        let remote_closed = a.poll(Now::from_millis(0)).expect("remote reset close");
        assert!(remote_closed.iter().any(|event| matches!(event,
            TransportEvent::StreamClosed { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));
    }

    #[test]
    fn wrapper_transport_contract_orders_connection_and_stream_events() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        let mut a_events = Vec::new();
        let mut b_events = Vec::new();
        for _ in 0..32 {
            a_events.extend(a.poll(Now::from_millis(0)).expect("drive initiator"));
            b_events.extend(b.poll(Now::from_millis(0)).expect("drive responder"));
            let a_connected = a_events.iter().any(
                |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id),
            );
            let b_connected = b_events.iter().any(
                |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id),
            );
            if a_connected && b_connected {
                break;
            }
        }
        for (events, expected_peer) in [(&a_events, &b_peer), (&b_events, &a_peer)] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id))
                    .count(),
                1,
                "Connected must be emitted exactly once"
            );
            let connected = events
                .iter()
                .position(|event| {
                    matches!(event,
                        TransportEvent::Connected { id, endpoint }
                            if *id == circuit_id && endpoint.peer_id() == Some(expected_peer)
                    )
                })
                .expect("authenticated Connected event");
            assert!(!events[..connected].iter().any(|event| matches!(
                event,
                TransportEvent::StreamOpened { id, .. }
                    | TransportEvent::IncomingStream { id, .. }
                    | TransportEvent::StreamData { id, .. }
                    | TransportEvent::StreamRemoteWriteClosed { id, .. }
                    | TransportEvent::StreamClosed { id, .. }
                    if *id == circuit_id
            )));
        }
        assert!(
            a.poll(Now::from_millis(0))
                .expect("idle initiator")
                .is_empty()
        );
        assert!(
            b.poll(Now::from_millis(0))
                .expect("idle responder")
                .is_empty()
        );

        let stream = a.open_stream(circuit_id).expect("open stream");
        a.send_stream(circuit_id, stream, b"ordered".to_vec())
            .expect("send immediately after open");
        assert_eq!(
            a.poll(Now::from_millis(0)).expect("local stream event"),
            [TransportEvent::StreamOpened {
                id: circuit_id,
                stream_id: stream,
            }]
        );
        let inbound = b
            .poll(Now::from_millis(0))
            .expect("coalesced stream open and data");
        let incoming = inbound
            .iter()
            .position(|event| {
                matches!(event,
                    TransportEvent::IncomingStream { id, stream_id }
                        if *id == circuit_id && *stream_id == stream
                )
            })
            .expect("IncomingStream event");
        let data = inbound
            .iter()
            .position(|event| {
                matches!(event,
                    TransportEvent::StreamData { id, stream_id, data }
                        if *id == circuit_id && *stream_id == stream && data == b"ordered"
                )
            })
            .expect("StreamData event");
        assert!(incoming < data, "IncomingStream must precede StreamData");

        a.reset_stream(circuit_id, stream).expect("reset stream");
        assert_eq!(
            a.poll(Now::from_millis(0))
                .expect("immediate local terminal event"),
            [TransportEvent::StreamClosed {
                id: circuit_id,
                stream_id: stream,
            }]
        );
        assert_eq!(
            b.poll(Now::from_millis(0)).expect("remote terminal event"),
            [TransportEvent::StreamClosed {
                id: circuit_id,
                stream_id: stream,
            }]
        );
        assert!(
            a.poll(Now::from_millis(0))
                .expect("no events after local terminal")
                .is_empty()
        );
        assert!(
            b.poll(Now::from_millis(0))
                .expect("no events after remote terminal")
                .is_empty()
        );
    }

    #[test]
    fn wrapper_transport_contract_rejects_unknown_connection_and_stream_ids() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let unknown_connection = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 999)
            .expect("circuit id in range");
        let stream = StreamId::new(99);

        assert!(matches!(
            a.open_stream(unknown_connection),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert!(matches!(
            a.send_stream(unknown_connection, stream, vec![1]),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert!(matches!(
            a.close_stream_write(unknown_connection, stream),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert!(matches!(
            a.reset_stream(unknown_connection, stream),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert_eq!(
            a.close(unknown_connection),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );

        let oversized_stream = StreamId::new(u64::from(u32::MAX) + 1);
        assert_eq!(
            a.send_stream(unknown_connection, oversized_stream, vec![1]),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );
        assert_eq!(
            a.close_stream_write(unknown_connection, oversized_stream),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );
        assert_eq!(
            a.reset_stream(unknown_connection, oversized_stream),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );

        // An id congruent to a live substream modulo 2^32 must be rejected
        // rather than truncated onto it, on a live circuit too.
        let live = a.open_stream(circuit_id).expect("open a live substream");
        let aliased = StreamId::new(live.as_u64() + (1u64 << 32));
        for result in [
            a.send_stream(circuit_id, aliased, vec![1]),
            a.close_stream_write(circuit_id, aliased),
            a.reset_stream(circuit_id, aliased),
        ] {
            assert_eq!(
                result,
                Err(TransportError::StreamNotFound {
                    id: circuit_id,
                    stream_id: aliased,
                })
            );
        }

        for result in [
            a.send_stream(circuit_id, stream, vec![1]),
            a.close_stream_write(circuit_id, stream),
            a.reset_stream(circuit_id, stream),
        ] {
            assert_eq!(
                result,
                Err(TransportError::StreamNotFound {
                    id: circuit_id,
                    stream_id: stream,
                })
            );
        }
    }

    #[test]
    fn adoption_processes_pending_bridge_bytes_before_live_input() {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(inner_a, a_identity, CounterEntropy(10));
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        let _ = a.poll(Now::from_millis(0)).expect("initial A events");
        let _ = b.poll(Now::from_millis(0)).expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
        let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");
        let circuit_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("initiator adoption");
        let header = b
            .inner_mut()
            .poll(Now::from_millis(0))
            .expect("read pipelined header")
            .into_iter()
            .find_map(|event| match event {
                TransportEvent::StreamData { data, .. } => Some(data),
                _ => None,
            })
            .expect("initiator multistream header");
        let split = header.len() / 2;
        b.adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: a_peer.clone(),
            role: CircuitRole::Responder,
            pending_data: header[..split].to_vec(),
            remote_write_closed: false,
        })
        .expect("responder adoption with partial pending data");
        assert!(matches!(
            b.poll(Now::from_millis(0))
                .expect("incoming event")
                .as_slice(),
            [TransportEvent::IncomingConnection { .. }]
        ));
        b.inject_bridge_data(inner_conn, bridge, header[split..].to_vec());
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    }

    #[test]
    fn adoption_processes_pipelined_selection_and_noise_message() {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(inner_a, a_identity.clone(), CounterEntropy(10));
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        let _ = a.poll(Now::from_millis(0)).expect("initial A events");
        let _ = b.poll(Now::from_millis(0)).expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
        let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");

        let mut select = MultistreamSelect::dialer(NOISE_PROTOCOL_ID);
        select
            .handle_input(MultistreamInput::Start)
            .expect("scripted multistream start");
        let mut pending_data = Vec::new();
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                pending_data.extend(bytes);
            }
        }
        let mut scripted_listener = MultistreamSelect::listener([NOISE_PROTOCOL_ID.to_string()]);
        scripted_listener
            .handle_input(MultistreamInput::Start)
            .expect("scripted listener start");
        let listener_header = match scripted_listener.poll_output() {
            Some(MultistreamOutput::OutboundData(bytes)) => bytes,
            other => panic!("expected listener header, got {other:?}"),
        };
        select
            .handle_input(MultistreamInput::Data(listener_header))
            .expect("scripted dialer receives listener header");
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                pending_data.extend(bytes);
            }
        }
        let selection_len = pending_data.len();
        let mut scripted_noise = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Initiator,
            identity: a_identity,
            static_secret: [11; 32],
            ephemeral_secret: [12; 32],
            expected_peer: Some(b_peer.clone()),
        });
        scripted_noise
            .handle_input(NoiseInput::Start)
            .expect("scripted Noise start");
        while let Some(output) = scripted_noise.poll_output() {
            if let NoiseOutput::Outbound(bytes) = output {
                pending_data.extend(bytes);
            }
        }
        assert!(selection_len > 0 && pending_data.len() > selection_len);

        let circuit_id = b
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: a_peer.clone(),
                role: CircuitRole::Responder,
                pending_data,
                remote_write_closed: false,
            })
            .expect("responder adopts pipelined selection and Noise msg1");
        let responder_events = b
            .poll(Now::from_millis(0))
            .expect("responder incoming event");
        assert!(
            matches!(
                responder_events.as_slice(),
                [TransportEvent::IncomingConnection { id, .. }] if *id == circuit_id
            ),
            "unexpected pipelined adoption events: {responder_events:?}"
        );

        let a_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay,
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("real initiator adoption");
        assert_eq!(a_id, circuit_id);

        // The responder already consumed the scripted copy of the dialer's
        // selection and msg1, so discard the identical selection emitted by
        // the real initiator before letting it consume the responder reply.
        let duplicate_selection = b
            .inner_mut()
            .poll(Now::from_millis(0))
            .expect("duplicate selection");
        assert!(
            duplicate_selection
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        );
        let _ = a
            .poll(Now::from_millis(0))
            .expect("initiator consumes pipelined response");

        // Receiving the real selection reply emits the duplicate protocol
        // proposal and Noise msg1 before msg3 and the encrypted Yamux
        // selection. Drop those first two data events, then route the
        // remaining bridge events through the wrapper.
        let mut real_followup = b
            .inner_mut()
            .poll(Now::from_millis(0))
            .expect("real Noise follow-up");
        for expected in ["protocol proposal", "Noise msg1"] {
            let duplicate = real_followup
                .iter()
                .position(|event| matches!(event, TransportEvent::StreamData { .. }))
                .unwrap_or_else(|| panic!("duplicate {expected}"));
            real_followup.remove(duplicate);
        }
        for event in real_followup {
            b.handle_inner_event(event);
        }

        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    }

    #[test]
    fn decrypt_batch_crosses_yamux_selection_into_ready_frames() {
        let (mut a, mut b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();

        // Stop immediately after B reaches Ready. Its encrypted Yamux
        // selection confirmation is now queued for A, which has authenticated
        // B but not yet consumed that ciphertext, so it is still selecting.
        for _ in 0..32 {
            let _ = a
                .poll(Now::from_millis(0))
                .expect("drive initiator toward Yamux selection");
            let _ = b
                .poll(Now::from_millis(0))
                .expect("drive responder toward Yamux selection");
            if selecting_yamux(&a, circuit_id) && established(&b, circuit_id) {
                break;
            }
        }
        assert!(selecting_yamux(&a, circuit_id));
        assert!(established(&b, circuit_id));

        // Queue a Yamux SYN behind the already-encrypted selection reply,
        // then combine both Noise transport frames into one bridge read.
        // Noise decrypts them as two plaintexts in one output batch: the
        // first transitions A to Ready and the second must be routed through
        // that newly-created Ready state.
        let opened = b.open_stream(circuit_id).expect("open responder stream");
        let raw = a
            .inner_mut()
            .poll(Now::from_millis(0))
            .expect("read encrypted bridge batch");
        let chunks: Vec<_> = raw
            .into_iter()
            .filter_map(|event| match event {
                TransportEvent::StreamData {
                    stream_id, data, ..
                } if stream_id == bridge => Some(data),
                _ => None,
            })
            .collect();
        assert!(chunks.len() >= 2, "expected selection and Yamux frames");
        let coalesced = chunks.into_iter().flatten().collect();
        let inner_conn = a
            .circuits
            .get(&circuit_id)
            .expect("initiator circuit")
            .inner_conn;
        a.inject_bridge_data(inner_conn, bridge, coalesced);
        assert_eq!(
            a.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "an injected handshake completion must schedule keepalive arming"
        );

        let events = a
            .poll(Now::from_millis(0))
            .expect("drain cross-boundary outputs");
        assert!(events.iter().any(
            |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id)
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::IncomingStream { id, stream_id }
                if *id == circuit_id && *stream_id == opened
        )));
        assert_eq!(
            a.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "draining pending events must leave an immediate wakeup"
        );
        assert!(
            a.poll(Now::from_millis(0))
                .expect("arm keepalive")
                .is_empty()
        );
        assert_eq!(
            a.next_deadline(),
            Some(Deadline::from_millis(KEEPALIVE_INTERVAL_MS))
        );
    }

    fn assert_pre_ready_bridge_failure(events: &[TransportEvent], circuit_id: ConnectionId) {
        assert!(matches!(
            events,
            [
                TransportEvent::Error { id: error_id, .. },
                TransportEvent::Closed { id: closed_id },
            ] if *error_id == circuit_id && *closed_id == circuit_id
        ));
        assert!(!events.iter().any(|event| matches!(
            event,
            TransportEvent::Connected { id, .. } if *id == circuit_id
        )));
    }

    #[test]
    fn bridge_reset_mid_handshake_is_terminal() {
        let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();
        let inner_conn = ConnectionId::new(1);

        a.inject_bridge_closed(inner_conn, bridge);
        let events = a.poll(Now::from_millis(0)).expect("pre-ready bridge reset");
        assert_pre_ready_bridge_failure(&events, circuit_id);
        assert!(
            a.poll(Now::from_millis(0))
                .expect("consume reset acknowledgement")
                .is_empty()
        );

        a.inject_bridge_data(inner_conn, bridge, b"late".to_vec());
        a.inject_bridge_remote_write_closed(inner_conn, bridge);
        a.inject_bridge_closed(inner_conn, bridge);
        assert!(
            a.poll(Now::from_millis(0))
                .expect("nothing follows terminal close")
                .is_empty()
        );
    }

    #[test]
    fn bridge_remote_fin_mid_handshake_is_terminal() {
        let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();
        let inner_conn = ConnectionId::new(1);

        a.inject_bridge_remote_write_closed(inner_conn, bridge);
        let events = a.poll(Now::from_millis(0)).expect("pre-ready bridge FIN");
        assert_pre_ready_bridge_failure(&events, circuit_id);
        assert!(
            a.poll(Now::from_millis(0))
                .expect("consume reset acknowledgement")
                .is_empty()
        );

        a.inject_bridge_data(inner_conn, bridge, b"late".to_vec());
        assert!(
            a.poll(Now::from_millis(0))
                .expect("post-close data is ignored")
                .is_empty()
        );
    }

    #[test]
    fn adoption_is_idempotent_and_close_is_terminal() {
        let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_pair();
        let relay = identity(9).peer_id();
        let duplicate = a
            .adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("identical duplicate is idempotent");
        assert_eq!(duplicate, circuit_id);
        assert_eq!(
            a.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: bridge,
                relay: identity(8).peer_id(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            }),
            Err(AdoptError::ConflictingAdoption)
        );
        assert_eq!(
            a.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: bridge,
                relay,
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: true,
            }),
            Err(AdoptError::ConflictingAdoption)
        );
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        a.close(circuit_id).expect("graceful close");
        let events = a.poll(Now::from_millis(0)).expect("closed event");
        assert_eq!(events, vec![TransportEvent::Closed { id: circuit_id }]);
        assert!(matches!(
            a.open_stream(circuit_id),
            Err(TransportError::ConnectionNotFound { .. })
        ));
        a.inject_bridge_data(ConnectionId::new(1), bridge, b"late".to_vec());
        a.inject_bridge_remote_write_closed(ConnectionId::new(1), bridge);
        a.inject_bridge_closed(ConnectionId::new(1), bridge);
        assert!(
            a.poll(Now::from_millis(0))
                .expect("late bridge events are dropped")
                .is_empty()
        );
    }

    #[test]
    fn ready_close_sends_go_away_then_bridge_fin_without_reset() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let stream = a.open_stream(circuit_id).expect("open stream before close");
        let _ = a.poll(Now::from_millis(0)).expect("local stream open");
        let _ = b.poll(Now::from_millis(0)).expect("remote stream open");
        let _ = a.poll(Now::from_millis(0)).expect("stream acknowledgement");
        a.send_stream(circuit_id, stream, b"queued-before-close".to_vec())
            .expect("queue application data before close");

        a.close(circuit_id).expect("graceful circuit close");
        assert_eq!(a.inner().close_write_calls, 1);
        assert_eq!(a.inner().reset_calls, 0);
        assert_eq!(
            a.poll(Now::from_millis(0)).expect("local close event"),
            [
                TransportEvent::StreamClosed {
                    id: circuit_id,
                    stream_id: stream,
                },
                TransportEvent::Closed { id: circuit_id },
            ]
        );

        let peer_wire = b
            .inner_mut()
            .poll(Now::from_millis(0))
            .expect("peer bridge events");
        let data_positions: Vec<_> = peer_wire
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                matches!(event, TransportEvent::StreamData { .. }).then_some(index)
            })
            .collect();
        assert_eq!(
            data_positions.len(),
            2,
            "application data and encrypted GoAway must both reach the peer"
        );
        let go_away = data_positions[1];
        let fin = peer_wire
            .iter()
            .position(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
            .expect("bridge FIN reaches the peer");
        assert!(go_away < fin, "GoAway must be queued before bridge FIN");
        assert!(
            !peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
        );
        for event in peer_wire {
            b.handle_inner_event(event);
        }
        let peer_events = b
            .poll(Now::from_millis(0))
            .expect("peer observes data then GoAway");
        // The remote GoAway tears the substreams down the same way the local
        // close does: a `StreamClosed` each, then `Closed`. Both ends of a
        // graceful shutdown see the same sequence.
        assert!(
            matches!(
                peer_events.as_slice(),
                [
                    TransportEvent::StreamData { id, stream_id, data },
                    TransportEvent::StreamClosed {
                        id: stream_closed_id,
                        stream_id: closed_stream,
                    },
                    TransportEvent::Closed { id: closed_id },
                ] if *id == circuit_id
                    && *stream_id == stream
                    && data == b"queued-before-close"
                    && *stream_closed_id == circuit_id
                    && *closed_stream == stream
                    && *closed_id == circuit_id
            ),
            "unexpected peer close events: {peer_events:?}"
        );
        assert!(
            b.poll(Now::from_millis(0))
                .expect("terminal peer state")
                .is_empty()
        );
    }

    #[test]
    fn gracefully_closed_bridge_tombstones_are_bounded() {
        let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let inner_conn = ConnectionId::new(1);

        a.close(circuit_id).expect("graceful circuit close");
        let _ = a.poll(Now::from_millis(0)).expect("local close event");
        assert!(a.retired_bridges.contains(&(inner_conn, bridge)));

        for index in 0..MAX_RETIRED_BRIDGES {
            a.retire_bridge((
                inner_conn,
                StreamId::new(10_000 + u64::try_from(index).expect("usize fits u64")),
            ));
        }

        assert_eq!(a.retired_bridges.len(), MAX_RETIRED_BRIDGES);
        assert_eq!(a.retired_bridge_order.len(), MAX_RETIRED_BRIDGES);
        assert!(!a.retired_bridges.contains(&(inner_conn, bridge)));
    }

    #[test]
    fn ready_close_resets_bridge_when_fin_fails() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        a.inner_mut().fail_close_write = true;

        a.close(circuit_id).expect("fallback circuit close");
        assert_eq!(a.inner().close_write_calls, 1);
        assert_eq!(a.inner().reset_calls, 1);
        assert_eq!(
            a.poll(Now::from_millis(0)).expect("local close event"),
            [TransportEvent::Closed { id: circuit_id }]
        );

        let peer_wire = b
            .inner_mut()
            .poll(Now::from_millis(0))
            .expect("peer bridge events");
        assert!(
            peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        );
        assert!(
            peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
        );
        assert!(
            !peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
        );
        for event in peer_wire {
            b.handle_inner_event(event);
        }
        assert_eq!(
            b.poll(Now::from_millis(0))
                .expect("peer observes terminal close"),
            [TransportEvent::Closed { id: circuit_id }]
        );
    }

    #[test]
    fn a_dead_bridge_closes_the_circuit_without_an_error_event() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let stream = a.open_stream(circuit_id).expect("open stream");
        let _ = a.poll(Now::from_millis(0)).expect("drain local events");

        // The relay connection dies between polls, so flushing what the
        // session queued fails.
        a.inner_mut().fail_send = true;
        assert!(matches!(
            a.send_stream(circuit_id, stream, b"lost".to_vec()),
            Err(TransportError::StreamSendFailed { id, stream_id, .. })
                if id == circuit_id && stream_id == stream
        ));

        // The caller already learned why from that error, so only `Closed`
        // goes out -- reporting it twice would be noise.
        assert_eq!(
            a.poll(Now::from_millis(0)).expect("teardown events"),
            [TransportEvent::Closed { id: circuit_id }]
        );
        assert_eq!(
            a.close(circuit_id),
            Err(TransportError::ConnectionNotFound { id: circuit_id })
        );
    }

    #[test]
    fn close_before_ready_resets_bridge_and_is_terminal() {
        let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_close_observed_pair();
        let inner_conn = ConnectionId::new(1);

        a.close(circuit_id).expect("pre-ready close");
        assert_eq!(a.inner().close_write_calls, 0);
        assert_eq!(a.inner().reset_calls, 1);
        assert_eq!(
            a.poll(Now::from_millis(0)).expect("pre-ready close event"),
            [TransportEvent::Closed { id: circuit_id }]
        );
        assert_eq!(
            a.close(circuit_id),
            Err(TransportError::ConnectionNotFound { id: circuit_id })
        );
        assert!(
            a.poll(Now::from_millis(0))
                .expect("consume reset acknowledgement")
                .is_empty()
        );
        a.inject_bridge_data(inner_conn, bridge, b"late".to_vec());
        assert!(
            a.poll(Now::from_millis(0))
                .expect("post-close data is ignored")
                .is_empty()
        );
    }

    #[test]
    fn relay_connection_close_closes_each_ready_circuit_once() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let stream = a
            .open_stream(circuit_id)
            .expect("open stream before relay loss");
        let _ = a.poll(Now::from_millis(0)).expect("local stream open");
        let _ = b.poll(Now::from_millis(0)).expect("remote stream open");

        a.inner_mut()
            .close(ConnectionId::new(1))
            .expect("relay connection closes");
        let events = a.poll(Now::from_millis(0)).expect("relay close mapping");
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TransportEvent::Closed { id } if *id == circuit_id))
                .count(),
            1
        );
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Closed { id } if *id == ConnectionId::new(1)
        )));
        assert!(!events.iter().any(|event| matches!(
            event,
            TransportEvent::StreamClosed { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));
        assert!(
            a.poll(Now::from_millis(0))
                .expect("relay close is terminal")
                .is_empty()
        );
    }

    #[test]
    fn yamux_backpressure_is_stream_scoped_and_session_survives() {
        let receive_window = 256 * 1024;
        let max_buffered_send = 64;
        let config = YamuxConfig {
            receive_window,
            max_frame_len: 64 * 1024,
            max_streams: 8,
            max_buffered_send,
            max_total_buffered_send: 128,
        };
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) =
            setup_pair_with_yamux_config(Some(config));
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

        let initiator_stream = a.open_stream(circuit_id).expect("initiator stream");
        assert_eq!(initiator_stream.as_u64() % 2, 1);
        let _ = a.poll(Now::from_millis(0)).expect("local open");
        let _ = b.poll(Now::from_millis(0)).expect("remote open");

        let error = a
            .send_stream(
                circuit_id,
                initiator_stream,
                vec![0; receive_window as usize + max_buffered_send + 1],
            )
            .expect_err("send beyond the Yamux queue cap");
        assert!(matches!(error, TransportError::StreamSendFailed { .. }));
        a.send_stream(circuit_id, initiator_stream, b"still-alive".to_vec())
            .expect("backpressure must not poison the stream");
        assert!(
            b.poll(Now::from_millis(0))
                .expect("small data")
                .iter()
                .any(|event| matches!(
                    event,
                    TransportEvent::StreamData { data, .. } if data == b"still-alive"
                ))
        );

        let responder_stream = b.open_stream(circuit_id).expect("responder stream");
        assert_eq!(responder_stream.as_u64() % 2, 0);
    }

    #[test]
    fn adoption_rejects_invalid_preconditions_without_consuming_ids() {
        let relay = identity(9).peer_id();
        let local = identity(1);
        let remote = identity(2).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay.clone());
        let mut transport = CircuitTransport::new(inner, local, CounterEntropy(1));
        assert_eq!(
            transport.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(99),
                bridge_stream: StreamId::new(1),
                relay,
                remote_peer: remote,
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            }),
            Err(AdoptError::UnknownConnection)
        );
        assert!(transport.circuit_ids().is_empty());
    }

    #[test]
    fn direct_connection_wins_before_and_during_circuit_handshake() {
        let local = identity(1);
        let remote = identity(2).peer_id();
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), remote.clone());
        let mut direct_first = CircuitTransport::new(inner, local, CounterEntropy(1));
        let _ = direct_first
            .poll(Now::from_millis(0))
            .expect("record direct connection");
        assert_eq!(
            direct_first.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: StreamId::new(1),
                relay: relay.clone(),
                remote_peer: remote.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            }),
            Err(AdoptError::PeerAlreadyDirect)
        );

        let (mut a, _b, circuit_id, _bridge, _a_peer, b_peer) = setup_pair();
        a.inner_mut().push_event(TransportEvent::Connected {
            id: ConnectionId::new(2),
            endpoint: ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.1/udp/5001/quic-v1"
                    .parse()
                    .expect("direct endpoint"),
                b_peer,
            ),
        });
        let events = a
            .poll(Now::from_millis(0))
            .expect("direct connection arrives");
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Error { id, .. } if *id == circuit_id
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Closed { id } if *id == circuit_id
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Connected { id, .. } if *id == ConnectionId::new(2)
        )));
    }

    #[test]
    fn a_circuit_completing_after_a_direct_connection_never_reports_connected() {
        let (mut a, mut b, circuit_id, _bridge, _a_peer, b_peer) = setup_pair();
        for _ in 0..32 {
            let _ = a.poll(Now::from_millis(0)).expect("drive initiator");
            let _ = b.poll(Now::from_millis(0)).expect("drive responder");
            if selecting_yamux(&a, circuit_id) && established(&b, circuit_id) {
                break;
            }
        }
        assert!(selecting_yamux(&a, circuit_id));
        assert!(established(&b, circuit_id));

        // Register the direct connection without `record_direct`'s sweep of
        // still-negotiating circuits. That sweep normally kills the loser
        // first; arbitrating again when the session reports `Established` is
        // the backstop that keeps the invariant — no established circuit to a
        // peer that already has a direct connection — from resting on it.
        let direct = ConnectionId::new(2);
        a.direct_by_conn.insert(direct, b_peer.clone());
        a.direct_by_peer.entry(b_peer).or_default().insert(direct);

        // B's encrypted Yamux confirmation is already queued, so this poll is
        // what carries the circuit into Ready.
        let events = a.poll(Now::from_millis(0)).expect("complete the upgrade");
        assert_pre_ready_bridge_failure(&events, circuit_id);
        assert!(!a.circuits.contains_key(&circuit_id));
    }

    #[test]
    fn adoption_failures_leave_bridge_and_identifier_ownership_with_caller() {
        let local = identity(1);
        let remote = identity(2).peer_id();
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay.clone());
        let mut transport = CircuitTransport::new(inner, local, FailingEntropy);
        let _ = transport
            .poll(Now::from_millis(0))
            .expect("activate wrapped connection");
        let adoption = BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: StreamId::new(7),
            relay,
            remote_peer: remote,
            role: CircuitRole::Initiator,
            pending_data: Vec::new(),
            remote_write_closed: false,
        };
        // Adoption peeks the next id up front but must only consume it after
        // every fallible step, so a failure leaves the id space untouched. A
        // peek/allocate ordering regression would silently burn a sequence
        // number per failed adoption, which only this assertion catches.
        let unconsumed = transport
            .circuit_id_allocator
            .peek()
            .expect("fresh allocator");

        assert!(matches!(
            transport.adopt_bridge(adoption.clone()),
            Err(AdoptError::Entropy(_))
        ));
        assert!(transport.circuit_ids().is_empty());
        assert_eq!(transport.circuit_id_allocator.peek(), Some(unconsumed));

        assert_eq!(
            transport.adopt_bridge(BridgeAdoption {
                remote_write_closed: true,
                ..adoption.clone()
            }),
            Err(AdoptError::RemoteWriteClosed)
        );
        assert!(transport.circuit_ids().is_empty());
        assert_eq!(transport.circuit_id_allocator.peek(), Some(unconsumed));

        transport.circuit_id_allocator = ConnectionIdAllocator::starting_at(
            ConnectionNamespace::CIRCUIT,
            ConnectionId::MAX_SEQUENCE + 1,
        );
        assert_eq!(
            transport.adopt_bridge(BridgeAdoption {
                remote_write_closed: false,
                ..adoption
            }),
            Err(AdoptError::IdsExhausted)
        );
    }

    #[test]
    fn wrapped_high_bit_ids_are_rejected_without_becoming_circuits() {
        let local = identity(1);
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
        let mut transport = CircuitTransport::new(inner, local, CounterEntropy(1));
        let _ = transport
            .poll(Now::from_millis(0))
            .expect("initial direct event");
        // InMemoryTransport::dial is intentionally stubbed, so this fixture
        // covers polled collisions; dial-return collisions need a dial fake.
        let collision = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 77)
            .expect("circuit id in range");
        transport
            .inner_mut()
            .push_event(TransportEvent::IncomingConnection {
                id: collision,
                endpoint: ConnectionEndpoint::new(
                    "/ip4/203.0.113.7/udp/7007/quic-v1"
                        .parse()
                        .expect("collision endpoint"),
                ),
            });
        let events = transport
            .poll(Now::from_millis(0))
            .expect("collision event");
        assert_eq!(
            events,
            vec![TransportEvent::Error {
                id: collision,
                message: "wrapped transport allocated in the circuit connection-ID namespace"
                    .to_string(),
            }]
        );
        assert!(transport.circuit_ids().is_empty());
    }
}
