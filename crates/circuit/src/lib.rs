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
//! Ciphertext reaches the bridge through the wrapped transport's own
//! `send_stream`, so a full bridge is ordinary backpressure (ADR 0012): the
//! circuit keeps the one unsent tail, stops pulling from its session, and
//! resumes on the bridge's `StreamWritable`. Its own stream writes then fill
//! the circuit's Yamux send caps and report [`TransportError::Full`]; nothing
//! tears down.
//!
//! Fresh Noise key material comes from a [`minip2p_core::platform::EntropySource`]
//! the host injects — the same seam every other minip2p transport draws from,
//! so one adapter over a board's RNG serves a circuit transport and a TCP
//! transport at once.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use minip2p_core::platform::StdEntropy;
use minip2p_core::platform::{Deadline, EntropyError, EntropySource, Now};
use minip2p_core::{Bytes, Multiaddr, Protocol, retain_slice};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_secure_mux::{
    NOISE_WIRE_FRAME, SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole,
    YamuxConfig, YamuxError,
};
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, ConnectionIdAllocator,
    ConnectionNamespace, ConnectionState, InvalidLimit, StreamId, Transport, TransportError,
    TransportEvent, UnsettledConnections,
};
use thiserror::Error;

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
    pub pending_data: Bytes,
    /// Relay-protocol bytes the bridge refused as Full before adoption (the
    /// unsent tail of a STOP STATUS, say). They go out ahead of the circuit
    /// handshake, retried on the bridge's Writable like any other tail. At
    /// most one Noise message ([`NOISE_WIRE_FRAME`]) long.
    pub unsent_prefix: Bytes,
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
    /// [`BridgeAdoption::unsent_prefix`] is longer than one Noise message.
    #[error("the unsent prefix is longer than one Noise message")]
    PrefixTooLong,
}

/// Limits for one [`CircuitTransport`]: its circuits' Yamux limits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CircuitLimits {
    /// Limits applied to each circuit's Yamux session. Local opens beyond
    /// `max_streams` wait FIFO in an unbounded local-caller-only queue.
    pub yamux: YamuxConfig,
}

impl CircuitLimits {
    /// Checks the limits can work: the Yamux invariants hold.
    pub fn validate(&self) -> Result<(), InvalidLimit> {
        self.yamux.validate().map_err(|requirement| InvalidLimit {
            field: "CircuitLimits::yamux",
            requirement,
        })
    }
}

/// Why a circuit is being torn down.
struct Teardown(ConnectionCloseReason);

impl Teardown {
    fn fault(message: impl Into<String>) -> Self {
        Self(ConnectionCloseReason::Error(message.into()))
    }
}

impl From<SessionError> for Teardown {
    fn from(error: SessionError) -> Self {
        Self(error.close_reason())
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
    /// Ciphertext the bridge refused as Full, with the length it was counted
    /// at. While set, the session is not pulled; the bridge's
    /// `StreamWritable` retries it.
    bridge_tail: Option<(Bytes, usize)>,
}

impl Circuit {
    fn bridge_key(&self) -> (ConnectionId, StreamId) {
        (self.inner_conn, self.bridge_stream)
    }

    fn endpoint(&self, peer: Option<PeerId>) -> ConnectionEndpoint {
        let address =
            Multiaddr::from_protocols(vec![Protocol::P2p(self.relay), Protocol::P2pCircuit]);
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
    limits: CircuitLimits,
    circuits: BTreeMap<ConnectionId, Circuit>,
    /// Ended circuits whose delivered bytes are not settled yet; each still
    /// holds its circuit slot (ADR 0012).
    unsettled: UnsettledConnections,
    bridge_index: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    retired_bridges: BTreeSet<(ConnectionId, StreamId)>,
    /// Closed circuits whose bridge refused their last ciphertext as Full,
    /// by bridge: each finishes its bridge once it has written the rest.
    closing_bridges: BTreeMap<(ConnectionId, StreamId), Circuit>,
    retired_bridge_order: VecDeque<(ConnectionId, StreamId)>,
    active_inner: BTreeSet<ConnectionId>,
    direct_by_peer: BTreeMap<PeerId, BTreeSet<ConnectionId>>,
    direct_by_conn: BTreeMap<ConnectionId, PeerId>,
    pending: VecDeque<TransportEvent>,
    circuit_id_allocator: ConnectionIdAllocator,
}

impl<T, E> CircuitTransport<T, E> {
    /// Wraps a transport with an explicit entropy source and local identity,
    /// under [`CircuitLimits::default`].
    pub fn new(inner: T, identity: Ed25519Keypair, entropy: E) -> Self {
        Self::from_valid(inner, identity, entropy, CircuitLimits::default())
    }

    /// Wraps a transport under explicit limits, or returns the limit that
    /// cannot work ([`CircuitLimits::validate`]).
    pub fn with_limits(
        inner: T,
        identity: Ed25519Keypair,
        entropy: E,
        limits: CircuitLimits,
    ) -> Result<Self, InvalidLimit> {
        limits.validate()?;
        Ok(Self::from_valid(inner, identity, entropy, limits))
    }

    /// Builds the transport from limits that passed
    /// [`CircuitLimits::validate`].
    fn from_valid(inner: T, identity: Ed25519Keypair, entropy: E, limits: CircuitLimits) -> Self {
        Self {
            inner,
            entropy,
            identity,
            limits,
            circuits: BTreeMap::new(),
            unsettled: UnsettledConnections::new(),
            bridge_index: BTreeMap::new(),
            retired_bridges: BTreeSet::new(),
            closing_bridges: BTreeMap::new(),
            retired_bridge_order: VecDeque::new(),
            active_inner: BTreeSet::new(),
            direct_by_peer: BTreeMap::new(),
            direct_by_conn: BTreeMap::new(),
            pending: VecDeque::new(),
            circuit_id_allocator: ConnectionIdAllocator::new(ConnectionNamespace::CIRCUIT),
        }
    }

    /// The limits this transport runs under.
    pub fn limits(&self) -> &CircuitLimits {
        &self.limits
    }

    /// Returns whether an identifier belongs to a circuit connection.
    pub fn is_circuit(id: ConnectionId) -> bool {
        id.is_circuit()
    }

    /// Returns the active circuit connection identifiers.
    pub fn circuit_ids(&self) -> Vec<ConnectionId> {
        self.circuits.keys().copied().collect()
    }

    /// Returns whether a circuit is still active without collecting its identifiers.
    pub fn contains_circuit(&self, id: ConnectionId) -> bool {
        self.circuits.contains_key(&id)
    }

    /// Circuit slots in use: active circuits, plus ended ones whose delivered
    /// bytes are not yet acknowledged or abandoned (ADR 0012's unsettled
    /// connections). A host admitting new circuits counts these against its
    /// limit.
    pub fn circuit_slots(&self) -> usize {
        self.circuits.len() + self.unsettled.len()
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
        if adoption.unsent_prefix.len() > NOISE_WIRE_FRAME {
            return Err(AdoptError::PrefixTooLong);
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
            expected_peer: Some(adoption.remote_peer),
            yamux: self.limits.yamux.clone(),
        });
        let circuit = Circuit {
            id,
            inner_conn: adoption.inner_conn,
            bridge_stream: adoption.bridge_stream,
            relay: adoption.relay,
            remote_peer: adoption.remote_peer,
            role: adoption.role,
            session,
            bridge_tail: (!adoption.unsent_prefix.is_empty()).then(|| {
                let len = adoption.unsent_prefix.len();
                (Bytes::copy_from_slice(&adoption.unsent_prefix), len)
            }),
        };

        let consumed = self.circuit_id_allocator.allocate();
        debug_assert_eq!(consumed, Ok(id), "peeked id must match the allocated one");

        self.bridge_index.insert(key, id);
        if adoption.role == CircuitRole::Responder {
            self.pending.push_back(TransportEvent::IncomingConnection {
                id,
                endpoint: Box::new(circuit.endpoint(None)),
            });
        }
        self.circuits.insert(id, circuit);

        let start_result = self.with_circuit(id, |this, circuit| {
            circuit.session.start()?;
            this.pump(circuit)
        });
        if let Err(teardown) = start_result {
            self.fail_circuit(id, teardown.0);
            return Ok(id);
        }
        if !adoption.pending_data.is_empty() {
            self.feed_bridge(key, adoption.pending_data);
        }
        Ok(id)
    }

    /// Injects bytes read from a bridge outside the wrapped transport poll.
    ///
    /// The circuit consumes them and acknowledges them on the bridge stream,
    /// as it does for bridge bytes it reads itself: end-to-end credit is the
    /// circuit's own Yamux session's to give.
    pub fn inject_bridge_data(
        &mut self,
        inner_conn: ConnectionId,
        bridge_stream: StreamId,
        data: Bytes,
    ) {
        let len = data.len();
        self.feed_bridge((inner_conn, bridge_stream), data);
        self.ack_bridge(inner_conn, bridge_stream, len);
    }

    /// Acknowledges consumed bridge bytes on the wrapped transport. A bridge
    /// that has since closed or reset has nothing left to settle, which the
    /// wrapped transport treats as a no-op; nothing else can fail here.
    fn ack_bridge(&mut self, inner_conn: ConnectionId, bridge_stream: StreamId, bytes: usize) {
        match self.inner.ack_stream(inner_conn, bridge_stream, bytes) {
            Ok(()) | Err(_) => {}
        }
    }

    /// Feeds bridge bytes to the circuit's session.
    fn feed_bridge(&mut self, key: (ConnectionId, StreamId), data: Bytes) {
        let Some(id) = self.bridge_index.get(&key).copied() else {
            return;
        };
        let result = self.with_circuit(id, |this, circuit| {
            let fed = circuit.session.handle_input(data.into());
            let pumped = this.pump(circuit);
            fed.map_err(Teardown::from).and(pumped)
        });
        if let Err(teardown) = result {
            self.fail_circuit(id, teardown.0);
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
            self.fail_circuit(
                id,
                ConnectionCloseReason::Error("relay bridge remote write side closed".to_string()),
            );
        }
    }

    /// Reports that a bridge stream fully closed or reset.
    pub fn inject_bridge_closed(&mut self, inner_conn: ConnectionId, bridge_stream: StreamId) {
        let key = (inner_conn, bridge_stream);
        self.closing_bridges.remove(&key);
        self.release_retired_bridge(key);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            self.fail_circuit(
                id,
                ConnectionCloseReason::Error("relay bridge closed".to_string()),
            );
        }
    }

    /// Delivers a relay-side STOP_SENDING on a bridge stream.
    ///
    /// A bridge that can no longer carry our bytes cannot carry the circuit
    /// either, so the circuit fails and the bridge is reset.
    pub fn inject_bridge_write_stopped(
        &mut self,
        inner_conn: ConnectionId,
        bridge_stream: StreamId,
    ) {
        let key = (inner_conn, bridge_stream);
        if let Some(circuit) = self.closing_bridges.remove(&key) {
            self.reset_bridge(&circuit);
        }
        if let Some(id) = self.bridge_index.get(&key).copied() {
            self.fail_circuit(
                id,
                ConnectionCloseReason::Error("relay bridge write side stopped".to_string()),
            );
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
        self.closing_bridges.retain(|(conn, _), _| *conn != id);
        self.retired_bridges.retain(|(conn, _)| *conn != id);
        self.retired_bridge_order.retain(|(conn, _)| *conn != id);
    }

    /// Writes session bytes to the bridge while it accepts them, then turns
    /// session events into public transport events.
    fn pump(&mut self, circuit: &mut Circuit) -> Result<(), Teardown> {
        let written = self.write_bridge(circuit);
        while let Some(output) = circuit.session.poll_output() {
            let id = circuit.id;
            let event = match output {
                SessionOutput::Established { peer, .. } => {
                    if self
                        .direct_by_peer
                        .get(&peer)
                        .is_some_and(|connections| !connections.is_empty())
                    {
                        return Err(Teardown(ConnectionCloseReason::Local));
                    }
                    TransportEvent::Connected {
                        id,
                        endpoint: Box::new(circuit.endpoint(Some(peer))),
                    }
                }
                SessionOutput::StreamOpened { stream } => TransportEvent::StreamOpened {
                    id,
                    stream_id: stream,
                },
                SessionOutput::IncomingStream { stream } => TransportEvent::IncomingStream {
                    id,
                    stream_id: stream,
                },
                SessionOutput::StreamData { stream, data } => TransportEvent::StreamData {
                    id,
                    stream_id: stream,
                    data,
                },
                SessionOutput::StreamRemoteWriteClosed { stream } => {
                    TransportEvent::StreamRemoteWriteClosed {
                        id,
                        stream_id: stream,
                    }
                }
                SessionOutput::StreamClosed { stream } => TransportEvent::StreamClosed {
                    id,
                    stream_id: stream,
                },
                SessionOutput::StreamWritable { stream } => TransportEvent::StreamWritable {
                    id,
                    stream_id: stream,
                },
            };
            self.pending.push_back(event);
        }
        written
    }

    /// Sends the held tail, then session bytes, until the bridge is Full.
    ///
    /// The session is pulled only while nothing is held, so the circuit holds
    /// at most one refused message beyond what the bridge accepted.
    fn write_bridge(&mut self, circuit: &mut Circuit) -> Result<(), Teardown> {
        loop {
            let (bytes, counted) = match circuit.bridge_tail.take() {
                Some(tail) => tail,
                None => match circuit.session.poll_write()? {
                    Some(bytes) => {
                        let len = bytes.len();
                        (Bytes::from(bytes), len)
                    }
                    None => return Ok(()),
                },
            };
            match self
                .inner
                .send_stream(circuit.inner_conn, circuit.bridge_stream, bytes)
            {
                Ok(()) => {}
                Err(TransportError::Full { mut unsent, .. }) => {
                    let mut counted = counted;
                    retain_slice(&mut unsent, &mut counted);
                    circuit.bridge_tail = Some((unsent, counted));
                    return Ok(());
                }
                Err(error) => {
                    return Err(Teardown::fault(format!(
                        "relay bridge send failed: {error}"
                    )));
                }
            }
        }
    }

    /// Resumes a circuit whose bridge refused bytes as Full.
    fn bridge_writable(&mut self, id: ConnectionId) {
        let result = self.with_circuit(id, |this, circuit| this.pump(circuit));
        if let Err(teardown) = result {
            self.fail_circuit(id, teardown.0);
        }
    }

    /// Half-closes a closed circuit's bridge once the bridge has taken all
    /// its ciphertext, or holds the circuit until a `StreamWritable` lets
    /// [`write_bridge`](Self::write_bridge) send the rest.
    fn finish_bridge(&mut self, circuit: Circuit) {
        if circuit.bridge_tail.is_some() || circuit.session.has_pending_write() {
            self.closing_bridges.insert(circuit.bridge_key(), circuit);
        } else if self
            .inner
            .close_stream_write(circuit.inner_conn, circuit.bridge_stream)
            .is_err()
        {
            self.reset_bridge(&circuit);
        }
    }

    /// Resumes a closed circuit's bridge that refused bytes as Full.
    fn closing_bridge_writable(&mut self, key: (ConnectionId, StreamId)) {
        let Some(mut circuit) = self.closing_bridges.remove(&key) else {
            return;
        };
        if self.write_bridge(&mut circuit).is_ok() {
            self.finish_bridge(circuit);
        } else {
            self.reset_bridge(&circuit);
        }
    }

    fn reset_bridge(&mut self, circuit: &Circuit) {
        let reset_result = self
            .inner
            .reset_stream(circuit.inner_conn, circuit.bridge_stream);
        match reset_result {
            Ok(()) | Err(_) => {}
        }
    }

    /// Takes a circuit out of the active set for good, keeping its unsettled
    /// streams' counts.
    fn retire_circuit(&mut self, id: ConnectionId) -> Option<Circuit> {
        let circuit = self.circuits.remove(&id)?;
        self.unsettled
            .insert(id, circuit.session.unsettled_streams());
        Some(circuit)
    }

    /// Retires a circuit and resets its bridge, emitting `Closed` with
    /// `reason`.
    fn fail_circuit(&mut self, id: ConnectionId, reason: ConnectionCloseReason) {
        let Some(circuit) = self.retire_circuit(id) else {
            return;
        };
        let key = circuit.bridge_key();
        self.bridge_index.remove(&key);
        self.retire_bridge(key);
        let reset_result = self
            .inner
            .reset_stream(circuit.inner_conn, circuit.bridge_stream);
        match reset_result {
            Ok(()) | Err(_) => {}
        }
        self.pending
            .push_back(TransportEvent::Closed { id, reason });
    }

    fn record_direct(&mut self, id: ConnectionId, peer: PeerId) {
        if let Some(previous) = self.direct_by_conn.insert(id, peer)
            && previous != peer
            && let Some(ids) = self.direct_by_peer.get_mut(&previous)
        {
            ids.remove(&id);
            if ids.is_empty() {
                self.direct_by_peer.remove(&previous);
            }
        }
        self.direct_by_peer.entry(peer).or_default().insert(id);
        let losers: Vec<_> = self
            .circuits
            .iter()
            .filter_map(|(circuit_id, circuit)| {
                (!circuit.is_ready() && circuit.remote_peer == peer).then_some(*circuit_id)
            })
            .collect();
        for circuit_id in losers {
            self.fail_circuit(circuit_id, ConnectionCloseReason::Local);
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
            | TransportEvent::StreamWritable { id, .. }
            | TransportEvent::StreamRemoteWriteClosed { id, .. }
            | TransportEvent::StreamWriteStopped { id, .. }
            | TransportEvent::StreamClosed { id, .. }
            | TransportEvent::Closed { id, .. }
            | TransportEvent::Error { id, .. }
            | TransportEvent::IncomingConnection { id, .. }
            | TransportEvent::PeerIdentityVerified { id, .. } => Some(*id),
            TransportEvent::Listening { .. }
            | TransportEvent::ListenerError { .. }
            | TransportEvent::ListenerRecovered { .. } => None,
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
                } else if self.retired_bridges.contains(&key) {
                    self.ack_bridge(id, stream_id, data.len());
                } else {
                    self.pending.push_back(TransportEvent::StreamData {
                        id,
                        stream_id,
                        data,
                    });
                }
            }
            TransportEvent::StreamWritable { id, stream_id } => {
                let key = (id, stream_id);
                if let Some(circuit) = self.bridge_index.get(&key).copied() {
                    self.bridge_writable(circuit);
                } else if self.closing_bridges.contains_key(&key) {
                    self.closing_bridge_writable(key);
                } else if !self.retired_bridges.contains(&key) {
                    self.pending
                        .push_back(TransportEvent::StreamWritable { id, stream_id });
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
            TransportEvent::StreamWriteStopped {
                id,
                stream_id,
                error_code,
            } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) || self.closing_bridges.contains_key(&key) {
                    self.inject_bridge_write_stopped(id, stream_id);
                } else if !self.retired_bridges.contains(&key) {
                    self.pending.push_back(TransportEvent::StreamWriteStopped {
                        id,
                        stream_id,
                        error_code,
                    });
                }
            }
            TransportEvent::StreamClosed { id, stream_id } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key)
                    || self.retired_bridges.contains(&key)
                    || self.closing_bridges.contains_key(&key)
                {
                    self.inject_bridge_closed(id, stream_id);
                } else {
                    self.pending
                        .push_back(TransportEvent::StreamClosed { id, stream_id });
                }
            }
            TransportEvent::Closed { id, reason } => {
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
                    self.fail_circuit(
                        circuit_id,
                        ConnectionCloseReason::Error(format!("relay connection closed: {reason}")),
                    );
                }
                self.release_retired_bridges_for_connection(id);
                self.pending
                    .push_back(TransportEvent::Closed { id, reason });
            }
            other => self.pending.push_back(other),
        }
    }

    /// Runs one stream operation against a circuit's session and flushes
    /// whatever it queued.
    ///
    /// A failure that kills the session closes the circuit before returning,
    /// with the failure as its close reason, and returns
    /// [`TransportError::ConnectionClosed`] so the caller can tell its
    /// operation ended the circuit.
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

        if let Err(Teardown(reason)) = pumped {
            let message = reason.to_string();
            self.fail_circuit(id, reason);
            return Err(TransportError::ConnectionClosed {
                id,
                reason: message,
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
            Err(SessionError::Yamux(YamuxError::Full { stream, unsent })) => {
                Err(TransportError::Full {
                    id,
                    stream_id: StreamId::new(u64::from(stream)),
                    unsent,
                })
            }
            Err(SessionError::Yamux(YamuxError::AckExceedsDelivered {
                stream,
                acked,
                unacked,
            })) => Err(TransportError::AckExceedsDelivered {
                id,
                stream_id: StreamId::new(u64::from(stream)),
                acked,
                unacked,
            }),
            Err(SessionError::Yamux(error)) => Err(TransportError::PollError {
                reason: error.to_string(),
            }),
            Err(fatal) => {
                let reason = fatal.to_string();
                self.fail_circuit(id, ConnectionCloseReason::Error(reason.clone()));
                Err(TransportError::ConnectionClosed { id, reason })
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
        self.operate_session(id, SecureMuxSession::open_stream)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
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
        let result = self
            .operate_session(id, |session| session.close_stream_write(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamCloseWriteFailed {
                    id,
                    stream_id,
                    reason,
                })
            });
        self.pending
            .retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
        result
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.reset_stream(id, stream_id);
        }
        if self.unsettled.abandon(id, stream_id) {
            return Ok(());
        }
        let result = self
            .operate_session(id, |session| session.reset_stream(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamResetFailed {
                    id,
                    stream_id,
                    reason,
                })
            });
        self.pending
            .retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
        result
    }

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.ack_stream(id, stream_id, bytes);
        }
        if !self.circuits.contains_key(&id) {
            return self.unsettled.ack(id, stream_id, bytes).map(|_held| ());
        }
        self.operate_session(id, |session| session.ack_stream(stream_id, bytes))
    }

    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        if !id.is_circuit() {
            return self.inner.set_control_stream(id, stream_id, control);
        }
        if !self.circuits.contains_key(&id) {
            return;
        }
        let result = self.with_circuit(id, |this, circuit| {
            circuit.session.set_control_stream(stream_id, control)?;
            this.pump(circuit)
        });
        if let Err(teardown) = result {
            self.fail_circuit(id, teardown.0);
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        if !id.is_circuit() {
            return self.inner.close(id);
        }
        let mut circuit = self
            .retire_circuit(id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let key = circuit.bridge_key();
        self.bridge_index.remove(&key);
        self.retire_bridge(key);
        if circuit.session.go_away(0).is_ok() && self.pump(&mut circuit).is_ok() {
            self.finish_bridge(circuit);
        } else {
            self.reset_bridge(&circuit);
        }
        self.pending
            .retain(|event| !matches!(event, TransportEvent::StreamWritable { id: owner, .. } if *owner == id));
        self.pending.push_back(TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        });
        Ok(())
    }

    /// While events are buffered, the call only drains them and leaves the
    /// wrapped transport unread, but an established session with no deadline
    /// yet still gets its first time sample, so keepalive is armed whichever
    /// path completed the upgrade (such as
    /// [`inject_bridge_data`](Self::inject_bridge_data), which has no `now`).
    /// Sessions that already have a deadline advance only in a call that
    /// polls the wrapped transport first, so a keepalive reply it would
    /// deliver in that call is seen before the timer is checked.
    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        let reads_inner = self.pending.is_empty();
        if reads_inner {
            for event in self.inner.poll(now)? {
                self.handle_inner_event(event);
            }
        }
        for id in self.circuits.keys().copied().collect::<Vec<_>>() {
            if !self.circuits.get(&id).is_some_and(|circuit| {
                circuit.session.is_established()
                    && (reads_inner || circuit.session.next_deadline().is_none())
            }) {
                continue;
            }
            let result = self.with_circuit(id, |this, circuit| {
                circuit.session.poll(now)?;
                this.pump(circuit)
            });
            if let Err(teardown) = result {
                self.fail_circuit(id, teardown.0);
            }
        }
        Ok(self.drain_pending_events())
    }

    /// A circuit's ciphertext the bridge refused, or its session still
    /// holding output, a closed circuit's bridge not yet finished, or the
    /// inner transport's own pending writes (which carry the circuits'
    /// bridges and their FINs too).
    fn has_pending_writes(&self) -> bool {
        self.inner.has_pending_writes()
            || !self.closing_bridges.is_empty()
            || self
                .circuits
                .values()
                .any(|circuit| circuit.bridge_tail.is_some() || circuit.session.has_unsent_writes())
    }

    /// The earliest of the wrapped transport's deadline and the circuits'
    /// session keepalives, or immediate while events are buffered.
    ///
    /// Every established session has had a time sample by then (see
    /// [`poll`](Self::poll)), so this reports only real deadlines.
    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() {
            return Some(Deadline::IMMEDIATE);
        }
        let mut deadline = self.inner.next_deadline();
        for circuit in self.circuits.values() {
            deadline = Deadline::earliest_opt(deadline, circuit.session.next_deadline());
        }
        deadline
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_addresses()
    }

    fn local_addresses_revision(&self) -> Option<u64> {
        self.inner.local_addresses_revision()
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

/// Forwards to the wrapped transport, which owns the sockets. A circuit's own
/// buffered events need no readiness: `next_deadline` reports them as due now.
#[cfg(feature = "std")]
impl<T: minip2p_transport::PollSource, E: EntropySource> minip2p_transport::PollSource
    for CircuitTransport<T, E>
{
    fn attach(
        &mut self,
        registry: minip2p_transport::mio::Registry,
        tokens: minip2p_transport::TokenSpace,
        waker: alloc::sync::Arc<minip2p_transport::mio::Waker>,
    ) -> std::io::Result<()> {
        self.inner.attach(registry, tokens, waker)
    }

    fn dispatch(&mut self, event: &minip2p_transport::mio::event::Event) {
        self.inner.dispatch(event);
    }
}

/// Wraps a session failure as the stream error the transport contract expects.
///
/// Identifier and state errors pass through: they describe the request rather
/// than the stream operation, and callers match on them. So does
/// ConnectionClosed, which tells the swarm the failure already ended the
/// connection and is reported by its `Closed` alone.
fn stream_error(
    error: TransportError,
    wrap: impl FnOnce(String) -> TransportError,
) -> TransportError {
    match error {
        error @ (TransportError::ConnectionNotFound { .. }
        | TransportError::ConnectionClosed { .. }
        | TransportError::StreamNotFound { .. }
        | TransportError::InvalidState { .. }
        | TransportError::Full { .. }) => error,
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
mod tests;
