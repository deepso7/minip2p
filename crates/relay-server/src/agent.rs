use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Bytes, Multiaddr, PeerId, Protocol, SansIoProtocol};
use minip2p_platform::Now;
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopRequest, HopResponder, HopResponderInput, HopResponderOutput, Limit,
    MAX_PENDING_BRIDGE_SIZE, Reservation, STOP_PROTOCOL_ID, Status, StopInitiator,
    StopInitiatorInput, StopInitiatorOutcome, StopInitiatorOutput, encode_hop_status,
};
use minip2p_swarm::{SwarmCore, SwarmError, SwarmEvent};
use minip2p_transport::{ConnectionId, Transport};

use crate::address::normalize_addrs;
use crate::limiter::TokenBuckets;
use crate::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit,
    RelayServerAction, RelayServerAddressError, RelayServerConfig, RelayServerConfigError,
    RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind, RelayServerSendError,
    RelayServerToken, ReservationCloseReason, StreamKey,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpKey {
    V4([u8; 4]),
    V6([u8; 16]),
}

struct AdmissionLimiters {
    peer: Option<TokenBuckets<PeerId>>,
    ip: Option<TokenBuckets<IpKey>>,
}

impl AdmissionLimiters {
    fn new(peer: Option<RateLimit>, ip: Option<RateLimit>) -> Self {
        Self {
            peer: peer.map(TokenBuckets::new),
            ip: ip.map(TokenBuckets::new),
        }
    }

    fn consume(&mut self, peer_id: &PeerId, ip: Option<IpKey>, now_ms: u64) -> bool {
        if self
            .peer
            .as_mut()
            .is_some_and(|limiter| !limiter.consume(peer_id.clone(), now_ms))
        {
            return false;
        }
        if let (Some(limiter), Some(ip)) = (&mut self.ip, ip) {
            return limiter.consume(ip, now_ms);
        }
        true
    }

    fn sweep(&mut self, now_ms: u64) {
        if let Some(limiter) = &mut self.peer {
            limiter.sweep(now_ms);
        }
        if let Some(limiter) = &mut self.ip {
            limiter.sweep(now_ms);
        }
    }

    fn next_due(&self) -> Option<u64> {
        [
            self.peer.as_ref().and_then(TokenBuckets::next_due),
            self.ip.as_ref().and_then(TokenBuckets::next_due),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

struct Connection {
    peer_id: PeerId,
    address: Option<Multiaddr>,
    is_circuit: bool,
}

struct ReservationRecord {
    conn_id: ConnectionId,
    deadline_ms: u64,
}

struct PendingReservation {
    stream: StreamKey,
    peer_id: PeerId,
    conn_id: ConnectionId,
    renewed: bool,
    deadline_ms: u64,
    expires_unix_secs: Option<u64>,
}

enum SendEffect {
    CompleteHop(StreamKey),
    CommitReservation(PendingReservation),
    CommitCircuit(StreamKey),
    StopRequest(StreamKey),
    Forward {
        source_stream: StreamKey,
        direction: CircuitDirection,
        /// Length of the chunk sent, so a Full's unsent tail tells how much
        /// was accepted.
        chunk_len: usize,
    },
}

enum PendingOperation {
    OpenStop {
        source_stream: StreamKey,
        peer_id: PeerId,
        expected_conn_id: ConnectionId,
    },
    Send {
        peer_id: PeerId,
        effect: SendEffect,
    },
    Close {
        peer_id: PeerId,
        stream: StreamKey,
        circuit: Option<(StreamKey, CircuitLeg)>,
    },
    Reset {
        peer_id: PeerId,
    },
}

struct HopWorker {
    peer_id: PeerId,
    responder: HopResponder,
    deadline_ms: Option<u64>,
    request_known: bool,
    is_circuit: bool,
}

struct PendingCircuit {
    source_peer_id: PeerId,
    destination_peer_id: PeerId,
    destination_conn_id: ConnectionId,
    stop_stream: Option<StreamKey>,
    stop: Option<StopInitiator>,
    stop_deadline_ms: Option<u64>,
    source_pipelined: Vec<u8>,
    destination_pipelined: Vec<u8>,
    source_eof: bool,
    destination_eof: bool,
}

struct Circuit {
    source_peer_id: PeerId,
    destination_peer_id: PeerId,
    source_stream: StreamKey,
    destination_stream: StreamKey,
    deadline_ms: Option<u64>,
    bytes: CircuitByteCounts,
    to_destination: Forward,
    to_source: Forward,
}

impl Circuit {
    fn forward(&mut self, direction: CircuitDirection) -> &mut Forward {
        match direction {
            CircuitDirection::SourceToDestination => &mut self.to_destination,
            CircuitDirection::DestinationToSource => &mut self.to_source,
        }
    }

    /// The leg a direction reads from.
    fn origin(&self, direction: CircuitDirection) -> StreamKey {
        match direction {
            CircuitDirection::SourceToDestination => self.source_stream,
            CircuitDirection::DestinationToSource => self.destination_stream,
        }
    }

    /// The leg a direction writes to, with its peer and role.
    fn target(&self, direction: CircuitDirection) -> (PeerId, StreamKey, CircuitLeg) {
        match direction {
            CircuitDirection::SourceToDestination => (
                self.destination_peer_id.clone(),
                self.destination_stream,
                CircuitLeg::Destination,
            ),
            CircuitDirection::DestinationToSource => (
                self.source_peer_id.clone(),
                self.source_stream,
                CircuitLeg::Source,
            ),
        }
    }
}

/// One direction of a circuit: bytes read from the origin leg, in order,
/// until the target leg accepts them (ADR 0012).
///
/// Queued bytes stay unacknowledged until the target accepts them, so the
/// queue is bounded by the receive budget the origin was granted, and a full
/// target pauses the origin through withheld credit.
#[derive(Default)]
struct Forward {
    queue: VecDeque<Bytes>,
    /// Small reads copied together behind `queue`, so a peer sending tiny
    /// frames costs memory in proportion to its bytes, not its reads.
    small: Vec<u8>,
    /// Length of the payload the head was cut from, while the head is the
    /// unsent tail of a Full; zero while the head is a whole payload.
    head_counted: usize,
    send: SendState,
    fin: FinState,
}

/// Whether a direction may send its queue's head now.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum SendState {
    /// Nothing is outstanding.
    #[default]
    Idle,
    /// A send of the head awaits its result.
    Sending,
    /// The target answered Full; the head waits for its Writable.
    Blocked,
}

/// How far a direction's half-close has travelled.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum FinState {
    /// The origin has not half-closed.
    #[default]
    Open,
    /// The origin half-closed; the target's FIN follows the last byte.
    Received,
    /// The target's FIN has been requested.
    Requested,
    /// The target accepted its FIN.
    Accepted,
}

/// Reads shorter than this are coalesced into one queue entry of at least
/// this many bytes.
const COALESCE_BELOW: usize = 4096;

impl Forward {
    /// Queued bytes the origin is still owed acknowledgement for.
    fn unacked(&self) -> usize {
        self.queue.iter().map(Bytes::len).sum::<usize>() + self.small.len()
    }

    /// Appends a read behind everything already queued.
    fn push(&mut self, data: Bytes) {
        if data.len() < COALESCE_BELOW {
            self.small.extend_from_slice(&data);
            if self.small.len() >= COALESCE_BELOW {
                self.flush_small();
            }
        } else {
            self.flush_small();
            self.queue.push_back(data);
        }
    }

    /// Moves the coalesced small reads into the queue as one entry.
    fn flush_small(&mut self) {
        if !self.small.is_empty() {
            self.queue.push_back(Bytes::copy_from_slice(&self.small));
            self.small.clear();
        }
    }

    /// The next payload to send, if any.
    fn head(&mut self) -> Option<Bytes> {
        if self.queue.is_empty() {
            self.flush_small();
        }
        self.queue.front().cloned()
    }

    /// Records that the target accepted the head up to an `unsent` tail.
    fn accept(&mut self, unsent: Option<Bytes>) {
        self.send = SendState::Idle;
        let head = self.queue.pop_front().unwrap_or_default();
        let counted = if self.head_counted == 0 {
            head.len()
        } else {
            self.head_counted
        };
        self.head_counted = 0;
        if let Some(mut unsent) = unsent.filter(|unsent| !unsent.is_empty()) {
            // A tail shorter than half its original payload is copied, so
            // what it pins stays within twice the bytes it holds (ADR 0012).
            if unsent.len() < counted / 2 {
                unsent = Bytes::copy_from_slice(&unsent);
            } else if unsent.len() < counted {
                self.head_counted = counted;
            }
            self.queue.push_front(unsent);
            self.send = SendState::Blocked;
        }
    }
}

/// Whole-service deterministic relay policy and forwarding state.
pub struct RelayServerAgent {
    local_peer_id: PeerId,
    config: RelayServerConfig,
    accepting: bool,
    explicit_addrs: Option<Vec<Multiaddr>>,
    confirmed_addrs: Vec<Multiaddr>,
    listener_addrs: Vec<Multiaddr>,
    connections: BTreeMap<ConnectionId, Connection>,
    reservations: BTreeMap<PeerId, ReservationRecord>,
    hop_workers: BTreeMap<StreamKey, HopWorker>,
    rejected_hop_streams: BTreeMap<StreamKey, PeerId>,
    pending_circuits: BTreeMap<StreamKey, PendingCircuit>,
    stop_to_source: BTreeMap<StreamKey, StreamKey>,
    circuits: BTreeMap<StreamKey, Circuit>,
    actions: VecDeque<RelayServerAction>,
    events: VecDeque<RelayServerEvent>,
    pending_operations: BTreeMap<RelayServerToken, PendingOperation>,
    next_token: u64,
    last_event_tick_ms: Option<u64>,
    reservation_limiters: AdmissionLimiters,
    circuit_limiters: AdmissionLimiters,
}

impl RelayServerAgent {
    /// Installs the relay service's static directional Swarm roles.
    ///
    /// HOP is inbound and Identify-advertised; STOP is outbound only.
    pub fn register_swarm_roles<T, E>(swarm: &mut SwarmCore<T, E>) -> Result<(), SwarmError>
    where
        T: Transport,
        E: minip2p_platform::EntropySource,
    {
        swarm.add_inbound_protocol(HOP_PROTOCOL_ID)?;
        swarm.add_advertised_protocol(HOP_PROTOCOL_ID)?;
        swarm.add_outbound_protocol(STOP_PROTOCOL_ID)?;
        Ok(())
    }

    /// Creates an empty service after validating the full configuration.
    pub fn new(
        local_peer_id: PeerId,
        config: RelayServerConfig,
    ) -> Result<Self, RelayServerConfigError> {
        config.validate()?;
        Ok(Self {
            local_peer_id,
            reservation_limiters: AdmissionLimiters::new(
                config.reservation_rate_limit_per_peer,
                config.reservation_rate_limit_per_ip,
            ),
            circuit_limiters: AdmissionLimiters::new(
                config.circuit_rate_limit_per_peer,
                config.circuit_rate_limit_per_ip,
            ),
            config,
            accepting: true,
            explicit_addrs: None,
            confirmed_addrs: Vec::new(),
            listener_addrs: Vec::new(),
            connections: BTreeMap::new(),
            reservations: BTreeMap::new(),
            hop_workers: BTreeMap::new(),
            rejected_hop_streams: BTreeMap::new(),
            pending_circuits: BTreeMap::new(),
            stop_to_source: BTreeMap::new(),
            circuits: BTreeMap::new(),
            actions: VecDeque::new(),
            events: VecDeque::new(),
            pending_operations: BTreeMap::new(),
            next_token: 1,
            last_event_tick_ms: None,
        })
    }

    /// Pauses or resumes admission without terminating committed state.
    pub fn set_accepting(&mut self, accepting: bool) {
        self.accepting = accepting;
    }

    /// Atomically replaces the explicit announce source; empty clears it.
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected announce address for actionable host diagnostics."
    )]
    pub fn replace_announce_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerAddressError> {
        let normalized = normalize_addrs(&self.local_peer_id, addrs)?;
        self.explicit_addrs = (!normalized.is_empty()).then_some(normalized);
        Ok(())
    }

    /// Replaces the AutoNAT-confirmed direct-address source atomically.
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected confirmed address for actionable host diagnostics."
    )]
    pub fn set_confirmed_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerAddressError> {
        self.confirmed_addrs = normalize_addrs(&self.local_peer_id, addrs)?;
        Ok(())
    }

    /// Replaces the concrete bound-listener source atomically.
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected listener address for actionable host diagnostics."
    )]
    pub fn set_listener_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerAddressError> {
        self.listener_addrs = normalize_addrs(&self.local_peer_id, addrs)?;
        Ok(())
    }

    /// Returns the first non-empty normalized address source.
    pub fn selected_addrs(&self) -> &[Multiaddr] {
        if let Some(addrs) = &self.explicit_addrs {
            addrs
        } else if !self.confirmed_addrs.is_empty() {
            &self.confirmed_addrs
        } else {
            &self.listener_addrs
        }
    }

    /// Records the exact remote address supplied by the host's transport.
    pub fn set_connection_addr(&mut self, conn_id: ConnectionId, address: Multiaddr) {
        if let Some(connection) = self.connections.get_mut(&conn_id) {
            connection.address = Some(address);
        }
    }

    /// Feeds one Swarm event and returns whether the service claimed it.
    ///
    /// `is_circuit` says whether the event's connection is a relay circuit;
    /// for [`SwarmEvent::ConnectionReplaced`] it describes `new`.
    ///
    /// The first event for a `Now` sample processes due deadlines. Subsequent
    /// events with that same sample share the completed sweep; call
    /// [`handle_tick`](Self::handle_tick) to force a sweep independently.
    pub fn handle_event(&mut self, event: &SwarmEvent, is_circuit: bool, now: Now) -> bool {
        self.tick_before_event(now);
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                self.on_connection_established(peer_id.clone(), *conn_id, is_circuit);
                false
            }
            SwarmEvent::ConnectionClosed { peer_id, conn_id } => {
                self.on_connection_closed(peer_id, *conn_id);
                false
            }
            SwarmEvent::ConnectionReplaced { peer_id, old, new } => {
                self.on_connection_replaced(peer_id, *old, *new, is_circuit);
                false
            }
            SwarmEvent::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                protocol_id,
                initiated_locally,
            } if protocol_id == HOP_PROTOCOL_ID && !initiated_locally => {
                self.on_hop_ready(
                    peer_id.clone(),
                    StreamKey {
                        conn_id: *conn_id,
                        stream_id: *stream_id,
                    },
                    is_circuit,
                    now,
                );
                true
            }
            SwarmEvent::StreamData {
                peer_id: _,
                conn_id,
                stream_id,
                data,
            } => {
                let key = StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                };
                // Control messages are consumed as they are read. Circuit
                // payload, including payload pipelined before the circuit
                // commits, is acknowledged only once the other leg accepts
                // it. A committed source leg keeps its HOP worker, so the
                // circuit is checked first.
                if self.circuits.contains_key(&key) {
                    self.queue_forward(key, CircuitDirection::SourceToDestination, data.clone());
                    true
                } else if self.pending_circuits.contains_key(&key) {
                    self.append_pending_payload(key, CircuitDirection::SourceToDestination, data);
                    true
                } else if self.hop_workers.contains_key(&key) {
                    // Payload coalesced with CONNECT stays in the responder
                    // until the decision, unacknowledged.
                    let held = self.hop_bridge_len(key);
                    if self.feed_hop(key, HopResponderInput::Data(data.to_vec())) {
                        self.drain_hop(key, now);
                    }
                    let payload = self.hop_bridge_len(key).saturating_sub(held);
                    self.queue_ack(key, data.len().saturating_sub(payload));
                    true
                } else if self.rejected_hop_streams.contains_key(&key) {
                    self.queue_ack(key, data.len());
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied() {
                    if self.circuits.contains_key(&source_stream) {
                        self.queue_forward(
                            source_stream,
                            CircuitDirection::DestinationToSource,
                            data.clone(),
                        );
                    } else {
                        let bridged = if self
                            .feed_stop(source_stream, StopInitiatorInput::Data(data.to_vec()))
                        {
                            self.drain_stop(source_stream, now)
                        } else {
                            0
                        };
                        self.queue_ack(key, data.len().saturating_sub(bridged));
                    }
                    true
                } else {
                    false
                }
            }
            SwarmEvent::StreamRemoteWriteClosed {
                conn_id, stream_id, ..
            } => {
                let key = StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                };
                if self.circuits.contains_key(&key) {
                    self.circuit_eof(key, CircuitLeg::Source);
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.circuits.contains_key(&source_stream)
                {
                    self.circuit_eof(source_stream, CircuitLeg::Destination);
                    true
                } else if self.hop_workers.contains_key(&key) {
                    if let Some(circuit) = self.pending_circuits.get_mut(&key) {
                        circuit.source_eof = true;
                    }
                    if self.feed_hop(key, HopResponderInput::RemoteWriteClosed) {
                        self.drain_hop(key, now);
                    }
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.feed_stop(source_stream, StopInitiatorInput::RemoteWriteClosed)
                {
                    if let Some(circuit) = self.pending_circuits.get_mut(&source_stream) {
                        circuit.destination_eof = true;
                    }
                    self.drain_stop(source_stream, now);
                    true
                } else if self.pending_circuits.contains_key(&key) {
                    self.abort_pending_connect(key);
                    self.hop_workers.remove(&key);
                    true
                } else {
                    self.rejected_hop_streams.contains_key(&key)
                }
            }
            // Resumes a circuit direction paused on this leg. Other relay
            // streams never hold a tail (a Full control send fails), but
            // their wakeups are still claimed so they never reach the
            // application.
            SwarmEvent::StreamWritable {
                conn_id, stream_id, ..
            } => {
                let key = StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                };
                if self.circuits.contains_key(&key) {
                    self.resume_forward(key, CircuitDirection::DestinationToSource);
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied() {
                    self.resume_forward(source_stream, CircuitDirection::SourceToDestination);
                }
                self.claims_stream(key)
            }
            SwarmEvent::StreamWriteStopped {
                peer_id,
                conn_id,
                stream_id,
                ..
            } => self.on_stream_write_stopped(
                peer_id,
                StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                },
            ),
            SwarmEvent::StreamClosed {
                conn_id, stream_id, ..
            } => {
                let key = StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                };
                if self.circuits.contains_key(&key) {
                    self.circuit_leg_closed(key, CircuitLeg::Source);
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.circuits.contains_key(&source_stream)
                {
                    self.circuit_leg_closed(source_stream, CircuitLeg::Destination);
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.feed_stop(source_stream, StopInitiatorInput::RemoteReset)
                {
                    self.drain_stop(source_stream, now);
                    true
                } else if self.pending_circuits.contains_key(&key) {
                    self.abort_pending_connect(key);
                    self.hop_workers.remove(&key);
                    true
                } else {
                    let owned = self.hop_workers.contains_key(&key);
                    if owned {
                        self.cancel_pending_hop_ops(key);
                        self.hop_workers.remove(&key);
                    }
                    owned || self.rejected_hop_streams.remove(&key).is_some()
                }
            }
            _ => false,
        }
    }

    /// Processes every deadline due at or before `now`.
    pub fn handle_tick(&mut self, now: Now) {
        self.last_event_tick_ms = Some(now.monotonic_ms);
        let duration_limited: Vec<_> = self
            .circuits
            .iter()
            .filter_map(|(key, circuit)| {
                circuit
                    .deadline_ms
                    .is_some_and(|deadline| deadline <= now.monotonic_ms)
                    .then_some(*key)
            })
            .collect();
        for key in duration_limited {
            self.close_circuit(key, CircuitCloseReason::DurationLimit);
        }
        let timed_out: Vec<_> = self
            .hop_workers
            .iter()
            .filter_map(|(key, worker)| {
                worker
                    .deadline_ms
                    .is_some_and(|deadline| deadline <= now.monotonic_ms)
                    .then_some(*key)
            })
            .collect();
        for key in timed_out {
            if self.pending_circuits.contains_key(&key) {
                if let Some(worker) = self.hop_workers.get_mut(&key) {
                    worker.deadline_ms = None;
                }
                self.fail_pending_connect(key, Status::ConnectionFailed);
                continue;
            }
            if let Some(worker) = self.hop_workers.remove(&key) {
                self.cancel_pending_hop_ops(key);
                self.abort_pending_connect(key);
                self.queue_reset(worker.peer_id.clone(), key);
                if worker.request_known {
                    self.runtime_error(
                        RelayServerRuntimeErrorKind::ResetStream,
                        Some(worker.peer_id),
                        "inbound HOP control stream timed out".into(),
                    );
                }
            }
        }
        let stop_timed_out: Vec<_> = self
            .pending_circuits
            .iter()
            .filter_map(|(key, circuit)| {
                circuit
                    .stop_deadline_ms
                    .is_some_and(|deadline| deadline <= now.monotonic_ms)
                    .then_some(*key)
            })
            .collect();
        for key in stop_timed_out {
            self.fail_pending_connect(key, Status::ConnectionFailed);
        }
        // After the timeouts above: one may have cancelled a pending renewal,
        // and its reservation must not outlive this sweep.
        let renewing = self.renewing_peers();
        let expired: Vec<_> = self
            .reservations
            .iter()
            .filter_map(|(peer, reservation)| {
                (reservation.deadline_ms <= now.monotonic_ms && !renewing.contains(peer))
                    .then_some(peer.clone())
            })
            .collect();
        for peer_id in expired {
            self.reservations.remove(&peer_id);
            self.events.push_back(RelayServerEvent::ReservationClosed {
                peer_id,
                reason: ReservationCloseReason::Expired,
            });
        }
        self.reservation_limiters.sweep(now.monotonic_ms);
        self.circuit_limiters.sweep(now.monotonic_ms);
    }

    /// Resets a relay stream the peer stopped; returns whether we own it.
    ///
    /// Every relay stream needs to write, so a stopped one is reset; the
    /// `StreamClosed` that follows runs the usual teardown. Kept out of line
    /// and cold: inlined, its lookups slowed every `handle_event` call.
    #[cold]
    #[inline(never)]
    fn on_stream_write_stopped(&mut self, peer_id: &PeerId, key: StreamKey) -> bool {
        let owned = self.claims_stream(key);
        if owned {
            self.queue_reset(peer_id.clone(), key);
        }
        owned
    }

    /// Whether the relay claims `key` in any role, including a circuit still
    /// connecting. Cold and out of line for the same reason as
    /// [`Self::on_stream_write_stopped`]: inlined into `handle_event`, these
    /// lookups slowed every event.
    #[cold]
    #[inline(never)]
    fn claims_stream(&self, key: StreamKey) -> bool {
        self.circuits.contains_key(&key)
            || self.stop_to_source.contains_key(&key)
            || self.hop_workers.contains_key(&key)
            || self.pending_circuits.contains_key(&key)
            || self.rejected_hop_streams.contains_key(&key)
    }

    /// Sweeps deadlines before the first event in a driver batch.
    ///
    /// A single caller time sample is commonly shared by several events. New
    /// deadlines created while handling those events are in the future unless
    /// the clock has saturated, so rescanning unchanged state cannot make
    /// additional progress.
    fn tick_before_event(&mut self, now: Now) {
        if now.monotonic_ms == u64::MAX || self.last_event_tick_ms != Some(now.monotonic_ms) {
            self.handle_tick(now);
        }
    }

    /// Reports the result of an outbound stream open.
    pub fn stream_open_result(
        &mut self,
        token: RelayServerToken,
        result: Result<StreamKey, String>,
        _now: Now,
    ) {
        let Some(PendingOperation::OpenStop {
            source_stream,
            peer_id,
            expected_conn_id,
        }) = self.pending_operations.remove(&token)
        else {
            if let Ok(stream) = result
                && let Some(connection) = self.connections.get(&stream.conn_id)
            {
                self.queue_reset(connection.peer_id.clone(), stream);
            }
            return;
        };
        match result {
            Ok(stream) if stream.conn_id == expected_conn_id => {
                if let Some(circuit) = self.pending_circuits.get_mut(&source_stream) {
                    circuit.stop_stream = Some(stream);
                    let mut stop = StopInitiator::new(
                        circuit.source_peer_id.clone(),
                        Some(Limit {
                            duration: Some(self.config.max_circuit_duration_secs as u32),
                            data: Some(self.config.max_circuit_bytes),
                        }),
                    );
                    let outbound = stop.poll_output();
                    circuit.stop = Some(stop);
                    self.stop_to_source.insert(stream, source_stream);
                    if let Some(StopInitiatorOutput::Outbound(data)) = outbound {
                        self.queue_send(
                            peer_id,
                            stream,
                            data,
                            SendEffect::StopRequest(source_stream),
                        );
                    }
                } else {
                    self.queue_reset(peer_id, stream);
                }
            }
            Ok(stream) => {
                let reset_peer = self
                    .connections
                    .get(&stream.conn_id)
                    .map(|connection| connection.peer_id.clone())
                    .unwrap_or(peer_id);
                self.queue_reset(reset_peer, stream);
                self.fail_pending_connect(source_stream, Status::NoReservation);
            }
            Err(detail) => {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::OpenStream,
                    Some(peer_id),
                    detail,
                );
                self.fail_pending_connect(source_stream, Status::ConnectionFailed);
            }
        }
    }

    /// Reports how much of a queued send entered the transport's outbound
    /// queue.
    ///
    /// A forwarding chunk that comes back [`RelayServerSendError::Full`] is
    /// not a failure: the relay holds its unsent tail and resends it on the
    /// stream's [`SwarmEvent::StreamWritable`]. A Full control message fails
    /// like any other rejected send.
    pub fn send_stream_result(
        &mut self,
        token: RelayServerToken,
        result: Result<(), RelayServerSendError>,
        now: Now,
    ) {
        let Some(PendingOperation::Send { peer_id, effect }) =
            self.pending_operations.remove(&token)
        else {
            return;
        };
        if let (
            Err(RelayServerSendError::Full { unsent }),
            SendEffect::Forward {
                source_stream,
                direction,
                chunk_len,
            },
        ) = (&result, &effect)
            && unsent.len() <= *chunk_len
        {
            let accepted = chunk_len - unsent.len();
            self.forward_accepted(*source_stream, *direction, accepted, Some(unsent.clone()));
            return;
        }
        let result = result.map_err(|error| match error {
            RelayServerSendError::Full { unsent } => format!(
                "{} of the message's bytes did not fit the stream's send queue",
                unsent.len()
            ),
            RelayServerSendError::Failed(detail) => detail,
        });
        match result {
            Ok(()) => match effect {
                SendEffect::CommitReservation(pending) => {
                    // A renewal's reservation cannot have lapsed meanwhile:
                    // `handle_tick` keeps it alive while the renewal is pending.
                    if self
                        .connections
                        .get(&pending.conn_id)
                        .is_some_and(|connection| connection.peer_id == pending.peer_id)
                    {
                        self.reservations.insert(
                            pending.peer_id.clone(),
                            ReservationRecord {
                                conn_id: pending.conn_id,
                                deadline_ms: pending.deadline_ms,
                            },
                        );
                        self.events
                            .push_back(RelayServerEvent::ReservationAccepted {
                                peer_id: pending.peer_id,
                                renewed: pending.renewed,
                                expires_unix_secs: pending.expires_unix_secs,
                            });
                    }
                    self.complete_hop(pending.stream);
                }
                SendEffect::CommitCircuit(source_stream) => {
                    self.complete_hop(source_stream);
                    self.commit_circuit(source_stream, now);
                }
                SendEffect::StopRequest(_) => {}
                SendEffect::Forward {
                    source_stream,
                    direction,
                    chunk_len,
                } => self.forward_accepted(source_stream, direction, chunk_len, None),
                SendEffect::CompleteHop(stream) => self.complete_hop(stream),
            },
            Err(detail) => {
                let relevant = match effect {
                    SendEffect::Forward {
                        source_stream,
                        direction,
                        ..
                    } if self.circuits.contains_key(&source_stream) => {
                        self.close_circuit(
                            source_stream,
                            CircuitCloseReason::ForwardFailed { direction },
                        );
                        true
                    }
                    SendEffect::CommitCircuit(source_stream)
                        if self.pending_circuits.contains_key(&source_stream) =>
                    {
                        self.abort_pending_connect_both(source_stream);
                        true
                    }
                    SendEffect::StopRequest(source_stream)
                        if self.pending_circuits.contains_key(&source_stream) =>
                    {
                        self.fail_pending_connect(source_stream, Status::ConnectionFailed);
                        true
                    }
                    SendEffect::CommitReservation(pending) => {
                        self.complete_hop(pending.stream);
                        true
                    }
                    SendEffect::CompleteHop(stream) => {
                        self.complete_hop(stream);
                        true
                    }
                    _ => false,
                };
                if !relevant {
                    return;
                }
                self.runtime_error(
                    RelayServerRuntimeErrorKind::SendStream,
                    Some(peer_id),
                    detail,
                );
            }
        }
    }

    /// Reports completion of a write-side close request.
    pub fn close_stream_write_result(
        &mut self,
        token: RelayServerToken,
        result: Result<(), String>,
        _now: Now,
    ) {
        let Some(PendingOperation::Close {
            peer_id, circuit, ..
        }) = self.pending_operations.remove(&token)
        else {
            return;
        };
        match result {
            Ok(()) => {
                if let Some((source_stream, leg)) = circuit {
                    self.circuit_close_accepted(source_stream, leg);
                }
            }
            Err(detail) => {
                if let Some((source_stream, _)) = circuit {
                    if !self.circuits.contains_key(&source_stream) {
                        return;
                    }
                    self.close_circuit(source_stream, CircuitCloseReason::InternalFailure);
                }
                self.runtime_error(
                    RelayServerRuntimeErrorKind::CloseStream,
                    Some(peer_id),
                    detail,
                );
            }
        }
    }

    /// Reports completion of a reset request.
    pub fn reset_stream_result(
        &mut self,
        token: RelayServerToken,
        result: Result<(), String>,
        _now: Now,
    ) {
        let peer_id = match self.pending_operations.remove(&token) {
            Some(PendingOperation::Reset { peer_id }) => peer_id,
            _ => return,
        };
        if let Err(detail) = result {
            self.runtime_error(
                RelayServerRuntimeErrorKind::ResetStream,
                Some(peer_id),
                detail,
            );
        }
    }

    /// Removes the next host I/O action in causal order.
    pub fn poll_action(&mut self) -> Option<RelayServerAction> {
        self.actions.pop_front()
    }

    /// Removes the next application-visible event in causal order.
    pub fn poll_event(&mut self) -> Option<RelayServerEvent> {
        self.events.pop_front()
    }

    /// Returns milliseconds until the earliest timer, with zero meaning due.
    pub fn next_timeout(&self, now: Now) -> Option<u64> {
        let renewing = self.renewing_peers();
        let reservation = self
            .reservations
            .iter()
            .filter(|(peer, _)| !renewing.contains(peer))
            .map(|(_, value)| value.deadline_ms)
            .min();
        let hop = self
            .hop_workers
            .values()
            .filter_map(|value| value.deadline_ms)
            .min();
        let stop = self
            .pending_circuits
            .values()
            .filter_map(|value| value.stop_deadline_ms)
            .min();
        let circuit = self
            .circuits
            .values()
            .filter_map(|value| value.deadline_ms)
            .min();
        let limiter = [
            self.reservation_limiters.next_due(),
            self.circuit_limiters.next_due(),
        ]
        .into_iter()
        .flatten()
        .min();
        [reservation, hop, stop, circuit, limiter]
            .into_iter()
            .flatten()
            .min()
            .map(|due| due.saturating_sub(now.monotonic_ms))
    }

    /// Whether the stream is owned by a HOP worker, STOP worker, or circuit.
    pub fn owns_stream(&self, stream: StreamKey) -> bool {
        self.hop_workers.contains_key(&stream)
            || self.rejected_hop_streams.contains_key(&stream)
            || self.stop_to_source.contains_key(&stream)
            || self.circuits.contains_key(&stream)
    }

    /// Whether `peer_id` has a committed live reservation.
    #[cfg(test)]
    fn has_reservation(&self, peer_id: &PeerId) -> bool {
        self.reservations.contains_key(peer_id)
    }

    /// Returns the exact connection owning a committed reservation.
    #[cfg(test)]
    fn reservation_connection(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.reservations.get(peer_id).map(|record| record.conn_id)
    }

    /// Returns the number of committed reservations.
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Returns pending plus committed circuit slots.
    pub fn circuit_count(&self) -> usize {
        self.pending_circuits
            .len()
            .saturating_add(self.circuits.len())
    }

    /// Whether no action, event, or echoed result remains to be drained.
    pub fn is_idle(&self) -> bool {
        self.actions.is_empty() && self.events.is_empty() && self.pending_operations.is_empty()
    }

    fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        conn_id: ConnectionId,
        is_circuit: bool,
    ) {
        self.connections.insert(
            conn_id,
            Connection {
                peer_id,
                address: None,
                is_circuit,
            },
        );
    }

    /// Applies `new` before retiring `old`.
    ///
    /// A reservation on `old` moves to a direct `new` with its original
    /// expiry; a circuit `new` cannot hold one, so retiring `old` closes it.
    /// Uncommitted RESERVE exchanges and every circuit on `old` end with it.
    fn on_connection_replaced(
        &mut self,
        peer_id: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
        is_circuit: bool,
    ) {
        self.on_connection_established(peer_id.clone(), new, is_circuit);
        if !is_circuit
            && let Some(reservation) = self.reservations.get_mut(peer_id)
            && reservation.conn_id == old
        {
            reservation.conn_id = new;
        }
        self.on_connection_closed(peer_id, old);
    }

    fn on_connection_closed(&mut self, peer_id: &PeerId, conn_id: ConnectionId) {
        let affected: Vec<_> = self
            .circuits
            .iter()
            .filter_map(|(key, circuit)| {
                let leg = if circuit.source_stream.conn_id == conn_id {
                    Some(CircuitLeg::Source)
                } else if circuit.destination_stream.conn_id == conn_id {
                    Some(CircuitLeg::Destination)
                } else {
                    None
                }?;
                Some((*key, leg))
            })
            .collect();
        for (key, leg) in affected {
            self.close_circuit(key, CircuitCloseReason::ConnectionClosed { leg });
        }
        let pending: Vec<_> = self
            .pending_circuits
            .iter()
            .filter_map(|(source_stream, circuit)| {
                (source_stream.conn_id == conn_id || circuit.destination_conn_id == conn_id)
                    .then_some((*source_stream, source_stream.conn_id == conn_id))
            })
            .collect();
        for (source_stream, source_closed) in pending {
            if source_closed {
                self.abort_pending_connect(source_stream);
            } else {
                if let Some(circuit) = self.pending_circuits.get_mut(&source_stream)
                    && let Some(stop_stream) = circuit.stop_stream.take()
                {
                    self.stop_to_source.remove(&stop_stream);
                }
                self.fail_pending_connect(source_stream, Status::ConnectionFailed);
            }
        }
        self.connections.remove(&conn_id);
        if self
            .reservations
            .get(peer_id)
            .is_some_and(|reservation| reservation.conn_id == conn_id)
        {
            self.reservations.remove(peer_id);
            self.events.push_back(RelayServerEvent::ReservationClosed {
                peer_id: peer_id.clone(),
                reason: ReservationCloseReason::ConnectionClosed,
            });
        }
        let closed_hop_streams: Vec<_> = self
            .hop_workers
            .keys()
            .filter(|key| key.conn_id == conn_id)
            .copied()
            .collect();
        for stream in closed_hop_streams {
            self.cancel_pending_hop_ops(stream);
            self.hop_workers.remove(&stream);
        }
        self.rejected_hop_streams
            .retain(|key, _| key.conn_id != conn_id);
    }

    fn on_hop_ready(&mut self, peer_id: PeerId, key: StreamKey, is_circuit: bool, now: Now) {
        let Some(connection) = self.connections.get(&key.conn_id) else {
            self.rejected_hop_streams.insert(key, peer_id.clone());
            self.queue_reset(peer_id, key);
            return;
        };
        if connection.peer_id != peer_id {
            self.rejected_hop_streams.insert(key, peer_id.clone());
            self.queue_reset(peer_id, key);
            return;
        }
        let is_circuit = is_circuit || connection.is_circuit;
        let count = self
            .hop_workers
            .iter()
            .filter(|(stream, worker)| {
                stream.conn_id == key.conn_id && worker.deadline_ms.is_some()
            })
            .count();
        if count >= self.config.max_pending_hop_requests_per_connection {
            self.rejected_hop_streams.insert(key, peer_id.clone());
            self.queue_reset(peer_id, key);
            return;
        }
        let worker = HopWorker {
            peer_id: peer_id.clone(),
            responder: HopResponder::new(),
            deadline_ms: Some(
                now.monotonic_ms
                    .saturating_add(self.config.control_stream_timeout_ms),
            ),
            request_known: false,
            is_circuit,
        };
        self.hop_workers.insert(key, worker);
    }

    /// Delivers an input to a live HOP responder.
    ///
    /// Missing workers are stale stream events and need no new action. A
    /// responder error after the agent routed the event is an internal
    /// contract failure, so surface it before the caller decides whether to
    /// drain any output.
    fn feed_hop(&mut self, key: StreamKey, input: HopResponderInput) -> bool {
        let Some(worker) = self.hop_workers.get_mut(&key) else {
            return false;
        };
        let peer_id = worker.peer_id.clone();
        let result = worker.responder.handle_input(input);
        if let Err(error) = result {
            self.runtime_error(
                RelayServerRuntimeErrorKind::InternalInvariant,
                Some(peer_id),
                format!("HOP responder rejected routed input: {error}"),
            );
            return false;
        }
        true
    }

    /// Delivers an input to a pending STOP initiator, ignoring stale streams.
    fn feed_stop(&mut self, source_stream: StreamKey, input: StopInitiatorInput) -> bool {
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return false;
        };
        let Some(stop) = circuit.stop.as_mut() else {
            return false;
        };
        let peer_id = circuit.source_peer_id.clone();
        let result = stop.handle_input(input);
        if let Err(error) = result {
            self.runtime_error(
                RelayServerRuntimeErrorKind::InternalInvariant,
                Some(peer_id),
                format!("STOP initiator rejected routed input: {error}"),
            );
            return false;
        }
        true
    }

    fn drain_hop(&mut self, key: StreamKey, now: Now) {
        loop {
            let output = self
                .hop_workers
                .get_mut(&key)
                .and_then(|worker| worker.responder.poll_output());
            let Some(output) = output else { break };
            match output {
                HopResponderOutput::Request(HopRequest::Reserve) => {
                    let Some((peer_id, is_circuit)) =
                        self.hop_workers.get_mut(&key).map(|worker| {
                            worker.request_known = true;
                            (worker.peer_id.clone(), worker.is_circuit)
                        })
                    else {
                        break;
                    };
                    if is_circuit {
                        self.events.push_back(RelayServerEvent::ReservationDenied {
                            peer_id,
                            status: Status::PermissionDenied,
                        });
                        self.feed_hop(key, HopResponderInput::Reject(Status::PermissionDenied));
                    } else {
                        self.decide_reservation(key, now)
                    }
                }
                HopResponderOutput::Request(HopRequest::Connect {
                    destination_peer_id,
                }) => {
                    let Some(is_circuit) = self.hop_workers.get_mut(&key).map(|worker| {
                        worker.request_known = true;
                        worker.is_circuit
                    }) else {
                        break;
                    };
                    if is_circuit {
                        self.deny_connect(key, destination_peer_id, Status::PermissionDenied);
                    } else {
                        self.decide_connect(key, destination_peer_id, now);
                    }
                }
                HopResponderOutput::Outbound(data) => {
                    let Some(peer_id) = self
                        .hop_workers
                        .get(&key)
                        .map(|worker| worker.peer_id.clone())
                    else {
                        break;
                    };
                    self.queue_send(peer_id, key, data, SendEffect::CompleteHop(key));
                }
                HopResponderOutput::CloseWrite => {
                    let Some(peer_id) = self
                        .hop_workers
                        .get(&key)
                        .map(|worker| worker.peer_id.clone())
                    else {
                        break;
                    };
                    self.queue_close(peer_id, key);
                }
                HopResponderOutput::Reset => {
                    let Some(peer_id) = self
                        .hop_workers
                        .get(&key)
                        .map(|worker| worker.peer_id.clone())
                    else {
                        break;
                    };
                    self.queue_reset(peer_id, key);
                }
                // A committed circuit reads its source leg itself, and a
                // pending one buffers later reads directly, so only payload
                // coalesced with CONNECT arrives here, on acceptance. It
                // precedes everything buffered since.
                HopResponderOutput::BridgeData(data) => {
                    let Some(circuit) = self.pending_circuits.get_mut(&key) else {
                        continue;
                    };
                    let later = core::mem::replace(&mut circuit.source_pipelined, data);
                    self.append_pending_payload(key, CircuitDirection::SourceToDestination, &later);
                }
            }
        }
    }

    /// Drives a pending circuit's STOP initiator and returns how many
    /// destination payload bytes it moved into the pending circuit's buffer;
    /// those stay unacknowledged until forwarded or released.
    fn drain_stop(&mut self, source_stream: StreamKey, now: Now) -> usize {
        let mut bridged = 0;
        loop {
            let output = self
                .pending_circuits
                .get_mut(&source_stream)
                .and_then(|circuit| circuit.stop.as_mut())
                .and_then(SansIoProtocol::poll_output);
            let Some(output) = output else { break };
            match output {
                StopInitiatorOutput::Outcome(StopInitiatorOutcome::Accepted) => {
                    if let Some(circuit) = self.pending_circuits.get_mut(&source_stream) {
                        circuit.stop_deadline_ms = None;
                    }
                    if !self.feed_hop(
                        source_stream,
                        HopResponderInput::AcceptConnect {
                            limit: Some(Limit {
                                duration: Some(self.config.max_circuit_duration_secs as u32),
                                data: Some(self.config.max_circuit_bytes),
                            }),
                        },
                    ) {
                        self.fail_pending_connect(source_stream, Status::ConnectionFailed);
                        return bridged;
                    }
                    let Some(worker) = self.hop_workers.get_mut(&source_stream) else {
                        self.fail_pending_connect(source_stream, Status::ConnectionFailed);
                        return bridged;
                    };
                    let Some(HopResponderOutput::Outbound(data)) = worker.responder.poll_output()
                    else {
                        self.fail_pending_connect(source_stream, Status::ConnectionFailed);
                        return bridged;
                    };
                    let peer_id = worker.peer_id.clone();
                    self.queue_send(
                        peer_id,
                        source_stream,
                        data,
                        SendEffect::CommitCircuit(source_stream),
                    );
                    self.drain_hop(source_stream, now);
                }
                StopInitiatorOutput::Outcome(outcome) => {
                    self.fail_pending_connect(source_stream, outcome.hop_status());
                    return bridged;
                }
                StopInitiatorOutput::BridgeData(data) => {
                    if self.append_pending_payload(
                        source_stream,
                        CircuitDirection::DestinationToSource,
                        &data,
                    ) {
                        bridged += data.len();
                    }
                }
                StopInitiatorOutput::Outbound(data) => {
                    if let Some(circuit) = self.pending_circuits.get(&source_stream) {
                        let stream = circuit.stop_stream.expect("STOP output has a stream");
                        self.queue_send(
                            circuit.destination_peer_id.clone(),
                            stream,
                            data,
                            SendEffect::StopRequest(source_stream),
                        );
                    }
                }
                StopInitiatorOutput::CloseWrite => {
                    if let Some(circuit) = self.pending_circuits.get(&source_stream) {
                        self.queue_close(
                            circuit.destination_peer_id.clone(),
                            circuit.stop_stream.expect("STOP output has a stream"),
                        );
                    }
                }
                StopInitiatorOutput::Reset => {
                    if let Some(circuit) = self.pending_circuits.get(&source_stream) {
                        self.queue_reset(
                            circuit.destination_peer_id.clone(),
                            circuit.stop_stream.expect("STOP output has a stream"),
                        );
                    }
                }
            }
        }
        bridged
    }

    fn commit_circuit(&mut self, source_stream: StreamKey, now: Now) {
        let Some(pending) = self.pending_circuits.remove(&source_stream) else {
            return;
        };
        let Some(destination_stream) = pending.stop_stream else {
            return;
        };
        let deadline_ms = (self.config.max_circuit_duration_secs != 0).then(|| {
            now.monotonic_ms
                .saturating_add(self.config.max_circuit_duration_secs.saturating_mul(1_000))
        });
        self.circuits.insert(
            source_stream,
            Circuit {
                source_peer_id: pending.source_peer_id.clone(),
                destination_peer_id: pending.destination_peer_id.clone(),
                source_stream,
                destination_stream,
                deadline_ms,
                bytes: CircuitByteCounts::default(),
                to_destination: Forward::default(),
                to_source: Forward::default(),
            },
        );
        self.events.push_back(RelayServerEvent::CircuitOpened {
            source_peer_id: pending.source_peer_id,
            destination_peer_id: pending.destination_peer_id,
        });
        if !pending.source_pipelined.is_empty() {
            self.queue_forward(
                source_stream,
                CircuitDirection::SourceToDestination,
                pending.source_pipelined,
            );
        }
        if !pending.destination_pipelined.is_empty() {
            self.queue_forward(
                source_stream,
                CircuitDirection::DestinationToSource,
                pending.destination_pipelined,
            );
        }
        if pending.source_eof {
            self.circuit_eof(source_stream, CircuitLeg::Source);
        }
        if pending.destination_eof {
            self.circuit_eof(source_stream, CircuitLeg::Destination);
        }
    }

    /// Payload the HOP worker on `stream` holds behind its CONNECT.
    fn hop_bridge_len(&self, stream: StreamKey) -> usize {
        self.hop_workers
            .get(&stream)
            .map_or(0, |worker| worker.responder.pending_bridge_len())
    }

    /// Releases the credit of a dropped pending circuit's buffered payload,
    /// including what its HOP worker still holds (a no-op on a leg reset
    /// with it).
    fn release_pipelined(&mut self, source_stream: StreamKey, circuit: &PendingCircuit) {
        let held = self.hop_bridge_len(source_stream);
        self.queue_ack(source_stream, circuit.source_pipelined.len() + held);
        if let Some(stop_stream) = circuit.stop_stream {
            self.queue_ack(stop_stream, circuit.destination_pipelined.len());
        }
    }

    /// Buffers `data` on a pending circuit, returning whether it was kept;
    /// payload past the bound aborts the circuit.
    fn append_pending_payload(
        &mut self,
        source_stream: StreamKey,
        direction: CircuitDirection,
        data: &[u8],
    ) -> bool {
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return false;
        };
        let buffer = match direction {
            CircuitDirection::SourceToDestination => &mut circuit.source_pipelined,
            CircuitDirection::DestinationToSource => &mut circuit.destination_pipelined,
        };
        if buffer
            .len()
            .checked_add(data.len())
            .is_some_and(|len| len <= MAX_PENDING_BRIDGE_SIZE)
        {
            buffer.extend_from_slice(data);
            return true;
        }
        let peer_id = match direction {
            CircuitDirection::SourceToDestination => circuit.source_peer_id.clone(),
            CircuitDirection::DestinationToSource => circuit.destination_peer_id.clone(),
        };
        self.abort_pending_connect_both(source_stream);
        self.runtime_error(
            RelayServerRuntimeErrorKind::InternalInvariant,
            Some(peer_id),
            "pending circuit payload exceeded the 64 KiB directional bound".into(),
        );
        false
    }

    /// Queues `data` read from `direction`'s origin behind what it already
    /// holds, and sends it when that direction is idle.
    fn queue_forward(
        &mut self,
        source_stream: StreamKey,
        direction: CircuitDirection,
        data: impl Into<Bytes>,
    ) {
        let data: Bytes = data.into();
        if data.is_empty() {
            return;
        }
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        circuit.forward(direction).push(data);
        self.pump_forward(source_stream, direction);
    }

    /// Sends the head of an idle direction's queue, or its FIN once the
    /// origin half-closed and every byte was accepted.
    fn pump_forward(&mut self, source_stream: StreamKey, direction: CircuitDirection) {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        let (peer_id, stream, leg) = circuit.target(direction);
        let forward = circuit.forward(direction);
        if forward.send != SendState::Idle {
            return;
        }
        if let Some(data) = forward.head() {
            forward.send = SendState::Sending;
            let chunk_len = data.len();
            self.queue_send(
                peer_id,
                stream,
                data,
                SendEffect::Forward {
                    source_stream,
                    direction,
                    chunk_len,
                },
            );
        } else if forward.fin == FinState::Received {
            forward.fin = FinState::Requested;
            self.queue_circuit_close(peer_id, stream, source_stream, leg);
        }
    }

    /// Resumes a direction paused by a Full on its target leg.
    fn resume_forward(&mut self, source_stream: StreamKey, direction: CircuitDirection) {
        if let Some(circuit) = self.circuits.get_mut(&source_stream) {
            let forward = circuit.forward(direction);
            if forward.send == SendState::Blocked {
                forward.send = SendState::Idle;
                self.pump_forward(source_stream, direction);
            }
        }
    }

    /// Applies a forwarding send's result: `accepted` bytes of the head went
    /// out, and an `unsent` tail (after a Full) waits for the target's
    /// Writable. Accepted bytes are acknowledged to the origin and count
    /// toward the circuit's byte limit.
    fn forward_accepted(
        &mut self,
        source_stream: StreamKey,
        direction: CircuitDirection,
        accepted: usize,
        unsent: Option<Bytes>,
    ) {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        let origin = circuit.origin(direction);
        circuit.forward(direction).accept(unsent);
        let total = match direction {
            CircuitDirection::SourceToDestination => &mut circuit.bytes.source_to_destination,
            CircuitDirection::DestinationToSource => &mut circuit.bytes.destination_to_source,
        };
        *total = total.saturating_add(accepted as u64);
        let total = *total;
        self.queue_ack(origin, accepted);
        if self.config.max_circuit_bytes != 0 && total > self.config.max_circuit_bytes {
            self.close_circuit(source_stream, CircuitCloseReason::ByteLimit { direction });
        } else {
            self.pump_forward(source_stream, direction);
        }
    }

    fn close_circuit(&mut self, source_stream: StreamKey, reason: CircuitCloseReason) {
        let Some(mut circuit) = self.circuits.remove(&source_stream) else {
            return;
        };
        self.hop_workers.remove(&source_stream);
        self.stop_to_source.remove(&circuit.destination_stream);
        self.cancel_forward_ops(source_stream);
        let (reset_source, reset_destination) = match reason {
            CircuitCloseReason::Eof => (false, false),
            CircuitCloseReason::StreamReset {
                leg: CircuitLeg::Source,
            }
            | CircuitCloseReason::ConnectionClosed {
                leg: CircuitLeg::Source,
            } => (false, true),
            CircuitCloseReason::StreamReset {
                leg: CircuitLeg::Destination,
            }
            | CircuitCloseReason::ConnectionClosed {
                leg: CircuitLeg::Destination,
            } => (true, false),
            _ => (true, true),
        };
        if reset_source {
            self.queue_reset(circuit.source_peer_id.clone(), circuit.source_stream);
        }
        if reset_destination {
            self.queue_reset(
                circuit.destination_peer_id.clone(),
                circuit.destination_stream,
            );
        }
        // Bytes still queued were never forwarded; release the origins'
        // credit for them (a no-op on a leg reset above).
        for direction in [
            CircuitDirection::SourceToDestination,
            CircuitDirection::DestinationToSource,
        ] {
            let origin = circuit.origin(direction);
            let unacked = circuit.forward(direction).unacked();
            self.queue_ack(origin, unacked);
        }
        self.events.push_back(RelayServerEvent::CircuitClosed {
            source_peer_id: circuit.source_peer_id,
            destination_peer_id: circuit.destination_peer_id,
            bytes: circuit.bytes,
            reason,
        });
    }

    /// Records `leg`'s half-close; its FIN reaches the other leg after the
    /// last byte queued for it.
    fn circuit_eof(&mut self, source_stream: StreamKey, leg: CircuitLeg) {
        let direction = match leg {
            CircuitLeg::Source => CircuitDirection::SourceToDestination,
            CircuitLeg::Destination => CircuitDirection::DestinationToSource,
        };
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        let forward = circuit.forward(direction);
        if forward.fin == FinState::Open {
            forward.fin = FinState::Received;
            self.pump_forward(source_stream, direction);
        }
    }

    /// Handles `leg`'s stream closing. A leg that finished both ways (its
    /// half-close was read and the FIN forwarded to it accepted) closed
    /// cleanly, and the other direction keeps draining; anything else is a
    /// reset.
    fn circuit_leg_closed(&mut self, source_stream: StreamKey, leg: CircuitLeg) {
        let Some(circuit) = self.circuits.get(&source_stream) else {
            return;
        };
        let (from_leg, to_leg) = match leg {
            CircuitLeg::Source => (&circuit.to_destination, &circuit.to_source),
            CircuitLeg::Destination => (&circuit.to_source, &circuit.to_destination),
        };
        if from_leg.fin == FinState::Open || to_leg.fin != FinState::Accepted {
            self.close_circuit(source_stream, CircuitCloseReason::StreamReset { leg });
        }
    }

    /// Records that `leg` accepted the FIN forwarded to it.
    fn circuit_close_accepted(&mut self, source_stream: StreamKey, leg: CircuitLeg) {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        match leg {
            CircuitLeg::Source => circuit.to_source.fin = FinState::Accepted,
            CircuitLeg::Destination => circuit.to_destination.fin = FinState::Accepted,
        }
        if circuit.to_source.fin == FinState::Accepted
            && circuit.to_destination.fin == FinState::Accepted
        {
            self.close_circuit(source_stream, CircuitCloseReason::Eof);
        }
    }

    fn decide_reservation(&mut self, key: StreamKey, now: Now) {
        let Some(peer_id) = self
            .hop_workers
            .get(&key)
            .map(|worker| worker.peer_id.clone())
        else {
            return;
        };
        let renewed = self
            .reservations
            .get(&peer_id)
            .is_some_and(|reservation| reservation.conn_id == key.conn_id);
        let pending_for_peer = self.pending_operations.values().any(|operation| {
            matches!(
                operation,
                PendingOperation::Send {
                    effect: SendEffect::CommitReservation(pending),
                    ..
                } if pending.peer_id == peer_id
            )
        });
        let deadline_ms = now
            .monotonic_ms
            .saturating_add(self.config.reservation_duration_secs.saturating_mul(1_000));
        let expires_unix_secs = now
            .unix_seconds
            .map(|unix| unix.saturating_add(self.config.reservation_duration_secs));
        let wire = self
            .accepting
            .then(|| self.reservation_wire(expires_unix_secs))
            .flatten();
        let status = if wire.is_none() {
            Some(Status::ReservationRefused)
        // Renewals keep an admitted reservation alive and spend no token.
        } else if !renewed && !self.admit_new_reservation(&peer_id, key.conn_id, now.monotonic_ms)
            || pending_for_peer
        {
            Some(Status::ResourceLimitExceeded)
        } else {
            None
        };
        if let Some(status) = status {
            self.events.push_back(RelayServerEvent::ReservationDenied {
                peer_id: peer_id.clone(),
                status,
            });
            self.feed_hop(key, HopResponderInput::Reject(status));
            return;
        }

        let (reservation, limit) = wire.expect("availability checked above");
        if !self.feed_hop(
            key,
            HopResponderInput::AcceptReservation {
                reservation,
                limit: Some(limit),
            },
        ) {
            return;
        }
        let Some(worker) = self.hop_workers.get_mut(&key) else {
            return;
        };
        let Some(HopResponderOutput::Outbound(data)) = worker.responder.poll_output() else {
            self.runtime_error(
                RelayServerRuntimeErrorKind::InternalInvariant,
                Some(peer_id),
                "accepted reservation produced no response".into(),
            );
            return;
        };
        self.queue_send(
            peer_id.clone(),
            key,
            data,
            SendEffect::CommitReservation(PendingReservation {
                stream: key,
                peer_id,
                conn_id: key.conn_id,
                renewed,
                deadline_ms,
                expires_unix_secs,
            }),
        );
    }

    fn reservation_wire(&self, expires_unix_secs: Option<u64>) -> Option<(Reservation, Limit)> {
        let mut addrs = Vec::new();
        for address in self.selected_addrs() {
            let mut advertised = address.clone();
            advertised.push(Protocol::P2p(self.local_peer_id.clone()));
            addrs.push(advertised.to_bytes());
        }
        let limit = Limit {
            duration: Some(self.config.max_circuit_duration_secs as u32),
            data: Some(self.config.max_circuit_bytes),
        };
        while !addrs.is_empty() {
            let reservation = Reservation {
                expire: expires_unix_secs,
                addrs: addrs.clone(),
                voucher: None,
            };
            if encode_hop_status(Status::Ok, Some(reservation.clone()), Some(limit.clone())).is_ok()
            {
                return Some((reservation, limit));
            }
            addrs.pop();
        }
        None
    }

    /// Peers whose renewal response is already on the wire. Their
    /// reservation stays alive (and off the timer) until that renewal
    /// commits or fails: the client was promised the extension. The pending
    /// send is still bounded by its control stream's own timeout.
    fn renewing_peers(&self) -> BTreeSet<&PeerId> {
        self.pending_operations
            .values()
            .filter_map(|operation| match operation {
                PendingOperation::Send {
                    effect: SendEffect::CommitReservation(pending),
                    ..
                } if pending.renewed => Some(&pending.peer_id),
                _ => None,
            })
            .collect()
    }

    /// Admission for a new reservation: spends a rate-limit token, then
    /// checks `max_reservations` against committed and pending new ones.
    fn admit_new_reservation(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        now_ms: u64,
    ) -> bool {
        if !self.consume_reservation_limits(peer_id, conn_id, now_ms) {
            return false;
        }
        let pending_initial = self
            .pending_operations
            .values()
            .filter(|operation| {
                matches!(
                    operation,
                    PendingOperation::Send {
                        effect: SendEffect::CommitReservation(pending),
                        ..
                    } if !pending.renewed
                )
            })
            .count();
        self.reservations.len().saturating_add(pending_initial) < self.config.max_reservations
    }

    fn consume_reservation_limits(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        now_ms: u64,
    ) -> bool {
        let ip = self
            .connections
            .get(&conn_id)
            .and_then(|connection| connection.address.as_ref())
            .and_then(first_ip);
        self.reservation_limiters.consume(peer_id, ip, now_ms)
    }

    fn decide_connect(&mut self, key: StreamKey, destination_peer_id: PeerId, now: Now) {
        let Some(source_peer_id) = self
            .hop_workers
            .get(&key)
            .map(|worker| worker.peer_id.clone())
        else {
            return;
        };
        let destination_conn = self
            .reservations
            .get(&destination_peer_id)
            .map(|reservation| reservation.conn_id);
        let status = if !self.accepting
            || self
                .connections
                .get(&key.conn_id)
                .is_some_and(|connection| connection.is_circuit)
        {
            Some(Status::PermissionDenied)
        } else if !self.consume_circuit_limits(&source_peer_id, key.conn_id, now.monotonic_ms)
            || self.peer_circuit_count(&source_peer_id) >= self.config.max_circuits_per_peer
            || (source_peer_id != destination_peer_id
                && self.peer_circuit_count(&destination_peer_id)
                    >= self.config.max_circuits_per_peer)
            || self
                .pending_circuits
                .len()
                .saturating_add(self.circuits.len())
                >= self.config.max_circuits
        {
            Some(Status::ResourceLimitExceeded)
        } else if destination_conn.is_none()
            || destination_conn.is_some_and(|conn_id| {
                self.connections
                    .get(&conn_id)
                    .is_none_or(|connection| connection.peer_id != destination_peer_id)
            })
        {
            Some(Status::NoReservation)
        } else if self
            .pending_circuits
            .values()
            .filter(|circuit| {
                Some(circuit.destination_conn_id) == destination_conn
                    && circuit.stop_deadline_ms.is_some()
            })
            .count()
            >= self.config.max_pending_stop_requests_per_connection
        {
            Some(Status::ResourceLimitExceeded)
        } else {
            None
        };
        if let Some(status) = status {
            self.deny_connect(key, destination_peer_id, status);
            return;
        }
        let destination_conn_id = destination_conn.expect("checked above");
        self.pending_circuits.insert(
            key,
            PendingCircuit {
                source_peer_id: source_peer_id.clone(),
                destination_peer_id: destination_peer_id.clone(),
                destination_conn_id,
                stop_stream: None,
                stop: None,
                stop_deadline_ms: Some(
                    now.monotonic_ms
                        .saturating_add(self.config.control_stream_timeout_ms),
                ),
                source_pipelined: Vec::new(),
                destination_pipelined: Vec::new(),
                source_eof: false,
                destination_eof: false,
            },
        );
        let token = self.token();
        self.pending_operations.insert(
            token,
            PendingOperation::OpenStop {
                source_stream: key,
                peer_id: destination_peer_id.clone(),
                expected_conn_id: destination_conn_id,
            },
        );
        self.actions.push_back(RelayServerAction::OpenStream {
            token,
            peer_id: destination_peer_id,
            expected_conn_id: destination_conn_id,
            protocol_id: STOP_PROTOCOL_ID.into(),
        });
    }

    fn consume_circuit_limits(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        now_ms: u64,
    ) -> bool {
        let ip = self
            .connections
            .get(&conn_id)
            .and_then(|connection| connection.address.as_ref())
            .and_then(first_ip);
        self.circuit_limiters.consume(peer_id, ip, now_ms)
    }

    fn peer_circuit_count(&self, peer_id: &PeerId) -> usize {
        self.pending_circuits
            .values()
            .map(|circuit| (&circuit.source_peer_id, &circuit.destination_peer_id))
            .chain(
                self.circuits
                    .values()
                    .map(|circuit| (&circuit.source_peer_id, &circuit.destination_peer_id)),
            )
            .filter(|(source, destination)| *source == peer_id || *destination == peer_id)
            .count()
    }

    fn deny_connect(&mut self, key: StreamKey, destination_peer_id: PeerId, status: Status) {
        let Some(source_peer_id) = self
            .hop_workers
            .get(&key)
            .map(|worker| worker.peer_id.clone())
        else {
            return;
        };
        self.events.push_back(RelayServerEvent::CircuitDenied {
            source_peer_id,
            destination_peer_id,
            status,
        });
        self.feed_hop(key, HopResponderInput::Reject(status));
    }

    fn fail_pending_connect(&mut self, source_stream: StreamKey, status: Status) {
        let Some(circuit) = self.pending_circuits.remove(&source_stream) else {
            return;
        };
        self.release_pipelined(source_stream, &circuit);
        self.cancel_pending_control_ops(source_stream);
        if let Some(stop_stream) = circuit.stop_stream {
            self.stop_to_source.remove(&stop_stream);
            self.queue_reset(circuit.destination_peer_id.clone(), stop_stream);
        }
        self.deny_connect(source_stream, circuit.destination_peer_id, status);
        self.drain_hop(source_stream, Now::from_millis(0));
    }

    fn abort_pending_connect(&mut self, source_stream: StreamKey) {
        let Some(circuit) = self.pending_circuits.remove(&source_stream) else {
            return;
        };
        self.release_pipelined(source_stream, &circuit);
        self.cancel_pending_control_ops(source_stream);
        if let Some(stop_stream) = circuit.stop_stream {
            self.stop_to_source.remove(&stop_stream);
            self.queue_reset(circuit.destination_peer_id, stop_stream);
        }
    }

    fn abort_pending_connect_both(&mut self, source_stream: StreamKey) {
        self.abort_pending_connect(source_stream);
        if let Some(worker) = self.hop_workers.remove(&source_stream) {
            self.queue_reset(worker.peer_id, source_stream);
        }
    }

    fn cancel_pending_control_ops(&mut self, source_stream: StreamKey) {
        let tokens: Vec<_> = self
            .pending_operations
            .iter()
            .filter_map(|(token, operation)| {
                let matches = match operation {
                    PendingOperation::OpenStop {
                        source_stream: stream,
                        ..
                    } => *stream == source_stream,
                    PendingOperation::Send {
                        effect: SendEffect::StopRequest(stream) | SendEffect::CommitCircuit(stream),
                        ..
                    } => *stream == source_stream,
                    _ => false,
                };
                matches.then_some(*token)
            })
            .collect();
        self.cancel_operations(&tokens);
    }

    fn cancel_pending_hop_ops(&mut self, stream: StreamKey) {
        let tokens: Vec<_> = self
            .pending_operations
            .iter()
            .filter_map(|(token, operation)| {
                let matches = match operation {
                    PendingOperation::Send {
                        effect: SendEffect::CommitReservation(pending),
                        ..
                    } => pending.stream == stream,
                    PendingOperation::Send {
                        effect: SendEffect::CompleteHop(operation_stream),
                        ..
                    } => *operation_stream == stream,
                    PendingOperation::Close {
                        stream: operation_stream,
                        ..
                    } => *operation_stream == stream,
                    _ => false,
                };
                matches.then_some(*token)
            })
            .collect();
        self.cancel_operations(&tokens);
    }

    fn cancel_forward_ops(&mut self, source_stream: StreamKey) {
        let tokens: Vec<_> = self
            .pending_operations
            .iter()
            .filter_map(|(token, operation)| {
                matches!(
                    operation,
                    PendingOperation::Send {
                        effect: SendEffect::Forward { source_stream: stream, .. },
                        ..
                    } if *stream == source_stream
                )
                .then_some(*token)
            })
            .collect();
        self.cancel_operations(&tokens);
    }

    fn cancel_operations(&mut self, tokens: &[RelayServerToken]) {
        // Skip the action-queue scan: nothing to cancel.
        if tokens.is_empty() {
            return;
        }
        for token in tokens {
            self.pending_operations.remove(token);
        }
        self.actions.retain(|action| match action {
            RelayServerAction::OpenStream { token, .. }
            | RelayServerAction::SendStream { token, .. }
            | RelayServerAction::CloseStreamWrite { token, .. }
            | RelayServerAction::ResetStream { token, .. } => !tokens.contains(token),
            RelayServerAction::AckStream { .. } => true,
        });
    }

    fn complete_hop(&mut self, stream: StreamKey) {
        if let Some(worker) = self.hop_workers.get_mut(&stream) {
            worker.deadline_ms = None;
        }
    }

    fn queue_send(
        &mut self,
        peer_id: PeerId,
        stream: StreamKey,
        data: impl Into<Bytes>,
        effect: SendEffect,
    ) {
        let data = data.into();
        let token = self.token();
        self.pending_operations.insert(
            token,
            PendingOperation::Send {
                peer_id: peer_id.clone(),
                effect,
            },
        );
        self.actions.push_back(RelayServerAction::SendStream {
            token,
            peer_id,
            stream,
            data,
        });
    }

    /// Acknowledges `bytes` of `stream`'s delivered data as consumed.
    fn queue_ack(&mut self, stream: StreamKey, bytes: usize) {
        if bytes != 0 {
            self.actions
                .push_back(RelayServerAction::AckStream { stream, bytes });
        }
    }

    fn queue_close(&mut self, peer_id: PeerId, stream: StreamKey) {
        self.queue_close_for(peer_id, stream, None);
    }

    fn queue_circuit_close(
        &mut self,
        peer_id: PeerId,
        stream: StreamKey,
        source_stream: StreamKey,
        leg: CircuitLeg,
    ) {
        self.queue_close_for(peer_id, stream, Some((source_stream, leg)));
    }

    fn queue_close_for(
        &mut self,
        peer_id: PeerId,
        stream: StreamKey,
        circuit: Option<(StreamKey, CircuitLeg)>,
    ) {
        let token = self.token();
        self.pending_operations.insert(
            token,
            PendingOperation::Close {
                peer_id: peer_id.clone(),
                stream,
                circuit,
            },
        );
        self.actions.push_back(RelayServerAction::CloseStreamWrite {
            token,
            peer_id,
            stream,
        });
    }

    fn queue_reset(&mut self, peer_id: PeerId, stream: StreamKey) {
        let token = self.token();
        self.pending_operations.insert(
            token,
            PendingOperation::Reset {
                peer_id: peer_id.clone(),
            },
        );
        self.actions.push_back(RelayServerAction::ResetStream {
            token,
            peer_id,
            stream,
        });
    }

    fn token(&mut self) -> RelayServerToken {
        loop {
            let token = self.next_token;
            self.next_token = self.next_token.wrapping_add(1);
            if token != 0 {
                return RelayServerToken(token);
            }
        }
    }

    fn runtime_error(
        &mut self,
        kind: RelayServerRuntimeErrorKind,
        peer_id: Option<PeerId>,
        detail: String,
    ) {
        self.events
            .push_back(RelayServerEvent::Error(RelayServerRuntimeError {
                kind,
                peer_id,
                detail,
            }));
    }
}

fn first_ip(address: &Multiaddr) -> Option<IpKey> {
    address
        .protocols()
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Ip4(ip) => Some(IpKey::V4(*ip)),
            Protocol::Ip6(ip) if ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] => {
                Some(IpKey::V4([ip[12], ip[13], ip[14], ip[15]]))
            }
            Protocol::Ip6(ip) => Some(IpKey::V6(*ip)),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use minip2p_core::{Multiaddr, PeerId, Protocol};
    use minip2p_platform::Now;
    use minip2p_relay::{
        FrameDecode, HOP_PROTOCOL_ID, HopMessage, HopMessageType, MAX_MESSAGE_SIZE,
        MAX_PENDING_BRIDGE_SIZE, Peer, Status, decode_frame, encode_frame, encode_stop_status,
    };
    use minip2p_swarm::SwarmEvent;
    use minip2p_transport::{ConnectionId, StreamId};

    use super::*;
    use crate::{RateLimit, RelayServerAction, RelayServerConfig, RelayServerEvent, StreamKey};

    /// The next I/O action, leaving acknowledgements queued for the
    /// backpressure tests that inspect them.
    fn io_action(agent: &mut RelayServerAgent) -> Option<RelayServerAction> {
        let index = agent
            .actions
            .iter()
            .position(|action| !matches!(action, RelayServerAction::AckStream { .. }))?;
        agent.actions.remove(index)
    }

    fn direct_addr() -> Multiaddr {
        Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").unwrap()
    }

    fn establish(agent: &mut RelayServerAgent, peer_id: &PeerId, conn_id: ConnectionId) {
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer_id.clone(),
                conn_id,
            },
            false,
            Now::from_millis(0),
        );
    }

    fn replace(
        agent: &mut RelayServerAgent,
        peer_id: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
        new_is_circuit: bool,
        now_ms: u64,
    ) {
        agent.handle_event(
            &SwarmEvent::ConnectionReplaced {
                peer_id: peer_id.clone(),
                old,
                new,
            },
            new_is_circuit,
            Now::from_millis(now_ms),
        );
    }

    fn reserve_request() -> HopMessage {
        HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        }
    }

    fn feed_hop(
        agent: &mut RelayServerAgent,
        peer_id: &PeerId,
        stream: StreamKey,
        request: HopMessage,
        pipelined: &[u8],
    ) {
        agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer_id.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::from_millis(0),
        );
        let mut data = encode_frame(&request.encode());
        data.extend_from_slice(pipelined);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: peer_id.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                data: Bytes::from(data),
            },
            false,
            Now::from_millis(0),
        );
    }

    fn reserve(agent: &mut RelayServerAgent, peer_id: &PeerId, stream: StreamKey) {
        establish(agent, peer_id, stream.conn_id);
        feed_hop(
            agent,
            peer_id,
            stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        let RelayServerAction::SendStream { token, .. } = io_action(agent).unwrap() else {
            panic!("reservation response");
        };
        agent.send_stream_result(token, Ok(()), Now::from_millis(0));
        let _ = agent.poll_event();
        if let Some(RelayServerAction::CloseStreamWrite { token, .. }) = io_action(agent) {
            agent.close_stream_write_result(token, Ok(()), Now::from_millis(0));
        }
    }

    fn pending_circuit_success(
        config: RelayServerConfig,
        commit_ms: u64,
    ) -> (
        RelayServerAgent,
        PeerId,
        PeerId,
        StreamKey,
        StreamKey,
        RelayServerToken,
    ) {
        let (mut agent, source, destination, source_stream, stop_stream) =
            pending_stop(config, commit_ms);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination.clone(),
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(encode_stop_status(Status::Ok).unwrap()),
            },
            false,
            Now::from_millis(commit_ms),
        );
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("HOP success");
        };
        drop_acks(&mut agent);
        (
            agent,
            source,
            destination,
            source_stream,
            stop_stream,
            token,
        )
    }

    fn pending_stop(
        config: RelayServerConfig,
        now_ms: u64,
    ) -> (RelayServerAgent, PeerId, PeerId, StreamKey, StreamKey) {
        pending_stop_with_payload(config, now_ms, &[])
    }

    /// [`pending_stop`] with `pipelined` payload in the CONNECT's read.
    fn pending_stop_with_payload(
        mut config: RelayServerConfig,
        now_ms: u64,
        pipelined: &[u8],
    ) -> (RelayServerAgent, PeerId, PeerId, StreamKey, StreamKey) {
        config.reservation_rate_limit_per_peer = None;
        config.reservation_rate_limit_per_ip = None;
        config.circuit_rate_limit_per_peer = None;
        config.circuit_rate_limit_per_ip = None;
        let local = PeerId::from_public_key_protobuf(b"relay-connected-circuit");
        let source = PeerId::from_public_key_protobuf(b"source-connected-circuit");
        let destination = PeerId::from_public_key_protobuf(b"destination-connected-circuit");
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &destination,
            StreamKey {
                conn_id: ConnectionId::new(60),
                stream_id: StreamId::new(1),
            },
        );
        establish(&mut agent, &source, ConnectionId::new(61));
        let source_stream = StreamKey {
            conn_id: ConnectionId::new(61),
            stream_id: StreamId::new(2),
        };
        feed_hop(
            &mut agent,
            &source,
            source_stream,
            HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: destination.to_bytes(),
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            },
            pipelined,
        );
        let RelayServerAction::OpenStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("STOP open");
        };
        let stop_stream = StreamKey {
            conn_id: ConnectionId::new(60),
            stream_id: StreamId::new(3),
        };
        agent.stream_open_result(token, Ok(stop_stream), Now::from_millis(now_ms));
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("STOP request");
        };
        agent.send_stream_result(token, Ok(()), Now::from_millis(now_ms));
        (agent, source, destination, source_stream, stop_stream)
    }

    fn connected_circuit(
        config: RelayServerConfig,
        commit_ms: u64,
    ) -> (RelayServerAgent, PeerId, PeerId, StreamKey, StreamKey) {
        let (mut agent, source, destination, source_stream, stop_stream, token) =
            pending_circuit_success(config, commit_ms);
        agent.send_stream_result(token, Ok(()), Now::from_millis(commit_ms));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitOpened { .. })
        ));
        drop_acks(&mut agent);
        (agent, source, destination, source_stream, stop_stream)
    }

    /// Forgets queued acknowledgements of setup reads.
    fn drop_acks(agent: &mut RelayServerAgent) {
        agent
            .actions
            .retain(|action| !matches!(action, RelayServerAction::AckStream { .. }));
    }

    #[test]
    fn reservation_commits_only_after_success_response_is_accepted() {
        let local = PeerId::from_public_key_protobuf(b"relay");
        let remote = PeerId::from_public_key_protobuf(b"client");
        let conn_id = ConnectionId::new(1);
        let stream_id = StreamId::new(2);
        let mut agent = RelayServerAgent::new(local, RelayServerConfig::default()).unwrap();
        agent
            .replace_announce_addrs(vec![
                Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").unwrap(),
            ])
            .unwrap();
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: remote.clone(),
                conn_id,
            },
            false,
            Now::new(10, 1_000),
        );
        agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: remote.clone(),
                conn_id,
                stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::new(10, 1_000),
        );
        let request = encode_frame(
            &HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            }
            .encode(),
        );
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: remote.clone(),
                conn_id,
                stream_id,
                data: Bytes::from(request),
            },
            false,
            Now::new(10, 1_000),
        );

        assert_eq!(agent.poll_event(), None);
        let RelayServerAction::SendStream { token, stream, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("reservation decision sends its response");
        };
        assert_eq!(stream, StreamKey { conn_id, stream_id });
        agent.send_stream_result(token, Ok(()), Now::new(10, 1_000));

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationAccepted {
                peer_id,
                renewed: false,
                expires_unix_secs: Some(4_600),
            }) if peer_id == remote
        ));
        assert!(agent.has_reservation(&remote));
    }

    #[test]
    fn admitted_connect_opens_stop_on_the_reserved_exact_connection() {
        let local = PeerId::from_public_key_protobuf(b"relay");
        let source = PeerId::from_public_key_protobuf(b"source");
        let destination = PeerId::from_public_key_protobuf(b"destination");
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            circuit_rate_limit_per_peer: None,
            circuit_rate_limit_per_ip: None,
            max_circuit_bytes: 3,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let destination_stream = StreamKey {
            conn_id: ConnectionId::new(10),
            stream_id: StreamId::new(1),
        };
        reserve(&mut agent, &destination, destination_stream);
        establish(&mut agent, &source, ConnectionId::new(20));
        let source_stream = StreamKey {
            conn_id: ConnectionId::new(20),
            stream_id: StreamId::new(2),
        };
        feed_hop(
            &mut agent,
            &source,
            source_stream,
            HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: destination.to_bytes(),
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            },
            b"pipelined-source",
        );

        let Some(RelayServerAction::OpenStream {
            token,
            peer_id,
            expected_conn_id,
            protocol_id,
        }) = io_action(&mut agent)
        else {
            panic!("admitted CONNECT opens STOP");
        };
        assert_eq!(peer_id, destination);
        assert_eq!(expected_conn_id, destination_stream.conn_id);
        assert_eq!(protocol_id, minip2p_relay::STOP_PROTOCOL_ID);
        assert_eq!(agent.poll_event(), None);

        let stop_stream = StreamKey {
            conn_id: destination_stream.conn_id,
            stream_id: StreamId::new(9),
        };
        agent.stream_open_result(token, Ok(stop_stream), Now::from_millis(1));
        let RelayServerAction::SendStream { token, stream, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("STOP CONNECT request");
        };
        assert_eq!(stream, stop_stream);
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination.clone(),
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(encode_stop_status(Status::Ok).unwrap()),
            },
            false,
            Now::from_millis(2),
        );
        let RelayServerAction::SendStream { token, stream, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("HOP success response");
        };
        assert_eq!(stream, source_stream);
        agent.send_stream_result(token, Ok(()), Now::from_millis(2));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitOpened {
                source_peer_id,
                destination_peer_id,
            }) if source_peer_id == source && destination_peer_id == destination
        ));
        let RelayServerAction::SendStream {
            token,
            stream,
            data,
            ..
        } = io_action(&mut agent).unwrap()
        else {
            panic!("pipelined source payload is released after commit");
        };
        assert_eq!(stream, stop_stream);
        assert_eq!(&data[..], b"pipelined-source");
        agent.send_stream_result(token, Ok(()), Now::from_millis(2));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                bytes,
                reason: crate::CircuitCloseReason::ByteLimit {
                    direction: crate::CircuitDirection::SourceToDestination,
                },
                ..
            }) if bytes.source_to_destination == 16
                && bytes.destination_to_source == 0
        ));
    }

    #[test]
    fn failed_initial_response_does_not_create_a_reservation() {
        let local = PeerId::from_public_key_protobuf(b"relay-failed-response");
        let remote = PeerId::from_public_key_protobuf(b"client-failed-response");
        let stream = StreamKey {
            conn_id: ConnectionId::new(31),
            stream_id: StreamId::new(1),
        };
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        establish(&mut agent, &remote, stream.conn_id);
        feed_hop(
            &mut agent,
            &remote,
            stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("reservation response");
        };

        agent.send_stream_result(
            token,
            Err(RelayServerSendError::Failed("queue full".into())),
            Now::from_millis(0),
        );

        assert!(!agent.has_reservation(&remote));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::Error(crate::RelayServerRuntimeError {
                kind: crate::RelayServerRuntimeErrorKind::SendStream,
                ..
            }))
        ));
    }

    #[test]
    fn reservation_expires_at_exact_monotonic_deadline_once() {
        let local = PeerId::from_public_key_protobuf(b"relay-expiry");
        let remote = PeerId::from_public_key_protobuf(b"client-expiry");
        let mut config = RelayServerConfig {
            reservation_duration_secs: 1,
            ..RelayServerConfig::default()
        };
        config.reservation_rate_limit_per_peer = None;
        config.reservation_rate_limit_per_ip = None;
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &remote,
            StreamKey {
                conn_id: ConnectionId::new(32),
                stream_id: StreamId::new(1),
            },
        );

        agent.handle_tick(Now::from_millis(999));
        assert!(agent.has_reservation(&remote));
        agent.handle_tick(Now::from_millis(1_000));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationClosed {
                peer_id,
                reason: crate::ReservationCloseReason::Expired,
            }) if peer_id == remote
        ));
        agent.handle_tick(Now::from_millis(2_000));
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn same_time_events_expire_control_streams_before_the_first_event() {
        let local = PeerId::from_public_key_protobuf(b"relay-same-timeout");
        let peer = PeerId::from_public_key_protobuf(b"peer-same-timeout");
        let config = RelayServerConfig {
            control_stream_timeout_ms: 5,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        let stream = StreamKey {
            conn_id: ConnectionId::new(34),
            stream_id: StreamId::new(1),
        };
        establish(&mut agent, &peer, stream.conn_id);
        agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer,
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::from_millis(0),
        );

        let first = SwarmEvent::ConnectionEstablished {
            peer_id: PeerId::from_public_key_protobuf(b"first-at-deadline"),
            conn_id: ConnectionId::new(35),
        };
        let second = SwarmEvent::ConnectionEstablished {
            peer_id: PeerId::from_public_key_protobuf(b"second-at-deadline"),
            conn_id: ConnectionId::new(36),
        };
        agent.handle_event(&first, false, Now::from_millis(5));
        assert!(!agent.owns_stream(stream));
        agent.handle_event(&second, false, Now::from_millis(5));

        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::ResetStream { stream: reset, .. }) if reset == stream
        ));
        assert_eq!(io_action(&mut agent), None);
    }

    #[test]
    fn paused_reservation_is_denied_without_consuming_capacity() {
        let local = PeerId::from_public_key_protobuf(b"relay-paused");
        let remote = PeerId::from_public_key_protobuf(b"client-paused");
        let mut agent = RelayServerAgent::new(local, RelayServerConfig::default()).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        agent.set_accepting(false);
        let stream = StreamKey {
            conn_id: ConnectionId::new(33),
            stream_id: StreamId::new(1),
        };
        establish(&mut agent, &remote, stream.conn_id);
        feed_hop(
            &mut agent,
            &remote,
            stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationDenied {
                peer_id,
                status: Status::ReservationRefused,
            }) if peer_id == remote
        ));
        assert_eq!(agent.reservation_count(), 0);
    }

    #[test]
    fn paused_connect_is_permission_denied_without_reserving_capacity() {
        let mut agent = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"relay-paused-connect"),
            RelayServerConfig::default(),
        )
        .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let destination = PeerId::from_public_key_protobuf(b"paused-connect-destination");
        let source = PeerId::from_public_key_protobuf(b"paused-connect-source");
        reserve(
            &mut agent,
            &destination,
            StreamKey {
                conn_id: ConnectionId::new(331),
                stream_id: StreamId::new(1),
            },
        );
        establish(&mut agent, &source, ConnectionId::new(332));
        agent.set_accepting(false);
        feed_hop(
            &mut agent,
            &source,
            StreamKey {
                conn_id: ConnectionId::new(332),
                stream_id: StreamId::new(1),
            },
            HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: destination.to_bytes(),
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitDenied {
                status: Status::PermissionDenied,
                ..
            })
        ));
        assert_eq!(agent.circuit_count(), 0);
        assert!(!matches!(
            io_action(&mut agent),
            Some(RelayServerAction::OpenStream { .. })
        ));
    }

    #[test]
    fn full_capacity_renewal_replaces_only_after_delivery() {
        let local = PeerId::from_public_key_protobuf(b"relay-renewal");
        let remote = PeerId::from_public_key_protobuf(b"client-renewal");
        let config = RelayServerConfig {
            max_reservations: 1,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &remote,
            StreamKey {
                conn_id: ConnectionId::new(34),
                stream_id: StreamId::new(1),
            },
        );
        let renewal = StreamKey {
            conn_id: ConnectionId::new(34),
            stream_id: StreamId::new(2),
        };
        feed_hop(
            &mut agent,
            &remote,
            renewal,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("renewal response");
        };
        agent.send_stream_result(
            token,
            Err(RelayServerSendError::Failed("backpressure".into())),
            Now::from_millis(10),
        );
        assert_eq!(agent.reservation_connection(&remote), Some(renewal.conn_id));
        assert_eq!(agent.reservation_count(), 1);
    }

    #[test]
    fn renewal_spends_no_rate_token() {
        let remote = PeerId::from_public_key_protobuf(b"client-renewal-token");
        let conn_id = ConnectionId::new(343);
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: Some(RateLimit {
                capacity: 1,
                refill_interval_ms: 1_000_000,
            }),
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"relay-renewal-token"),
            config,
        )
        .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &remote,
            StreamKey {
                conn_id,
                stream_id: StreamId::new(1),
            },
        );
        for stream_id in [2, 3] {
            let stream = StreamKey {
                conn_id,
                stream_id: StreamId::new(stream_id),
            };
            feed_hop(&mut agent, &remote, stream, reserve_request(), &[]);
            let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
                panic!("renewal response");
            };
            agent.send_stream_result(token, Ok(()), Now::from_millis(0));
            assert!(matches!(
                agent.poll_event(),
                Some(RelayServerEvent::ReservationAccepted { renewed: true, .. })
            ));
            while io_action(&mut agent).is_some() {}
        }
    }

    #[test]
    fn pending_reservation_response_holds_peer_and_global_capacity() {
        let config = RelayServerConfig {
            max_reservations: 1,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"relay-pending-reservation"),
            config,
        )
        .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let first = PeerId::from_public_key_protobuf(b"first-pending-reservation");
        let second = PeerId::from_public_key_protobuf(b"second-pending-reservation");
        let first_conn = ConnectionId::new(341);
        establish(&mut agent, &first, first_conn);
        feed_hop(
            &mut agent,
            &first,
            StreamKey {
                conn_id: first_conn,
                stream_id: StreamId::new(1),
            },
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        let RelayServerAction::SendStream {
            token: first_token, ..
        } = io_action(&mut agent).unwrap()
        else {
            panic!("first reservation response");
        };

        for (peer_id, conn_id, stream_id) in [
            (first.clone(), first_conn, StreamId::new(2)),
            (second.clone(), ConnectionId::new(342), StreamId::new(1)),
        ] {
            if peer_id == second {
                establish(&mut agent, &peer_id, conn_id);
            }
            feed_hop(
                &mut agent,
                &peer_id,
                StreamKey { conn_id, stream_id },
                HopMessage {
                    kind: HopMessageType::Reserve,
                    peer: None,
                    reservation: None,
                    limit: None,
                    status: None,
                },
                &[],
            );
            assert!(matches!(
                agent.poll_event(),
                Some(RelayServerEvent::ReservationDenied {
                    status: Status::ResourceLimitExceeded,
                    ..
                })
            ));
            let _ = io_action(&mut agent);
        }

        agent.send_stream_result(first_token, Ok(()), Now::from_millis(1));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationAccepted { renewed: false, .. })
        ));
        assert_eq!(agent.reservation_count(), 1);
    }

    #[test]
    fn timed_out_reservation_response_cannot_commit_from_a_stale_send_result() {
        let config = RelayServerConfig {
            control_stream_timeout_ms: 10,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"relay-stale-reservation-response"),
            config,
        )
        .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let peer = PeerId::from_public_key_protobuf(b"stale-reservation-response");
        let stream = StreamKey {
            conn_id: ConnectionId::new(344),
            stream_id: StreamId::new(1),
        };
        establish(&mut agent, &peer, stream.conn_id);
        feed_hop(
            &mut agent,
            &peer,
            stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("reservation response");
        };

        agent.handle_tick(Now::from_millis(10));
        agent.send_stream_result(token, Ok(()), Now::from_millis(10));

        assert!(!agent.has_reservation(&peer));
        assert!(
            !core::iter::from_fn(|| agent.poll_event())
                .any(|event| matches!(event, RelayServerEvent::ReservationAccepted { .. }))
        );
    }

    #[test]
    fn terminal_hop_cleanup_releases_pending_reservation_capacity() {
        for close_connection in [false, true] {
            let config = RelayServerConfig {
                max_reservations: 1,
                reservation_rate_limit_per_peer: None,
                reservation_rate_limit_per_ip: None,
                ..RelayServerConfig::default()
            };
            let mut agent = RelayServerAgent::new(
                PeerId::from_public_key_protobuf(b"relay-terminal-reservation"),
                config,
            )
            .unwrap();
            agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
            let first = PeerId::from_public_key_protobuf(b"first-terminal-reservation");
            let first_stream = StreamKey {
                conn_id: ConnectionId::new(345),
                stream_id: StreamId::new(1),
            };
            establish(&mut agent, &first, first_stream.conn_id);
            feed_hop(
                &mut agent,
                &first,
                first_stream,
                HopMessage {
                    kind: HopMessageType::Reserve,
                    peer: None,
                    reservation: None,
                    limit: None,
                    status: None,
                },
                &[],
            );
            let _ = io_action(&mut agent);

            let terminal = if close_connection {
                SwarmEvent::ConnectionClosed {
                    peer_id: first,
                    conn_id: first_stream.conn_id,
                }
            } else {
                SwarmEvent::StreamClosed {
                    peer_id: first,
                    conn_id: first_stream.conn_id,
                    stream_id: first_stream.stream_id,
                }
            };
            agent.handle_event(&terminal, false, Now::from_millis(1));
            while io_action(&mut agent).is_some() {}

            let second = PeerId::from_public_key_protobuf(b"second-terminal-reservation");
            let second_stream = StreamKey {
                conn_id: ConnectionId::new(346),
                stream_id: StreamId::new(1),
            };
            establish(&mut agent, &second, second_stream.conn_id);
            feed_hop(
                &mut agent,
                &second,
                second_stream,
                HopMessage {
                    kind: HopMessageType::Reserve,
                    peer: None,
                    reservation: None,
                    limit: None,
                    status: None,
                },
                &[],
            );

            assert!(!matches!(
                agent.poll_event(),
                Some(RelayServerEvent::ReservationDenied { .. })
            ));
            assert!(matches!(
                io_action(&mut agent),
                Some(RelayServerAction::SendStream {
                    peer_id,
                    stream,
                    ..
                }) if peer_id == second && stream == second_stream
            ));
        }
    }

    fn single_reservation_agent(duration_secs: u64) -> (RelayServerAgent, PeerId) {
        let config = RelayServerConfig {
            reservation_duration_secs: duration_secs,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent =
            RelayServerAgent::new(PeerId::from_public_key_protobuf(b"relay-replace"), config)
                .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let remote = PeerId::from_public_key_protobuf(b"client-replace");
        reserve(
            &mut agent,
            &remote,
            StreamKey {
                conn_id: ConnectionId::new(35),
                stream_id: StreamId::new(1),
            },
        );
        (agent, remote)
    }

    #[test]
    fn direct_replacement_rebinds_reservation_with_its_original_expiry() {
        let (mut agent, remote) = single_reservation_agent(1);
        let new = ConnectionId::new(36);
        replace(&mut agent, &remote, ConnectionId::new(35), new, false, 500);
        assert_eq!(agent.reservation_connection(&remote), Some(new));
        assert_eq!(agent.poll_event(), None);

        // A stale close for the old connection cannot touch the rebound reservation.
        agent.handle_event(
            &SwarmEvent::ConnectionClosed {
                peer_id: remote.clone(),
                conn_id: ConnectionId::new(35),
            },
            false,
            Now::from_millis(500),
        );
        assert_eq!(agent.reservation_connection(&remote), Some(new));

        agent.handle_tick(Now::from_millis(1_000));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationClosed {
                reason: crate::ReservationCloseReason::Expired,
                ..
            })
        ));
    }

    #[test]
    fn circuit_replacement_closes_reservation() {
        let (mut agent, remote) = single_reservation_agent(60);
        replace(
            &mut agent,
            &remote,
            ConnectionId::new(35),
            ConnectionId::new(36),
            true,
            1,
        );
        assert!(!agent.has_reservation(&remote));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationClosed {
                peer_id,
                reason: crate::ReservationCloseReason::ConnectionClosed,
            }) if peer_id == remote
        ));
    }

    #[test]
    fn address_sources_use_first_non_empty_and_invalid_replacement_is_atomic() {
        let local = PeerId::from_public_key_protobuf(b"relay-address-source");
        let mut agent = RelayServerAgent::new(local, RelayServerConfig::default()).unwrap();
        let listener = Multiaddr::from_str("/ip4/192.0.2.1/tcp/1").unwrap();
        let confirmed = Multiaddr::from_str("/ip4/192.0.2.2/tcp/2").unwrap();
        let explicit = Multiaddr::from_str("/ip4/192.0.2.3/tcp/3").unwrap();
        agent.set_listener_addrs(vec![listener.clone()]).unwrap();
        assert_eq!(agent.selected_addrs(), [listener]);
        agent.set_confirmed_addrs(vec![confirmed.clone()]).unwrap();
        assert_eq!(agent.selected_addrs(), core::slice::from_ref(&confirmed));
        agent
            .replace_announce_addrs(vec![explicit.clone()])
            .unwrap();
        assert_eq!(agent.selected_addrs(), core::slice::from_ref(&explicit));

        assert!(
            agent
                .replace_announce_addrs(vec![Multiaddr::from_str("/ip4/0.0.0.0/tcp/9").unwrap(),])
                .is_err()
        );
        assert_eq!(agent.selected_addrs(), [explicit]);
        agent.replace_announce_addrs(Vec::new()).unwrap();
        assert_eq!(agent.selected_addrs(), [confirmed]);
    }

    #[test]
    fn hop_over_circuit_negotiates_then_denies_with_permission_status() {
        let local = PeerId::from_public_key_protobuf(b"relay-circuit-hop");
        let remote = PeerId::from_public_key_protobuf(b"client-circuit-hop");
        let conn_id = ConnectionId::new(37);
        let stream = StreamKey {
            conn_id,
            stream_id: StreamId::new(1),
        };
        let mut agent = RelayServerAgent::new(local, RelayServerConfig::default()).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: remote.clone(),
                conn_id,
            },
            true,
            Now::from_millis(0),
        );
        agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: remote.clone(),
                conn_id,
                stream_id: stream.stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            true,
            Now::from_millis(0),
        );
        let request = encode_frame(
            &HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            }
            .encode(),
        );
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: remote.clone(),
                conn_id,
                stream_id: stream.stream_id,
                data: Bytes::from(request),
            },
            true,
            Now::from_millis(0),
        );

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationDenied {
                peer_id,
                status: Status::PermissionDenied,
            }) if peer_id == remote
        ));
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::SendStream { .. })
        ));
    }

    #[test]
    fn stored_circuit_connection_classification_denies_reserve() {
        let local = PeerId::from_public_key_protobuf(b"relay-stored-circuit");
        let remote = PeerId::from_public_key_protobuf(b"client-stored-circuit");
        let conn_id = ConnectionId::new(381);
        let stream = StreamKey {
            conn_id,
            stream_id: StreamId::new(1),
        };
        let mut agent = RelayServerAgent::new(local, RelayServerConfig::default()).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: remote.clone(),
                conn_id,
            },
            true,
            Now::from_millis(0),
        );

        feed_hop(
            &mut agent,
            &remote,
            stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationDenied {
                status: Status::PermissionDenied,
                ..
            })
        ));
        assert_eq!(agent.reservation_count(), 0);
    }

    #[test]
    fn hop_cap_stream_is_owned_until_its_terminal_event() {
        let local = PeerId::from_public_key_protobuf(b"relay-hop-cap");
        let remote = PeerId::from_public_key_protobuf(b"client-hop-cap");
        let conn_id = ConnectionId::new(38);
        let stream = StreamKey {
            conn_id,
            stream_id: StreamId::new(1),
        };
        let config = RelayServerConfig {
            max_pending_hop_requests_per_connection: 0,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        establish(&mut agent, &remote, conn_id);

        assert!(agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: remote.clone(),
                conn_id,
                stream_id: stream.stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::from_millis(0),
        ));
        assert!(agent.owns_stream(stream));
        let RelayServerAction::ResetStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("capped stream is reset");
        };
        agent.reset_stream_result(token, Ok(()), Now::from_millis(0));
        assert!(agent.owns_stream(stream));

        assert!(agent.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: remote,
                conn_id,
                stream_id: stream.stream_id,
            },
            false,
            Now::from_millis(1),
        ));
        assert!(!agent.owns_stream(stream));
    }

    #[test]
    fn accepted_reservation_disarms_its_hop_control_timeout() {
        let local = PeerId::from_public_key_protobuf(b"relay-disarm");
        let remote = PeerId::from_public_key_protobuf(b"client-disarm");
        let config = RelayServerConfig {
            control_stream_timeout_ms: 5,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &remote,
            StreamKey {
                conn_id: ConnectionId::new(39),
                stream_id: StreamId::new(1),
            },
        );

        agent.handle_tick(Now::from_millis(5));

        assert!(agent.has_reservation(&remote));
        assert_eq!(io_action(&mut agent), None);
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn replacement_cancels_an_uncommitted_reserve_on_old() {
        let remote = PeerId::from_public_key_protobuf(b"client-old-input");
        let old_stream = StreamKey {
            conn_id: ConnectionId::new(40),
            stream_id: StreamId::new(1),
        };
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent =
            RelayServerAgent::new(PeerId::from_public_key_protobuf(b"relay-old-input"), config)
                .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        establish(&mut agent, &remote, old_stream.conn_id);
        feed_hop(&mut agent, &remote, old_stream, reserve_request(), &[]);
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("reservation response");
        };

        replace(
            &mut agent,
            &remote,
            old_stream.conn_id,
            ConnectionId::new(41),
            false,
            1,
        );
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));

        assert!(!agent.has_reservation(&remote));
        assert!(!agent.owns_stream(old_stream));
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn directional_equality_stays_open_and_failed_send_counts_no_bytes() {
        let config = RelayServerConfig {
            max_circuit_bytes: 3,
            ..RelayServerConfig::default()
        };
        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(config, 10);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
                data: Bytes::from_static(b"abc"),
            },
            false,
            Now::from_millis(11),
        );
        let RelayServerAction::SendStream { token, stream, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("source payload forward");
        };
        assert_eq!(stream, stop_stream);
        agent.send_stream_result(token, Ok(()), Now::from_millis(11));
        assert_eq!(agent.poll_event(), None, "equality remains open");

        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from_static(b"not-counted"),
            },
            false,
            Now::from_millis(12),
        );
        let RelayServerAction::SendStream { token, stream, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("destination payload forward");
        };
        assert_eq!(stream, source_stream);
        agent.send_stream_result(
            token,
            Err(RelayServerSendError::Failed("queue rejected".into())),
            Now::from_millis(12),
        );
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                bytes: CircuitByteCounts {
                    source_to_destination: 3,
                    destination_to_source: 0,
                },
                reason: CircuitCloseReason::ForwardFailed {
                    direction: CircuitDirection::DestinationToSource,
                },
                ..
            })
        ));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::SendStream,
                ..
            }))
        ));
    }

    #[test]
    fn circuit_duration_is_commit_relative_and_terminal_once() {
        let config = RelayServerConfig {
            max_circuit_duration_secs: 1,
            ..RelayServerConfig::default()
        };
        let (mut agent, source, _, source_stream, _) = connected_circuit(config, 10);
        agent.handle_tick(Now::from_millis(1_009));
        assert_eq!(agent.poll_event(), None);
        agent.handle_tick(Now::from_millis(1_010));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::DurationLimit,
                ..
            })
        ));
        agent.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            Now::from_millis(1_010),
        );
        agent.handle_tick(Now::from_millis(2_000));
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn write_stop_on_a_circuit_leg_resets_it_before_teardown() {
        let (mut agent, _, destination, _, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        let claimed = agent.handle_event(
            &SwarmEvent::StreamWriteStopped {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                error_code: 0,
            },
            false,
            Now::from_millis(1),
        );
        assert!(claimed);
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::ResetStream { stream, .. }) if stream == stop_stream
        ));
    }

    #[test]
    fn bidirectional_eof_propagates_half_closes_and_finishes_cleanly() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        agent.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            Now::from_millis(1),
        );
        let RelayServerAction::CloseStreamWrite { token, stream, .. } =
            io_action(&mut agent).unwrap()
        else {
            panic!("source EOF propagates");
        };
        assert_eq!(stream, stop_stream);
        agent.close_stream_write_result(token, Ok(()), Now::from_millis(1));
        assert_eq!(agent.poll_event(), None);

        agent.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
            },
            false,
            Now::from_millis(2),
        );
        let RelayServerAction::CloseStreamWrite { token, stream, .. } =
            io_action(&mut agent).unwrap()
        else {
            panic!("destination EOF propagates");
        };
        assert_eq!(stream, source_stream);
        agent.close_stream_write_result(token, Ok(()), Now::from_millis(2));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::Eof,
                bytes,
                ..
            }) if bytes == CircuitByteCounts::default()
        ));
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn control_timeouts_release_hop_and_stop_ownership() {
        let local = PeerId::from_public_key_protobuf(b"relay-timeouts");
        let peer = PeerId::from_public_key_protobuf(b"peer-timeouts");
        let config = RelayServerConfig {
            control_stream_timeout_ms: 5,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config.clone()).unwrap();
        let hop = StreamKey {
            conn_id: ConnectionId::new(80),
            stream_id: StreamId::new(1),
        };
        establish(&mut agent, &peer, hop.conn_id);
        agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer,
                conn_id: hop.conn_id,
                stream_id: hop.stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::from_millis(0),
        );
        agent.handle_tick(Now::from_millis(5));
        assert!(!agent.owns_stream(hop));
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::ResetStream { stream, .. }) if stream == hop
        ));

        let (mut agent, _, _, _, stop) = pending_stop(config, 0);
        agent.handle_tick(Now::from_millis(5));
        assert!(agent.pending_circuits.is_empty());
        assert!(!agent.owns_stream(stop));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitDenied {
                status: Status::ConnectionFailed,
                ..
            })
        ));
    }

    #[test]
    fn stop_refusal_statuses_map_exactly_to_hop() {
        for status in [Status::ResourceLimitExceeded, Status::PermissionDenied] {
            let (mut agent, _, destination, _, stop) =
                pending_stop(RelayServerConfig::default(), 0);
            agent.handle_event(
                &SwarmEvent::StreamData {
                    peer_id: destination,
                    conn_id: stop.conn_id,
                    stream_id: stop.stream_id,
                    data: Bytes::from(encode_stop_status(status).unwrap()),
                },
                false,
                Now::from_millis(1),
            );
            assert!(matches!(
                agent.poll_event(),
                Some(RelayServerEvent::CircuitDenied { status: found, .. }) if found == status
            ));
            assert!(agent.pending_circuits.is_empty());
        }
    }

    #[test]
    fn reservation_ip_limit_uses_the_first_ip_on_the_exact_connection() {
        let local = PeerId::from_public_key_protobuf(b"relay-ip-limit");
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: Some(RateLimit {
                capacity: 1,
                refill_interval_ms: 1_000,
            }),
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        for (index, tail) in [[198, 51, 100, 1], [198, 51, 100, 2]]
            .into_iter()
            .enumerate()
        {
            let peer = PeerId::from_public_key_protobuf(&[b'p', index as u8]);
            let conn_id = ConnectionId::new(90 + index as u64);
            let stream = StreamKey {
                conn_id,
                stream_id: StreamId::new(1),
            };
            establish(&mut agent, &peer, conn_id);
            agent.set_connection_addr(
                conn_id,
                Multiaddr::from_protocols(vec![
                    Protocol::Ip4([203, 0, 113, 9]),
                    Protocol::Tcp(4001),
                    Protocol::Ip4(tail),
                ]),
            );
            feed_hop(
                &mut agent,
                &peer,
                stream,
                HopMessage {
                    kind: HopMessageType::Reserve,
                    peer: None,
                    reservation: None,
                    limit: None,
                    status: None,
                },
                &[],
            );
            if index == 0 {
                let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap()
                else {
                    panic!("first IP token admits");
                };
                agent.send_stream_result(token, Ok(()), Now::from_millis(0));
                let _ = agent.poll_event();
                let _ = io_action(&mut agent);
            } else {
                assert!(matches!(
                    agent.poll_event(),
                    Some(RelayServerEvent::ReservationDenied {
                        status: Status::ResourceLimitExceeded,
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_shares_the_ipv4_rate_limit_bucket() {
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: Some(RateLimit {
                capacity: 1,
                refill_interval_ms: 1_000,
            }),
            ..RelayServerConfig::default()
        };
        let mut agent =
            RelayServerAgent::new(PeerId::from_public_key_protobuf(b"relay-mapped-ip"), config)
                .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let addresses = [
            Multiaddr::from_protocols(vec![Protocol::Ip4([203, 0, 113, 9]), Protocol::Tcp(1)]),
            Multiaddr::from_protocols(vec![
                Protocol::Ip6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 9]),
                Protocol::Tcp(1),
            ]),
        ];
        for (index, address) in addresses.into_iter().enumerate() {
            let peer = PeerId::from_public_key_protobuf(&[b'm', index as u8]);
            let conn_id = ConnectionId::new(95 + index as u64);
            establish(&mut agent, &peer, conn_id);
            agent.set_connection_addr(conn_id, address);
            feed_hop(
                &mut agent,
                &peer,
                StreamKey {
                    conn_id,
                    stream_id: StreamId::new(1),
                },
                HopMessage {
                    kind: HopMessageType::Reserve,
                    peer: None,
                    reservation: None,
                    limit: None,
                    status: None,
                },
                &[],
            );
            if index == 0 {
                let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap()
                else {
                    panic!("IPv4 request admitted");
                };
                agent.send_stream_result(token, Ok(()), Now::from_millis(0));
                let _ = agent.poll_event();
                let _ = io_action(&mut agent);
            } else {
                assert!(matches!(
                    agent.poll_event(),
                    Some(RelayServerEvent::ReservationDenied {
                        status: Status::ResourceLimitExceeded,
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn reservation_addresses_truncate_to_a_wire_prefix_and_empty_refuses() {
        let local = PeerId::from_public_key_protobuf(b"relay-address-wire");
        let mut agent = RelayServerAgent::new(local.clone(), RelayServerConfig::default()).unwrap();
        let addrs: Vec<_> = (0..160)
            .map(|index| {
                Multiaddr::from_str(&format!(
                    "/dns4/{index}.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example/tcp/4001"
                ))
                .unwrap()
            })
            .collect();
        agent.replace_announce_addrs(addrs.clone()).unwrap();
        let (reservation, limit) = agent.reservation_wire(Some(1)).unwrap();
        assert!(!reservation.addrs.is_empty());
        assert!(reservation.addrs.len() < addrs.len());
        assert_eq!(reservation.voucher, None);
        let expected: Vec<_> = addrs
            .iter()
            .take(reservation.addrs.len())
            .map(|address| {
                let mut address = address.clone();
                address.push(Protocol::P2p(local.clone()));
                address.to_bytes()
            })
            .collect();
        assert_eq!(reservation.addrs, expected);
        let encoded = encode_hop_status(Status::Ok, Some(reservation), Some(limit)).unwrap();
        assert!(matches!(
            decode_frame(&encoded),
            FrameDecode::Complete { payload, consumed }
                if payload.len() <= MAX_MESSAGE_SIZE && consumed == encoded.len()
        ));

        let peer = PeerId::from_public_key_protobuf(b"empty-address-client");
        let stream = StreamKey {
            conn_id: ConnectionId::new(100),
            stream_id: StreamId::new(1),
        };
        let mut empty = RelayServerAgent::new(local, RelayServerConfig::default()).unwrap();
        establish(&mut empty, &peer, stream.conn_id);
        feed_hop(
            &mut empty,
            &peer,
            stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        assert!(matches!(
            empty.poll_event(),
            Some(RelayServerEvent::ReservationDenied {
                status: Status::ReservationRefused,
                ..
            })
        ));
    }

    #[test]
    fn self_and_global_circuit_capacity_are_enforced() {
        let peer = PeerId::from_public_key_protobuf(b"self-circuit-peer");
        let mut config = RelayServerConfig {
            max_circuits: 4,
            max_circuits_per_peer: 2,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            circuit_rate_limit_per_peer: None,
            circuit_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"self-circuit-relay"),
            config.clone(),
        )
        .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &peer,
            StreamKey {
                conn_id: ConnectionId::new(110),
                stream_id: StreamId::new(1),
            },
        );
        for stream_id in [2, 3, 4] {
            feed_hop(
                &mut agent,
                &peer,
                StreamKey {
                    conn_id: ConnectionId::new(110),
                    stream_id: StreamId::new(stream_id),
                },
                HopMessage {
                    kind: HopMessageType::Connect,
                    peer: Some(Peer {
                        id: peer.to_bytes(),
                        addrs: Vec::new(),
                    }),
                    reservation: None,
                    limit: None,
                    status: None,
                },
                &[],
            );
            if stream_id <= 3 {
                assert!(matches!(
                    io_action(&mut agent),
                    Some(RelayServerAction::OpenStream { .. })
                ));
            } else {
                assert!(matches!(
                    agent.poll_event(),
                    Some(RelayServerEvent::CircuitDenied {
                        status: Status::ResourceLimitExceeded,
                        ..
                    })
                ));
            }
        }

        config.max_circuits = 0;
        let mut zero = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"zero-global-relay"),
            config,
        )
        .unwrap();
        zero.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let destination = PeerId::from_public_key_protobuf(b"zero-global-destination");
        let source = PeerId::from_public_key_protobuf(b"zero-global-source");
        reserve(
            &mut zero,
            &destination,
            StreamKey {
                conn_id: ConnectionId::new(120),
                stream_id: StreamId::new(1),
            },
        );
        establish(&mut zero, &source, ConnectionId::new(121));
        feed_hop(
            &mut zero,
            &source,
            StreamKey {
                conn_id: ConnectionId::new(121),
                stream_id: StreamId::new(1),
            },
            HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: destination.to_bytes(),
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        assert!(matches!(
            zero.poll_event(),
            Some(RelayServerEvent::CircuitDenied {
                status: Status::ResourceLimitExceeded,
                ..
            })
        ));
    }

    #[test]
    fn zero_circuit_limits_are_advertised_and_remain_unlimited() {
        let config = RelayServerConfig {
            max_circuit_duration_secs: 0,
            max_circuit_bytes: 0,
            ..RelayServerConfig::default()
        };
        let mut probe = RelayServerAgent::new(
            PeerId::from_public_key_protobuf(b"zero-limit-probe"),
            config.clone(),
        )
        .unwrap();
        probe.replace_announce_addrs(vec![direct_addr()]).unwrap();
        let (reservation, limit) = probe.reservation_wire(None).unwrap();
        assert_eq!(limit.duration, Some(0));
        assert_eq!(limit.data, Some(0));
        let encoded = encode_hop_status(Status::Ok, Some(reservation), Some(limit)).unwrap();
        let FrameDecode::Complete { payload, .. } = decode_frame(&encoded) else {
            panic!("zero limit response is framed");
        };
        let advertised = HopMessage::decode(payload).unwrap().limit.unwrap();
        assert_eq!(advertised.duration, Some(0));
        assert_eq!(advertised.data, Some(0));

        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(config, 0);
        for (peer_id, stream, data) in [
            (source, source_stream, vec![1; 256]),
            (destination, stop_stream, vec![2; 256]),
        ] {
            agent.handle_event(
                &SwarmEvent::StreamData {
                    peer_id,
                    conn_id: stream.conn_id,
                    stream_id: stream.stream_id,
                    data: Bytes::from(data),
                },
                false,
                Now::from_millis(1),
            );
            let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
                panic!("unlimited forwarding");
            };
            agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        }
        agent.handle_tick(Now::from_millis(1_000_000));
        assert!(agent.owns_stream(source_stream));
        assert!(agent.owns_stream(stop_stream));
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn zero_stop_cap_denies_without_opening_a_stream() {
        let local = PeerId::from_public_key_protobuf(b"relay-stop-cap");
        let source = PeerId::from_public_key_protobuf(b"source-stop-cap");
        let destination = PeerId::from_public_key_protobuf(b"destination-stop-cap");
        let config = RelayServerConfig {
            max_pending_stop_requests_per_connection: 0,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            circuit_rate_limit_per_peer: None,
            circuit_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        reserve(
            &mut agent,
            &destination,
            StreamKey {
                conn_id: ConnectionId::new(70),
                stream_id: StreamId::new(1),
            },
        );
        establish(&mut agent, &source, ConnectionId::new(71));
        feed_hop(
            &mut agent,
            &source,
            StreamKey {
                conn_id: ConnectionId::new(71),
                stream_id: StreamId::new(2),
            },
            HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: destination.to_bytes(),
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitDenied {
                status: Status::ResourceLimitExceeded,
                ..
            })
        ));
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::SendStream { .. })
        ));
    }

    #[test]
    fn failed_hop_success_delivery_cleans_both_precommit_legs() {
        let (mut agent, _, _, source_stream, stop_stream, token) =
            pending_circuit_success(RelayServerConfig::default(), 0);

        agent.send_stream_result(
            token,
            Err(RelayServerSendError::Failed("source queue failed".into())),
            Now::from_millis(0),
        );

        assert!(!agent.owns_stream(source_stream));
        assert!(!agent.owns_stream(stop_stream));
        let reset_streams: Vec<_> = core::iter::from_fn(|| io_action(&mut agent))
            .filter_map(|action| match action {
                RelayServerAction::ResetStream { stream, .. } => Some(stream),
                _ => None,
            })
            .collect();
        assert!(reset_streams.contains(&source_stream));
        assert!(reset_streams.contains(&stop_stream));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::SendStream,
                ..
            }))
        ));
        assert_eq!(agent.poll_event(), None, "no uncommitted lifecycle");
    }

    #[test]
    fn source_payload_arriving_during_stop_rtt_is_forwarded_after_commit() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            pending_stop(RelayServerConfig::default(), 0);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
                data: Bytes::from_static(b"during-stop-rtt"),
            },
            false,
            Now::from_millis(1),
        );
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(encode_stop_status(Status::Ok).unwrap()),
            },
            false,
            Now::from_millis(1),
        );
        let RelayServerAction::SendStream { token, .. } = io_action(&mut agent).unwrap() else {
            panic!("HOP success");
        };
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        let _ = agent.poll_event();
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::SendStream { stream, data, .. })
                if stream == stop_stream && data[..] == b"during-stop-rtt"[..]
        ));
    }

    #[test]
    fn precommit_payload_is_bounded_in_both_directions() {
        for direction in [
            CircuitDirection::SourceToDestination,
            CircuitDirection::DestinationToSource,
        ] {
            let (mut agent, source, destination, source_stream, stop_stream, token) =
                pending_circuit_success(RelayServerConfig::default(), 0);
            let (peer_id, stream) = match direction {
                CircuitDirection::SourceToDestination => (source, source_stream),
                CircuitDirection::DestinationToSource => (destination, stop_stream),
            };
            agent.handle_event(
                &SwarmEvent::StreamData {
                    peer_id,
                    conn_id: stream.conn_id,
                    stream_id: stream.stream_id,
                    data: Bytes::from(vec![0; MAX_PENDING_BRIDGE_SIZE + 1]),
                },
                false,
                Now::from_millis(1),
            );
            agent.send_stream_result(token, Ok(()), Now::from_millis(1));

            assert!(!agent.owns_stream(source_stream));
            assert!(!agent.owns_stream(stop_stream));
            assert!(!matches!(
                agent.poll_event(),
                Some(RelayServerEvent::CircuitOpened { .. })
            ));
        }
    }

    #[test]
    fn source_reset_while_connect_is_pending_cleans_the_stop_leg() {
        let (mut agent, source, _, source_stream, stop_stream, _) =
            pending_circuit_success(RelayServerConfig::default(), 0);

        agent.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            Now::from_millis(1),
        );

        assert!(agent.pending_circuits.is_empty());
        assert!(!agent.owns_stream(source_stream));
        assert!(!agent.owns_stream(stop_stream));
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::ResetStream { stream, .. }) if stream == stop_stream
        ));
        assert_eq!(io_action(&mut agent), None);
        assert_eq!(agent.poll_event(), None, "no uncommitted lifecycle");
    }

    #[test]
    fn source_eof_while_connect_is_pending_propagates_after_commit() {
        let (mut agent, source, _, source_stream, stop_stream, token) =
            pending_circuit_success(RelayServerConfig::default(), 0);

        agent.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            Now::from_millis(1),
        );
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitOpened { .. })
        ));
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::CloseStreamWrite { stream, .. }) if stream == stop_stream
        ));
    }

    #[test]
    fn destination_eof_while_connect_is_pending_propagates_after_commit() {
        let (mut agent, _, destination, source_stream, stop_stream, token) =
            pending_circuit_success(RelayServerConfig::default(), 0);

        agent.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
            },
            false,
            Now::from_millis(1),
        );
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitOpened { .. })
        ));
        assert!(matches!(
            io_action(&mut agent),
            Some(RelayServerAction::CloseStreamWrite { stream, .. }) if stream == source_stream
        ));
    }

    #[test]
    fn dual_pending_eof_propagates_both_halves_after_buffered_payload() {
        let (mut agent, source, destination, source_stream, stop_stream, token) =
            pending_circuit_success(RelayServerConfig::default(), 0);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: source.clone(),
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
                data: Bytes::from_static(b"buffered"),
            },
            false,
            Now::from_millis(1),
        );
        for (peer_id, stream) in [(source, source_stream), (destination, stop_stream)] {
            agent.handle_event(
                &SwarmEvent::StreamRemoteWriteClosed {
                    peer_id,
                    conn_id: stream.conn_id,
                    stream_id: stream.stream_id,
                },
                false,
                Now::from_millis(1),
            );
        }
        let buffered = actions(&mut agent);
        assert_eq!(
            acked(&buffered, source_stream),
            0,
            "pre-commit payload waits to be forwarded"
        );
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitOpened { .. })
        ));

        // The destination's FIN waits behind the buffered payload; the
        // source's goes at once.
        let committed = actions(&mut agent);
        let forward = sent(&committed, stop_stream, b"buffered");
        let close_tokens = |actions: &[RelayServerAction]| -> Vec<_> {
            actions
                .iter()
                .filter_map(|action| match action {
                    RelayServerAction::CloseStreamWrite { token, stream, .. } => {
                        Some((*token, *stream))
                    }
                    _ => None,
                })
                .collect()
        };
        let source_close = close_tokens(&committed);
        assert_eq!(source_close.len(), 1, "{committed:?}");
        assert_eq!(source_close[0].1, source_stream);

        agent.send_stream_result(forward, Ok(()), Now::from_millis(1));
        let drained = actions(&mut agent);
        let destination_close = close_tokens(&drained);
        assert_eq!(destination_close.len(), 1, "{drained:?}");
        assert_eq!(destination_close[0].1, stop_stream);
        assert_eq!(
            acked(&drained, source_stream),
            8,
            "acknowledged once forwarded"
        );

        agent.close_stream_write_result(source_close[0].0, Ok(()), Now::from_millis(1));
        assert_eq!(agent.poll_event(), None, "one half close remains in flight");
        agent.close_stream_write_result(destination_close[0].0, Ok(()), Now::from_millis(1));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::Eof,
                bytes: CircuitByteCounts {
                    source_to_destination: 8,
                    destination_to_source: 0,
                },
                ..
            })
        ));
    }

    #[test]
    fn dual_pending_eof_close_failure_is_internal_failure() {
        let (mut agent, source, destination, source_stream, stop_stream, token) =
            pending_circuit_success(RelayServerConfig::default(), 0);
        for (peer_id, stream) in [(source, source_stream), (destination, stop_stream)] {
            agent.handle_event(
                &SwarmEvent::StreamRemoteWriteClosed {
                    peer_id,
                    conn_id: stream.conn_id,
                    stream_id: stream.stream_id,
                },
                false,
                Now::from_millis(1),
            );
        }
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        let _ = agent.poll_event();
        let RelayServerAction::CloseStreamWrite { token, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("first propagated half close");
        };

        agent.close_stream_write_result(token, Err("fin rejected".into()), Now::from_millis(1));

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::InternalFailure,
                ..
            })
        ));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::CloseStream,
                ..
            }))
        ));
    }

    #[test]
    fn replacing_a_leg_connection_closes_its_circuit() {
        for leg in [CircuitLeg::Source, CircuitLeg::Destination] {
            let (mut agent, source, destination, source_stream, stop_stream) =
                connected_circuit(RelayServerConfig::default(), 0);
            let (peer, old, other_stream) = match leg {
                CircuitLeg::Source => (&source, source_stream.conn_id, stop_stream),
                CircuitLeg::Destination => (&destination, stop_stream.conn_id, source_stream),
            };
            replace(&mut agent, peer, old, ConnectionId::new(62), false, 1);

            assert!(
                matches!(
                    agent.poll_event(),
                    Some(RelayServerEvent::CircuitClosed {
                        reason: CircuitCloseReason::ConnectionClosed { leg: closed },
                        ..
                    }) if closed == leg
                ),
                "{leg:?}"
            );
            assert_eq!(agent.circuit_count(), 0, "{leg:?}");
            assert!(
                matches!(
                    io_action(&mut agent),
                    Some(RelayServerAction::ResetStream { stream, .. }) if stream == other_stream
                ),
                "{leg:?}: the surviving leg's stream is reset"
            );
            // Only the destination's own reservation follows its connection.
            let reservation_conn = match leg {
                CircuitLeg::Source => stop_stream.conn_id,
                CircuitLeg::Destination => ConnectionId::new(62),
            };
            assert_eq!(
                agent.reservation_connection(&destination),
                Some(reservation_conn),
                "{leg:?}"
            );
        }
    }

    #[test]
    fn replacing_the_destination_fails_a_pending_connect() {
        let (mut agent, _, destination, source_stream, stop_stream) =
            pending_stop(RelayServerConfig::default(), 0);
        replace(
            &mut agent,
            &destination,
            stop_stream.conn_id,
            ConnectionId::new(62),
            false,
            1,
        );

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitDenied {
                status: Status::ConnectionFailed,
                ..
            })
        ));
        let actions: Vec<_> = core::iter::from_fn(|| io_action(&mut agent)).collect();
        assert!(
            actions.iter().any(|action| matches!(
                action,
                RelayServerAction::SendStream { stream, .. } if *stream == source_stream
            )),
            "the source hears the failure: {actions:?}"
        );
        assert!(agent.pending_circuits.is_empty());
        assert!(agent.stop_to_source.is_empty());
        assert!(!agent.owns_stream(stop_stream));
    }

    fn data(peer_id: &PeerId, stream: StreamKey, data: &'static [u8]) -> SwarmEvent {
        SwarmEvent::StreamData {
            peer_id: peer_id.clone(),
            conn_id: stream.conn_id,
            stream_id: stream.stream_id,
            data: Bytes::from_static(data),
        }
    }

    fn writable(peer_id: &PeerId, stream: StreamKey) -> SwarmEvent {
        SwarmEvent::StreamWritable {
            peer_id: peer_id.clone(),
            conn_id: stream.conn_id,
            stream_id: stream.stream_id,
        }
    }

    fn actions(agent: &mut RelayServerAgent) -> Vec<RelayServerAction> {
        core::iter::from_fn(|| agent.poll_action()).collect()
    }

    /// The token of the only send in `actions`, after checking its target
    /// and bytes.
    fn sent(actions: &[RelayServerAction], to: StreamKey, bytes: &[u8]) -> RelayServerToken {
        let sends: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                RelayServerAction::SendStream {
                    token,
                    stream,
                    data,
                    ..
                } => Some((*token, *stream, data.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1, "one send: {actions:?}");
        assert_eq!((sends[0].1, &sends[0].2[..]), (to, bytes), "{actions:?}");
        sends[0].0
    }

    fn acked(actions: &[RelayServerAction], stream: StreamKey) -> usize {
        actions
            .iter()
            .filter_map(|action| match action {
                RelayServerAction::AckStream { stream: s, bytes } if *s == stream => Some(*bytes),
                _ => None,
            })
            .sum()
    }

    fn full(unsent: &'static [u8]) -> Result<(), RelayServerSendError> {
        Err(RelayServerSendError::Full {
            unsent: Bytes::from_static(unsent),
        })
    }

    #[test]
    fn a_full_destination_pauses_the_source_until_writable() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        agent.handle_event(&data(&source, source_stream, b"abcdef"), false, now);
        let first = actions(&mut agent);
        assert_eq!(acked(&first, source_stream), 0, "nothing accepted yet");
        let token = sent(&first, stop_stream, b"abcdef");

        // The destination takes three bytes: only those are acknowledged,
        // so the source's credit stays withheld for the rest.
        agent.send_stream_result(token, full(b"def"), now);
        let paused = actions(&mut agent);
        assert_eq!(paused.len(), 1, "{paused:?}");
        assert_eq!(acked(&paused, source_stream), 3);
        assert_eq!(agent.poll_event(), None, "the circuit stays open");

        // More source bytes queue behind the held tail.
        agent.handle_event(&data(&source, source_stream, b"gh"), false, now);
        assert_eq!(actions(&mut agent), Vec::new());

        // The destination's Writable resumes forwarding, in order.
        assert!(agent.handle_event(&writable(&destination, stop_stream), false, now));
        let token = sent(&actions(&mut agent), stop_stream, b"def");
        agent.send_stream_result(token, Ok(()), now);
        let resumed = actions(&mut agent);
        assert_eq!(acked(&resumed, source_stream), 3);
        let token = sent(&resumed, stop_stream, b"gh");
        agent.send_stream_result(token, Ok(()), now);
        assert_eq!(acked(&actions(&mut agent), source_stream), 2);
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn a_source_fin_follows_the_last_held_byte() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        agent.handle_event(&data(&source, source_stream, b"abcd"), false, now);
        let token = sent(&actions(&mut agent), stop_stream, b"abcd");
        agent.send_stream_result(token, full(b"cd"), now);
        agent.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: source.clone(),
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            now,
        );
        assert!(
            !actions(&mut agent)
                .iter()
                .any(|action| matches!(action, RelayServerAction::CloseStreamWrite { .. })),
            "no FIN while bytes are held"
        );

        agent.handle_event(&writable(&destination, stop_stream), false, now);
        let token = sent(&actions(&mut agent), stop_stream, b"cd");
        agent.send_stream_result(token, Ok(()), now);
        assert!(matches!(
            &actions(&mut agent)[..],
            [
                RelayServerAction::AckStream { .. },
                RelayServerAction::CloseStreamWrite { stream, .. },
            ] if *stream == stop_stream
        ));
    }

    #[test]
    fn a_leg_that_closes_gracefully_keeps_the_other_direction_draining() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        let half_close =
            |peer_id: &PeerId, stream: StreamKey| SwarmEvent::StreamRemoteWriteClosed {
                peer_id: peer_id.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
            };
        // The source finishes first; its FIN reaches the destination.
        agent.handle_event(&half_close(&source, source_stream), false, now);
        let Some(RelayServerAction::CloseStreamWrite { token, .. }) = io_action(&mut agent) else {
            panic!("source FIN forwarded");
        };
        agent.close_stream_write_result(token, Ok(()), now);

        // The destination answers, the source leg is full, then the
        // destination finishes and its stream closes cleanly.
        agent.handle_event(&data(&destination, stop_stream, b"reply"), false, now);
        let token = sent(&actions(&mut agent), source_stream, b"reply");
        agent.send_stream_result(token, full(b"ly"), now);
        agent.handle_event(&half_close(&destination, stop_stream), false, now);
        agent.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
            },
            false,
            now,
        );
        assert_eq!(agent.poll_event(), None, "the circuit stays open");
        let closed = actions(&mut agent);
        assert!(
            !closed
                .iter()
                .any(|action| matches!(action, RelayServerAction::ResetStream { .. })),
            "nothing is reset: {closed:?}"
        );

        // The held reply still reaches the source, then its FIN.
        agent.handle_event(&writable(&source, source_stream), false, now);
        let token = sent(&actions(&mut agent), source_stream, b"ly");
        agent.send_stream_result(token, Ok(()), now);
        let Some(RelayServerAction::CloseStreamWrite { token, stream, .. }) = io_action(&mut agent)
        else {
            panic!("destination FIN forwarded");
        };
        assert_eq!(stream, source_stream);
        agent.close_stream_write_result(token, Ok(()), now);
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::Eof,
                bytes: CircuitByteCounts {
                    source_to_destination: 0,
                    destination_to_source: 5,
                },
                ..
            })
        ));
    }

    #[test]
    fn pipelined_payload_is_acknowledged_only_once_forwarded() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            pending_stop(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        let _ = actions(&mut agent);
        agent.handle_event(&data(&source, source_stream, b"abcd"), false, now);
        assert_eq!(acked(&actions(&mut agent), source_stream), 0);

        // The STOP response carries destination payload behind it: only the
        // response itself is consumed now.
        let status = encode_stop_status(Status::Ok).unwrap();
        let mut response = status.clone();
        response.extend_from_slice(b"xy");
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination.clone(),
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(response),
            },
            false,
            now,
        );
        let accepted = actions(&mut agent);
        assert_eq!(acked(&accepted, stop_stream), status.len());
        let hop_success = sent(&accepted, source_stream, &accepted_hop_success(&accepted));
        agent.send_stream_result(hop_success, Ok(()), now);
        let _ = agent.poll_event();

        // Both buffers are forwarded on commit and acknowledged as accepted.
        let forwards = actions(&mut agent);
        let to_destination = forwards.iter().find_map(|action| match action {
            RelayServerAction::SendStream { token, stream, .. } if *stream == stop_stream => {
                Some(*token)
            }
            _ => None,
        });
        let to_source = forwards.iter().find_map(|action| match action {
            RelayServerAction::SendStream { token, stream, .. } if *stream == source_stream => {
                Some(*token)
            }
            _ => None,
        });
        agent.send_stream_result(to_destination.unwrap(), full(b"cd"), now);
        assert_eq!(acked(&actions(&mut agent), source_stream), 2);
        agent.send_stream_result(to_source.unwrap(), Ok(()), now);
        assert_eq!(acked(&actions(&mut agent), stop_stream), 2);
    }

    /// The bytes of the one HOP success send in `actions`.
    fn accepted_hop_success(actions: &[RelayServerAction]) -> Vec<u8> {
        actions
            .iter()
            .find_map(|action| match action {
                RelayServerAction::SendStream { data, .. } => Some(data.to_vec()),
                _ => None,
            })
            .expect("HOP success")
    }

    #[test]
    fn payload_coalesced_with_connect_is_acknowledged_only_once_forwarded() {
        let config = RelayServerConfig::default();
        let (mut agent, _, destination, source_stream, stop_stream) =
            pending_stop_with_payload(config, 0, b"abcd");
        let now = Now::from_millis(1);
        // The CONNECT read acknowledged only its own frame.
        let connect = encode_frame(
            &HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: destination.to_bytes(),
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            }
            .encode(),
        );
        assert_eq!(acked(&actions(&mut agent), source_stream), connect.len());

        let status = encode_stop_status(Status::Ok).unwrap();
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(status.clone()),
            },
            false,
            now,
        );
        let accepted = actions(&mut agent);
        assert_eq!(acked(&accepted, stop_stream), status.len());
        assert_eq!(acked(&accepted, source_stream), 0);
        let hop_success = sent(&accepted, source_stream, &accepted_hop_success(&accepted));
        agent.send_stream_result(hop_success, Ok(()), now);
        let token = sent(&actions(&mut agent), stop_stream, b"abcd");
        agent.send_stream_result(token, full(b"cd"), now);
        assert_eq!(acked(&actions(&mut agent), source_stream), 2);
    }

    #[test]
    fn payload_held_with_connect_precedes_later_pipelined_reads() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            pending_stop_with_payload(RelayServerConfig::default(), 0, b"ab");
        let now = Now::from_millis(1);
        let _ = actions(&mut agent);
        agent.handle_event(&data(&source, source_stream, b"cd"), false, now);
        let status = encode_stop_status(Status::Ok).unwrap();
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(status),
            },
            false,
            now,
        );
        let accepted = actions(&mut agent);
        let hop_success = sent(&accepted, source_stream, &accepted_hop_success(&accepted));
        agent.send_stream_result(hop_success, Ok(()), now);
        let token = sent(&actions(&mut agent), stop_stream, b"abcd");
        agent.send_stream_result(token, Ok(()), now);
        assert_eq!(acked(&actions(&mut agent), source_stream), 4);
    }

    #[test]
    fn tiny_reads_to_a_paused_destination_are_coalesced_in_order() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        agent.handle_event(&data(&source, source_stream, b"\xff"), false, now);
        let token = sent(&actions(&mut agent), stop_stream, b"\xff");
        agent.send_stream_result(token, full(b"\xff"), now);
        let _ = actions(&mut agent);

        // One-byte reads while the destination is full cost one queue entry
        // per coalesced run, not one per read.
        let expected: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        for byte in &expected {
            agent.handle_event(
                &SwarmEvent::StreamData {
                    peer_id: source.clone(),
                    conn_id: source_stream.conn_id,
                    stream_id: source_stream.stream_id,
                    data: Bytes::copy_from_slice(&[*byte]),
                },
                false,
                now,
            );
        }
        assert!(actions(&mut agent).is_empty());
        assert!(agent.circuits[&source_stream].to_destination.queue.len() <= 4);

        // Resuming delivers every byte in order and acknowledges each once.
        agent.handle_event(&writable(&destination, stop_stream), false, now);
        let (mut delivered, mut acks) = (Vec::new(), 0);
        let mut pending = actions(&mut agent);
        while !pending.is_empty() {
            acks += acked(&pending, source_stream);
            let Some((token, data)) = pending.iter().find_map(|action| match action {
                RelayServerAction::SendStream { token, data, .. } => Some((*token, data.clone())),
                _ => None,
            }) else {
                break;
            };
            delivered.extend_from_slice(&data);
            agent.send_stream_result(token, Ok(()), now);
            pending = actions(&mut agent);
        }
        assert_eq!(delivered[0], 0xff);
        assert_eq!(&delivered[1..], &expected[..]);
        assert_eq!(acks, 1 + expected.len());
        assert_eq!(agent.circuits[&source_stream].to_destination.unacked(), 0);
    }

    #[test]
    fn a_failed_connect_releases_payload_held_with_the_connect() {
        let (mut agent, _, destination, source_stream, stop_stream) =
            pending_stop_with_payload(RelayServerConfig::default(), 0, b"abcd");
        let _ = actions(&mut agent);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(encode_stop_status(Status::PermissionDenied).unwrap()),
            },
            false,
            Now::from_millis(1),
        );
        assert_eq!(acked(&actions(&mut agent), source_stream), 4);
    }

    #[test]
    fn a_failed_connect_releases_the_credit_of_pipelined_payload() {
        let (mut agent, source, destination, source_stream, stop_stream) =
            pending_stop(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        let _ = actions(&mut agent);
        agent.handle_event(&data(&source, source_stream, b"abcd"), false, now);
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: Bytes::from(encode_stop_status(Status::PermissionDenied).unwrap()),
            },
            false,
            now,
        );
        assert_eq!(acked(&actions(&mut agent), source_stream), 4);
    }

    #[test]
    fn an_accepted_prefix_counts_toward_the_byte_limit() {
        let config = RelayServerConfig {
            max_circuit_bytes: 3,
            ..RelayServerConfig::default()
        };
        let (mut agent, source, _, source_stream, stop_stream) = connected_circuit(config, 0);
        let now = Now::from_millis(1);
        agent.handle_event(&data(&source, source_stream, b"abcdef"), false, now);
        let token = sent(&actions(&mut agent), stop_stream, b"abcdef");
        agent.send_stream_result(token, full(b"ef"), now);
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                bytes: CircuitByteCounts {
                    source_to_destination: 4,
                    destination_to_source: 0,
                },
                reason: CircuitCloseReason::ByteLimit {
                    direction: CircuitDirection::SourceToDestination,
                },
                ..
            })
        ));
        let closed = actions(&mut agent);
        let resets = closed
            .iter()
            .filter(|action| matches!(action, RelayServerAction::ResetStream { .. }))
            .count();
        assert_eq!(resets, 2, "both legs reset: {closed:?}");
    }

    #[test]
    fn the_duration_limit_closes_a_paused_circuit() {
        let config = RelayServerConfig {
            max_circuit_duration_secs: 1,
            ..RelayServerConfig::default()
        };
        let (mut agent, source, _, source_stream, stop_stream) = connected_circuit(config, 0);
        let now = Now::from_millis(1);
        agent.handle_event(&data(&source, source_stream, b"abcd"), false, now);
        let token = sent(&actions(&mut agent), stop_stream, b"abcd");
        agent.send_stream_result(token, full(b"abcd"), now);

        agent.handle_tick(Now::from_millis(1_000));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::DurationLimit,
                ..
            })
        ));
    }

    #[test]
    fn closing_releases_the_credit_of_bytes_never_forwarded() {
        let (mut agent, source, _, source_stream, stop_stream) =
            connected_circuit(RelayServerConfig::default(), 0);
        let now = Now::from_millis(1);
        agent.handle_event(&data(&source, source_stream, b"abcd"), false, now);
        let token = sent(&actions(&mut agent), stop_stream, b"abcd");
        agent.send_stream_result(token, full(b"cd"), now);
        agent.handle_event(&data(&source, source_stream, b"ef"), false, now);
        assert_eq!(acked(&actions(&mut agent), source_stream), 2);

        // The source resets: its stream is not reset by the relay, so it
        // stays unsettled until the four held bytes are acknowledged.
        agent.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            now,
        );
        assert_eq!(acked(&actions(&mut agent), source_stream), 4);
    }

    #[test]
    fn failed_eof_half_close_terminates_the_committed_circuit() {
        let (mut agent, source, _, source_stream, _) =
            connected_circuit(RelayServerConfig::default(), 0);
        agent.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: source,
                conn_id: source_stream.conn_id,
                stream_id: source_stream.stream_id,
            },
            false,
            Now::from_millis(1),
        );
        let RelayServerAction::CloseStreamWrite { token, .. } = io_action(&mut agent).unwrap()
        else {
            panic!("half close action");
        };

        agent.close_stream_write_result(
            token,
            Err("half close failed".into()),
            Now::from_millis(1),
        );

        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::InternalFailure,
                ..
            })
        ));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::CloseStream,
                ..
            }))
        ));
    }

    /// One-second reservations, so a tick reaches the deadline long before
    /// the control-stream timeout.
    fn short_reservations() -> RelayServerConfig {
        RelayServerConfig {
            reservation_duration_secs: 1,
            ..RelayServerConfig::default()
        }
    }

    /// Reserves for `peer`, decides a renewal, then ticks past the
    /// reservation's deadline before the renewal's response is reported
    /// sent. Returns the renewal's send token.
    fn renew_past_deadline(
        agent: &mut RelayServerAgent,
        peer: &PeerId,
        conn_id: ConnectionId,
    ) -> RelayServerToken {
        let stream = |stream_id| StreamKey {
            conn_id,
            stream_id: StreamId::new(stream_id),
        };
        reserve(agent, peer, stream(1));
        feed_hop(agent, peer, stream(2), reserve_request(), &[]);
        let Some(RelayServerAction::SendStream { token, .. }) = io_action(agent) else {
            panic!("renewal response");
        };
        while io_action(agent).is_some() {}
        agent.handle_tick(Now::from_millis(1_000));
        token
    }

    fn relay(config: RelayServerConfig) -> RelayServerAgent {
        let mut agent =
            RelayServerAgent::new(PeerId::from_public_key_protobuf(b"relay-lapse"), config)
                .unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        agent
    }

    #[test]
    fn a_renewal_on_the_wire_keeps_its_reservation_alive_until_it_commits() {
        let mut agent = relay(short_reservations());
        let peer = PeerId::from_public_key_protobuf(b"client-renewing");
        let token = renew_past_deadline(&mut agent, &peer, ConnectionId::new(351));
        assert!(
            agent.poll_event().is_none(),
            "the client was already sent SUCCESS for the renewal"
        );
        assert_ne!(
            agent.next_timeout(Now::from_millis(1_000)),
            Some(0),
            "the kept-alive deadline must not spin the host's timer"
        );

        agent.send_stream_result(token, Ok(()), Now::from_millis(1_000));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationAccepted { renewed: true, .. })
        ));
        assert_eq!(agent.reservation_count(), 1);
    }

    #[test]
    fn a_failed_renewal_lets_its_reservation_expire() {
        let mut agent = relay(short_reservations());
        let peer = PeerId::from_public_key_protobuf(b"client-renewal-failed");
        let token = renew_past_deadline(&mut agent, &peer, ConnectionId::new(352));

        agent.send_stream_result(
            token,
            Err(RelayServerSendError::Failed("stream reset".into())),
            Now::from_millis(1_000),
        );
        while agent.poll_event().is_some() {}
        agent.handle_tick(Now::from_millis(1_001));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationClosed {
                reason: ReservationCloseReason::Expired,
                ..
            })
        ));
        assert!(!agent.has_reservation(&peer));
    }

    #[test]
    fn a_renewal_timing_out_with_its_reservation_expires_it_in_the_same_tick() {
        let mut agent = relay(RelayServerConfig {
            control_stream_timeout_ms: 1_000,
            ..short_reservations()
        });
        let peer = PeerId::from_public_key_protobuf(b"client-renewal-timeout");
        renew_past_deadline(&mut agent, &peer, ConnectionId::new(353));

        let mut events = Vec::new();
        while let Some(event) = agent.poll_event() {
            events.push(event);
        }
        assert!(
            events.iter().any(|event| matches!(
                event,
                RelayServerEvent::ReservationClosed {
                    reason: ReservationCloseReason::Expired,
                    ..
                }
            )),
            "{events:?}"
        );
        assert_eq!(agent.reservation_count(), 0);
    }
}
