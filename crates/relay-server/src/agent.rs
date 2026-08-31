use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId, Protocol, SansIoProtocol};
use minip2p_platform::Now;
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopRequest, HopResponder, HopResponderInput, HopResponderOutput, Limit,
    MAX_PENDING_BRIDGE_SIZE, Reservation, STOP_PROTOCOL_ID, Status, StopInitiator,
    StopInitiatorInput, StopInitiatorOutcome, StopInitiatorOutput, encode_hop_status,
};
use minip2p_swarm::{ConnectionCloseCause, DriverError, SwarmEvent, SwarmRuntime};
use minip2p_transport::{ConnectionId, Transport};

use crate::address::normalize_addrs;
use crate::limiter::TokenBuckets;
use crate::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit,
    RelayServerAction, RelayServerAddressError, RelayServerConfig, RelayServerConfigError,
    RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind, RelayServerToken,
    ReservationCloseReason, StreamKey,
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
    expires_unix_secs: Option<u64>,
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
        bytes: u64,
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
    source_eof: bool,
    destination_eof: bool,
    source_write_closed: bool,
    destination_write_closed: bool,
    source_to_destination_in_flight: bool,
    destination_to_source_in_flight: bool,
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
    pub fn register_swarm_roles<T, E>(swarm: &mut SwarmRuntime<T, E>) -> Result<(), DriverError>
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

    /// Returns the exact remote transport address known for a connection.
    pub fn connection_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.connections.get(&conn_id)?.address.as_ref()
    }

    /// Feeds one Swarm event and returns whether the service claimed it.
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
            SwarmEvent::ConnectionClosed {
                peer_id,
                conn_id,
                cause,
            } => {
                self.on_connection_closed(peer_id, *conn_id, *cause);
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
                if self.pending_circuits.contains_key(&key) {
                    self.append_pending_payload(key, CircuitDirection::SourceToDestination, data);
                    true
                } else if self.hop_workers.contains_key(&key) {
                    if self.feed_hop(key, HopResponderInput::Data(data.clone())) {
                        self.drain_hop(key, now);
                    }
                    true
                } else if self.rejected_hop_streams.contains_key(&key) {
                    true
                } else if self.circuits.contains_key(&key) {
                    self.queue_forward(key, CircuitDirection::SourceToDestination, data.clone());
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied() {
                    if self.feed_stop(source_stream, StopInitiatorInput::Data(data.clone())) {
                        self.drain_stop(source_stream, now);
                    } else if self.circuits.contains_key(&source_stream) {
                        self.queue_forward(
                            source_stream,
                            CircuitDirection::DestinationToSource,
                            data.clone(),
                        );
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
            SwarmEvent::StreamClosed {
                conn_id, stream_id, ..
            } => {
                let key = StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                };
                if self.circuits.contains_key(&key) {
                    self.close_circuit(
                        key,
                        CircuitCloseReason::StreamReset {
                            leg: CircuitLeg::Source,
                        },
                    );
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.circuits.contains_key(&source_stream)
                {
                    self.close_circuit(
                        source_stream,
                        CircuitCloseReason::StreamReset {
                            leg: CircuitLeg::Destination,
                        },
                    );
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
        let expired: Vec<_> = self
            .reservations
            .iter()
            .filter_map(|(peer, reservation)| {
                (reservation.deadline_ms <= now.monotonic_ms).then_some(peer.clone())
            })
            .collect();
        for peer_id in expired {
            self.reservations.remove(&peer_id);
            self.events.push_back(RelayServerEvent::ReservationClosed {
                peer_id,
                reason: ReservationCloseReason::Expired,
            });
        }
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
        self.reservation_limiters.sweep(now.monotonic_ms);
        self.circuit_limiters.sweep(now.monotonic_ms);
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

    /// Reports whether a queued send entered the transport's outbound queue.
    pub fn send_stream_result(
        &mut self,
        token: RelayServerToken,
        result: Result<(), String>,
        _now: Now,
    ) {
        let Some(PendingOperation::Send { peer_id, effect }) =
            self.pending_operations.remove(&token)
        else {
            return;
        };
        match result {
            Ok(()) => match effect {
                SendEffect::CommitReservation(pending) => {
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
                                expires_unix_secs: pending.expires_unix_secs,
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
                    self.commit_circuit(source_stream, _now);
                }
                SendEffect::StopRequest(_) => {}
                SendEffect::Forward {
                    source_stream,
                    direction,
                    bytes,
                } => self.forward_accepted(source_stream, direction, bytes),
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
        let reservation = self
            .reservations
            .values()
            .map(|value| value.deadline_ms)
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
    pub fn has_reservation(&self, peer_id: &PeerId) -> bool {
        self.reservations.contains_key(peer_id)
    }

    /// Returns the exact connection owning a committed reservation.
    pub fn reservation_connection(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.reservations.get(peer_id).map(|record| record.conn_id)
    }

    /// Returns optional wall-clock expiry metadata for a reservation.
    pub fn reservation_expires_unix_secs(&self, peer_id: &PeerId) -> Option<u64> {
        self.reservations.get(peer_id)?.expires_unix_secs
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
        let replaced: Vec<_> = self
            .connections
            .iter()
            .filter_map(|(id, connection)| {
                (connection.peer_id == peer_id && *id != conn_id).then_some(*id)
            })
            .collect();
        for old_conn_id in replaced {
            self.on_connection_closed(&peer_id, old_conn_id, ConnectionCloseCause::Superseded);
        }
        if let Some(old) = self.reservations.get(&peer_id)
            && old.conn_id != conn_id
        {
            self.reservations.remove(&peer_id);
            self.events.push_back(RelayServerEvent::ReservationClosed {
                peer_id: peer_id.clone(),
                reason: ReservationCloseReason::Superseded,
            });
        }
        self.connections.insert(
            conn_id,
            Connection {
                peer_id,
                address: None,
                is_circuit,
            },
        );
    }

    fn on_connection_closed(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        cause: ConnectionCloseCause,
    ) {
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
            self.close_circuit(key, CircuitCloseReason::ConnectionClosed { leg, cause });
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
                reason: match cause {
                    ConnectionCloseCause::Transport => ReservationCloseReason::ConnectionClosed,
                    ConnectionCloseCause::Superseded => ReservationCloseReason::Superseded,
                },
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
                HopResponderOutput::BridgeData(data) => {
                    if self.pending_circuits.contains_key(&key) {
                        self.append_pending_payload(
                            key,
                            CircuitDirection::SourceToDestination,
                            &data,
                        );
                    } else if self.circuits.contains_key(&key) {
                        self.queue_forward(key, CircuitDirection::SourceToDestination, data);
                    }
                }
            }
        }
    }

    fn drain_stop(&mut self, source_stream: StreamKey, now: Now) {
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
                        return;
                    }
                    let Some(worker) = self.hop_workers.get_mut(&source_stream) else {
                        self.fail_pending_connect(source_stream, Status::ConnectionFailed);
                        return;
                    };
                    let Some(HopResponderOutput::Outbound(data)) = worker.responder.poll_output()
                    else {
                        self.fail_pending_connect(source_stream, Status::ConnectionFailed);
                        return;
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
                    return;
                }
                StopInitiatorOutput::BridgeData(data) => {
                    self.append_pending_payload(
                        source_stream,
                        CircuitDirection::DestinationToSource,
                        &data,
                    );
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
                source_eof: false,
                destination_eof: false,
                source_write_closed: false,
                destination_write_closed: false,
                source_to_destination_in_flight: false,
                destination_to_source_in_flight: false,
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

    fn append_pending_payload(
        &mut self,
        source_stream: StreamKey,
        direction: CircuitDirection,
        data: &[u8],
    ) {
        let Some(circuit) = self.pending_circuits.get_mut(&source_stream) else {
            return;
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
            return;
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
    }

    fn queue_forward(
        &mut self,
        source_stream: StreamKey,
        direction: CircuitDirection,
        data: Vec<u8>,
    ) {
        if data.is_empty() {
            return;
        }
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        let in_flight = match direction {
            CircuitDirection::SourceToDestination => &mut circuit.source_to_destination_in_flight,
            CircuitDirection::DestinationToSource => &mut circuit.destination_to_source_in_flight,
        };
        if *in_flight {
            self.close_circuit(source_stream, CircuitCloseReason::InternalFailure);
            self.runtime_error(
                RelayServerRuntimeErrorKind::InternalInvariant,
                None,
                "same-direction forwarding send was not echoed before new input".into(),
            );
            return;
        }
        *in_flight = true;
        let (peer_id, stream) = match direction {
            CircuitDirection::SourceToDestination => (
                circuit.destination_peer_id.clone(),
                circuit.destination_stream,
            ),
            CircuitDirection::DestinationToSource => {
                (circuit.source_peer_id.clone(), circuit.source_stream)
            }
        };
        let bytes = data.len().min(u64::MAX as usize) as u64;
        let token = self.token();
        self.pending_operations.insert(
            token,
            PendingOperation::Send {
                peer_id: peer_id.clone(),
                effect: SendEffect::Forward {
                    source_stream,
                    direction,
                    bytes,
                },
            },
        );
        self.actions.push_back(RelayServerAction::SendStream {
            token,
            peer_id,
            stream,
            data,
        });
    }

    fn forward_accepted(
        &mut self,
        source_stream: StreamKey,
        direction: CircuitDirection,
        bytes: u64,
    ) {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        let total = match direction {
            CircuitDirection::SourceToDestination => {
                circuit.source_to_destination_in_flight = false;
                circuit.bytes.source_to_destination =
                    circuit.bytes.source_to_destination.saturating_add(bytes);
                circuit.bytes.source_to_destination
            }
            CircuitDirection::DestinationToSource => {
                circuit.destination_to_source_in_flight = false;
                circuit.bytes.destination_to_source =
                    circuit.bytes.destination_to_source.saturating_add(bytes);
                circuit.bytes.destination_to_source
            }
        };
        if self.config.max_circuit_bytes != 0 && total > self.config.max_circuit_bytes {
            self.close_circuit(source_stream, CircuitCloseReason::ByteLimit { direction });
        } else {
            self.finish_eof_if_drained(source_stream);
        }
    }

    fn close_circuit(&mut self, source_stream: StreamKey, reason: CircuitCloseReason) {
        let Some(circuit) = self.circuits.remove(&source_stream) else {
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
                ..
            } => (false, true),
            CircuitCloseReason::StreamReset {
                leg: CircuitLeg::Destination,
            }
            | CircuitCloseReason::ConnectionClosed {
                leg: CircuitLeg::Destination,
                ..
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
        self.events.push_back(RelayServerEvent::CircuitClosed {
            source_peer_id: circuit.source_peer_id,
            destination_peer_id: circuit.destination_peer_id,
            bytes: circuit.bytes,
            reason,
        });
    }

    fn circuit_eof(&mut self, source_stream: StreamKey, leg: CircuitLeg) {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        let (peer_id, stream, target_leg) = match leg {
            CircuitLeg::Source => {
                if circuit.source_eof {
                    return;
                }
                circuit.source_eof = true;
                (
                    circuit.destination_peer_id.clone(),
                    circuit.destination_stream,
                    CircuitLeg::Destination,
                )
            }
            CircuitLeg::Destination => {
                if circuit.destination_eof {
                    return;
                }
                circuit.destination_eof = true;
                (
                    circuit.source_peer_id.clone(),
                    circuit.source_stream,
                    CircuitLeg::Source,
                )
            }
        };
        self.queue_circuit_close(peer_id, stream, source_stream, target_leg);
        self.finish_eof_if_drained(source_stream);
    }

    fn circuit_close_accepted(&mut self, source_stream: StreamKey, leg: CircuitLeg) {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        match leg {
            CircuitLeg::Source => circuit.source_write_closed = true,
            CircuitLeg::Destination => circuit.destination_write_closed = true,
        }
        self.finish_eof_if_drained(source_stream);
    }

    fn finish_eof_if_drained(&mut self, source_stream: StreamKey) {
        let finished = self.circuits.get(&source_stream).is_some_and(|circuit| {
            circuit.source_eof
                && circuit.destination_eof
                && circuit.source_write_closed
                && circuit.destination_write_closed
                && !circuit.source_to_destination_in_flight
                && !circuit.destination_to_source_in_flight
        });
        if finished {
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
        } else if !self.consume_reservation_limits(&peer_id, key.conn_id, now.monotonic_ms) {
            Some(Status::ResourceLimitExceeded)
        } else {
            (pending_for_peer
                || (!renewed
                    && self.reservations.len().saturating_add(pending_initial)
                        >= self.config.max_reservations))
                .then_some(Status::ResourceLimitExceeded)
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
        for token in tokens {
            self.pending_operations.remove(token);
        }
        self.actions.retain(|action| {
            let token = match action {
                RelayServerAction::OpenStream { token, .. }
                | RelayServerAction::SendStream { token, .. }
                | RelayServerAction::CloseStreamWrite { token, .. }
                | RelayServerAction::ResetStream { token, .. } => token,
            };
            !tokens.contains(token)
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
        data: Vec<u8>,
        effect: SendEffect,
    ) {
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
                data,
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
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
            panic!("reservation response");
        };
        agent.send_stream_result(token, Ok(()), Now::from_millis(0));
        let _ = agent.poll_event();
        if let Some(RelayServerAction::CloseStreamWrite { token, .. }) = agent.poll_action() {
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
                data: encode_stop_status(Status::Ok).unwrap(),
            },
            false,
            Now::from_millis(commit_ms),
        );
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
            panic!("HOP success");
        };
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
        mut config: RelayServerConfig,
        now_ms: u64,
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
            &[],
        );
        let RelayServerAction::OpenStream { token, .. } = agent.poll_action().unwrap() else {
            panic!("STOP open");
        };
        let stop_stream = StreamKey {
            conn_id: ConnectionId::new(60),
            stream_id: StreamId::new(3),
        };
        agent.stream_open_result(token, Ok(stop_stream), Now::from_millis(now_ms));
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
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
        (agent, source, destination, source_stream, stop_stream)
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
                data: request,
            },
            false,
            Now::new(10, 1_000),
        );

        assert_eq!(agent.poll_event(), None);
        let RelayServerAction::SendStream { token, stream, .. } = agent.poll_action().unwrap()
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
        }) = agent.poll_action()
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
        let RelayServerAction::SendStream { token, stream, .. } = agent.poll_action().unwrap()
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
                data: encode_stop_status(Status::Ok).unwrap(),
            },
            false,
            Now::from_millis(2),
        );
        let RelayServerAction::SendStream { token, stream, .. } = agent.poll_action().unwrap()
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
        } = agent.poll_action().unwrap()
        else {
            panic!("pipelined source payload is released after commit");
        };
        assert_eq!(stream, stop_stream);
        assert_eq!(data, b"pipelined-source");
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
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
            panic!("reservation response");
        };

        agent.send_stream_result(token, Err("queue full".into()), Now::from_millis(0));

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
            agent.poll_action(),
            Some(RelayServerAction::ResetStream { stream: reset, .. }) if reset == stream
        ));
        assert_eq!(agent.poll_action(), None);
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
            agent.poll_action(),
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
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
            panic!("renewal response");
        };
        agent.send_stream_result(token, Err("backpressure".into()), Now::from_millis(10));
        assert_eq!(agent.reservation_connection(&remote), Some(renewal.conn_id));
        assert_eq!(agent.reservation_count(), 1);
    }

    #[test]
    fn successful_full_capacity_renewal_consumes_a_rate_token() {
        let remote = PeerId::from_public_key_protobuf(b"client-renewal-token");
        let conn_id = ConnectionId::new(343);
        let config = RelayServerConfig {
            max_reservations: 1,
            reservation_rate_limit_per_peer: Some(RateLimit {
                capacity: 2,
                refill_interval_ms: 1_000,
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
            feed_hop(
                &mut agent,
                &remote,
                StreamKey {
                    conn_id,
                    stream_id: StreamId::new(stream_id),
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
            if stream_id == 2 {
                let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap()
                else {
                    panic!("renewal response");
                };
                agent.send_stream_result(token, Ok(()), Now::from_millis(10));
                assert!(matches!(
                    agent.poll_event(),
                    Some(RelayServerEvent::ReservationAccepted { renewed: true, .. })
                ));
                let _ = agent.poll_action();
                assert_eq!(agent.reservation_count(), 1);
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
        } = agent.poll_action().unwrap()
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
            let _ = agent.poll_action();
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
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
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
            let _ = agent.poll_action();

            let terminal = if close_connection {
                SwarmEvent::ConnectionClosed {
                    peer_id: first,
                    conn_id: first_stream.conn_id,
                    cause: ConnectionCloseCause::Transport,
                }
            } else {
                SwarmEvent::StreamClosed {
                    peer_id: first,
                    conn_id: first_stream.conn_id,
                    stream_id: first_stream.stream_id,
                }
            };
            agent.handle_event(&terminal, false, Now::from_millis(1));
            while agent.poll_action().is_some() {}

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
                agent.poll_action(),
                Some(RelayServerAction::SendStream {
                    peer_id,
                    stream,
                    ..
                }) if peer_id == second && stream == second_stream
            ));
        }
    }

    #[test]
    fn stale_old_connection_close_cannot_remove_replacement_reservation() {
        let local = PeerId::from_public_key_protobuf(b"relay-stale");
        let remote = PeerId::from_public_key_protobuf(b"client-stale");
        let config = RelayServerConfig {
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
                conn_id: ConnectionId::new(35),
                stream_id: StreamId::new(1),
            },
        );
        establish(&mut agent, &remote, ConnectionId::new(36));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::ReservationClosed {
                reason: crate::ReservationCloseReason::Superseded,
                ..
            })
        ));
        reserve(
            &mut agent,
            &remote,
            StreamKey {
                conn_id: ConnectionId::new(36),
                stream_id: StreamId::new(1),
            },
        );

        agent.handle_event(
            &SwarmEvent::ConnectionClosed {
                peer_id: remote.clone(),
                conn_id: ConnectionId::new(35),
                cause: minip2p_swarm::ConnectionCloseCause::Superseded,
            },
            false,
            Now::from_millis(1),
        );

        assert_eq!(
            agent.reservation_connection(&remote),
            Some(ConnectionId::new(36))
        );
        assert_eq!(agent.poll_event(), None);
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
                data: request,
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
            agent.poll_action(),
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
        let RelayServerAction::ResetStream { token, .. } = agent.poll_action().unwrap() else {
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
        assert_eq!(agent.poll_action(), None);
        assert_eq!(agent.poll_event(), None);
    }

    #[test]
    fn stale_old_connection_cannot_commit_after_defensive_replacement() {
        let local = PeerId::from_public_key_protobuf(b"relay-old-input");
        let remote = PeerId::from_public_key_protobuf(b"client-old-input");
        let old = ConnectionId::new(40);
        let new = ConnectionId::new(41);
        let old_stream = StreamKey {
            conn_id: old,
            stream_id: StreamId::new(1),
        };
        let config = RelayServerConfig {
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        let mut agent = RelayServerAgent::new(local, config).unwrap();
        agent.replace_announce_addrs(vec![direct_addr()]).unwrap();
        establish(&mut agent, &remote, old);
        establish(&mut agent, &remote, new);

        feed_hop(
            &mut agent,
            &remote,
            old_stream,
            HopMessage {
                kind: HopMessageType::Reserve,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            },
            &[],
        );
        while let Some(action) = agent.poll_action() {
            match action {
                RelayServerAction::SendStream { token, .. } => {
                    agent.send_stream_result(token, Ok(()), Now::from_millis(1));
                }
                RelayServerAction::ResetStream { token, .. } => {
                    agent.reset_stream_result(token, Ok(()), Now::from_millis(1));
                }
                RelayServerAction::CloseStreamWrite { token, .. } => {
                    agent.close_stream_write_result(token, Ok(()), Now::from_millis(1));
                }
                RelayServerAction::OpenStream { .. } => panic!("no STOP open"),
            }
        }

        assert_eq!(agent.reservation_connection(&remote), None);
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
                data: b"abc".to_vec(),
            },
            false,
            Now::from_millis(11),
        );
        let RelayServerAction::SendStream { token, stream, .. } = agent.poll_action().unwrap()
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
                data: b"not-counted".to_vec(),
            },
            false,
            Now::from_millis(12),
        );
        let RelayServerAction::SendStream { token, stream, .. } = agent.poll_action().unwrap()
        else {
            panic!("destination payload forward");
        };
        assert_eq!(stream, source_stream);
        agent.send_stream_result(token, Err("queue rejected".into()), Now::from_millis(12));
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
            agent.poll_action().unwrap()
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
            agent.poll_action().unwrap()
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
            agent.poll_action(),
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
                    data: encode_stop_status(status).unwrap(),
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
                let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap()
                else {
                    panic!("first IP token admits");
                };
                agent.send_stream_result(token, Ok(()), Now::from_millis(0));
                let _ = agent.poll_event();
                let _ = agent.poll_action();
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
                let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap()
                else {
                    panic!("IPv4 request admitted");
                };
                agent.send_stream_result(token, Ok(()), Now::from_millis(0));
                let _ = agent.poll_event();
                let _ = agent.poll_action();
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
                    agent.poll_action(),
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
                    data,
                },
                false,
                Now::from_millis(1),
            );
            let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
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
            agent.poll_action(),
            Some(RelayServerAction::SendStream { .. })
        ));
    }

    #[test]
    fn failed_hop_success_delivery_cleans_both_precommit_legs() {
        let (mut agent, _, _, source_stream, stop_stream, token) =
            pending_circuit_success(RelayServerConfig::default(), 0);

        agent.send_stream_result(
            token,
            Err("source queue failed".into()),
            Now::from_millis(0),
        );

        assert!(!agent.owns_stream(source_stream));
        assert!(!agent.owns_stream(stop_stream));
        let reset_streams: Vec<_> = core::iter::from_fn(|| agent.poll_action())
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
                data: b"during-stop-rtt".to_vec(),
            },
            false,
            Now::from_millis(1),
        );
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: destination,
                conn_id: stop_stream.conn_id,
                stream_id: stop_stream.stream_id,
                data: encode_stop_status(Status::Ok).unwrap(),
            },
            false,
            Now::from_millis(1),
        );
        let RelayServerAction::SendStream { token, .. } = agent.poll_action().unwrap() else {
            panic!("HOP success");
        };
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        let _ = agent.poll_event();
        assert!(matches!(
            agent.poll_action(),
            Some(RelayServerAction::SendStream { stream, data, .. })
                if stream == stop_stream && data == b"during-stop-rtt"
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
                    data: vec![0; MAX_PENDING_BRIDGE_SIZE + 1],
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
            agent.poll_action(),
            Some(RelayServerAction::ResetStream { stream, .. }) if stream == stop_stream
        ));
        assert_eq!(agent.poll_action(), None);
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
            agent.poll_action(),
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
            agent.poll_action(),
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
                data: b"buffered".to_vec(),
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
        agent.send_stream_result(token, Ok(()), Now::from_millis(1));
        assert!(matches!(
            agent.poll_event(),
            Some(RelayServerEvent::CircuitOpened { .. })
        ));

        let mut forward = None;
        let mut closes = Vec::new();
        while let Some(action) = agent.poll_action() {
            match action {
                RelayServerAction::SendStream {
                    token,
                    stream,
                    data,
                    ..
                } => {
                    assert_eq!(stream, stop_stream);
                    assert_eq!(data, b"buffered");
                    forward = Some(token);
                }
                RelayServerAction::CloseStreamWrite { token, stream, .. } => {
                    closes.push((token, stream));
                }
                action => panic!("unexpected action: {action:?}"),
            }
        }
        assert!(closes.iter().any(|(_, stream)| *stream == source_stream));
        assert!(closes.iter().any(|(_, stream)| *stream == stop_stream));
        assert_eq!(agent.poll_event(), None, "payload remains in flight");

        agent.send_stream_result(forward.unwrap(), Ok(()), Now::from_millis(1));
        assert_eq!(agent.poll_event(), None, "half closes remain in flight");
        let close_count = closes.len();
        for (index, (token, _)) in closes.into_iter().enumerate() {
            agent.close_stream_write_result(token, Ok(()), Now::from_millis(1));
            if index + 1 != close_count {
                assert_eq!(agent.poll_event(), None, "one half close remains in flight");
            }
        }
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
        let RelayServerAction::CloseStreamWrite { token, .. } = agent.poll_action().unwrap() else {
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
    fn a_second_same_direction_send_before_echo_fails_boundedly() {
        let (mut agent, source, _, source_stream, _) =
            connected_circuit(RelayServerConfig::default(), 0);
        for data in [b"first".as_slice(), b"second".as_slice()] {
            agent.handle_event(
                &SwarmEvent::StreamData {
                    peer_id: source.clone(),
                    conn_id: source_stream.conn_id,
                    stream_id: source_stream.stream_id,
                    data: data.to_vec(),
                },
                false,
                Now::from_millis(1),
            );
        }

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
                kind: RelayServerRuntimeErrorKind::InternalInvariant,
                ..
            }))
        ));
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
        let RelayServerAction::CloseStreamWrite { token, .. } = agent.poll_action().unwrap() else {
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
}
