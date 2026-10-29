use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::RangeInclusive;

use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Bytes, Multiaddr, PeerId, Protocol};
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopRequest, HopResponder, HopResponderOutput, Limit, MAX_PENDING_BRIDGE_SIZE,
    RelayError, Reservation, STOP_PROTOCOL_ID, Status, StopInitiator, StopInitiatorOutcome,
    StopInitiatorOutput, encode_hop_status,
};
use minip2p_swarm::{
    DriverError, SwarmCore, SwarmError, SwarmErrorKind, SwarmEvent, SwarmRuntimeError,
};
use minip2p_transport::{ConnectionId, StreamId, Transport};

use crate::address::normalize_addrs;
use crate::limiter::TokenBuckets;
use crate::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit,
    RelayServerAddrSource, RelayServerAddressError, RelayServerConfig, RelayServerConfigError,
    RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind, RelaySwarm,
    RelaySwarmError, ReservationCloseReason, StreamKey,
};

/// The key per-IP admission limits share: an IPv4 address (IPv4-mapped
/// IPv6 included) or an IPv6 /64, since one host commonly holds a whole /64.
/// Held as integers, so a map lookup compares words rather than calling
/// `memcmp` per key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpKey {
    V4(u32),
    V6Prefix(u64),
}

/// What an admission key holds: its reservations or its circuits.
#[derive(Clone, Copy)]
enum Held {
    Reservations,
    Circuits,
}

/// One admission key's live reservations and circuits.
#[derive(Debug, Default, Eq, PartialEq)]
struct IpLoad {
    reservations: usize,
    circuits: usize,
}

impl IpLoad {
    fn count(&mut self, held: Held) -> &mut usize {
        match held {
            Held::Reservations => &mut self.reservations,
            Held::Circuits => &mut self.circuits,
        }
    }
}

/// Live reservations and circuits per admission key, in one map so a key
/// that still holds the other kind is only decremented, not removed.
#[derive(Debug, Default, Eq, PartialEq)]
struct IpTally(BTreeMap<IpKey, IpLoad>);

impl IpTally {
    /// Whether `key` already holds `max` of `held`. A connection without an
    /// IP has no key and is never at the cap.
    fn is_full(&self, key: Option<&IpKey>, held: Held, max: usize) -> bool {
        let count = |load: &IpLoad| match held {
            Held::Reservations => load.reservations,
            Held::Circuits => load.circuits,
        };
        key.is_some_and(|key| self.0.get(key).map_or(0, count) >= max)
    }

    fn add(&mut self, key: Option<&IpKey>, held: Held) {
        if let Some(key) = key {
            *self.0.entry(key.clone()).or_default().count(held) += 1;
        }
    }

    fn remove(&mut self, key: Option<&IpKey>, held: Held) {
        let Some(key) = key else {
            return;
        };
        // One descent: the entry both decrements and, once empty, removes.
        if let Entry::Occupied(mut entry) = self.0.entry(key.clone()) {
            *entry.get_mut().count(held) -= 1;
            if *entry.get() == IpLoad::default() {
                entry.remove();
            }
        }
    }
}

struct AdmissionLimiters {
    peer: Option<TokenBuckets<PeerId>>,
    ip: Option<TokenBuckets<IpKey>>,
}

impl AdmissionLimiters {
    fn new(peer: Option<RateLimit>, ip: Option<RateLimit>, max_entries: usize) -> Self {
        Self {
            peer: peer.map(|limit| TokenBuckets::new(limit, max_entries)),
            ip: ip.map(|limit| TokenBuckets::new(limit, max_entries)),
        }
    }

    /// Whether every applicable bucket holds a token, spending none. A key
    /// new to a full limiter map has no token.
    fn allows(&mut self, peer_id: &PeerId, ip: Option<&IpKey>, now_ms: u64) -> bool {
        let peer = self
            .peer
            .as_mut()
            .is_none_or(|limiter| limiter.allows(peer_id, now_ms));
        let ip = match (&mut self.ip, ip) {
            (Some(limiter), Some(ip)) => limiter.allows(ip, now_ms),
            _ => true,
        };
        peer && ip
    }

    /// Spends one token from every applicable bucket. Call only after
    /// [`Self::allows`] and every other admission check passed, so a refused
    /// request never costs a token.
    fn consume(&mut self, peer_id: &PeerId, ip: Option<IpKey>, now_ms: u64) {
        if let Some(limiter) = &mut self.peer {
            limiter.consume(peer_id.clone(), now_ms);
        }
        if let (Some(limiter), Some(ip)) = (&mut self.ip, ip) {
            limiter.consume(ip, now_ms);
        }
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
    /// Admission key of the connection's remote address, read from the swarm
    /// when the connection was established.
    ip: Option<IpKey>,
    is_circuit: bool,
}

struct ReservationRecord {
    conn_id: ConnectionId,
    /// The admission key it counts against, fixed when first admitted.
    ip: Option<IpKey>,
}

struct HopWorker {
    peer_id: PeerId,
    responder: HopResponder,
    request_known: bool,
    is_circuit: bool,
}

struct PendingCircuit {
    source_peer_id: PeerId,
    destination_peer_id: PeerId,
    source_ip: Option<IpKey>,
    destination_ip: Option<IpKey>,
    destination_conn_id: ConnectionId,
    /// The STOP stream while the relay still owns it: `None` once its
    /// connection or negotiation is gone.
    stop_stream: Option<StreamKey>,
    /// The STOP exchange, from the stream's `StreamReady` on.
    stop: Option<StopInitiator>,
    source_pipelined: Vec<u8>,
    destination_pipelined: Vec<u8>,
    /// The source half-closed while the circuit waited on STOP. The
    /// destination cannot: a STOP stream that half-closes before its STATUS
    /// fails the circuit, and the STATUS commits it in the same call.
    source_eof: bool,
}

/// A STOP stream the relay gave up before it closed: its circuit failed or
/// was abandoned, or its open landed on the wrong connection. The relay
/// keeps claiming the stream's events, so they never reach another owner,
/// until its terminal event or its connection's close.
struct RetiredStop {
    peer_id: PeerId,
    /// Whether the stream finished negotiating and has been reset. A stream
    /// still negotiating cannot be reset; its late `StreamReady` resets it.
    ready: bool,
}

struct Circuit {
    source_peer_id: PeerId,
    destination_peer_id: PeerId,
    source_ip: Option<IpKey>,
    destination_ip: Option<IpKey>,
    source_stream: StreamKey,
    destination_stream: StreamKey,
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

    /// The leg a direction writes to, with its peer and its queue, borrowed
    /// together so a send needs no copy of the peer.
    fn target(&mut self, direction: CircuitDirection) -> (&PeerId, StreamKey, &mut Forward) {
        match direction {
            CircuitDirection::SourceToDestination => (
                &self.destination_peer_id,
                self.destination_stream,
                &mut self.to_destination,
            ),
            CircuitDirection::DestinationToSource => (
                &self.source_peer_id,
                self.source_stream,
                &mut self.to_source,
            ),
        }
    }
}

/// The leg `direction` writes to.
fn target_leg(direction: CircuitDirection) -> CircuitLeg {
    match direction {
        CircuitDirection::SourceToDestination => CircuitLeg::Destination,
        CircuitDirection::DestinationToSource => CircuitLeg::Source,
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
    /// The target answered Full; the head waits for its Writable.
    blocked: bool,
    fin: FinState,
}

/// How far a direction's half-close has travelled.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum FinState {
    /// The origin has not half-closed.
    #[default]
    Open,
    /// The origin half-closed; the target's FIN follows the last byte.
    Received,
    /// The target accepted its FIN.
    Accepted,
}

/// Reads shorter than this are coalesced into one queue entry, flushed once
/// it reaches this size or sooner when forwarding or ordering needs it.
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
            self.blocked = true;
        }
    }
}

/// Deadlines keyed by their owner and ordered by due time, so the earliest
/// and the due ones are found without visiting every owner.
struct Deadlines<K> {
    by_key: BTreeMap<K, u64>,
    by_due: BTreeSet<(u64, K)>,
}

impl<K: Ord + Clone> Deadlines<K> {
    fn new() -> Self {
        Self {
            by_key: BTreeMap::new(),
            by_due: BTreeSet::new(),
        }
    }

    /// Sets or replaces `key`'s deadline.
    fn set(&mut self, key: K, deadline_ms: u64) {
        self.remove(&key);
        self.by_due.insert((deadline_ms, key.clone()));
        self.by_key.insert(key, deadline_ms);
    }

    /// Removes `key`'s deadline, returning it.
    fn remove(&mut self, key: &K) -> Option<u64> {
        let deadline_ms = self.by_key.remove(key)?;
        self.by_due.remove(&(deadline_ms, key.clone()));
        Some(deadline_ms)
    }

    fn contains(&self, key: &K) -> bool {
        self.by_key.contains_key(key)
    }

    /// Deadlines in due order.
    fn iter(&self) -> impl Iterator<Item = (u64, &K)> {
        self.by_due
            .iter()
            .map(|(deadline_ms, key)| (*deadline_ms, key))
    }

    fn earliest(&self) -> Option<u64> {
        self.by_due.first().map(|(deadline_ms, _)| *deadline_ms)
    }

    /// Owners due at or before `now_ms`, in key order so a sweep handles
    /// them in the same order however their deadlines fall.
    fn due(&self, now_ms: u64) -> Vec<K> {
        let mut due: Vec<K> = self
            .iter()
            .take_while(|(deadline_ms, _)| *deadline_ms <= now_ms)
            .map(|(_, key)| key.clone())
            .collect();
        due.sort_unstable();
        due
    }
}

/// Every stream key on `conn_id`. `StreamKey` orders by connection first,
/// so a range over it visits only that connection's streams.
fn connection_streams(conn_id: ConnectionId) -> RangeInclusive<StreamKey> {
    StreamKey {
        conn_id,
        stream_id: StreamId::new(0),
    }..=StreamKey {
        conn_id,
        stream_id: StreamId::new(u64::MAX),
    }
}

/// Every `pending_by_destination` entry for destination `conn_id`.
fn pending_to(conn_id: ConnectionId) -> RangeInclusive<(ConnectionId, StreamKey)> {
    let first = StreamKey {
        conn_id: ConnectionId::new(0),
        stream_id: StreamId::new(0),
    };
    let last = StreamKey {
        conn_id: ConnectionId::new(u64::MAX),
        stream_id: StreamId::new(u64::MAX),
    };
    (conn_id, first)..=(conn_id, last)
}

/// The swarm and time sample of one agent call. Every command the agent
/// issues runs through it, inline, at the caller's time.
struct Io<'a> {
    swarm: &'a mut dyn RelaySwarm,
    now: Now,
}

impl Io<'_> {
    fn now_ms(&self) -> u64 {
        self.now.monotonic_ms
    }

    /// Acknowledges `bytes` of `stream`'s delivered data as consumed.
    fn ack(&mut self, stream: StreamKey, bytes: usize) {
        if bytes != 0 {
            self.swarm.ack_stream(stream, bytes);
        }
    }
}

/// Why a control message did not fully enter its stream.
fn control_send_failure(error: RelaySwarmError) -> String {
    match error {
        RelaySwarmError(DriverError::Full { unsent, .. }) => format!(
            "{} of the message's bytes did not fit the stream's send queue",
            unsent.len()
        ),
        error => error.to_string(),
    }
}

/// The negotiation failure an event reports for an outbound stream: the
/// swarm's error naming it. A negotiation that fails ends with that error,
/// not a `StreamClosed`.
fn failed_negotiation(event: &SwarmEvent) -> Option<(StreamKey, &str)> {
    match event {
        SwarmEvent::Error(SwarmRuntimeError {
            kind:
                SwarmErrorKind::Multistream
                | SwarmErrorKind::UnsupportedProtocol
                | SwarmErrorKind::OpenStreamFailed,
            conn_id: Some(conn_id),
            stream_id: Some(stream_id),
            detail,
            ..
        }) => Some((
            StreamKey {
                conn_id: *conn_id,
                stream_id: *stream_id,
            },
            detail,
        )),
        _ => None,
    }
}

/// Whole-service deterministic relay policy and forwarding state.
///
/// Lookups by connection, peer, stream, and due time go through indexes
/// kept beside the primary maps, so per-event and per-tick cost does not
/// grow with unrelated reservations or circuits. Every insert and removal
/// goes through the helpers that keep them in step.
pub struct RelayServerAgent {
    local_peer_id: PeerId,
    config: RelayServerConfig,
    accepting: bool,
    explicit_addrs: Option<Vec<Multiaddr>>,
    confirmed_addrs: Vec<Multiaddr>,
    listener_addrs: Vec<Multiaddr>,
    /// Last rejection of each host-refreshed source, cleared by its next
    /// accepted refresh.
    confirmed_addrs_error: Option<RelayServerAddressError>,
    listener_addrs_error: Option<RelayServerAddressError>,
    connections: BTreeMap<ConnectionId, Connection>,
    reservations: BTreeMap<PeerId, ReservationRecord>,
    reservation_deadlines: Deadlines<PeerId>,
    hop_workers: BTreeMap<StreamKey, HopWorker>,
    /// HOP workers whose control exchange is still bounded by a deadline.
    hop_deadlines: Deadlines<StreamKey>,
    rejected_hop_streams: BTreeMap<StreamKey, PeerId>,
    pending_circuits: BTreeMap<StreamKey, PendingCircuit>,
    /// Pending circuits, by source stream, whose STOP exchange has not
    /// been accepted yet.
    stop_deadlines: Deadlines<StreamKey>,
    /// Pending circuits by destination connection, then source stream.
    pending_by_destination: BTreeSet<(ConnectionId, StreamKey)>,
    /// Destination (STOP) stream to source stream, for pending circuits
    /// with an open STOP stream and every committed circuit.
    stop_to_source: BTreeMap<StreamKey, StreamKey>,
    /// STOP streams given up before they closed, by stream.
    retired_stops: BTreeMap<StreamKey, RetiredStop>,
    circuits: BTreeMap<StreamKey, Circuit>,
    circuit_deadlines: Deadlines<StreamKey>,
    /// Pending plus committed circuits per endpoint peer, a self-circuit
    /// counted once.
    peer_circuits: BTreeMap<PeerId, usize>,
    events: VecDeque<RelayServerEvent>,
    last_event_tick_ms: Option<u64>,
    reservation_limiters: AdmissionLimiters,
    circuit_limiters: AdmissionLimiters,
    /// Pending plus committed circuits and committed reservations per
    /// admission key, a circuit whose ends share a key counted once.
    ip_tally: IpTally,
}

impl RelayServerAgent {
    /// Installs the relay service's static directional Swarm roles.
    ///
    /// HOP is inbound and Identify-advertised; STOP is outbound only.
    pub fn register_swarm_roles<T, E>(swarm: &mut SwarmCore<T, E>) -> Result<(), SwarmError>
    where
        T: Transport,
        E: minip2p_core::platform::EntropySource,
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
                config.max_rate_limit_entries,
            ),
            circuit_limiters: AdmissionLimiters::new(
                config.circuit_rate_limit_per_peer,
                config.circuit_rate_limit_per_ip,
                config.max_rate_limit_entries,
            ),
            ip_tally: IpTally::default(),
            config,
            accepting: true,
            explicit_addrs: None,
            confirmed_addrs: Vec::new(),
            listener_addrs: Vec::new(),
            confirmed_addrs_error: None,
            listener_addrs_error: None,
            connections: BTreeMap::new(),
            reservations: BTreeMap::new(),
            reservation_deadlines: Deadlines::new(),
            hop_workers: BTreeMap::new(),
            hop_deadlines: Deadlines::new(),
            rejected_hop_streams: BTreeMap::new(),
            pending_circuits: BTreeMap::new(),
            stop_deadlines: Deadlines::new(),
            pending_by_destination: BTreeSet::new(),
            stop_to_source: BTreeMap::new(),
            retired_stops: BTreeMap::new(),
            circuits: BTreeMap::new(),
            circuit_deadlines: Deadlines::new(),
            peer_circuits: BTreeMap::new(),
            events: VecDeque::new(),
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
    ///
    /// On rejection the previous confirmed addresses stay in effect. The
    /// outcome is also queued for [`poll_event`](Self::poll_event) as
    /// [`RelayServerEvent::AddrsRejected`] or [`RelayServerEvent::AddrsRestored`]
    /// when the source's health changes, so callers may ignore the `Result`.
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected confirmed address for actionable host diagnostics."
    )]
    pub fn set_confirmed_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerAddressError> {
        self.refresh_addrs(RelayServerAddrSource::Confirmed, addrs)
    }

    /// Replaces the concrete bound-listener source atomically.
    ///
    /// On rejection the previous listener addresses stay in effect. The
    /// outcome is also queued for [`poll_event`](Self::poll_event) as
    /// [`RelayServerEvent::AddrsRejected`] or [`RelayServerEvent::AddrsRestored`]
    /// when the source's health changes, so callers may ignore the `Result`.
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected listener address for actionable host diagnostics."
    )]
    pub fn set_listener_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerAddressError> {
        self.refresh_addrs(RelayServerAddrSource::Listener, addrs)
    }

    /// Replaces one host-refreshed source, queueing an event only when its
    /// failure state (or its failing error) changes.
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected address for actionable host diagnostics."
    )]
    fn refresh_addrs(
        &mut self,
        source: RelayServerAddrSource,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerAddressError> {
        let result = normalize_addrs(&self.local_peer_id, addrs);
        let (current, failure) = match source {
            RelayServerAddrSource::Listener => {
                (&mut self.listener_addrs, &mut self.listener_addrs_error)
            }
            RelayServerAddrSource::Confirmed => {
                (&mut self.confirmed_addrs, &mut self.confirmed_addrs_error)
            }
        };
        match result {
            Ok(addrs) => {
                *current = addrs;
                if failure.take().is_some() {
                    self.events
                        .push_back(RelayServerEvent::AddrsRestored { source });
                }
                Ok(())
            }
            Err(error) => {
                if failure.as_ref() != Some(&error) {
                    *failure = Some(error.clone());
                    self.events.push_back(RelayServerEvent::AddrsRejected {
                        source,
                        error: error.clone(),
                    });
                }
                Err(error)
            }
        }
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

    /// Feeds one Swarm event and returns whether the service claimed it.
    ///
    /// `is_circuit` says whether the event's connection is a relay circuit;
    /// for [`SwarmEvent::ConnectionReplaced`] it describes `new`. Every
    /// command the event causes runs on `swarm` before this returns.
    ///
    /// The first event for a `Now` sample processes due deadlines. Subsequent
    /// events with that same sample share the completed sweep; call
    /// [`handle_tick`](Self::handle_tick) to force a sweep independently.
    pub fn handle_event<S: RelaySwarm>(
        &mut self,
        swarm: &mut S,
        event: &SwarmEvent,
        is_circuit: bool,
        now: Now,
    ) -> bool {
        self.dispatch(&mut Io { swarm, now }, event, is_circuit)
    }

    /// Processes every deadline due at or before `now`, running the
    /// commands they cause on `swarm`.
    pub fn handle_tick<S: RelaySwarm>(&mut self, swarm: &mut S, now: Now) {
        self.sweep(&mut Io { swarm, now });
    }

    fn dispatch(&mut self, io: &mut Io<'_>, event: &SwarmEvent, is_circuit: bool) -> bool {
        self.tick_before_event(io);
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                self.on_connection_established(io, peer_id.clone(), *conn_id, is_circuit);
                false
            }
            SwarmEvent::ConnectionClosed {
                peer_id, conn_id, ..
            } => {
                self.on_connection_closed(io, peer_id, *conn_id);
                false
            }
            SwarmEvent::ConnectionReplaced { peer_id, old, new } => {
                self.on_connection_replaced(io, peer_id, *old, *new, is_circuit);
                false
            }
            SwarmEvent::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                protocol_id,
                initiated_locally,
            } => {
                let key = StreamKey {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                };
                if *initiated_locally {
                    self.on_stop_ready(io, key)
                } else if protocol_id == HOP_PROTOCOL_ID {
                    self.on_hop_ready(io, peer_id.clone(), key, is_circuit);
                    true
                } else {
                    false
                }
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
                    self.queue_forward(
                        io,
                        key,
                        CircuitDirection::SourceToDestination,
                        data.clone(),
                    );
                    true
                } else if self.pending_circuits.contains_key(&key) {
                    self.append_pending_payload(
                        io,
                        key,
                        CircuitDirection::SourceToDestination,
                        data,
                    );
                    true
                } else if self.hop_workers.contains_key(&key) {
                    // Payload coalesced with CONNECT stays in the responder
                    // until the decision, unacknowledged.
                    let held = self.hop_bridge_len(key);
                    if self.feed_hop(key, |hop| hop.on_data(data)) {
                        self.drain_hop(io, key);
                    }
                    let payload = self.hop_bridge_len(key).saturating_sub(held);
                    io.ack(key, data.len().saturating_sub(payload));
                    true
                } else if self.rejected_hop_streams.contains_key(&key) {
                    io.ack(key, data.len());
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied() {
                    if self.circuits.contains_key(&source_stream) {
                        self.queue_forward(
                            io,
                            source_stream,
                            CircuitDirection::DestinationToSource,
                            data.clone(),
                        );
                    } else {
                        let bridged = if self.feed_stop(source_stream, |stop| stop.on_data(data)) {
                            self.drain_stop(io, source_stream)
                        } else {
                            0
                        };
                        io.ack(key, data.len().saturating_sub(bridged));
                    }
                    true
                } else if self.retired_stops.contains_key(&key) {
                    io.ack(key, data.len());
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
                    self.circuit_eof(io, key, CircuitLeg::Source);
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.circuits.contains_key(&source_stream)
                {
                    self.circuit_eof(io, source_stream, CircuitLeg::Destination);
                    true
                } else if self.hop_workers.contains_key(&key) {
                    if let Some(circuit) = self.pending_circuits.get_mut(&key) {
                        circuit.source_eof = true;
                    }
                    if self.feed_hop(key, |hop| {
                        hop.on_remote_write_closed();
                        Ok(())
                    }) {
                        self.drain_hop(io, key);
                    }
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.feed_stop(source_stream, StopInitiator::on_remote_write_closed)
                {
                    self.drain_stop(io, source_stream);
                    true
                } else if self.pending_circuits.contains_key(&key) {
                    self.abort_pending_connect(io, key);
                    self.remove_hop_worker(key);
                    true
                } else {
                    self.rejected_hop_streams.contains_key(&key)
                        || self.retired_stops.contains_key(&key)
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
                // Resuming can finish or fail the circuit and remove it, so
                // the claim is decided before.
                let claimed = self.claims_stream(key);
                if self.circuits.contains_key(&key) {
                    self.resume_forward(io, key, CircuitDirection::DestinationToSource);
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied() {
                    self.resume_forward(io, source_stream, CircuitDirection::SourceToDestination);
                }
                claimed
            }
            SwarmEvent::StreamWriteStopped {
                peer_id,
                conn_id,
                stream_id,
                ..
            } => self.on_stream_write_stopped(
                io,
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
                let claimed = if self.circuits.contains_key(&key) {
                    self.circuit_leg_closed(io, key, CircuitLeg::Source);
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.circuits.contains_key(&source_stream)
                {
                    self.circuit_leg_closed(io, source_stream, CircuitLeg::Destination);
                    true
                } else if let Some(source_stream) = self.stop_to_source.get(&key).copied()
                    && self.feed_stop(source_stream, StopInitiator::on_remote_reset)
                {
                    self.drain_stop(io, source_stream);
                    true
                } else if self.stop_to_source.contains_key(&key) {
                    self.on_open_failed(
                        io,
                        key,
                        "stream closed before protocol negotiation completed",
                    )
                } else if self.pending_circuits.contains_key(&key) {
                    self.abort_pending_connect(io, key);
                    self.remove_hop_worker(key);
                    true
                } else {
                    let owned = self.remove_hop_worker(key).is_some();
                    owned || self.rejected_hop_streams.remove(&key).is_some()
                };
                // The stream is gone: a STOP stream retired above, or
                // earlier, needs no more claiming.
                self.retired_stops.remove(&key).is_some() || claimed
            }
            event => match failed_negotiation(event) {
                Some((key, detail)) => self.on_open_failed(io, key, detail),
                None => false,
            },
        }
    }

    /// Processes every deadline due at or before the call's time.
    fn sweep(&mut self, io: &mut Io<'_>) {
        let now_ms = io.now_ms();
        self.last_event_tick_ms = Some(now_ms);
        for key in self.circuit_deadlines.due(now_ms) {
            self.close_circuit(io, key, CircuitCloseReason::DurationLimit);
        }
        for key in self.hop_deadlines.due(now_ms) {
            if self.pending_circuits.contains_key(&key) {
                self.hop_deadlines.remove(&key);
                self.fail_pending_connect(io, key, Status::ConnectionFailed);
                continue;
            }
            if let Some(worker) = self.remove_hop_worker(key) {
                self.reset(io, worker.peer_id.clone(), key);
                if worker.request_known {
                    self.runtime_error(
                        RelayServerRuntimeErrorKind::ResetStream,
                        Some(worker.peer_id),
                        "inbound HOP control stream timed out".into(),
                    );
                }
            }
        }
        for key in self.stop_deadlines.due(now_ms) {
            self.fail_pending_connect(io, key, Status::ConnectionFailed);
        }
        for peer_id in self.reservation_deadlines.due(now_ms) {
            self.remove_reservation(&peer_id);
            self.events.push_back(RelayServerEvent::ReservationClosed {
                peer_id,
                reason: ReservationCloseReason::Expired,
            });
        }
        self.reservation_limiters.sweep(now_ms);
        self.circuit_limiters.sweep(now_ms);
    }

    /// Resets a relay stream the peer stopped; returns whether we own it.
    ///
    /// Every relay stream needs to write, so a stopped one is reset; the
    /// `StreamClosed` that follows runs the usual teardown. Kept out of line
    /// and cold: inlined, its lookups slowed every `handle_event` call.
    #[cold]
    #[inline(never)]
    fn on_stream_write_stopped(
        &mut self,
        io: &mut Io<'_>,
        peer_id: &PeerId,
        key: StreamKey,
    ) -> bool {
        let owned = self.claims_stream(key);
        if owned {
            self.reset(io, peer_id.clone(), key);
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
            || self.retired_stops.contains_key(&key)
    }

    /// Sweeps deadlines before the first event in a driver batch.
    ///
    /// A single caller time sample is commonly shared by several events. New
    /// deadlines created while handling those events are in the future unless
    /// the clock has saturated, so rescanning unchanged state cannot make
    /// additional progress.
    fn tick_before_event(&mut self, io: &mut Io<'_>) {
        let now_ms = io.now_ms();
        if now_ms == u64::MAX || self.last_event_tick_ms != Some(now_ms) {
            self.sweep(io);
        }
    }

    /// Settles a STOP stream's negotiation: sends the STOP CONNECT of the
    /// circuit still waiting on it, or resets a stream the relay retired
    /// while it negotiated. Returns whether the stream is the relay's.
    ///
    /// Settlement runs behind the event's deadline sweep, so readiness at
    /// the circuit's deadline finds it already timed out.
    #[cold]
    #[inline(never)]
    fn on_stop_ready(&mut self, io: &mut Io<'_>, key: StreamKey) -> bool {
        if let Some(retired) = self.retired_stops.get_mut(&key) {
            if !retired.ready {
                retired.ready = true;
                let peer_id = retired.peer_id.clone();
                self.reset(io, peer_id, key);
            }
            return true;
        }
        let Some(source_stream) = self.stop_to_source.get(&key).copied() else {
            return false;
        };
        let limit = self.circuit_limit();
        if let Some(circuit) = self.pending_circuits.get_mut(&source_stream)
            && circuit.stop.is_none()
        {
            // The initiator's first output is the STOP CONNECT request.
            circuit.stop = Some(StopInitiator::new(
                circuit.source_peer_id.clone(),
                Some(limit),
            ));
            self.drain_stop(io, source_stream);
        }
        true
    }

    /// Settles a STOP stream whose negotiation failed or whose stream closed
    /// first. Returns whether the stream is the relay's.
    #[cold]
    #[inline(never)]
    fn on_open_failed(&mut self, io: &mut Io<'_>, key: StreamKey, detail: &str) -> bool {
        if self.retired_stops.remove(&key).is_some() {
            return true;
        }
        let Some(source_stream) = self.stop_to_source.get(&key).copied() else {
            return false;
        };
        if let Some(circuit) = self.pending_circuits.get_mut(&source_stream)
            && circuit.stop.is_none()
        {
            // The stream is gone: nothing to reset or claim.
            circuit.stop_stream = None;
            self.stop_to_source.remove(&key);
            let peer_id = circuit.destination_peer_id.clone();
            self.runtime_error(
                RelayServerRuntimeErrorKind::OpenStream,
                Some(peer_id),
                detail.into(),
            );
            self.fail_pending_connect(io, source_stream, Status::ConnectionFailed);
        }
        true
    }

    /// Removes the next application-visible event in causal order.
    pub fn poll_event(&mut self) -> Option<RelayServerEvent> {
        self.events.pop_front()
    }

    /// Returns when the earliest timer is due on the monotonic timeline, or
    /// `None` when no timer is armed.
    ///
    /// An overdue timer reports its past due time, so it is already expired
    /// at `now`; call [`handle_tick`](Self::handle_tick) once it expires.
    pub fn next_deadline(&self, _now: Now) -> Option<Deadline> {
        let reservation = self.reservation_deadlines.earliest();
        let hop = self.hop_deadlines.earliest();
        let stop = self.stop_deadlines.earliest();
        let circuit = self.circuit_deadlines.earliest();
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
            .map(Deadline::from_millis)
    }

    /// Whether the stream is owned by a HOP worker, STOP worker, or circuit,
    /// including a stream the relay gave up and still claims until it
    /// closes.
    pub fn owns_stream(&self, stream: StreamKey) -> bool {
        self.hop_workers.contains_key(&stream)
            || self.rejected_hop_streams.contains_key(&stream)
            || self.stop_to_source.contains_key(&stream)
            || self.retired_stops.contains_key(&stream)
            || self.circuits.contains_key(&stream)
    }

    /// The exact connection owning `peer_id`'s committed reservation.
    /// Exposed for test support.
    #[doc(hidden)]
    pub fn reservation_connection(&self, peer_id: &PeerId) -> Option<ConnectionId> {
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

    fn on_connection_established(
        &mut self,
        io: &Io<'_>,
        peer_id: PeerId,
        conn_id: ConnectionId,
        is_circuit: bool,
    ) {
        let ip = io.swarm.connection_remote_addr(conn_id).and_then(first_ip);
        self.connections.insert(
            conn_id,
            Connection {
                peer_id,
                ip,
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
        io: &mut Io<'_>,
        peer_id: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
        is_circuit: bool,
    ) {
        self.on_connection_established(io, peer_id.clone(), new, is_circuit);
        if !is_circuit
            && let Some(reservation) = self.reservations.get_mut(peer_id)
            && reservation.conn_id == old
        {
            reservation.conn_id = new;
        }
        self.on_connection_closed(io, peer_id, old);
    }

    fn on_connection_closed(&mut self, io: &mut Io<'_>, peer_id: &PeerId, conn_id: ConnectionId) {
        // Circuits are keyed by their source stream, so source legs are a
        // range; destination legs come through `stop_to_source`, keyed by
        // the destination stream. Collected by circuit so they close in
        // circuit order, a circuit with both legs here as its source.
        let mut affected: BTreeMap<StreamKey, CircuitLeg> = self
            .stop_to_source
            .range(connection_streams(conn_id))
            .map(|(_, source_stream)| *source_stream)
            .filter(|source_stream| self.circuits.contains_key(source_stream))
            .map(|source_stream| (source_stream, CircuitLeg::Destination))
            .collect();
        affected.extend(
            self.circuits
                .range(connection_streams(conn_id))
                .map(|(source_stream, _)| (*source_stream, CircuitLeg::Source)),
        );
        for (key, leg) in affected {
            self.close_circuit(io, key, CircuitCloseReason::ConnectionClosed { leg });
        }
        // Likewise for pending circuits: whether the source leg closed.
        let mut pending: BTreeMap<StreamKey, bool> = self
            .pending_by_destination
            .range(pending_to(conn_id))
            .map(|(_, source_stream)| (*source_stream, false))
            .collect();
        pending.extend(
            self.pending_circuits
                .range(connection_streams(conn_id))
                .map(|(source_stream, _)| (*source_stream, true)),
        );
        for (source_stream, source_closed) in pending {
            if source_closed {
                self.abort_pending_connect(io, source_stream);
            } else {
                // The STOP stream went with its connection: nothing to reset.
                if let Some(circuit) = self.pending_circuits.get_mut(&source_stream)
                    && let Some(stop_stream) = circuit.stop_stream.take()
                {
                    self.stop_to_source.remove(&stop_stream);
                    if circuit.stop.is_none() {
                        let peer_id = circuit.destination_peer_id.clone();
                        self.runtime_error(
                            RelayServerRuntimeErrorKind::OpenStream,
                            Some(peer_id),
                            format!(
                                "destination connection {conn_id} closed during protocol negotiation"
                            ),
                        );
                    }
                }
                self.fail_pending_connect(io, source_stream, Status::ConnectionFailed);
            }
        }
        self.connections.remove(&conn_id);
        if self
            .reservations
            .get(peer_id)
            .is_some_and(|reservation| reservation.conn_id == conn_id)
        {
            self.remove_reservation(peer_id);
            self.events.push_back(RelayServerEvent::ReservationClosed {
                peer_id: peer_id.clone(),
                reason: ReservationCloseReason::ConnectionClosed,
            });
        }
        let closed_hop_streams: Vec<_> = self
            .hop_workers
            .range(connection_streams(conn_id))
            .map(|(stream, _)| *stream)
            .collect();
        for stream in closed_hop_streams {
            self.remove_hop_worker(stream);
        }
        let rejected: Vec<_> = self
            .rejected_hop_streams
            .range(connection_streams(conn_id))
            .map(|(stream, _)| *stream)
            .collect();
        for stream in rejected {
            self.rejected_hop_streams.remove(&stream);
        }
        // Last: the cleanup above may have retired STOP streams here.
        let retired: Vec<_> = self
            .retired_stops
            .range(connection_streams(conn_id))
            .map(|(stream, _)| *stream)
            .collect();
        for stream in retired {
            self.retired_stops.remove(&stream);
        }
    }

    fn on_hop_ready(&mut self, io: &mut Io<'_>, peer_id: PeerId, key: StreamKey, is_circuit: bool) {
        let Some(connection) = self.connections.get(&key.conn_id) else {
            self.rejected_hop_streams.insert(key, peer_id.clone());
            self.reset(io, peer_id, key);
            return;
        };
        if connection.peer_id != peer_id {
            self.rejected_hop_streams.insert(key, peer_id.clone());
            self.reset(io, peer_id, key);
            return;
        }
        let is_circuit = is_circuit || connection.is_circuit;
        // Every HOP worker on the connection holds a slot, not only the ones
        // still waiting on a reply. A finished worker stays to claim its
        // stream's events until the peer closes the stream, so counting only
        // the waiting ones would let a peer that never closes open one HOP
        // stream per muxer slot, on every connection it holds. Circuit legs
        // keep their worker too, and are bounded by `max_circuits` and
        // `max_circuits_per_peer` instead. The range visits only this
        // connection's workers.
        let count = self
            .hop_workers
            .range(connection_streams(key.conn_id))
            .filter(|(stream, _)| {
                !self.circuits.contains_key(stream) && !self.pending_circuits.contains_key(stream)
            })
            .count();
        if count >= self.config.max_pending_hop_requests_per_connection {
            self.rejected_hop_streams.insert(key, peer_id.clone());
            self.reset(io, peer_id, key);
            return;
        }
        let worker = HopWorker {
            peer_id: peer_id.clone(),
            responder: HopResponder::new(),
            request_known: false,
            is_circuit,
        };
        self.hop_workers.insert(key, worker);
        self.hop_deadlines.set(
            key,
            io.now_ms()
                .saturating_add(self.config.control_stream_timeout_ms),
        );
    }

    /// Delivers an input to a live HOP responder.
    ///
    /// Missing workers are stale stream events and need no new action. A
    /// responder error after the agent routed the event is an internal
    /// contract failure, so surface it before the caller decides whether to
    /// drain any output.
    fn feed_hop(
        &mut self,
        key: StreamKey,
        input: impl FnOnce(&mut HopResponder) -> Result<(), RelayError>,
    ) -> bool {
        let Some(worker) = self.hop_workers.get_mut(&key) else {
            return false;
        };
        let peer_id = worker.peer_id.clone();
        let result = input(&mut worker.responder);
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

    /// Delivers an input to a pending STOP initiator; returns false for a
    /// stale stream.
    fn feed_stop(
        &mut self,
        source_stream: StreamKey,
        input: impl FnOnce(&mut StopInitiator),
    ) -> bool {
        let Some(stop) = self
            .pending_circuits
            .get_mut(&source_stream)
            .and_then(|circuit| circuit.stop.as_mut())
        else {
            return false;
        };
        input(stop);
        true
    }

    /// Runs a HOP responder's outputs. A control reply that does not fully
    /// enter its stream stops the worker: its stream is reset, and nothing
    /// the responder produced after the reply (its FIN) takes effect.
    fn drain_hop(&mut self, io: &mut Io<'_>, key: StreamKey) {
        while let Some(worker) = self.hop_workers.get_mut(&key) {
            let Some(output) = worker.responder.poll_output() else {
                break;
            };
            let peer_id = worker.peer_id.clone();
            match output {
                HopResponderOutput::Request(HopRequest::Reserve) => {
                    worker.request_known = true;
                    if worker.is_circuit {
                        self.events.push_back(RelayServerEvent::ReservationDenied {
                            peer_id,
                            status: Status::PermissionDenied,
                        });
                        self.feed_hop(key, |hop| hop.reject(Status::PermissionDenied));
                    } else {
                        self.decide_reservation(io, key);
                    }
                }
                HopResponderOutput::Request(HopRequest::Connect {
                    destination_peer_id,
                }) => {
                    worker.request_known = true;
                    if worker.is_circuit {
                        self.deny_connect(key, destination_peer_id, Status::PermissionDenied);
                    } else {
                        self.decide_connect(io, key, destination_peer_id);
                    }
                }
                HopResponderOutput::Outbound(data) => {
                    match io
                        .swarm
                        .send_stream(&peer_id, key, data.into(), io.now_ms())
                    {
                        Ok(()) => self.complete_hop(key),
                        Err(error) => self.abort_hop_reply(io, peer_id, key, error),
                    }
                }
                HopResponderOutput::CloseWrite => self.close(io, peer_id, key),
                HopResponderOutput::Reset => self.reset(io, peer_id, key),
                // Payload coalesced with CONNECT follows acceptance, which
                // `accept_pending_circuit` drains itself; a committed or
                // pending circuit reads its source leg directly.
                HopResponderOutput::BridgeData(_) => {}
            }
        }
    }

    /// Drives a pending circuit's STOP initiator and returns how many
    /// destination payload bytes it moved into the pending circuit's buffer;
    /// those stay unacknowledged until forwarded or released.
    ///
    /// An accepted STOP commits the circuit only once every output is
    /// drained, so payload the destination pipelined behind its STATUS is
    /// buffered first and forwarded with the commit.
    fn drain_stop(&mut self, io: &mut Io<'_>, source_stream: StreamKey) -> usize {
        let mut bridged = 0;
        let mut accepted = false;
        while let Some(circuit) = self.pending_circuits.get_mut(&source_stream) {
            let Some(output) = circuit.stop.as_mut().and_then(StopInitiator::poll_output) else {
                break;
            };
            let peer_id = circuit.destination_peer_id.clone();
            let stream = circuit.stop_stream;
            match output {
                StopInitiatorOutput::Outcome(StopInitiatorOutcome::Accepted) => accepted = true,
                StopInitiatorOutput::Outcome(outcome) => {
                    self.fail_pending_connect(io, source_stream, outcome.hop_status());
                    return bridged;
                }
                StopInitiatorOutput::BridgeData(data) => {
                    if self.append_pending_payload(
                        io,
                        source_stream,
                        CircuitDirection::DestinationToSource,
                        &data,
                    ) {
                        bridged += data.len();
                    }
                }
                StopInitiatorOutput::Outbound(data) => {
                    let Some(stream) = stream else { break };
                    if let Err(error) =
                        io.swarm
                            .send_stream(&peer_id, stream, data.into(), io.now_ms())
                    {
                        self.fail_pending_connect(io, source_stream, Status::ConnectionFailed);
                        self.runtime_error(
                            RelayServerRuntimeErrorKind::SendStream,
                            Some(peer_id),
                            control_send_failure(error),
                        );
                        return bridged;
                    }
                }
                StopInitiatorOutput::CloseWrite => {
                    if let Some(stream) = stream {
                        self.close(io, peer_id, stream);
                    }
                }
                StopInitiatorOutput::Reset => {
                    if let Some(stream) = stream {
                        self.reset(io, peer_id, stream);
                    }
                }
            }
        }
        if accepted {
            self.accept_pending_circuit(io, source_stream);
        }
        bridged
    }

    /// The destination accepted STOP: answers the source's CONNECT and, once
    /// the transport takes that success, commits the circuit.
    fn accept_pending_circuit(&mut self, io: &mut Io<'_>, source_stream: StreamKey) {
        if !self.pending_circuits.contains_key(&source_stream) {
            return;
        }
        self.stop_deadlines.remove(&source_stream);
        let limit = self.circuit_limit();
        if !self.feed_hop(source_stream, |hop| hop.accept_connect(Some(limit))) {
            self.fail_pending_connect(io, source_stream, Status::ConnectionFailed);
            return;
        }
        let Some(worker) = self.hop_workers.get_mut(&source_stream) else {
            self.fail_pending_connect(io, source_stream, Status::ConnectionFailed);
            return;
        };
        let Some(HopResponderOutput::Outbound(reply)) = worker.responder.poll_output() else {
            self.fail_pending_connect(io, source_stream, Status::ConnectionFailed);
            return;
        };
        let peer_id = worker.peer_id.clone();
        // Payload coalesced with CONNECT follows the reply; it precedes
        // everything buffered since.
        let mut held = Vec::new();
        while let Some(output) = worker.responder.poll_output() {
            if let HopResponderOutput::BridgeData(data) = output {
                held.extend_from_slice(&data);
            }
        }
        if !held.is_empty()
            && let Some(circuit) = self.pending_circuits.get_mut(&source_stream)
        {
            let later = core::mem::replace(&mut circuit.source_pipelined, held);
            if !self.append_pending_payload(
                io,
                source_stream,
                CircuitDirection::SourceToDestination,
                &later,
            ) {
                return;
            }
        }
        match io
            .swarm
            .send_stream(&peer_id, source_stream, reply.into(), io.now_ms())
        {
            Ok(()) => {
                self.complete_hop(source_stream);
                self.commit_circuit(io, source_stream);
            }
            Err(error) => {
                self.abort_pending_connect_both(io, source_stream);
                self.runtime_error(
                    RelayServerRuntimeErrorKind::SendStream,
                    Some(peer_id),
                    control_send_failure(error),
                );
            }
        }
    }

    fn circuit_limit(&self) -> Limit {
        Limit {
            duration: Some(self.config.max_circuit_duration_secs as u32),
            data: Some(self.config.max_circuit_bytes),
        }
    }

    /// Commits a pending circuit whose HOP success the source took, then
    /// forwards both sides' pipelined payload and the source's half-close.
    /// Both directions are queued before either sends, so a close the first
    /// causes still releases the second's credit.
    fn commit_circuit(&mut self, io: &mut Io<'_>, source_stream: StreamKey) {
        let Some(pending) = self.remove_pending_circuit(source_stream) else {
            return;
        };
        let Some(destination_stream) = pending.stop_stream else {
            return;
        };
        if self.config.max_circuit_duration_secs != 0 {
            self.circuit_deadlines.set(
                source_stream,
                io.now_ms()
                    .saturating_add(self.config.max_circuit_duration_secs.saturating_mul(1_000)),
            );
        }
        self.hold_circuit(
            &pending.source_peer_id,
            &pending.destination_peer_id,
            pending.source_ip.as_ref(),
            pending.destination_ip.as_ref(),
        );
        let mut circuit = Circuit {
            source_peer_id: pending.source_peer_id.clone(),
            destination_peer_id: pending.destination_peer_id.clone(),
            source_ip: pending.source_ip,
            destination_ip: pending.destination_ip,
            source_stream,
            destination_stream,
            bytes: CircuitByteCounts::default(),
            to_destination: Forward::default(),
            to_source: Forward::default(),
        };
        if !pending.source_pipelined.is_empty() {
            circuit.to_destination.push(pending.source_pipelined.into());
        }
        if pending.source_eof {
            circuit.to_destination.fin = FinState::Received;
        }
        if !pending.destination_pipelined.is_empty() {
            circuit.to_source.push(pending.destination_pipelined.into());
        }
        self.circuits.insert(source_stream, circuit);
        self.events.push_back(RelayServerEvent::CircuitOpened {
            source_peer_id: pending.source_peer_id,
            destination_peer_id: pending.destination_peer_id,
        });
        self.pump_forward(io, source_stream, CircuitDirection::SourceToDestination);
        self.pump_forward(io, source_stream, CircuitDirection::DestinationToSource);
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
    fn release_pipelined(
        &self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        circuit: &PendingCircuit,
    ) {
        let held = self.hop_bridge_len(source_stream);
        io.ack(source_stream, circuit.source_pipelined.len() + held);
        if let Some(stop_stream) = circuit.stop_stream {
            io.ack(stop_stream, circuit.destination_pipelined.len());
        }
    }

    /// Buffers `data` on a pending circuit, returning whether it was kept;
    /// payload past the bound aborts the circuit.
    fn append_pending_payload(
        &mut self,
        io: &mut Io<'_>,
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
        self.abort_pending_connect_both(io, source_stream);
        self.runtime_error(
            RelayServerRuntimeErrorKind::InternalInvariant,
            Some(peer_id),
            "pending circuit payload exceeded the 64 KiB directional bound".into(),
        );
        false
    }

    /// Queues `data` read from `direction`'s origin behind what it already
    /// holds, and sends what the target takes.
    fn queue_forward(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        direction: CircuitDirection,
        data: Bytes,
    ) {
        if data.is_empty() {
            return;
        }
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return;
        };
        circuit.forward(direction).push(data);
        self.pump_forward(io, source_stream, direction);
    }

    /// Sends a direction's queue, head first, until it empties, the target
    /// answers Full, or the circuit closes; then its FIN once the origin
    /// half-closed and every byte was accepted.
    fn pump_forward(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        direction: CircuitDirection,
    ) {
        loop {
            let Some(circuit) = self.circuits.get_mut(&source_stream) else {
                return;
            };
            let (peer_id, stream, forward) = circuit.target(direction);
            if forward.blocked {
                return;
            }
            let Some(data) = forward.head() else {
                if forward.fin == FinState::Received {
                    let leg = target_leg(direction);
                    match io.swarm.close_stream_write(peer_id, stream, io.now_ms()) {
                        Ok(()) => self.circuit_close_accepted(io, source_stream, leg),
                        Err(error) => {
                            let peer_id = peer_id.clone();
                            self.close_circuit(
                                io,
                                source_stream,
                                CircuitCloseReason::InternalFailure,
                            );
                            self.runtime_error(
                                RelayServerRuntimeErrorKind::CloseStream,
                                Some(peer_id),
                                error.to_string(),
                            );
                        }
                    }
                }
                return;
            };
            let chunk_len = data.len();
            let unsent = match io.swarm.send_stream(peer_id, stream, data, io.now_ms()) {
                Ok(()) => None,
                Err(RelaySwarmError(DriverError::Full { unsent, .. }))
                    if unsent.len() <= chunk_len =>
                {
                    Some(unsent)
                }
                Err(error) => {
                    let peer_id = peer_id.clone();
                    self.close_circuit(
                        io,
                        source_stream,
                        CircuitCloseReason::ForwardFailed { direction },
                    );
                    self.runtime_error(
                        RelayServerRuntimeErrorKind::SendStream,
                        Some(peer_id),
                        error.to_string(),
                    );
                    return;
                }
            };
            if !self.forward_accepted(io, source_stream, direction, chunk_len, unsent) {
                return;
            }
        }
    }

    /// Resumes a direction paused by a Full on its target leg.
    fn resume_forward(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        direction: CircuitDirection,
    ) {
        if let Some(circuit) = self.circuits.get_mut(&source_stream) {
            let forward = circuit.forward(direction);
            if forward.blocked {
                forward.blocked = false;
                self.pump_forward(io, source_stream, direction);
            }
        }
    }

    /// Applies a forwarding send's result: the head of `chunk_len` bytes went
    /// out but for an `unsent` tail (after a Full), which waits for the
    /// target's Writable. Accepted bytes are acknowledged to the origin and
    /// count toward the circuit's byte limit. Returns whether the direction
    /// may send again now.
    fn forward_accepted(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        direction: CircuitDirection,
        chunk_len: usize,
        unsent: Option<Bytes>,
    ) -> bool {
        let Some(circuit) = self.circuits.get_mut(&source_stream) else {
            return false;
        };
        let accepted = chunk_len - unsent.as_ref().map_or(0, Bytes::len);
        let origin = circuit.origin(direction);
        let forward = circuit.forward(direction);
        forward.accept(unsent);
        let blocked = forward.blocked;
        let total = match direction {
            CircuitDirection::SourceToDestination => &mut circuit.bytes.source_to_destination,
            CircuitDirection::DestinationToSource => &mut circuit.bytes.destination_to_source,
        };
        *total = total.saturating_add(accepted as u64);
        let total = *total;
        io.ack(origin, accepted);
        if self.config.max_circuit_bytes != 0 && total > self.config.max_circuit_bytes {
            self.close_circuit(
                io,
                source_stream,
                CircuitCloseReason::ByteLimit { direction },
            );
            return false;
        }
        !blocked
    }

    fn close_circuit(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        reason: CircuitCloseReason,
    ) {
        let Some(mut circuit) = self.remove_circuit(source_stream) else {
            return;
        };
        self.remove_hop_worker(source_stream);
        self.stop_to_source.remove(&circuit.destination_stream);
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
            self.reset(io, circuit.source_peer_id.clone(), circuit.source_stream);
        }
        if reset_destination {
            self.reset(
                io,
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
            io.ack(origin, unacked);
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
    fn circuit_eof(&mut self, io: &mut Io<'_>, source_stream: StreamKey, leg: CircuitLeg) {
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
            self.pump_forward(io, source_stream, direction);
        }
    }

    /// Handles `leg`'s stream closing. A leg that finished both ways (its
    /// half-close was read and the FIN forwarded to it accepted) closed
    /// cleanly, and the other direction keeps draining; anything else is a
    /// reset.
    fn circuit_leg_closed(&mut self, io: &mut Io<'_>, source_stream: StreamKey, leg: CircuitLeg) {
        let Some(circuit) = self.circuits.get(&source_stream) else {
            return;
        };
        let (from_leg, to_leg) = match leg {
            CircuitLeg::Source => (&circuit.to_destination, &circuit.to_source),
            CircuitLeg::Destination => (&circuit.to_source, &circuit.to_destination),
        };
        if from_leg.fin == FinState::Open || to_leg.fin != FinState::Accepted {
            self.close_circuit(io, source_stream, CircuitCloseReason::StreamReset { leg });
        }
    }

    /// Records that `leg` accepted the FIN forwarded to it.
    fn circuit_close_accepted(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
        leg: CircuitLeg,
    ) {
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
            self.close_circuit(io, source_stream, CircuitCloseReason::Eof);
        }
    }

    /// Decides a RESERVE and, once the transport takes its success reply,
    /// commits the reservation.
    fn decide_reservation(&mut self, io: &mut Io<'_>, key: StreamKey) {
        let Some(peer_id) = self
            .hop_workers
            .get(&key)
            .map(|worker| worker.peer_id.clone())
        else {
            return;
        };
        let now = io.now;
        let renewal = self
            .reservations
            .get(&peer_id)
            .filter(|reservation| reservation.conn_id == key.conn_id);
        let renewed = renewal.is_some();
        // A renewal keeps the key it was admitted under.
        let ip = match renewal {
            Some(reservation) => reservation.ip.clone(),
            None => self.connection_ip(key.conn_id),
        };
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
        } else if !renewed && !self.admit_new_reservation(&peer_id, ip.as_ref(), now.monotonic_ms) {
            Some(Status::ResourceLimitExceeded)
        } else {
            None
        };
        if let Some(status) = status {
            self.events.push_back(RelayServerEvent::ReservationDenied {
                peer_id: peer_id.clone(),
                status,
            });
            self.feed_hop(key, |hop| hop.reject(status));
            return;
        }

        let (reservation, limit) = wire.expect("availability checked above");
        if !self.feed_hop(key, |hop| hop.accept_reservation(reservation, Some(limit))) {
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
        if let Err(error) = io
            .swarm
            .send_stream(&peer_id, key, data.into(), now.monotonic_ms)
        {
            self.abort_hop_reply(io, peer_id, key, error);
            return;
        }
        if self
            .connections
            .get(&key.conn_id)
            .is_some_and(|connection| connection.peer_id == peer_id)
        {
            self.insert_reservation(peer_id.clone(), key.conn_id, ip, deadline_ms);
            self.events
                .push_back(RelayServerEvent::ReservationAccepted {
                    peer_id,
                    renewed,
                    expires_unix_secs,
                });
        }
        self.complete_hop(key);
    }

    fn reservation_wire(&self, expires_unix_secs: Option<u64>) -> Option<(Reservation, Limit)> {
        let mut addrs = Vec::new();
        for address in self.selected_addrs() {
            let mut advertised = address.clone();
            advertised.push(Protocol::P2p(self.local_peer_id.clone()));
            addrs.push(advertised.to_bytes());
        }
        let limit = self.circuit_limit();
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

    /// Admission for a new reservation: needs a rate-limit token and room
    /// under `max_reservations` and `max_reservations_per_ip`, and spends the
    /// token only when all hold.
    fn admit_new_reservation(&mut self, peer_id: &PeerId, ip: Option<&IpKey>, now_ms: u64) -> bool {
        if !self.reservation_limiters.allows(peer_id, ip, now_ms) {
            return false;
        }
        if self.reservations.len() >= self.config.max_reservations
            || self
                .ip_tally
                .is_full(ip, Held::Reservations, self.config.max_reservations_per_ip)
        {
            return false;
        }
        self.reservation_limiters
            .consume(peer_id, ip.cloned(), now_ms);
        true
    }

    /// The admission key of `conn_id`'s remote address's first IP.
    fn connection_ip(&self, conn_id: ConnectionId) -> Option<IpKey> {
        self.connections
            .get(&conn_id)
            .and_then(|connection| connection.ip.clone())
    }

    /// Decides a CONNECT and, when admitted, opens STOP on the destination's
    /// exact reserved connection. The circuit then waits for that stream's
    /// `StreamReady`.
    fn decide_connect(&mut self, io: &mut Io<'_>, key: StreamKey, destination_peer_id: PeerId) {
        let Some(source_peer_id) = self
            .hop_workers
            .get(&key)
            .map(|worker| worker.peer_id.clone())
        else {
            return;
        };
        let now_ms = io.now_ms();
        let destination_conn = self
            .reservations
            .get(&destination_peer_id)
            .map(|reservation| reservation.conn_id);
        let source_ip = self.connection_ip(key.conn_id);
        let destination_ip = destination_conn.and_then(|conn_id| self.connection_ip(conn_id));
        let max_per_ip = self.config.max_circuits_per_ip;
        let status = if !self.accepting
            || self
                .connections
                .get(&key.conn_id)
                .is_some_and(|connection| connection.is_circuit)
        {
            Some(Status::PermissionDenied)
        } else if !self
            .circuit_limiters
            .allows(&source_peer_id, source_ip.as_ref(), now_ms)
            || self.peer_circuit_count(&source_peer_id) >= self.config.max_circuits_per_peer
            || (source_peer_id != destination_peer_id
                && self.peer_circuit_count(&destination_peer_id)
                    >= self.config.max_circuits_per_peer)
            || circuit_ip_keys(source_ip.as_ref(), destination_ip.as_ref())
                .any(|ip| self.ip_tally.is_full(Some(ip), Held::Circuits, max_per_ip))
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
        } else if destination_conn.is_some_and(|conn_id| {
            self.pending_stop_count(conn_id) >= self.config.max_pending_stop_requests_per_connection
        }) {
            Some(Status::ResourceLimitExceeded)
        } else {
            None
        };
        if let Some(status) = status {
            self.deny_connect(key, destination_peer_id, status);
            return;
        }
        // Admitted: only now does the request cost a token.
        self.circuit_limiters
            .consume(&source_peer_id, source_ip.clone(), now_ms);
        let destination_conn_id = destination_conn.expect("checked above");
        // The swarm may be ahead of the events delivered so far.
        let opened = if io
            .swarm
            .connection_remote_addr(destination_conn_id)
            .is_none()
        {
            Err(format!(
                "expected destination connection {destination_conn_id} is no longer active"
            ))
        } else {
            io.swarm
                .open_stream(&destination_peer_id, STOP_PROTOCOL_ID, now_ms)
                .map_err(|error| error.to_string())
        };
        let stop_stream = match opened {
            Ok(stream) if stream.conn_id == destination_conn_id => stream,
            // Opens are peer-scoped: this one landed on a connection that
            // replaced the reservation's.
            Ok(stream) => {
                self.retire_stop(io, destination_peer_id.clone(), stream, false);
                self.deny_connect(key, destination_peer_id, Status::NoReservation);
                return;
            }
            Err(detail) => {
                self.runtime_error(
                    RelayServerRuntimeErrorKind::OpenStream,
                    Some(destination_peer_id.clone()),
                    detail,
                );
                self.deny_connect(key, destination_peer_id, Status::ConnectionFailed);
                return;
            }
        };
        self.insert_pending_circuit(
            key,
            PendingCircuit {
                source_peer_id,
                destination_peer_id,
                source_ip,
                destination_ip,
                destination_conn_id,
                stop_stream: Some(stop_stream),
                stop: None,
                source_pipelined: Vec::new(),
                destination_pipelined: Vec::new(),
                source_eof: false,
            },
            now_ms.saturating_add(self.config.control_stream_timeout_ms),
        );
    }

    fn peer_circuit_count(&self, peer_id: &PeerId) -> usize {
        self.peer_circuits.get(peer_id).copied().unwrap_or(0)
    }

    /// Pending circuits to `conn_id` whose STOP exchange is outstanding.
    fn pending_stop_count(&self, conn_id: ConnectionId) -> usize {
        self.pending_by_destination
            .range(pending_to(conn_id))
            .filter(|(_, source_stream)| self.stop_deadlines.contains(source_stream))
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
        self.feed_hop(key, |hop| hop.reject(status));
    }

    /// Fails a pending circuit, answering its CONNECT with `status`.
    fn fail_pending_connect(&mut self, io: &mut Io<'_>, source_stream: StreamKey, status: Status) {
        let Some(destination_peer_id) = self.drop_pending_circuit(io, source_stream) else {
            return;
        };
        self.deny_connect(source_stream, destination_peer_id, status);
        self.drain_hop(io, source_stream);
    }

    /// Drops a pending circuit whose source leg is going away, leaving its
    /// CONNECT unanswered.
    fn abort_pending_connect(&mut self, io: &mut Io<'_>, source_stream: StreamKey) {
        self.drop_pending_circuit(io, source_stream);
    }

    /// Removes a pending circuit, releases its buffered payload's credit, and
    /// retires its STOP stream. Returns its destination peer.
    fn drop_pending_circuit(
        &mut self,
        io: &mut Io<'_>,
        source_stream: StreamKey,
    ) -> Option<PeerId> {
        let circuit = self.remove_pending_circuit(source_stream)?;
        self.release_pipelined(io, source_stream, &circuit);
        if let Some(stop_stream) = circuit.stop_stream {
            self.stop_to_source.remove(&stop_stream);
            self.retire_stop(
                io,
                circuit.destination_peer_id.clone(),
                stop_stream,
                circuit.stop.is_some(),
            );
        }
        Some(circuit.destination_peer_id)
    }

    fn abort_pending_connect_both(&mut self, io: &mut Io<'_>, source_stream: StreamKey) {
        self.abort_pending_connect(io, source_stream);
        if let Some(worker) = self.remove_hop_worker(source_stream) {
            self.reset(io, worker.peer_id, source_stream);
        }
    }

    /// Gives up a STOP stream the relay still owns. A negotiated stream is
    /// reset now; one still negotiating cannot be, so its `StreamReady`
    /// resets it. Either way the relay claims the stream's events until it
    /// closes.
    fn retire_stop(&mut self, io: &mut Io<'_>, peer_id: PeerId, stream: StreamKey, ready: bool) {
        if ready {
            self.reset(io, peer_id.clone(), stream);
        }
        self.retired_stops
            .insert(stream, RetiredStop { peer_id, ready });
    }

    fn complete_hop(&mut self, stream: StreamKey) {
        self.hop_deadlines.remove(&stream);
    }

    /// A HOP reply did not fully enter the stream: the worker stops, its
    /// stream is reset rather than half-closed, so the peer never reads a
    /// truncated reply as complete, and the relay claims the stream's
    /// events until it closes.
    fn abort_hop_reply(
        &mut self,
        io: &mut Io<'_>,
        peer_id: PeerId,
        stream: StreamKey,
        error: RelaySwarmError,
    ) {
        self.remove_hop_worker(stream);
        self.rejected_hop_streams.insert(stream, peer_id.clone());
        self.reset(io, peer_id.clone(), stream);
        self.runtime_error(
            RelayServerRuntimeErrorKind::SendStream,
            Some(peer_id),
            control_send_failure(error),
        );
    }

    /// Half-closes a control stream's write side.
    fn close(&mut self, io: &mut Io<'_>, peer_id: PeerId, stream: StreamKey) {
        if let Err(error) = io.swarm.close_stream_write(&peer_id, stream, io.now_ms()) {
            self.runtime_error(
                RelayServerRuntimeErrorKind::CloseStream,
                Some(peer_id),
                error.to_string(),
            );
        }
    }

    fn reset(&mut self, io: &mut Io<'_>, peer_id: PeerId, stream: StreamKey) {
        if let Err(error) = io.swarm.reset_stream(&peer_id, stream, io.now_ms()) {
            self.runtime_error(
                RelayServerRuntimeErrorKind::ResetStream,
                Some(peer_id),
                error.to_string(),
            );
        }
    }

    // Inserts and removals that keep the indexes in step with their maps.

    fn insert_reservation(
        &mut self,
        peer_id: PeerId,
        conn_id: ConnectionId,
        ip: Option<IpKey>,
        deadline_ms: u64,
    ) {
        self.reservation_deadlines.set(peer_id.clone(), deadline_ms);
        self.ip_tally.add(ip.as_ref(), Held::Reservations);
        if let Some(replaced) = self
            .reservations
            .insert(peer_id, ReservationRecord { conn_id, ip })
        {
            self.ip_tally
                .remove(replaced.ip.as_ref(), Held::Reservations);
        }
    }

    fn remove_reservation(&mut self, peer_id: &PeerId) {
        self.reservation_deadlines.remove(peer_id);
        if let Some(removed) = self.reservations.remove(peer_id) {
            self.ip_tally
                .remove(removed.ip.as_ref(), Held::Reservations);
        }
    }

    fn remove_hop_worker(&mut self, stream: StreamKey) -> Option<HopWorker> {
        self.hop_deadlines.remove(&stream);
        self.hop_workers.remove(&stream)
    }

    fn insert_pending_circuit(
        &mut self,
        source_stream: StreamKey,
        circuit: PendingCircuit,
        stop_deadline_ms: u64,
    ) {
        self.hold_circuit(
            &circuit.source_peer_id,
            &circuit.destination_peer_id,
            circuit.source_ip.as_ref(),
            circuit.destination_ip.as_ref(),
        );
        self.pending_by_destination
            .insert((circuit.destination_conn_id, source_stream));
        if let Some(stop_stream) = circuit.stop_stream {
            self.stop_to_source.insert(stop_stream, source_stream);
        }
        self.stop_deadlines.set(source_stream, stop_deadline_ms);
        self.pending_circuits.insert(source_stream, circuit);
    }

    fn remove_pending_circuit(&mut self, source_stream: StreamKey) -> Option<PendingCircuit> {
        let circuit = self.pending_circuits.remove(&source_stream)?;
        self.stop_deadlines.remove(&source_stream);
        self.pending_by_destination
            .remove(&(circuit.destination_conn_id, source_stream));
        self.release_circuit(
            &circuit.source_peer_id,
            &circuit.destination_peer_id,
            circuit.source_ip.as_ref(),
            circuit.destination_ip.as_ref(),
        );
        Some(circuit)
    }

    fn remove_circuit(&mut self, source_stream: StreamKey) -> Option<Circuit> {
        let circuit = self.circuits.remove(&source_stream)?;
        self.circuit_deadlines.remove(&source_stream);
        self.release_circuit(
            &circuit.source_peer_id,
            &circuit.destination_peer_id,
            circuit.source_ip.as_ref(),
            circuit.destination_ip.as_ref(),
        );
        Some(circuit)
    }

    /// Counts one more circuit against each endpoint peer and admission key,
    /// one shared by both ends once.
    fn hold_circuit(
        &mut self,
        source: &PeerId,
        destination: &PeerId,
        source_ip: Option<&IpKey>,
        destination_ip: Option<&IpKey>,
    ) {
        for peer in circuit_endpoints(source, destination) {
            *self.peer_circuits.entry(peer.clone()).or_default() += 1;
        }
        for ip in circuit_ip_keys(source_ip, destination_ip) {
            self.ip_tally.add(Some(ip), Held::Circuits);
        }
    }

    fn release_circuit(
        &mut self,
        source: &PeerId,
        destination: &PeerId,
        source_ip: Option<&IpKey>,
        destination_ip: Option<&IpKey>,
    ) {
        for ip in circuit_ip_keys(source_ip, destination_ip) {
            self.ip_tally.remove(Some(ip), Held::Circuits);
        }
        for peer in circuit_endpoints(source, destination) {
            if let Some(count) = self.peer_circuits.get_mut(peer) {
                *count -= 1;
                if *count == 0 {
                    self.peer_circuits.remove(peer);
                }
            }
        }
    }

    /// Asserts every index matches a rebuild from the primary maps. Exposed
    /// for test support.
    #[doc(hidden)]
    pub fn assert_indexes_consistent(&self) {
        fn assert_deadlines<K: Ord + Clone + core::fmt::Debug>(
            deadlines: &Deadlines<K>,
            owners: BTreeSet<&K>,
        ) {
            let by_due: BTreeSet<_> = deadlines
                .by_key
                .iter()
                .map(|(key, deadline_ms)| (*deadline_ms, key.clone()))
                .collect();
            assert_eq!(by_due, deadlines.by_due);
            let keys: BTreeSet<_> = deadlines.by_key.keys().collect();
            assert!(keys.is_subset(&owners), "deadline without an owner");
        }
        assert_deadlines(&self.hop_deadlines, self.hop_workers.keys().collect());
        assert_deadlines(&self.stop_deadlines, self.pending_circuits.keys().collect());
        assert_deadlines(&self.circuit_deadlines, self.circuits.keys().collect());
        if self.config.max_circuit_duration_secs != 0 {
            assert_eq!(self.circuit_deadlines.by_key.len(), self.circuits.len());
        }
        // Every reservation is on the timer.
        assert_deadlines(
            &self.reservation_deadlines,
            self.reservations.keys().collect(),
        );
        assert_eq!(
            self.reservation_deadlines.by_key.len(),
            self.reservations.len()
        );

        let pending_by_destination: BTreeSet<_> = self
            .pending_circuits
            .iter()
            .map(|(key, circuit)| (circuit.destination_conn_id, *key))
            .collect();
        assert_eq!(pending_by_destination, self.pending_by_destination);
        let stop_to_source: BTreeMap<_, _> = self
            .pending_circuits
            .iter()
            .filter_map(|(key, circuit)| circuit.stop_stream.map(|stop| (stop, *key)))
            .chain(
                self.circuits
                    .iter()
                    .map(|(key, circuit)| (circuit.destination_stream, *key)),
            )
            .collect();
        assert_eq!(stop_to_source, self.stop_to_source);
        assert!(
            self.retired_stops
                .keys()
                .all(|stream| !self.stop_to_source.contains_key(stream)),
            "a retired STOP stream is still in use"
        );
        let mut peer_circuits = BTreeMap::new();
        let endpoints = self
            .pending_circuits
            .values()
            .map(|circuit| (&circuit.source_peer_id, &circuit.destination_peer_id))
            .chain(
                self.circuits
                    .values()
                    .map(|circuit| (&circuit.source_peer_id, &circuit.destination_peer_id)),
            );
        for (source, destination) in endpoints {
            for peer in circuit_endpoints(source, destination) {
                *peer_circuits.entry(peer.clone()).or_insert(0) += 1;
            }
        }
        assert_eq!(peer_circuits, self.peer_circuits);
        let mut ip_tally = IpTally::default();
        let ends = self
            .pending_circuits
            .values()
            .map(|circuit| (&circuit.source_ip, &circuit.destination_ip))
            .chain(
                self.circuits
                    .values()
                    .map(|circuit| (&circuit.source_ip, &circuit.destination_ip)),
            );
        for (source, destination) in ends {
            for ip in circuit_ip_keys(source.as_ref(), destination.as_ref()) {
                ip_tally.add(Some(ip), Held::Circuits);
            }
        }
        for reservation in self.reservations.values() {
            ip_tally.add(reservation.ip.as_ref(), Held::Reservations);
        }
        assert_eq!(ip_tally, self.ip_tally);
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

/// A circuit's distinct endpoint peers.
fn circuit_endpoints<'a>(
    source: &'a PeerId,
    destination: &'a PeerId,
) -> impl Iterator<Item = &'a PeerId> {
    core::iter::once(source).chain((destination != source).then_some(destination))
}

/// A circuit's distinct admission keys; ends without an IP have none.
fn circuit_ip_keys<'a>(
    source: Option<&'a IpKey>,
    destination: Option<&'a IpKey>,
) -> impl Iterator<Item = &'a IpKey> {
    source
        .into_iter()
        .chain(destination.filter(|destination| Some(*destination) != source))
}

fn first_ip(address: &Multiaddr) -> Option<IpKey> {
    address
        .protocols()
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Ip4(ip) => Some(IpKey::V4(u32::from_be_bytes(*ip))),
            Protocol::Ip6(ip) => {
                let ip = u128::from_be_bytes(*ip);
                // IPv4-mapped (`::ffff:a.b.c.d`) counts as its IPv4 address.
                Some(if ip >> 32 == 0xffff {
                    IpKey::V4(ip as u32)
                } else {
                    IpKey::V6Prefix((ip >> 64) as u64)
                })
            }
            _ => None,
        })
}

// Agent behaviour is tested through the shared fake swarm in
// `tests/common`; only private helpers are tested here.
#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn admission_keys_fold_ipv4_mapped_ipv6_and_each_ipv6_slash_64() {
        let key = |address: &str| first_ip(&Multiaddr::from_str(address).unwrap());
        assert_eq!(
            key("/ip6/::ffff:198.51.100.7/tcp/1"),
            key("/ip4/198.51.100.7/tcp/1")
        );
        assert_eq!(
            key("/ip6/2001:db8:1:2::1/tcp/1"),
            key("/ip6/2001:db8:1:2:ffff::9/udp/1/quic-v1")
        );
        assert_ne!(
            key("/ip6/2001:db8:1:2::1/tcp/1"),
            key("/ip6/2001:db8:1:3::1/tcp/1")
        );
        assert_ne!(
            key("/ip6/::c633:6407/tcp/1"),
            key("/ip4/198.51.100.7/tcp/1")
        );
    }
}
