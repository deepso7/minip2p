//! Sans-I/O core of the swarm.
//!
//! [`SwarmCore`] is a pure state machine: it consumes [`SwarmInput`] values
//! through [`SwarmCore::handle_input`], emits [`SwarmOutput`] values through
//! [`SwarmCore::poll_output`], and reports quiescence through
//! [`SwarmCore::is_idle`]. Outputs wrap [`SwarmAction`] commands for a driver
//! to execute against a concrete transport and [`SwarmEvent`] notifications
//! for the application. No sockets, no async runtime, no clock reads.
//!
//! `no_std + alloc` compatible. The std [`crate::Swarm`] driver is a thin
//! wrapper that owns a transport, reads the clock via [`std::time::Instant`],
//! and shuttles events and actions between the transport and the core.
//!
//! # Driver contract
//!
//! External drivers should follow a drain loop:
//!
//! 1. perform one mutation (`handle_input` or an application-facing method
//!    such as `ping`);
//! 2. drain [`SwarmOutput`] values from [`SwarmCore::poll_output`], executing
//!    each action and feeding driver results back through `handle_input`;
//! 3. repeat output draining until no new outputs are produced.
//!
//! After a full drain, [`SwarmCore::is_idle`] returns `true`. Treating that as
//! the handoff point before waiting on external I/O keeps the Sans-I/O state
//! machine deterministic and avoids leaving protocol bytes buffered inside the
//! core.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use minip2p_core::{Multiaddr, PeerId, SansIoProtocol};
use minip2p_identify::{
    IDENTIFY_PROTOCOL_ID, IdentifyAction, IdentifyConfig, IdentifyEvent, IdentifyInput,
    IdentifyMessage, IdentifyOutput, IdentifyProtocol,
};
use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
use minip2p_ping::{
    PING_PAYLOAD_LEN, PING_PROTOCOL_ID, PingAction, PingConfig, PingEvent, PingInput, PingOutput,
    PingProtocol,
};
use minip2p_transport::{ConnectionId, StreamId, TransportEvent};

use crate::events::{
    OpenStreamToken, SwarmAction, SwarmError, SwarmErrorKind, SwarmEvent, SwarmInput, SwarmOutput,
    SwarmRuntimeError,
};

// ---------------------------------------------------------------------------
// Protocol identification
// ---------------------------------------------------------------------------

/// Protocol ids reserved for the swarm's built-in handlers.
///
/// Inbound routing dispatches these ids to the identify and ping state
/// machines before consulting user registrations, so a user protocol under
/// a reserved id could never receive traffic. [`SwarmCore::add_protocol`]
/// rejects them with [`SwarmError::ReservedProtocol`].
pub const RESERVED_PROTOCOL_IDS: [&str; 2] = [IDENTIFY_PROTOCOL_ID, PING_PROTOCOL_ID];

/// Identifies which protocol owns a negotiated stream.
///
/// Kept private; callers refer to protocols by their string ids via
/// [`SwarmCore::open_stream`] and the `protocol_id` fields of
/// [`SwarmEvent::StreamReady`] / [`SwarmEvent::StreamData`].
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
    /// Remote transport address per connection, captured from the
    /// `ConnectionEndpoint` that arrives with the transport's
    /// `Connected` / `IncomingConnection` / `PeerIdentityVerified`
    /// events. Used to populate Identify's `observedAddr` so the remote
    /// peer learns which of their transport addresses we saw them dial
    /// us from.
    conn_to_remote_addr: BTreeMap<ConnectionId, Multiaddr>,

    // --- Stream tracking ---
    /// Inbound streams being negotiated (server-side multistream-select).
    inbound_negotiators: BTreeMap<(ConnectionId, StreamId), MultistreamSelect>,
    /// Outbound streams being negotiated (client-side multistream-select).
    outbound_negotiators: BTreeMap<(ConnectionId, StreamId), PendingOutbound>,
    /// Streams that completed negotiation: maps to the owning protocol.
    stream_owner: BTreeMap<(ConnectionId, StreamId), ProtocolKind>,
    /// Outstanding OpenStream requests keyed by token; populated when the
    /// core emits `SwarmAction::OpenStream` and drained when the driver
    /// reports the allocated stream id back via [`SwarmInput::StreamOpened`].
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
    /// Absolute `now_ms` at which the in-flight ping to each peer becomes
    /// overdue. The ping protocol keeps its deadline bookkeeping private,
    /// so the core records its own copy whenever it forwards a successful
    /// `SendPing`; [`SwarmCore::next_timeout`] derives the earliest internal
    /// timer from this map. Entries are cleared when the ping resolves
    /// (RTT measured, timeout fired, outbound stream closed, peer removed)
    /// and pruned on every tick once their deadline has passed.
    ping_deadlines: BTreeMap<PeerId, u64>,
    /// Copy of [`PingConfig::request_timeout_ms`] used to compute
    /// `ping_deadlines` entries.
    ping_timeout_ms: u64,
    /// Snapshot of the transport's local listening addresses, refreshed
    /// by the driver at the top of each `poll()` tick. Used to
    /// auto-populate Identify's `listen_addrs` so advertised addresses
    /// always reflect what we're actually bound to.
    local_addresses: Vec<Multiaddr>,
    /// Latest Identify payload received for each peer.
    peer_info: BTreeMap<PeerId, IdentifyMessage>,
    /// Peers for which `PeerReady` has already been emitted.
    ready_peers: BTreeSet<PeerId>,
    /// Peers that have been surfaced through `ConnectionEstablished`.
    established_peers: BTreeSet<PeerId>,

    // --- Output queues ---
    events: VecDeque<SwarmEvent>,
    actions: VecDeque<SwarmAction>,
}

impl SwarmCore {
    /// Creates a new core with the given identify and ping configs.
    pub fn new(identify_config: IdentifyConfig, ping_config: PingConfig) -> Self {
        let supported_protocols = vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
        ];

        let ping_timeout_ms = ping_config.request_timeout_ms;
        Self {
            ping: PingProtocol::new(ping_config),
            identify: IdentifyProtocol::new(identify_config),
            conn_to_peer: BTreeMap::new(),
            peer_to_conn: BTreeMap::new(),
            conn_to_remote_addr: BTreeMap::new(),
            inbound_negotiators: BTreeMap::new(),
            outbound_negotiators: BTreeMap::new(),
            stream_owner: BTreeMap::new(),
            pending_opens: BTreeMap::new(),
            next_open_token: 1,
            supported_protocols,
            user_protocols: Vec::new(),
            pending_pings: BTreeMap::new(),
            ping_deadlines: BTreeMap::new(),
            ping_timeout_ms,
            local_addresses: Vec::new(),
            peer_info: BTreeMap::new(),
            ready_peers: BTreeSet::new(),
            established_peers: BTreeSet::new(),
            events: VecDeque::new(),
            actions: VecDeque::new(),
        }
    }

    /// Updates the core's snapshot of the transport's local listening
    /// addresses.
    ///
    /// The std driver calls this at the top of each `poll()` tick; a
    /// Sans-I/O caller should call it whenever its transport's bound
    /// set changes (e.g. after `listen()` or `close()` on a listener).
    pub fn set_local_addresses(&mut self, addrs: Vec<Multiaddr>) {
        self.local_addresses = addrs;
    }

    /// Registers an application protocol id that this swarm will accept on
    /// inbound streams and allow for outbound opens via
    /// [`Self::open_stream`].
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]: inbound routing gives the built-in
    /// handlers precedence, so a user registration under one of those ids
    /// could never receive traffic.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), SwarmError> {
        let id = protocol_id.into();
        if RESERVED_PROTOCOL_IDS.contains(&id.as_str()) {
            return Err(SwarmError::ReservedProtocol { protocol_id: id });
        }
        if !self.user_protocols.iter().any(|p| p == &id) {
            self.user_protocols.push(id.clone());
        }
        if !self.supported_protocols.iter().any(|p| p == &id) {
            self.supported_protocols.push(id.clone());
        }
        self.identify.add_protocol(id);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Egress (driver drains these)
    // -----------------------------------------------------------------------

    /// Returns the next core output, if any.
    ///
    /// Actions are prioritized over application events because executing an
    /// action can feed more input back into the core. Once no actions remain,
    /// events are yielded in FIFO order.
    pub fn poll_output(&mut self) -> Option<SwarmOutput> {
        if let Some(action) = self.actions.pop_front() {
            return Some(SwarmOutput::Action(action));
        }
        self.events.pop_front().map(SwarmOutput::Event)
    }

    /// Returns true when the core has no pending driver actions or
    /// application-visible events.
    ///
    /// Custom Sans-I/O drivers can use this as a cheap assertion that they
    /// have fully drained the core before waiting on sockets, timers, or
    /// application input again.
    pub fn is_idle(&self) -> bool {
        self.actions.is_empty() && self.events.is_empty()
    }

    /// Returns the milliseconds from `now_ms` until the earliest internal
    /// protocol timer is due, or `None` when no timer is armed.
    ///
    /// Today the only internal timers are ping request timeouts: one is
    /// armed whenever a ping payload is in flight to a peer. `Some(0)` means
    /// a timer is already due and the caller should feed
    /// [`SwarmInput::Tick`] immediately.
    ///
    /// Drivers should cap their wait/sleep budget with this value before
    /// blocking on external I/O, so a `Tick` is delivered promptly when the
    /// timer fires instead of only after the next transport event. The std
    /// [`crate::Swarm`] driver already does this in its `poll_next` loop.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        self.ping_deadlines
            .values()
            .min()
            .map(|due| due.saturating_sub(now_ms))
    }

    /// Feeds one external input into the core.
    pub fn handle_input(&mut self, input: SwarmInput) {
        match input {
            SwarmInput::Transport { event, now_ms } => self.handle_transport_event(event, now_ms),
            SwarmInput::Tick { now_ms } => self.handle_tick(now_ms),
            SwarmInput::StreamOpened {
                conn_id,
                stream_id,
                token,
                now_ms,
            } => self.handle_stream_opened(conn_id, stream_id, token, now_ms),
            SwarmInput::OpenStreamFailed {
                token,
                reason,
                now_ms,
            } => self.handle_open_stream_failed(token, reason, now_ms),
            SwarmInput::RuntimeError(error) => self.record_runtime_error(error),
        }
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
            self.ping
                .handle_input(PingInput::SendPing {
                    peer_id: peer_id.clone(),
                    payload,
                    now_ms,
                })
                .map_err(|e| SwarmError::PingError {
                    reason: format!("{e}"),
                })?;
            self.record_ping_deadline(peer_id, now_ms);
            self.drain_ping_outputs();
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
    /// reports back via [`SwarmInput::StreamOpened`].
    pub fn open_stream(&mut self, peer_id: &PeerId, protocol_id: &str) -> Result<(), SwarmError> {
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
        if self.ready_peers.contains(peer_id)
            && !self
                .peer_info
                .get(peer_id)
                .map(|info| info.protocols.iter().any(|p| p == protocol_id))
                .unwrap_or(false)
        {
            return Err(SwarmError::RemoteDoesNotSupport {
                peer_id: peer_id.clone(),
                protocol_id: protocol_id.to_string(),
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
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_stream_conn(peer_id, stream_id)?;
        self.actions.push_back(SwarmAction::SendStream {
            conn_id,
            stream_id,
            data,
        });
        Ok(())
    }

    /// Half-closes our write side of a user stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_stream_conn(peer_id, stream_id)?;
        self.actions
            .push_back(SwarmAction::CloseStreamWrite { conn_id, stream_id });
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_stream_conn(peer_id, stream_id)?;
        self.actions
            .push_back(SwarmAction::ResetStream { conn_id, stream_id });
        Ok(())
    }

    /// Closes the connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        self.actions
            .push_back(SwarmAction::CloseConnection { conn_id });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Connection / peer lookup helpers (driver uses these)
    // -----------------------------------------------------------------------

    /// Returns the primary connection id currently mapped to `peer_id`.
    pub fn conn_for(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.peer_to_conn.get(peer_id).copied()
    }

    /// Returns the peers that have been surfaced to the application as connected.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.established_peers.iter().cloned().collect()
    }

    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.peer_info.get(peer_id)
    }

    /// Returns whether `peer_id` has reached the application-ready state.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.ready_peers.contains(peer_id)
    }

    /// Returns the peer id currently mapped to `conn_id`, if any.
    pub fn peer_for(&self, conn_id: ConnectionId) -> Option<&PeerId> {
        self.conn_to_peer.get(&conn_id)
    }

    // -----------------------------------------------------------------------
    // Ingress
    // -----------------------------------------------------------------------

    fn record_runtime_error(&mut self, error: SwarmRuntimeError) {
        self.events.push_back(SwarmEvent::Error(error));
    }

    fn handle_transport_event(&mut self, event: TransportEvent, now_ms: u64) {
        match event {
            TransportEvent::Connected { id, endpoint } => {
                self.conn_to_remote_addr
                    .insert(id, endpoint.transport().clone());
                if let Some(peer_id) = endpoint.peer_id() {
                    self.register_connection(id, peer_id.clone());
                } else {
                    // Peer identity is not yet known. Synthesize a placeholder PeerId
                    // for internal bookkeeping so protocol handlers can still
                    // operate. No ConnectionEstablished event yet -- we emit
                    // one when the real identity arrives via
                    // PeerIdentityVerified.
                    let _ = self.ensure_peer_id_for_conn(id);
                }
            }
            TransportEvent::PeerIdentityVerified { id, endpoint, .. } => {
                // Refresh the recorded transport address -- on mutual-TLS
                // QUIC the `Connected` event precedes identity verification,
                // and the transport may emit a more accurate endpoint here
                // (e.g. with the real remote address observed after
                // migration).
                self.conn_to_remote_addr
                    .insert(id, endpoint.transport().clone());
                if let Some(peer_id) = endpoint.peer_id() {
                    self.upgrade_connection_identity(id, peer_id.clone());
                }
            }
            TransportEvent::IncomingConnection { id, endpoint } => {
                self.conn_to_remote_addr
                    .insert(id, endpoint.transport().clone());
            }
            TransportEvent::IncomingStream { id, stream_id } => {
                self.handle_incoming_stream(id, stream_id);
            }
            TransportEvent::StreamOpened { .. } => {
                // Outbound stream id allocation is driver-synchronous; the
                // core tracks opens via `SwarmInput::StreamOpened` rather than this
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
                self.emit_error(
                    SwarmErrorKind::Transport,
                    self.established_peer_for_conn(id),
                    Some(id),
                    format!("transport error on connection {id}: {message}"),
                );
            }
        }
    }

    fn handle_tick(&mut self, now_ms: u64) {
        let _ = self.ping.handle_input(PingInput::Tick { now_ms });
        self.collect_protocol_events();
        // Safety net for deadlines whose ping was resolved without a
        // corresponding ping event (e.g. the stream fully closed): the tick
        // above has fired the Timeout for anything still pending at its
        // deadline, so a past-due entry can never be load-bearing anymore.
        // Dropping it keeps `next_timeout` from reporting a stale timer.
        self.ping_deadlines.retain(|_, due| *due > now_ms);
    }

    fn handle_stream_opened(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        token: OpenStreamToken,
        _now_ms: u64,
    ) {
        let Some(pending) = self.pending_opens.remove(&token) else {
            self.emit_error(
                SwarmErrorKind::Driver,
                None,
                None,
                format!("unknown OpenStream token {} reported by driver", token.0),
            );
            return;
        };

        // Guard against the driver reporting a different connection id than
        // the one we asked to open on.
        if pending.conn_id != conn_id {
            self.emit_error(
                SwarmErrorKind::Driver,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                format!(
                    "driver opened stream on connection {} but core requested {}",
                    conn_id, pending.conn_id
                ),
            );
            return;
        }

        let mut negotiator = MultistreamSelect::dialer(pending.protocol.as_str());
        if let Err(error) = negotiator.handle_input(MultistreamInput::Start) {
            self.emit_error(
                SwarmErrorKind::Multistream,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                format!("multistream start failed on outbound stream {stream_id}: {error}"),
            );
        }
        while let Some(output) = negotiator.poll_output() {
            self.handle_multistream_output(conn_id, stream_id, output, &mut None);
        }

        self.outbound_negotiators.insert(
            (conn_id, stream_id),
            PendingOutbound {
                negotiator,
                target: pending.target,
            },
        );
    }

    fn handle_open_stream_failed(&mut self, token: OpenStreamToken, reason: String, _now_ms: u64) {
        let pending = self.pending_opens.remove(&token);
        let (peer_id, conn_id, detail) = match pending {
            Some(p) => (
                self.established_peer_for_conn(p.conn_id),
                Some(p.conn_id),
                format!(
                    "open_stream for protocol '{}' on connection {} failed: {reason}",
                    p.protocol, p.conn_id
                ),
            ),
            None => (
                None,
                None,
                format!("open_stream failed (unknown token): {reason}"),
            ),
        };
        self.emit_error(SwarmErrorKind::OpenStreamFailed, peer_id, conn_id, detail);
    }

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

    fn require_stream_conn(
        &self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<ConnectionId, SwarmError> {
        self.stream_owner
            .iter()
            .find_map(|((conn_id, sid), protocol)| {
                if *sid == stream_id
                    && matches!(protocol, ProtocolKind::User(_))
                    && self.conn_to_peer.get(conn_id) == Some(peer_id)
                {
                    Some(*conn_id)
                } else {
                    None
                }
            })
            .ok_or_else(|| SwarmError::StreamNotFound {
                peer_id: peer_id.clone(),
                stream_id,
            })
    }

    fn conn_for_owned_stream(
        &self,
        peer_id: &PeerId,
        stream_id: StreamId,
        expected: ProtocolKind,
    ) -> Option<ConnectionId> {
        self.stream_owner
            .iter()
            .find_map(|((conn_id, sid), protocol)| {
                if *sid == stream_id
                    && *protocol == expected
                    && self.conn_to_peer.get(conn_id) == Some(peer_id)
                {
                    Some(*conn_id)
                } else {
                    None
                }
            })
    }

    fn established_peer_for_conn(&self, conn_id: ConnectionId) -> Option<PeerId> {
        let peer_id = self.conn_to_peer.get(&conn_id)?;
        if self.established_peers.contains(peer_id) {
            Some(peer_id.clone())
        } else {
            None
        }
    }

    fn emit_error(
        &mut self,
        kind: SwarmErrorKind,
        peer_id: Option<PeerId>,
        conn_id: Option<ConnectionId>,
        detail: impl Into<String>,
    ) {
        self.events.push_back(SwarmEvent::Error(SwarmRuntimeError {
            kind,
            peer_id,
            conn_id,
            detail: detail.into(),
        }));
    }

    fn try_emit_peer_ready(&mut self, peer_id: &PeerId) {
        if self.ready_peers.contains(peer_id) {
            return;
        }
        let Some(info) = self.peer_info.get(peer_id) else {
            return;
        };
        if !self.peer_to_conn.contains_key(peer_id) {
            return;
        }

        self.ready_peers.insert(peer_id.clone());
        self.events.push_back(SwarmEvent::PeerReady {
            peer_id: peer_id.clone(),
            protocols: info.protocols.clone(),
        });
    }

    fn find_negotiated_ping_stream(&self, peer_id: &PeerId) -> Option<StreamId> {
        self.ping.outbound_stream(peer_id)
    }

    /// Arms the internal ping-timeout timer for `peer_id` after a
    /// successful `SendPing`.
    ///
    /// The ping protocol fires its timeout on the first tick where
    /// `now_ms - sent_at_ms > request_timeout_ms`, i.e. strictly past the
    /// timeout, so the timer is due one millisecond after it.
    fn record_ping_deadline(&mut self, peer_id: &PeerId, now_ms: u64) {
        let due = now_ms
            .saturating_add(self.ping_timeout_ms)
            .saturating_add(1);
        self.ping_deadlines.insert(peer_id.clone(), due);
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
        self.pending_opens
            .values()
            .any(|open| open.conn_id == conn && matches!(open.target, ProtocolKind::Ping))
    }

    fn queue_open_protocol_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        target: ProtocolKind,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        debug_assert_eq!(
            self.conn_to_peer.get(&conn_id),
            Some(peer_id),
            "protocol opens must use a connection mapped to the requested peer"
        );
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
            .push_back(SwarmAction::OpenStream { conn_id, token });
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
        if let Some(&existing_id) = self.peer_to_conn.get(&peer_id)
            && existing_id != id
        {
            self.supersede_connection(existing_id);
        }

        self.conn_to_peer.insert(id, peer_id.clone());
        self.peer_to_conn.insert(peer_id.clone(), id);

        if is_new {
            self.established_peers.insert(peer_id.clone());
            self.events.push_back(SwarmEvent::ConnectionEstablished {
                peer_id: peer_id.clone(),
            });

            // Auto-open identify.
            if let Err(e) = self.queue_open_protocol_stream(
                &peer_id,
                IDENTIFY_PROTOCOL_ID,
                ProtocolKind::IdentifyInitiator,
            ) {
                self.emit_error(
                    SwarmErrorKind::Identify,
                    Some(peer_id.clone()),
                    Some(id),
                    format!("failed to queue identify stream to {peer_id}: {e}"),
                );
            }

            if self.pending_pings.contains_key(&peer_id)
                && self.find_negotiated_ping_stream(&peer_id).is_none()
                && !self.has_pending_ping_stream(&peer_id)
                && let Err(e) =
                    self.queue_open_protocol_stream(&peer_id, PING_PROTOCOL_ID, ProtocolKind::Ping)
            {
                self.emit_error(
                    SwarmErrorKind::Ping,
                    Some(peer_id.clone()),
                    Some(id),
                    format!("failed to requeue pending ping stream to {peer_id}: {e}"),
                );
            }
        }
    }

    fn supersede_connection(&mut self, old_id: ConnectionId) {
        if let Some(peer_id) = self.conn_to_peer.remove(&old_id) {
            let pending_ping = self.pending_pings.remove(&peer_id);
            let _ = self.ping.handle_input(PingInput::RemovePeer {
                peer_id: peer_id.clone(),
            });
            let _ = self.identify.handle_input(IdentifyInput::RemovePeer {
                peer_id: peer_id.clone(),
            });
            self.drain_ping_outputs();
            self.drain_identify_outputs();
            if let Some(payload) = pending_ping {
                self.pending_pings.insert(peer_id.clone(), payload);
            }
            self.ping_deadlines.remove(&peer_id);
            self.peer_info.remove(&peer_id);
            self.ready_peers.remove(&peer_id);
            self.established_peers.remove(&peer_id);
        }
        self.conn_to_remote_addr.remove(&old_id);
        self.stream_owner.retain(|(cid, _), _| *cid != old_id);
        self.inbound_negotiators
            .retain(|(cid, _), _| *cid != old_id);
        self.outbound_negotiators
            .retain(|(cid, _), _| *cid != old_id);
        self.pending_opens.retain(|_, p| p.conn_id != old_id);
        self.actions
            .push_back(SwarmAction::CloseConnection { conn_id: old_id });
    }

    fn upgrade_connection_identity(&mut self, conn_id: ConnectionId, new_peer_id: PeerId) {
        let existing = self.conn_to_peer.get(&conn_id).cloned();

        match existing {
            Some(ref current) if *current == new_peer_id => return,
            Some(ref stale) => {
                self.peer_to_conn.remove(stale);
                let _ = self.ping.handle_input(PingInput::MigratePeer {
                    old_peer_id: stale.clone(),
                    new_peer_id: new_peer_id.clone(),
                });
                let _ = self.identify.handle_input(IdentifyInput::MigratePeer {
                    old_peer_id: stale.clone(),
                    new_peer_id: new_peer_id.clone(),
                });
                self.drain_ping_outputs();
                self.drain_identify_outputs();
                if let Some(payload) = self.pending_pings.remove(stale) {
                    self.pending_pings.insert(new_peer_id.clone(), payload);
                }
                if let Some(due) = self.ping_deadlines.remove(stale) {
                    self.ping_deadlines.insert(new_peer_id.clone(), due);
                }
                if let Some(info) = self.peer_info.remove(stale) {
                    self.peer_info.insert(new_peer_id.clone(), info);
                }
                if self.ready_peers.remove(stale) {
                    self.ready_peers.insert(new_peer_id.clone());
                }
                if self.established_peers.remove(stale) {
                    self.established_peers.insert(new_peer_id.clone());
                }
                self.migrate_buffered_events(stale, &new_peer_id);
            }
            None => {}
        }

        self.conn_to_peer.insert(conn_id, new_peer_id.clone());
        self.peer_to_conn.insert(new_peer_id.clone(), conn_id);
        self.established_peers.insert(new_peer_id.clone());

        self.events.push_back(SwarmEvent::ConnectionEstablished {
            peer_id: new_peer_id.clone(),
        });

        self.try_emit_peer_ready(&new_peer_id);

        if let Err(e) = self.queue_open_protocol_stream(
            &new_peer_id,
            IDENTIFY_PROTOCOL_ID,
            ProtocolKind::IdentifyInitiator,
        ) {
            self.emit_error(
                SwarmErrorKind::Identify,
                Some(new_peer_id.clone()),
                Some(conn_id),
                format!(
                    "failed to queue identify stream to {new_peer_id} after identity upgrade: {e}"
                ),
            );
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
                | SwarmEvent::StreamReady { peer_id, .. }
                | SwarmEvent::StreamData { peer_id, .. }
                | SwarmEvent::StreamRemoteWriteClosed { peer_id, .. }
                | SwarmEvent::StreamClosed { peer_id, .. } => {
                    if peer_id == old {
                        *peer_id = new.clone();
                    }
                }
                SwarmEvent::PeerReady { peer_id, .. } => {
                    if peer_id == old {
                        *peer_id = new.clone();
                    }
                }
                SwarmEvent::Error(error) => {
                    if error.peer_id.as_ref() == Some(old) {
                        error.peer_id = Some(new.clone());
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: stream event handling
    // -----------------------------------------------------------------------

    fn handle_incoming_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let mut listener = MultistreamSelect::listener(self.supported_protocols.clone());
        if let Err(error) = listener.handle_input(MultistreamInput::Start) {
            self.emit_error(
                SwarmErrorKind::Multistream,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                format!("multistream start failed on inbound stream {stream_id}: {error}"),
            );
        }
        self.inbound_negotiators
            .insert((conn_id, stream_id), listener);

        while let Some(output) = self
            .inbound_negotiators
            .get_mut(&(conn_id, stream_id))
            .and_then(SansIoProtocol::poll_output)
        {
            self.handle_multistream_output(conn_id, stream_id, output, &mut None);
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
                let _ = self.ping.handle_input(PingInput::StreamData {
                    peer_id,
                    stream_id,
                    data,
                    now_ms,
                });
                self.drain_ping_outputs();
            }
            ProtocolKind::IdentifyInitiator => {
                let _ = self.identify.handle_input(IdentifyInput::StreamData {
                    peer_id,
                    stream_id,
                    data,
                });
                self.drain_identify_outputs();
            }
            ProtocolKind::IdentifyResponder => {
                // Responder doesn't expect data; ignore.
            }
            ProtocolKind::User(_) => {
                self.events.push_back(SwarmEvent::StreamData {
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
                let _ = self
                    .ping
                    .handle_input(PingInput::StreamRemoteWriteClosed { peer_id, stream_id });
                self.drain_ping_outputs();
            }
            ProtocolKind::IdentifyInitiator => {
                let _ = self
                    .identify
                    .handle_input(IdentifyInput::StreamRemoteWriteClosed { peer_id, stream_id });
                self.drain_identify_outputs();
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(_) => {
                self.events
                    .push_back(SwarmEvent::StreamRemoteWriteClosed { peer_id, stream_id });
            }
        }
    }

    fn handle_stream_closed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);

        if let Some(protocol) = self.stream_owner.remove(&key)
            && let Some(peer_id) = self.conn_to_peer.get(&conn_id).cloned()
        {
            match protocol {
                ProtocolKind::Ping => {
                    let _ = self
                        .ping
                        .handle_input(PingInput::StreamClosed { peer_id, stream_id });
                    self.drain_ping_outputs();
                }
                ProtocolKind::IdentifyInitiator | ProtocolKind::IdentifyResponder => {
                    let _ = self
                        .identify
                        .handle_input(IdentifyInput::StreamClosed { peer_id, stream_id });
                    self.drain_identify_outputs();
                }
                ProtocolKind::User(_) => {
                    self.events
                        .push_back(SwarmEvent::StreamClosed { peer_id, stream_id });
                }
            }
        }

        self.inbound_negotiators.remove(&key);
        self.outbound_negotiators.remove(&key);
    }

    fn handle_connection_closed(&mut self, conn_id: ConnectionId) {
        self.conn_to_remote_addr.remove(&conn_id);

        if let Some(peer_id) = self.conn_to_peer.remove(&conn_id) {
            let was_active = self.peer_to_conn.get(&peer_id) == Some(&conn_id);
            if was_active {
                self.peer_to_conn.remove(&peer_id);
                let _ = self.ping.handle_input(PingInput::RemovePeer {
                    peer_id: peer_id.clone(),
                });
                let _ = self.identify.handle_input(IdentifyInput::RemovePeer {
                    peer_id: peer_id.clone(),
                });
                self.drain_ping_outputs();
                self.drain_identify_outputs();
                self.pending_pings.remove(&peer_id);
                self.ping_deadlines.remove(&peer_id);
                self.peer_info.remove(&peer_id);
                self.ready_peers.remove(&peer_id);
                self.established_peers.remove(&peer_id);
                self.events
                    .push_back(SwarmEvent::ConnectionClosed { peer_id });
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

        let mut negotiated_protocol = None;
        if let Err(error) = negotiator.handle_input(MultistreamInput::Data(data.to_vec())) {
            self.emit_error(
                SwarmErrorKind::Multistream,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                format!("multistream input failed on inbound stream {stream_id}: {error}"),
            );
            self.inbound_negotiators.remove(&key);
            self.actions
                .push_back(SwarmAction::ResetStream { conn_id, stream_id });
            return;
        }

        while let Some(output) = self
            .inbound_negotiators
            .get_mut(&key)
            .and_then(SansIoProtocol::poll_output)
        {
            if self.handle_multistream_output(conn_id, stream_id, output, &mut negotiated_protocol)
            {
                self.inbound_negotiators.remove(&key);
                self.actions
                    .push_back(SwarmAction::ResetStream { conn_id, stream_id });
                return;
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

        if let Err(error) = pending
            .negotiator
            .handle_input(MultistreamInput::Data(data.to_vec()))
        {
            self.emit_error(
                SwarmErrorKind::Multistream,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                format!("multistream input failed on outbound stream {stream_id}: {error}"),
            );
            self.outbound_negotiators.remove(&key);
            self.actions
                .push_back(SwarmAction::ResetStream { conn_id, stream_id });
            return;
        }
        let target = pending.target.clone();
        let mut negotiated = false;

        while let Some(output) = self
            .outbound_negotiators
            .get_mut(&key)
            .and_then(|pending| pending.negotiator.poll_output())
        {
            match output {
                MultistreamOutput::Negotiated { .. } => negotiated = true,
                MultistreamOutput::NotAvailable => {
                    self.emit_error(
                        SwarmErrorKind::UnsupportedProtocol,
                        self.established_peer_for_conn(conn_id),
                        Some(conn_id),
                        format!("remote peer does not support protocol for stream {stream_id}"),
                    );
                    self.outbound_negotiators.remove(&key);
                    self.actions
                        .push_back(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }
                other => {
                    if self.handle_multistream_output(conn_id, stream_id, other, &mut None) {
                        self.outbound_negotiators.remove(&key);
                        self.actions
                            .push_back(SwarmAction::ResetStream { conn_id, stream_id });
                        return;
                    }
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

    fn handle_multistream_output(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        output: MultistreamOutput,
        negotiated_protocol: &mut Option<String>,
    ) -> bool {
        match output {
            MultistreamOutput::OutboundData(bytes) => {
                self.actions.push_back(SwarmAction::SendStream {
                    conn_id,
                    stream_id,
                    data: bytes,
                });
                false
            }
            MultistreamOutput::Negotiated { protocol } => {
                *negotiated_protocol = Some(protocol);
                false
            }
            MultistreamOutput::NotAvailable => true,
            MultistreamOutput::ProtocolError { reason } => {
                self.emit_error(
                    SwarmErrorKind::Multistream,
                    self.established_peer_for_conn(conn_id),
                    Some(conn_id),
                    format!("multistream error on stream {stream_id}: {reason}"),
                );
                true
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
            let _ = self
                .ping
                .handle_input(PingInput::RegisterInboundStream { peer_id, stream_id });
            self.drain_ping_outputs();
            return;
        }

        if protocol == IDENTIFY_PROTOCOL_ID {
            // Populate Identify's observedAddr field with the transport
            // address we recorded for this connection. The address is
            // cached when TransportEvent::Connected /
            // TransportEvent::IncomingConnection / PeerIdentityVerified
            // arrives; a missing entry means the driver never provided an
            // endpoint for this conn_id, in which case we legitimately
            // can't fill observedAddr and the field is omitted.
            let observed_addr = self.conn_to_remote_addr.get(&conn_id).cloned();
            // Snapshot of the transport's listening addresses at this
            // moment; the driver keeps `local_addresses` refreshed.
            let listen_addrs = self.local_addresses.clone();
            let responder_peer_id = peer_id.clone();
            match self
                .identify
                .handle_input(IdentifyInput::RegisterOutboundStream {
                    peer_id,
                    stream_id,
                    observed_addr,
                    listen_addrs,
                }) {
                Ok(()) => {
                    // Only record ownership on success, so a rejected
                    // registration doesn't leave the stream tracked here
                    // with no owning handler.
                    self.stream_owner
                        .insert((conn_id, stream_id), ProtocolKind::IdentifyResponder);
                    self.drain_identify_outputs();
                }
                Err(e) => {
                    // Registration refused (e.g. identify already has a
                    // responder stream for this peer). Don't leak the
                    // underlying transport stream -- reset it so the
                    // remote knows we're not going to respond.
                    self.emit_error(
                        SwarmErrorKind::IdentifyStreamRejected,
                        Some(responder_peer_id),
                        Some(conn_id),
                        format!("identify responder error: {e}"),
                    );
                    self.actions
                        .push_back(SwarmAction::ResetStream { conn_id, stream_id });
                }
            }
            return;
        }

        if self.user_protocols.iter().any(|p| p == protocol) {
            self.stream_owner.insert(
                (conn_id, stream_id),
                ProtocolKind::User(protocol.to_string()),
            );
            self.events.push_back(SwarmEvent::StreamReady {
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
                if let Err(e) = self.ping.handle_input(PingInput::RegisterOutboundStream {
                    peer_id: peer_id.clone(),
                    stream_id,
                }) {
                    self.emit_error(
                        SwarmErrorKind::Ping,
                        Some(peer_id.clone()),
                        Some(conn_id),
                        format!("ping register error: {e}"),
                    );
                    self.stream_owner.remove(&(conn_id, stream_id));
                    self.actions
                        .push_back(SwarmAction::ResetStream { conn_id, stream_id });
                    return;
                }
                self.drain_ping_outputs();

                if let Some(payload) = self.pending_pings.remove(&peer_id) {
                    match self.ping.handle_input(PingInput::SendPing {
                        peer_id: peer_id.clone(),
                        payload,
                        now_ms,
                    }) {
                        Ok(()) => {
                            self.record_ping_deadline(&peer_id, now_ms);
                            self.drain_ping_outputs();
                        }
                        Err(e) => self.emit_error(
                            SwarmErrorKind::Ping,
                            Some(peer_id.clone()),
                            Some(conn_id),
                            format!("deferred ping send failed: {e}"),
                        ),
                    }
                }
            }
            ProtocolKind::IdentifyInitiator => {
                let _ = self
                    .identify
                    .handle_input(IdentifyInput::RegisterInboundStream { peer_id, stream_id });
                self.drain_identify_outputs();
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(protocol_id) => {
                self.events.push_back(SwarmEvent::StreamReady {
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
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::Ping)
                {
                    self.actions.push_back(SwarmAction::SendStream {
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
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::Ping)
                {
                    self.actions
                        .push_back(SwarmAction::CloseStreamWrite { conn_id, stream_id });
                }
            }
            PingAction::ResetStream {
                ref peer_id,
                stream_id,
            } => {
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::Ping)
                {
                    self.actions
                        .push_back(SwarmAction::ResetStream { conn_id, stream_id });
                }
            }
        }
    }

    fn execute_identify_action(&mut self, action: IdentifyAction) {
        match action {
            IdentifyAction::Send {
                ref peer_id,
                stream_id,
                ref data,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    self.actions.push_back(SwarmAction::SendStream {
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
                        .push_back(SwarmAction::CloseStreamWrite { conn_id, stream_id });
                }
            }
        }
    }

    fn drain_ping_outputs(&mut self) {
        while let Some(output) = self.ping.poll_output() {
            match output {
                PingOutput::Action(action) => self.execute_ping_action(action),
                PingOutput::Event(event) => self.handle_ping_event(event),
            }
        }
    }

    fn drain_identify_outputs(&mut self) {
        while let Some(output) = self.identify.poll_output() {
            match output {
                IdentifyOutput::Action(action) => self.execute_identify_action(action),
                IdentifyOutput::Event(event) => self.handle_identify_event(event),
            }
        }
    }

    fn collect_protocol_events(&mut self) {
        self.drain_ping_outputs();
        self.drain_identify_outputs();
    }

    fn handle_ping_event(&mut self, event: PingEvent) {
        match event {
            PingEvent::RttMeasured {
                peer_id, rtt_ms, ..
            } => {
                self.ping_deadlines.remove(&peer_id);
                self.events
                    .push_back(SwarmEvent::PingRttMeasured { peer_id, rtt_ms });
            }
            PingEvent::Timeout { peer_id, .. } => {
                self.ping_deadlines.remove(&peer_id);
                self.events.push_back(SwarmEvent::PingTimeout { peer_id });
            }
            PingEvent::OutboundStreamClosed { ref peer_id, .. } => {
                // The outbound stream carried the in-flight ping (if any);
                // its close disarms the timer.
                self.ping_deadlines.remove(peer_id);
            }
            PingEvent::ProtocolViolation {
                peer_id, reason, ..
            } => {
                self.emit_error(
                    SwarmErrorKind::Ping,
                    Some(peer_id.clone()),
                    self.conn_for(&peer_id),
                    format!("ping protocol violation from {peer_id}: {reason}"),
                );
            }
            _ => {}
        }
    }

    fn handle_identify_event(&mut self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Received { peer_id, info } => {
                self.peer_info.insert(peer_id.clone(), info.clone());
                self.events.push_back(SwarmEvent::IdentifyReceived {
                    peer_id: peer_id.clone(),
                    info,
                });
                self.try_emit_peer_ready(&peer_id);
            }
            IdentifyEvent::Error { error, .. } => {
                self.emit_error(
                    SwarmErrorKind::Identify,
                    None,
                    None,
                    format!("identify error: {error}"),
                );
            }
        }
    }
}

impl SansIoProtocol for SwarmCore {
    type Input = SwarmInput;
    type Output = SwarmOutput;
    type Error = Infallible;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        Self::handle_input(self, input);
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        Self::poll_output(self)
    }

    fn is_idle(&self) -> bool {
        Self::is_idle(self)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use minip2p_identify::IdentifyConfig;
    use minip2p_ping::PingConfig;
    use minip2p_transport::{ConnectionEndpoint, ConnectionId, StreamId, TransportEvent};

    use super::*;

    fn test_core() -> SwarmCore {
        SwarmCore::new(
            IdentifyConfig {
                protocol_version: "minip2p-test/0.1.0".into(),
                agent_version: "minip2p-test/0.1.0".into(),
                protocols: Vec::new(),
                public_key: Vec::new(),
            },
            PingConfig::default(),
        )
    }

    fn loopback_transport() -> Multiaddr {
        Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").expect("valid multiaddr")
    }

    fn feed(core: &mut SwarmCore, event: TransportEvent) {
        core.handle_input(SwarmInput::Transport { event, now_ms: 0 });
    }

    fn drain_actions(core: &mut SwarmCore) -> Vec<SwarmAction> {
        let mut actions = Vec::new();
        while let Some(output) = core.poll_output() {
            match output {
                SwarmOutput::Action(action) => actions.push(action),
                SwarmOutput::Event(_) => {}
            }
        }
        actions
    }

    fn drain_events(core: &mut SwarmCore) -> Vec<SwarmEvent> {
        let mut events = Vec::new();
        while let Some(output) = core.poll_output() {
            match output {
                SwarmOutput::Action(_) => {}
                SwarmOutput::Event(event) => events.push(event),
            }
        }
        events
    }

    #[test]
    fn swarm_core_implements_common_sans_io_protocol_trait() {
        fn drive_idle<S: SansIoProtocol<Input = SwarmInput, Output = SwarmOutput>>(engine: &mut S) {
            let _ = engine.handle_input(SwarmInput::Tick { now_ms: 0 });
            while engine.poll_output().is_some() {}
            assert!(engine.is_idle());
        }

        let mut core = test_core();
        drive_idle(&mut core);
    }

    #[test]
    fn add_protocol_rejects_reserved_builtin_ids() {
        let mut core = test_core();
        for reserved in RESERVED_PROTOCOL_IDS {
            let error = core
                .add_protocol(reserved)
                .expect_err("built-in ids must be rejected");
            assert_eq!(
                error,
                SwarmError::ReservedProtocol {
                    protocol_id: reserved.into()
                }
            );
        }
        core.add_protocol("/myapp/1.0.0")
            .expect("application ids must be accepted");
        assert!(core.user_protocols.iter().any(|p| p == "/myapp/1.0.0"));
    }

    #[test]
    fn is_idle_reflects_pending_actions_and_events() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(1);

        assert!(core.is_idle());

        feed(
            &mut core,
            TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        assert!(!core.is_idle());

        while core.poll_output().is_some() {}
        assert!(core.is_idle());
    }

    #[test]
    fn outbound_ping_registration_without_payload_leaves_protocol_idle() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(2);
        let stream_id = StreamId::new(9);

        core.conn_to_peer.insert(conn_id, peer_id.clone());
        core.peer_to_conn.insert(peer_id, conn_id);

        core.on_outbound_negotiated(conn_id, stream_id, ProtocolKind::Ping, 0);

        assert!(core.ping.is_idle());
        assert!(core.poll_output().is_none());
    }

    #[test]
    fn transport_error_does_not_surface_synthetic_peer_id() {
        let mut core = test_core();
        let conn_id = ConnectionId::new(7);

        feed(
            &mut core,
            TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::new(loopback_transport()),
            },
        );
        feed(
            &mut core,
            TransportEvent::Error {
                id: conn_id,
                message: "boom".into(),
            },
        );

        let events = drain_events(&mut core);
        let error = events
            .iter()
            .find_map(|event| match event {
                SwarmEvent::Error(error) => Some(error),
                _ => None,
            })
            .expect("transport error should surface");
        assert_eq!(error.peer_id, None);
        assert_eq!(error.conn_id, Some(conn_id));
    }

    #[test]
    fn transport_error_keeps_established_peer_id() {
        let mut core = test_core();
        let conn_id = ConnectionId::new(8);
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");

        feed(
            &mut core,
            TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        feed(
            &mut core,
            TransportEvent::Error {
                id: conn_id,
                message: "boom".into(),
            },
        );

        let events = drain_events(&mut core);
        let error = events
            .iter()
            .find_map(|event| match event {
                SwarmEvent::Error(error) if error.kind == SwarmErrorKind::Transport => Some(error),
                _ => None,
            })
            .expect("transport error should surface");
        assert_eq!(error.peer_id.as_ref(), Some(&peer_id));
        assert_eq!(error.conn_id, Some(conn_id));
    }

    #[test]
    fn stream_send_uses_connection_that_owns_stream() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let original_conn = ConnectionId::new(1);
        let newer_conn = ConnectionId::new(2);
        let stream_id = StreamId::new(4);

        core.conn_to_peer.insert(original_conn, peer_id.clone());
        core.conn_to_peer.insert(newer_conn, peer_id.clone());
        core.peer_to_conn.insert(peer_id.clone(), newer_conn);
        core.stream_owner.insert(
            (original_conn, stream_id),
            ProtocolKind::User("/minip2p/test/1.0.0".into()),
        );

        core.send_stream(&peer_id, stream_id, b"ok".to_vec())
            .expect("user stream should be active on original connection");
        let actions = drain_actions(&mut core);

        assert!(matches!(
            actions.as_slice(),
            [SwarmAction::SendStream { conn_id, stream_id: sid, data }]
                if *conn_id == original_conn && *sid == stream_id && data == b"ok"
        ));
    }

    #[test]
    fn superseding_connection_invalidates_old_streams() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let original_conn = ConnectionId::new(10);
        let newer_conn = ConnectionId::new(11);
        let stream_id = StreamId::new(8);

        feed(
            &mut core,
            TransportEvent::Connected {
                id: original_conn,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        core.stream_owner.insert(
            (original_conn, stream_id),
            ProtocolKind::User("/minip2p/test/1.0.0".into()),
        );

        feed(
            &mut core,
            TransportEvent::Connected {
                id: newer_conn,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );

        let err = core
            .send_stream(&peer_id, stream_id, b"lost".to_vec())
            .expect_err("supersede should remove streams owned by original connection");
        assert!(matches!(
            err,
            SwarmError::StreamNotFound { peer_id: p, stream_id: s }
                if p == peer_id && s == stream_id
        ));
    }

    #[test]
    fn superseding_connection_resets_stale_ping_stream() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let original_conn = ConnectionId::new(10);
        let newer_conn = ConnectionId::new(11);
        let stale_stream = StreamId::new(8);

        feed(
            &mut core,
            TransportEvent::Connected {
                id: original_conn,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        core.stream_owner
            .insert((original_conn, stale_stream), ProtocolKind::Ping);
        core.ping
            .handle_input(PingInput::RegisterOutboundStream {
                peer_id: peer_id.clone(),
                stream_id: stale_stream,
            })
            .expect("register ping stream");
        while core.ping.poll_output().is_some() {}

        feed(
            &mut core,
            TransportEvent::Connected {
                id: newer_conn,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        while core.poll_output().is_some() {}

        core.ping(&peer_id, [7; PING_PAYLOAD_LEN], 42)
            .expect("ping should open a fresh stream on the newer connection");
        let actions = drain_actions(&mut core);

        assert!(
            actions
                .iter()
                .any(|action| matches!(action, SwarmAction::OpenStream { conn_id, .. } if *conn_id == newer_conn)),
            "ping should negotiate a fresh stream on the active connection, got {actions:?}"
        );
        assert!(
            !actions.iter().any(|action| matches!(
                action,
                SwarmAction::SendStream {
                    conn_id,
                    stream_id,
                    ..
                } if *conn_id == newer_conn && *stream_id == stale_stream
            )),
            "ping must not send on a stream id from the superseded connection"
        );
    }

    #[test]
    fn superseding_connection_requeues_pending_ping_open() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let original_conn = ConnectionId::new(10);
        let newer_conn = ConnectionId::new(11);

        feed(
            &mut core,
            TransportEvent::Connected {
                id: original_conn,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        while core.poll_output().is_some() {}
        core.ping(&peer_id, [7; PING_PAYLOAD_LEN], 42)
            .expect("ping should queue an open on the original connection");

        feed(
            &mut core,
            TransportEvent::Connected {
                id: newer_conn,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        let actions = drain_actions(&mut core);

        assert!(
            actions
                .iter()
                .any(|action| matches!(action, SwarmAction::OpenStream { conn_id, .. } if *conn_id == newer_conn)),
            "pending ping should be re-opened on the active connection, got {actions:?}"
        );
    }

    #[test]
    fn inbound_ping_response_uses_stream_owner_connection() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let original_conn = ConnectionId::new(10);
        let newer_conn = ConnectionId::new(11);
        let inbound_stream = StreamId::new(8);

        core.conn_to_peer.insert(original_conn, peer_id.clone());
        core.conn_to_peer.insert(newer_conn, peer_id.clone());
        core.peer_to_conn.insert(peer_id.clone(), newer_conn);
        core.stream_owner
            .insert((original_conn, inbound_stream), ProtocolKind::Ping);
        core.ping
            .handle_input(PingInput::RegisterInboundStream {
                peer_id: peer_id.clone(),
                stream_id: inbound_stream,
            })
            .expect("register inbound ping stream");
        while core.ping.poll_output().is_some() {}

        core.ping
            .handle_input(PingInput::StreamData {
                peer_id,
                stream_id: inbound_stream,
                data: [7; PING_PAYLOAD_LEN].to_vec(),
                now_ms: 42,
            })
            .expect("receive inbound ping");
        core.drain_ping_outputs();
        let actions = drain_actions(&mut core);

        assert!(matches!(
            actions.as_slice(),
            [SwarmAction::SendStream {
                conn_id,
                stream_id,
                data
            }] if *conn_id == original_conn
                && *stream_id == inbound_stream
                && data == &[7; PING_PAYLOAD_LEN]
        ));
    }

    /// Registers `peer_id` as connected on `conn_id` with a fully
    /// negotiated outbound ping stream, draining all setup outputs.
    fn setup_outbound_ping_stream(
        core: &mut SwarmCore,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) {
        feed(
            core,
            TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::with_peer_id(loopback_transport(), peer_id.clone()),
            },
        );
        while core.poll_output().is_some() {}
        core.stream_owner
            .insert((conn_id, stream_id), ProtocolKind::Ping);
        core.ping
            .handle_input(PingInput::RegisterOutboundStream {
                peer_id: peer_id.clone(),
                stream_id,
            })
            .expect("register outbound ping stream");
        while core.ping.poll_output().is_some() {}
    }

    #[test]
    fn next_timeout_arms_on_ping_and_clears_on_rtt() {
        let mut core = test_core(); // default request_timeout_ms = 10_000
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(1);
        let stream_id = StreamId::new(4);
        setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

        assert_eq!(
            core.next_timeout(0),
            None,
            "no timer armed before a ping is in flight"
        );

        let payload = [7u8; PING_PAYLOAD_LEN];
        core.ping(&peer_id, payload, 1_000).expect("send ping");

        // The ping protocol times out strictly past request_timeout_ms, so
        // the timer is due one millisecond after sent_at + timeout.
        assert_eq!(core.next_timeout(1_000), Some(10_001));
        assert_eq!(core.next_timeout(5_000), Some(6_001));
        assert_eq!(
            core.next_timeout(11_001),
            Some(0),
            "past-due timer reports zero"
        );

        // The echoed payload resolves the ping and disarms the timer.
        core.handle_input(SwarmInput::Transport {
            event: TransportEvent::StreamData {
                id: conn_id,
                stream_id,
                data: payload.to_vec(),
            },
            now_ms: 1_500,
        });
        assert_eq!(core.next_timeout(1_500), None);
        let events = drain_events(&mut core);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, SwarmEvent::PingRttMeasured { .. }))
        );
    }

    #[test]
    fn next_timeout_disarms_after_timeout_tick() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(1);
        let stream_id = StreamId::new(4);
        setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

        core.ping(&peer_id, [7u8; PING_PAYLOAD_LEN], 1_000)
            .expect("send ping");

        // An early tick must not disarm the timer.
        core.handle_input(SwarmInput::Tick { now_ms: 5_000 });
        assert_eq!(core.next_timeout(5_000), Some(6_001));

        // A tick past the deadline fires the timeout and disarms the timer.
        core.handle_input(SwarmInput::Tick { now_ms: 11_001 });
        let events = drain_events(&mut core);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, SwarmEvent::PingTimeout { .. }))
        );
        assert_eq!(core.next_timeout(11_001), None);
    }

    #[test]
    fn next_timeout_prunes_stale_deadline_after_silent_stream_close() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(1);
        let stream_id = StreamId::new(4);
        setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

        core.ping(&peer_id, [7u8; PING_PAYLOAD_LEN], 0)
            .expect("send ping");

        // A full stream close clears the ping protocol's pending state
        // without emitting a ping event; the core's deadline entry goes
        // stale until the first tick at/past its due time prunes it.
        feed(
            &mut core,
            TransportEvent::StreamClosed {
                id: conn_id,
                stream_id,
            },
        );
        assert_eq!(core.next_timeout(0), Some(10_001));

        core.handle_input(SwarmInput::Tick { now_ms: 10_001 });
        assert_eq!(core.next_timeout(10_001), None);
        let events = drain_events(&mut core);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, SwarmEvent::PingTimeout { .. })),
            "the ping was already resolved; pruning must not surface a timeout"
        );
    }

    #[test]
    fn next_timeout_cleared_when_connection_closes() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(1);
        let stream_id = StreamId::new(4);
        setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

        core.ping(&peer_id, [7u8; PING_PAYLOAD_LEN], 0)
            .expect("send ping");
        assert_eq!(core.next_timeout(0), Some(10_001));

        feed(&mut core, TransportEvent::Closed { id: conn_id });
        assert_eq!(core.next_timeout(0), None);
    }

    #[test]
    fn next_timeout_armed_by_deferred_ping_send() {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
        let conn_id = ConnectionId::new(2);
        let stream_id = StreamId::new(9);

        core.conn_to_peer.insert(conn_id, peer_id.clone());
        core.peer_to_conn.insert(peer_id.clone(), conn_id);
        core.pending_pings
            .insert(peer_id.clone(), [7u8; PING_PAYLOAD_LEN]);

        // Negotiation completing at 2_000 fires the queued payload and must
        // arm the timer from that send time.
        core.on_outbound_negotiated(conn_id, stream_id, ProtocolKind::Ping, 2_000);
        assert_eq!(core.next_timeout(2_000), Some(10_001));
        assert_eq!(core.next_timeout(4_000), Some(8_001));
    }
}
