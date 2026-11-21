//! Transport-free swarm state behind [`SwarmCore`](crate::SwarmCore).
//!
//! [`SwarmState`] holds every piece of connection, stream, and protocol
//! bookkeeping, and the swarm's three queues:
//!
//! - ordinary transport work ([`Action`]), which [`SwarmCore`](crate::SwarmCore)
//!   dispatches eagerly, feeding each result straight back in;
//! - the single application event queue;
//! - deferred connection closes, which wait until the caller has drained the
//!   event queue (a Connection replacement delivers `ConnectionReplaced`
//!   before its old connection is closed).
//!
//! [`SwarmState::next_action`] is the one place those queues are ordered.
//! No transport, clock, or entropy lives here, so the state machine stays
//! deterministic and testable on its own.
//!
//! # Layout
//!
//! This module holds the state's types, the [`SwarmState`] struct, and its
//! entry points: configuration, the queues, transport ingress
//! ([`SwarmState::handle_transport_event`], [`SwarmState::handle_tick`]), and
//! the deadline the core waits on. The rest of `SwarmState` is split into
//! `impl` blocks by concern:
//!
//! - `connections`: dials, establishment, connection races, Connection
//!   replacement, identity upgrades, closes, and connection / peer lookups;
//! - `streams`: application stream intents, write backpressure (ADR 0012),
//!   the stream-owner index, and transport stream events;
//! - `negotiation`: multistream-select on inbound and outbound streams, and
//!   its deadlines;
//! - `identify`: the Identify handler, the first-Identify deadline, and peer
//!   readiness;
//! - `ping`: ping attempts, their deadlines, and the Ping handler.
//!
//! Private methods moved into those modules are `pub(super)`; `tests` covers the whole
//! state.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::RangeInclusive;

use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Bytes, Multiaddr, PeerAddr, PeerId};
use minip2p_identify::{IDENTIFY_PROTOCOL_ID, IdentifyConfig, IdentifyMessage, IdentifyProtocol};
use minip2p_multistream_select::MultistreamSelect;
use minip2p_ping::{PING_PAYLOAD_LEN, PING_PROTOCOL_ID, PingConfig, PingProtocol};
use minip2p_transport::{ConnectionId, ConnectionToken, StreamId, TransportEvent};

use crate::events::{
    IdentifyFailure, PingFailure, SwarmError, SwarmErrorKind, SwarmEvent, SwarmRuntimeError,
};
use crate::held::HeldWrites;

mod admission;
mod connections;
mod identify;
mod negotiation;
mod ping;
mod streams;

// ---------------------------------------------------------------------------
// Protocol identification
// ---------------------------------------------------------------------------

/// Protocol ids reserved for the swarm's built-in handlers.
///
/// Inbound routing dispatches these ids to the identify and ping state
/// machines before consulting user registrations, so a user protocol under
/// a reserved id could never receive traffic. [`crate::SwarmCore::add_protocol`]
/// rejects them with [`SwarmError::ReservedProtocol`].
pub const RESERVED_PROTOCOL_IDS: [&str; 2] = [IDENTIFY_PROTOCOL_ID, PING_PROTOCOL_ID];

/// How long a peer's current direct connection counts as one half of a
/// connection race, in the core's `now_ms`.
///
/// Two direct connections to one peer that register within this window are
/// two halves of one race, and both peers must keep the same one even though
/// each may see them arrive in a different order. The newest therefore does
/// not simply win:
///
/// - In opposite directions (a simultaneous dial: each peer registers its own
///   dial first and the other's second), both keep the connection dialed by
///   the lower [`PeerId`].
/// - In the same direction (two of one peer's candidate dials), both keep the
///   one with the lower [`ConnectionToken`], which the two ends of a
///   connection share. Without a token on both, the newest wins.
///
/// The other is closed unannounced. Inside the window a peer that reconnects
/// the same way (say, restarted with the same identity) is indistinguishable
/// from a candidate race and may lose to its old connection. Past the window
/// the newest connection wins as usual, so a peer reconnecting after its old
/// connection died silently still gets through. Kept well under the
/// transports' idle timeouts.
///
/// This is the default; [`crate::SwarmBuilder::simultaneous_dial_window_ms`]
/// overrides it. Both peers settle the race on their own clocks, so they
/// should use the same window.
pub const SIMULTANEOUS_DIAL_WINDOW_MS: u64 = 5_000;

/// Default for [`SwarmTimeouts::negotiation_ms`]: how long an outbound or
/// inbound stream may spend in multistream-select negotiation.
///
/// The clock starts when the transport reports the stream opened
/// ([`TransportEvent::StreamOpened`]), so time a transport holds the open
/// (QUIC waiting for the peer's stream credit) does not count. A stream the
/// peer has not agreed to by then is reset and reported as a
/// [`SwarmErrorKind::OpenStreamFailed`] error naming it, timed by the `now`
/// samples the host passes in. It does not apply to our own ping stream or to
/// a connection's first outbound Identify stream: their own deadlines
/// ([`SwarmTimeouts::ping_ms`], [`SwarmTimeouts::identify_ms`]) cover their
/// negotiation.
///
/// An inbound stream's clock starts when it arrives
/// ([`TransportEvent::IncomingStream`]), whatever protocol the peer goes on to
/// propose (ping and Identify included). If the peer has not finished
/// negotiating by then, the stream is reset and reported as a
/// [`SwarmErrorKind::Multistream`] error, so a peer cannot hold stream slots
/// by opening streams it never negotiates.
pub const OUTBOUND_NEGOTIATION_TIMEOUT_MS: u64 = 30_000;

/// Default for [`SwarmTimeouts::identify_ms`]: how long a connection's first
/// Identify exchange may take: opening the stream, negotiating it, and the
/// peer's reply, counted from the connection establishing. A connection that
/// is not identified by then is reported in [`SwarmEvent::IdentifyFailed`]
/// and closed. Generous, because a peer that connects while the link is
/// loaded (a bulk transfer filling a slow uplink) can take well over 10 s.
pub const IDENTIFY_TIMEOUT_MS: u64 = 30_000;

/// The swarm's protocol deadlines, in milliseconds. Every field must be
/// above zero; [`crate::SwarmBuilder::build_core`] rejects a zero with
/// [`crate::SwarmError::ZeroTimeout`].
///
/// `identify_ms` and `ping_ms` each bound their whole exchange, its
/// negotiation included, so `negotiation_ms` does not cut them short; it
/// bounds the negotiation of every other outbound stream, and of every
/// inbound stream. On a slow or
/// loaded link, size them from how long each exchange actually takes there,
/// plus slack for a retransmission. The `minip2p-rs` README's deadline table
/// lists the Endpoint and transport deadlines beside these and how they
/// relate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwarmTimeouts {
    /// How long an outbound stream may negotiate its protocol, from the
    /// transport's `StreamOpened` (not ping or first-Identify streams), and
    /// an inbound stream, from its `IncomingStream`. Default [`OUTBOUND_NEGOTIATION_TIMEOUT_MS`] (30 s).
    pub negotiation_ms: u64,
    /// How long a connection's first Identify may take (open, negotiation,
    /// reply), from the connection establishing. Default
    /// [`IDENTIFY_TIMEOUT_MS`] (30 s).
    pub identify_ms: u64,
    /// How long a ping attempt may take (open, negotiation, echo), from the
    /// `ping` call, before [`SwarmEvent::PingFailed`] with
    /// [`TimedOut`](crate::PingFailure::TimedOut). Default 10 s
    /// ([`PingConfig::default`]). The swarm only pings when the host asks.
    pub ping_ms: u64,
}

impl Default for SwarmTimeouts {
    fn default() -> Self {
        Self {
            negotiation_ms: OUTBOUND_NEGOTIATION_TIMEOUT_MS,
            identify_ms: IDENTIFY_TIMEOUT_MS,
            ping_ms: PingConfig::default().request_timeout_ms,
        }
    }
}

impl SwarmTimeouts {
    /// Rejects a zero deadline, naming the field.
    pub fn validate(&self) -> Result<(), crate::SwarmError> {
        for (field, value) in [
            ("negotiation_ms", self.negotiation_ms),
            ("identify_ms", self.identify_ms),
            ("ping_ms", self.ping_ms),
        ] {
            if value == 0 {
                return Err(crate::SwarmError::ZeroTimeout { field });
            }
        }
        Ok(())
    }
}

/// Identifies which protocol owns a negotiated stream.
///
/// Kept private; callers refer to protocols by their string ids via
/// [`crate::SwarmCore::open_stream`] and the `protocol_id` fields of
/// [`SwarmEvent::StreamReady`] / [`SwarmEvent::StreamData`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum ProtocolKind {
    Ping,
    /// Identify responder: we send our info.
    IdentifyResponder,
    /// Identify initiator: we receive their info.
    IdentifyInitiator,
    /// A user-registered protocol, with its string ID retained so events
    /// can surface it back to the application.
    User(String),
}

/// `SwarmState::stream_owner` key. Field order is sort order: peer and stream
/// come first so a `(peer, stream)` lookup is a range query.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OwnedStream {
    peer_id: PeerId,
    stream_id: StreamId,
    conn_id: ConnectionId,
}

impl OwnedStream {
    /// Every key for `peer_id` with a stream id in `first..=last`, on any
    /// connection.
    fn peer_range(peer_id: &PeerId, first: StreamId, last: StreamId) -> RangeInclusive<Self> {
        let key = |stream_id, conn_id| Self {
            peer_id: *peer_id,
            stream_id,
            conn_id,
        };
        key(first, ConnectionId::new(0))..=key(last, ConnectionId::new(u64::MAX))
    }
}

/// An inbound stream in multistream-select negotiation.
struct PendingInbound {
    negotiator: MultistreamSelect,
    /// When the negotiation is given up and the stream reset: the stream's
    /// arrival plus [`SwarmTimeouts::negotiation_ms`].
    deadline_ms: u64,
}

/// Tracks a pending outbound stream that is still negotiating multistream-select.
struct PendingOutbound {
    negotiator: MultistreamSelect,
    target: ProtocolKind,
    /// When the negotiation is given up; see
    /// [`SwarmTimeouts::negotiation_ms`]. `None` until the transport
    /// reports the stream opened, and for good when the stream's protocol
    /// bounds it with its own deadline (`SwarmState::has_own_deadline`).
    deadline_ms: Option<u64>,
    /// The peer's stop-sending code, when it arrived after our proposal
    /// went out: handled as the negotiated protocol would once it is.
    write_stopped: Option<u64>,
}

/// Transport work the state queues for [`crate::SwarmCore`] to dispatch.
///
/// Private vocabulary: protocol handlers queue work while they mutate state,
/// and the core runs each action's transport call once the handler returns,
/// feeding the result straight back in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    /// Open an outbound stream for one of the swarm's own protocols and start
    /// negotiating `protocol` on it. A failure is reported as an event.
    OpenStream {
        conn_id: ConnectionId,
        protocol: String,
        target: ProtocolKind,
    },
    /// Send bytes on a stream. The state owns the retry of a Full write.
    SendStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    },
    /// Half-close our write side on a stream.
    CloseStreamWrite {
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// Abruptly reset a stream in both directions.
    ResetStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// Gracefully close a connection.
    CloseConnection { conn_id: ConnectionId },
    /// Acknowledge `bytes` of a stream's delivered data as consumed
    /// (`Transport::ack_stream`).
    ///
    /// The state acknowledges what it consumes itself: negotiation, ping, and
    /// Identify bytes, and data for streams it no longer routes. Bytes it
    /// hands to the application in [`SwarmEvent::StreamData`] are the
    /// application's to acknowledge.
    AckStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    },
    /// Settle a stream of a connection that already ended, abandoning its
    /// unacknowledged bytes (`Transport::reset_stream`, ADR 0012). A
    /// transport holding nothing for it makes this a no-op.
    SettleStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// Mark a stream as one of the swarm's control streams, or back as an
    /// application stream (`Transport::set_control_stream`). Every stream is
    /// control while multistream negotiates it, and ping and Identify
    /// streams stay so; a stream negotiated for an application protocol
    /// becomes an application stream before the application sees it.
    SetControlStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
        control: bool,
    },
}

fn stream_action_matches(action: &Action, conn_id: ConnectionId, stream_id: StreamId) -> bool {
    matches!(
        action,
        Action::SendStream {
            conn_id: action_conn,
            stream_id: action_stream,
            ..
        }
            | Action::CloseStreamWrite {
                conn_id: action_conn,
                stream_id: action_stream,
            }
            | Action::ResetStream {
                conn_id: action_conn,
                stream_id: action_stream,
            }
            | Action::SetControlStream {
                conn_id: action_conn,
                stream_id: action_stream,
                ..
            }
            if *action_conn == conn_id && *action_stream == stream_id
    )
}

fn connection_action_matches(action: &Action, conn_id: ConnectionId) -> bool {
    match action {
        Action::OpenStream {
            conn_id: action_conn,
            ..
        }
        | Action::SendStream {
            conn_id: action_conn,
            ..
        }
        | Action::CloseStreamWrite {
            conn_id: action_conn,
            ..
        }
        | Action::ResetStream {
            conn_id: action_conn,
            ..
        }
        | Action::CloseConnection {
            conn_id: action_conn,
        }
        | Action::AckStream {
            conn_id: action_conn,
            ..
        }
        | Action::SettleStream {
            conn_id: action_conn,
            ..
        }
        | Action::SetControlStream {
            conn_id: action_conn,
            ..
        } => *action_conn == conn_id,
    }
}

/// Whether a replacement drops `action` for the replaced connection `old`.
/// Acknowledgements and settlements stay: delivered bytes remain counted
/// after the connection ends until they are released (ADR 0012).
fn dropped_on_replacement(action: &Action, old: ConnectionId) -> bool {
    connection_action_matches(action, old)
        && !matches!(
            action,
            Action::AckStream { .. } | Action::SettleStream { .. }
        )
}

/// The stream a write or write-side close addresses.
fn stream_write_key(action: &Action) -> Option<(ConnectionId, StreamId)> {
    match action {
        Action::SendStream {
            conn_id, stream_id, ..
        }
        | Action::CloseStreamWrite { conn_id, stream_id } => Some((*conn_id, *stream_id)),
        _ => None,
    }
}

/// Most bytes the core holds for one stream of its own protocols before it
/// resets the stream: a peer that keeps sending pings while reading none of
/// the echoes cannot grow the hold without bound.
const MAX_HELD_PER_STREAM: usize = 64 * 1024;

/// The connection a transport event belongs to; `None` for listener events.
fn transport_event_connection(event: &TransportEvent) -> Option<ConnectionId> {
    match event {
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
        TransportEvent::Listening { .. } => None,
    }
}

fn push_unique(protocols: &mut Vec<String>, protocol_id: String) {
    if !protocols.iter().any(|existing| existing == &protocol_id) {
        protocols.push(protocol_id);
    }
}

// ---------------------------------------------------------------------------
// SwarmState
// ---------------------------------------------------------------------------

/// Transport-free swarm state; see the module docs.
pub(crate) struct SwarmState {
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
    inbound_negotiators: BTreeMap<(ConnectionId, StreamId), PendingInbound>,
    /// Outbound streams being negotiated (client-side multistream-select).
    outbound_negotiators: BTreeMap<(ConnectionId, StreamId), PendingOutbound>,
    /// Streams that completed negotiation: maps to the owning protocol.
    ///
    /// Keyed peer-first so the `(peer, stream)` lookups behind the ping and
    /// Identify handlers are a range query rather than a scan. Each key's peer is
    /// always `conn_to_peer[conn]`; [`Self::set_conn_peer`] rekeys on change.
    stream_owner: BTreeMap<OwnedStream, ProtocolKind>,
    pub(crate) inbound_limits: BTreeMap<String, NonZeroUsize>,
    admitted_inbound: BTreeMap<(ConnectionId, StreamId), String>,
    queued_inbound: VecDeque<admission::QueuedInbound>,
    /// User streams for which a reset has already been queued.
    reset_pending: BTreeSet<(ConnectionId, StreamId)>,
    /// Streams deliberately forgotten by their consumer until transport close.
    abandoned_streams: BTreeSet<(ConnectionId, StreamId)>,

    // --- Configuration ---
    /// Protocol IDs accepted by inbound multistream-select negotiation.
    inbound_protocols: Vec<String>,
    /// Protocol IDs applications and composed services may open outbound.
    outbound_protocols: Vec<String>,

    // --- Bookkeeping ---
    /// Each peer's running ping attempt. An entry is removed exactly when
    /// the attempt ends: by `PingRttMeasured`, by `PingFailed` (mostly
    /// [`Self::fail_ping`]), or silently with its connection.
    pings: BTreeMap<PeerId, PingAttempt>,
    /// The protocol deadlines; `ping_ms` computes `pings` deadlines.
    timeouts: SwarmTimeouts,
    /// Snapshot of the transport's local listening addresses, refreshed
    /// by the core at the top of each `poll()` tick. Used to
    /// auto-populate Identify's `listen_addrs` so advertised addresses
    /// always reflect what we're actually bound to.
    local_addresses: Vec<Multiaddr>,
    /// Latest Identify payload received for each peer.
    peer_info: BTreeMap<PeerId, IdentifyMessage>,
    /// Peers whose current connection has emitted `PeerReady`. Cleared on a
    /// Connection replacement: readiness belongs to a connection.
    ready_peers: BTreeSet<PeerId>,
    /// Peers that have been surfaced through `ConnectionEstablished`.
    established_peers: BTreeSet<PeerId>,
    /// Connections whose first Identify has not succeeded yet. Dropped when
    /// it succeeds or the connection leaves.
    first_identify: BTreeMap<ConnectionId, FirstIdentify>,
    /// Connections in a lifecycle phase other than an inbound handshake or
    /// an established connection: our dials that have not established, and
    /// connections closing unannounced. An entry leaves when the dial
    /// establishes or the transport reports the connection closed.
    conn_phases: BTreeMap<ConnectionId, ConnPhase>,
    /// This node's peer id, derived from the Identify public key. Breaks
    /// simultaneous-dial ties; see [`SIMULTANEOUS_DIAL_WINDOW_MS`].
    local_peer_id: PeerId,
    /// How and when each peer's current connection took its slot, for the
    /// connection-race tie-break. Dropped when it leaves the slot.
    registrations: BTreeMap<ConnectionId, Registration>,
    /// How long a new connection can lose a race to the current one;
    /// defaults to [`SIMULTANEOUS_DIAL_WINDOW_MS`].
    pub(crate) simultaneous_dial_window_ms: u64,

    // --- Write backpressure (ADR 0012) ---
    /// Unsent tails of the core's own writes (negotiation, ping, Identify),
    /// and the writes and closes queued behind them.
    held: HeldWrites,
    /// User streams whose write the core refused because `held` had bytes for
    /// them; they get a `StreamWritable` once `held` is replayed.
    user_writable_wanted: BTreeSet<(ConnectionId, StreamId)>,
    /// User streams whose write side the application closed or reset: no
    /// `StreamWritable` reaches them, even one the transport had already
    /// queued. Cleared when the stream closes.
    user_write_ended: BTreeSet<(ConnectionId, StreamId)>,
    /// Streams negotiated for an application protocol while `held` had
    /// negotiation bytes for them. They stay control streams, so those bytes
    /// keep the reserve, until the held tail is replayed.
    pending_demotions: BTreeSet<(ConnectionId, StreamId)>,

    // --- Queues ---
    /// The application event queue. An event here has not been delivered:
    /// [`crate::SwarmCore::poll`] and the std `Swarm` take events from it.
    pub(crate) events: VecDeque<SwarmEvent>,
    /// Ordinary transport work, dispatched before any event is delivered.
    actions: VecDeque<Action>,
    /// Connections whose close waits until the event queue has been drained.
    /// A Connection replacement uses this to deliver `ConnectionReplaced`
    /// before asking the transport to close the old connection.
    pub(crate) deferred_closes: VecDeque<ConnectionId>,
}

/// Where a connection's first Identify exchange stands, until it succeeds.
#[derive(Clone, Copy)]
enum FirstIdentify {
    /// Still running; given up at `deadline_ms` ([`SwarmTimeouts::identify_ms`]).
    Running { deadline_ms: u64 },
    /// Failed: the connection is closing and never becomes ready.
    Failed(IdentifyFailure),
}

/// A running ping attempt to one peer.
struct PingAttempt {
    /// Absolute deadline ([`SwarmTimeouts::ping_ms`] from the `ping` call),
    /// covering the whole attempt: the open, the negotiation and the echo.
    deadline_ms: u64,
    /// The payload waiting for the ping stream to negotiate; `None` once it
    /// was sent and Ping holds the echo in flight.
    queued: Option<[u8; PING_PAYLOAD_LEN]>,
}

/// An outbound dial waiting to establish, keyed by the transport connection id.
struct PendingDial {
    addr: PeerAddr,
    last_error: Option<String>,
}

/// Where a connection without an ordinary lifecycle stands; see
/// `SwarmState::conn_phases`.
enum ConnPhase {
    /// Our dial, not yet established. A close before it establishes is
    /// reported as [`SwarmEvent::DialFailed`].
    Dialing(PendingDial),
    /// Our dial that must not establish (after a failed
    /// [`crate::SwarmCore::abort_dial`]): its establish is rejected as
    /// `DialFailed` so it cannot displace the peer's current connection.
    Vetoed(PendingDial),
    /// Closing without being announced, or no longer announced: an aborted
    /// dial, a rejected establish, a race loser, or a connection handed
    /// over by a Connection replacement. Every transport event on it but
    /// `Closed` is ignored, so nothing late can register it, and its close
    /// is silent.
    Closing,
}

impl ConnPhase {
    /// The dial this phase still waits on, if any.
    fn dial(&self) -> Option<&PendingDial> {
        match self {
            Self::Dialing(dial) | Self::Vetoed(dial) => Some(dial),
            Self::Closing => None,
        }
    }
}

/// How and when a peer's current connection took its slot.
#[derive(Clone, Copy)]
struct Registration {
    /// Came from one of our dials rather than the peer's.
    outbound: bool,
    at_ms: u64,
    /// The transport's token for the connection, if it has one.
    token: Option<ConnectionToken>,
}

impl SwarmState {
    /// Creates the state with the given identify config and deadlines.
    ///
    /// The local peer id is derived from `identify_config.public_key`.
    pub fn new(identify_config: IdentifyConfig, timeouts: SwarmTimeouts) -> Self {
        let local_peer_id = PeerId::from_public_key_protobuf(&identify_config.public_key);
        let inbound_protocols = vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
        ];

        Self {
            ping: PingProtocol::new(PingConfig {
                request_timeout_ms: timeouts.ping_ms,
            }),
            identify: IdentifyProtocol::new(identify_config),
            conn_to_peer: BTreeMap::new(),
            peer_to_conn: BTreeMap::new(),
            conn_to_remote_addr: BTreeMap::new(),
            inbound_negotiators: BTreeMap::new(),
            outbound_negotiators: BTreeMap::new(),
            stream_owner: BTreeMap::new(),
            inbound_limits: BTreeMap::new(),
            admitted_inbound: BTreeMap::new(),
            queued_inbound: VecDeque::new(),
            reset_pending: BTreeSet::new(),
            abandoned_streams: BTreeSet::new(),
            inbound_protocols,
            outbound_protocols: Vec::new(),
            pings: BTreeMap::new(),
            timeouts,
            local_addresses: Vec::new(),
            peer_info: BTreeMap::new(),
            ready_peers: BTreeSet::new(),
            established_peers: BTreeSet::new(),
            first_identify: BTreeMap::new(),
            conn_phases: BTreeMap::new(),
            local_peer_id,
            registrations: BTreeMap::new(),
            simultaneous_dial_window_ms: SIMULTANEOUS_DIAL_WINDOW_MS,
            events: VecDeque::new(),
            held: HeldWrites::new(),
            user_writable_wanted: BTreeSet::new(),
            user_write_ended: BTreeSet::new(),
            pending_demotions: BTreeSet::new(),
            actions: VecDeque::new(),
            deferred_closes: VecDeque::new(),
        }
    }

    /// Updates the core's snapshot of the transport's local listening
    /// addresses.
    ///
    /// The core calls this at the top of each `poll()` tick, so the
    /// snapshot follows the transport's bound set.
    pub fn set_local_addresses(&mut self, addrs: Vec<Multiaddr>) {
        self.local_addresses = addrs;
    }

    /// The current snapshot of addresses Identify will advertise.
    pub fn local_addresses(&self) -> &[Multiaddr] {
        &self.local_addresses
    }

    /// Registers an application protocol id that this swarm will accept on
    /// inbound streams and allow for outbound opens via
    /// [`crate::SwarmCore::open_stream`].
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]: inbound routing gives the built-in
    /// handlers precedence, so a user registration under one of those ids
    /// could never receive traffic.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), SwarmError> {
        let id = protocol_id.into();
        Self::validate_service_protocol(&id)?;
        push_unique(&mut self.inbound_protocols, id.clone());
        push_unique(&mut self.outbound_protocols, id.clone());
        self.identify.add_protocol(id);
        Ok(())
    }

    /// Registers a protocol only for inbound negotiation by a composed service.
    pub fn add_inbound_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), SwarmError> {
        let id = protocol_id.into();
        Self::validate_service_protocol(&id)?;
        push_unique(&mut self.inbound_protocols, id);
        Ok(())
    }

    /// Registers a protocol only for outbound opens by a composed service.
    pub fn add_outbound_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), SwarmError> {
        let id = protocol_id.into();
        Self::validate_service_protocol(&id)?;
        push_unique(&mut self.outbound_protocols, id);
        Ok(())
    }

    /// Adds a protocol only to future Identify responses for a composed service.
    pub fn add_advertised_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), SwarmError> {
        let id = protocol_id.into();
        Self::validate_service_protocol(&id)?;
        self.identify.add_protocol(id);
        Ok(())
    }

    fn validate_service_protocol(protocol_id: &str) -> Result<(), SwarmError> {
        if RESERVED_PROTOCOL_IDS.contains(&protocol_id) {
            return Err(SwarmError::ReservedProtocol {
                protocol_id: protocol_id.into(),
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queues (the core drains these)
    // -----------------------------------------------------------------------

    /// Returns the next transport action to dispatch, if any.
    ///
    /// Ordinary actions come first, as soon as they are queued: dispatching
    /// one can queue more, and that cascade runs to completion. Deferred
    /// closes come only once the event queue is empty, so the application
    /// has been handed every event ordered before them.
    ///
    /// A write or close for a stream whose earlier write came back Full is
    /// never returned: it joins the held tail instead, so it cannot overtake
    /// it (see [`Self::handle_send_full`]).
    pub fn next_action(&mut self) -> Option<Action> {
        while let Some(action) = self.actions.pop_front() {
            if let Some(action) = self.hold_action(action) {
                return Some(action);
            }
        }
        if self.events.is_empty() {
            return self
                .deferred_closes
                .pop_front()
                .map(|conn_id| Action::CloseConnection { conn_id });
        }
        None
    }

    /// Takes the next application event, delivering it.
    pub fn next_event(&mut self) -> Option<SwarmEvent> {
        while let Some(event) = self.events.pop_front() {
            // A replayed tail that came back Full while this Writable waited
            // holds the stream again: wait for the next Writable instead, or
            // for none once a close is queued behind the held bytes.
            if let SwarmEvent::StreamWritable {
                conn_id, stream_id, ..
            } = &event
                && self.held.is_held(*conn_id, *stream_id)
            {
                if !self.held.is_closing(*conn_id, *stream_id) {
                    self.user_writable_wanted.insert((*conn_id, *stream_id));
                }
                continue;
            }
            return Some(event);
        }
        None
    }

    /// Whether undelivered events or deferred closes are waiting: the core
    /// has work due now whatever its timers say.
    pub fn has_pending_work(&self) -> bool {
        !self.events.is_empty() || !self.deferred_closes.is_empty()
    }

    /// Whether no action, event, or deferred close is queued.
    #[cfg(test)]
    pub fn is_idle(&self) -> bool {
        self.actions.is_empty() && self.events.is_empty() && self.deferred_closes.is_empty()
    }

    /// Returns when the earliest internal protocol timer is due, or `None`
    /// when no timer is armed.
    ///
    /// The internal timers are ping attempt deadlines, first-Identify
    /// deadlines, and inbound and outbound negotiation deadlines. All are stored as
    /// absolute due times, so `now` is unused; an overdue
    /// timer reports its past due time, which tells the host to run
    /// [`Self::handle_tick`] now.
    pub fn next_deadline(&self, _now: Now) -> Option<Deadline> {
        let negotiations = self
            .outbound_negotiators
            .values()
            .filter_map(|pending| pending.deadline_ms)
            .chain(self.inbound_negotiators.values().map(|p| p.deadline_ms));
        self.pings
            .values()
            .map(|attempt| attempt.deadline_ms)
            .chain(
                self.first_identify
                    .values()
                    .filter_map(|state| match state {
                        FirstIdentify::Running { deadline_ms } => Some(*deadline_ms),
                        FirstIdentify::Failed(_) => None,
                    }),
            )
            .chain(negotiations)
            .min()
            .map(Deadline::from_millis)
    }

    // -----------------------------------------------------------------------
    // Ingress
    // -----------------------------------------------------------------------

    /// Queues a runtime error the core met while dispatching an action.
    pub fn record_runtime_error(&mut self, error: SwarmRuntimeError) {
        self.events.push_back(SwarmEvent::Error(error));
    }

    /// Feeds one transport event at `now_ms`.
    pub fn handle_transport_event(&mut self, event: TransportEvent, now_ms: u64) {
        if let Some(id) = transport_event_connection(&event)
            && matches!(self.conn_phases.get(&id), Some(ConnPhase::Closing))
        {
            // Whatever announced or reported the connection already did;
            // only its final close is bookkeeping.
            match event {
                TransportEvent::Closed { reason, .. } => self.handle_connection_closed(id, reason),
                // Nobody will read it, so the state consumes it.
                TransportEvent::StreamData {
                    stream_id, data, ..
                } => self.actions.push_back(Action::AckStream {
                    conn_id: id,
                    stream_id,
                    bytes: data.len(),
                }),
                _ => {}
            }
            return;
        }
        match event {
            TransportEvent::Connected { id, endpoint } => {
                self.conn_to_remote_addr
                    .insert(id, endpoint.transport().clone());
                if matches!(self.conn_phases.get(&id), Some(ConnPhase::Vetoed(_))) {
                    self.reject_pending_establish(id);
                    return;
                }
                if let Some(peer_id) = endpoint.peer_id() {
                    self.register_connection(id, *peer_id, endpoint.token(), now_ms);
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
                if matches!(self.conn_phases.get(&id), Some(ConnPhase::Vetoed(_))) {
                    self.reject_pending_establish(id);
                    return;
                }
                if let Some(peer_id) = endpoint.peer_id() {
                    self.upgrade_connection_identity(id, *peer_id, endpoint.token(), now_ms);
                }
            }
            TransportEvent::IncomingConnection { id, endpoint } => {
                self.conn_to_remote_addr
                    .insert(id, endpoint.transport().clone());
            }
            TransportEvent::IncomingStream { id, stream_id } => {
                self.handle_incoming_stream(id, stream_id, now_ms);
            }
            TransportEvent::StreamOpened { id, stream_id } => {
                // Outbound stream ids come back synchronously from
                // `Transport::open_stream` (see `start_outbound`); this marks
                // the stream as actually opened, which starts its deadline.
                let covered = self
                    .outbound_negotiators
                    .get(&(id, stream_id))
                    .is_some_and(|pending| self.has_own_deadline(id, &pending.target));
                if !covered
                    && let Some(pending) = self.outbound_negotiators.get_mut(&(id, stream_id))
                {
                    pending.deadline_ms = Some(now_ms.saturating_add(self.timeouts.negotiation_ms));
                }
            }
            TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } => {
                self.handle_stream_data(id, stream_id, data, now_ms);
            }
            TransportEvent::StreamWritable { id, stream_id } => {
                self.handle_stream_writable(id, stream_id);
            }
            TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                self.handle_stream_remote_write_closed(id, stream_id);
            }
            TransportEvent::StreamWriteStopped {
                id,
                stream_id,
                error_code,
            } => {
                self.handle_stream_write_stopped(id, stream_id, error_code);
            }
            TransportEvent::StreamClosed { id, stream_id } => {
                self.handle_stream_closed(id, stream_id);
            }
            TransportEvent::Closed { id, reason } => {
                self.handle_connection_closed(id, reason);
            }
            TransportEvent::Listening { .. } => {}
            TransportEvent::Error { id, message } => {
                if let Some(ConnPhase::Dialing(pending) | ConnPhase::Vetoed(pending)) =
                    self.conn_phases.get_mut(&id)
                {
                    pending.last_error = Some(message);
                    // Attempt-owned and raw outbound dials report through
                    // DialFailed on close. Emitting Error here would leak a
                    // second diagnostic the connect engine cannot consume.
                    return;
                }
                self.emit_error(
                    SwarmErrorKind::Transport,
                    self.established_peer_for_conn(id),
                    Some(id),
                    format!("transport error on connection {id}: {message}"),
                );
            }
        }
    }

    /// Advances protocol timers to `now_ms`.
    pub fn handle_tick(&mut self, now_ms: u64) {
        self.ping.on_tick(now_ms);
        self.collect_protocol_events();
        let overdue: Vec<PeerId> = self
            .pings
            .iter()
            .filter(|(_, attempt)| attempt.deadline_ms <= now_ms)
            .map(|(peer_id, _)| *peer_id)
            .collect();
        for peer_id in overdue {
            self.fail_ping(&peer_id, PingFailure::TimedOut);
        }
        self.expire_outbound_negotiations(now_ms);
        self.expire_inbound_negotiations(now_ms);
        let expired: Vec<ConnectionId> = self
            .first_identify
            .iter()
            .filter(|(_, state)| {
                matches!(state, FirstIdentify::Running { deadline_ms } if *deadline_ms <= now_ms)
            })
            .map(|(conn_id, _)| *conn_id)
            .collect();
        for conn_id in expired {
            self.fail_first_identify(conn_id, IdentifyFailure::TimedOut);
        }
    }

    // -----------------------------------------------------------------------
    // Internal: state helpers
    // -----------------------------------------------------------------------

    fn emit_error(
        &mut self,
        kind: SwarmErrorKind,
        peer_id: Option<PeerId>,
        conn_id: Option<ConnectionId>,
        detail: impl Into<String>,
    ) {
        self.emit_error_for_stream(kind, peer_id, conn_id, None, detail);
    }

    fn emit_error_for_stream(
        &mut self,
        kind: SwarmErrorKind,
        peer_id: Option<PeerId>,
        conn_id: Option<ConnectionId>,
        stream_id: Option<StreamId>,
        detail: impl Into<String>,
    ) {
        self.events.push_back(SwarmEvent::Error(SwarmRuntimeError {
            kind,
            peer_id,
            conn_id,
            stream_id,
            detail: detail.into(),
        }));
    }

    // -----------------------------------------------------------------------
    // Internal: execute protocol-handler actions
    // -----------------------------------------------------------------------

    // Ping and Identify outputs are drained right after the input that
    // produced them, so the peer's current connection is the one the event
    // came from. `handle_ping_event` and `handle_identify_event` fix it at
    // queue time: a later replacement must not re-attribute it.
    fn collect_protocol_events(&mut self) {
        self.drain_ping_outputs();
        self.drain_identify_outputs();
    }
}

#[cfg(test)]
mod tests;
