//! One QUIC connection: the quinn-proto engine plus the adapter's stream
//! bookkeeping (half-close tracking, write queues, the read gate of ADR 0012,
//! and stream-slot accounting). An `h3` connection also runs a
//! [`WtSession`], which authenticates it and owns its HTTP/3 streams.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use minip2p_core::Protocol;
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, ConnectionState, ConnectionToken,
    SendCaps, StreamId, TransportError, TransportEvent,
};
use minip2p_webtransport::h3::{code, h3_code_to_webtransport, webtransport_code_to_h3};
use quinn_proto::crypto::rustls::HandshakeData;
use quinn_proto::{
    ConnectionError, ConnectionHandle, Dir, Event, FinishError, ReadError, StreamEvent, VarInt,
    WriteError,
};

use crate::diagnostics::ConnectionCounters;
use crate::socket::Sockets;
use crate::webtransport::{ReadEnd, WebTransportContext, WtEvent, WtSession};

/// TLS exporter label for the connection token both ends derive.
const TOKEN_LABEL: &[u8] = b"minip2p quic connection token";

/// Upper bound on engine passes per service: each pass handles what the
/// previous one's events and endpoint events produced.
const MAX_SERVICE_PASSES: usize = 4;

/// Most queued bytes one stream hands the engine per turn of the send
/// scheduler, so backlogged streams share the peer's connection credit.
const SEND_QUANTUM: usize = 64 * 1024;

/// Bounds on a WebTransport session's Closing phase: `max(3 × RTT, 500 ms)`,
/// capped at 2 s. A peer-ended session may close QUIC sooner; one we closed
/// waits it out (see [`QuicConnection::finish_wt_closing`]).
const WT_CLOSE_MIN: Duration = Duration::from_millis(500);
const WT_CLOSE_MAX: Duration = Duration::from_secs(2);

/// What servicing a connection needs from its transport.
pub(crate) struct Cx<'a> {
    pub(crate) endpoint: &'a mut quinn_proto::Endpoint,
    /// Each transmit leaves from the socket of its destination's family.
    pub(crate) sockets: &'a mut Sockets,
    /// Reused for every transmit.
    pub(crate) send_buf: &'a mut Vec<u8>,
    pub(crate) events: &'a mut Vec<TransportEvent>,
}

/// A queued write operation for a QUIC stream.
#[derive(Debug)]
struct PendingStreamWrite {
    /// Payload bytes the engine has not accepted yet.
    bytes: Bytes,
    /// The length `bytes` was counted at. Once the unsent tail is shorter
    /// than half of it, the tail moves to its own buffer so a slice cannot
    /// pin a much larger allocation (ADR 0012).
    counted: usize,
    /// If true, this entry is the stream's FIN.
    fin: bool,
    /// The WebTransport stream prefix: queued ahead of the caller's bytes
    /// and never counted against the send caps.
    internal: bool,
}

impl PendingStreamWrite {
    /// A data write retaining `bytes`, sliced from a payload counted at
    /// `counted` bytes.
    fn data(bytes: Bytes, counted: usize) -> Self {
        let mut write = Self {
            bytes,
            counted,
            fin: false,
            internal: false,
        };
        write.bound_retained();
        write
    }

    /// A FIN-only entry (empty payload, closes the write side).
    fn fin() -> Self {
        Self {
            bytes: Bytes::new(),
            counted: 0,
            fin: true,
            internal: false,
        }
    }

    /// A WebTransport stream prefix, outside the caller's accounting.
    fn prefix(bytes: Vec<u8>) -> Self {
        Self {
            counted: bytes.len(),
            bytes: Bytes::from(bytes),
            fin: false,
            internal: true,
        }
    }

    /// Drops the first `len` bytes, which the engine accepted.
    fn advance(&mut self, len: usize) {
        self.bytes = self.bytes.slice(len..);
        self.bound_retained();
    }

    fn bound_retained(&mut self) {
        minip2p_core::retain_slice(&mut self.bytes, &mut self.counted);
    }
}

/// Queued writes for one stream, never empty while stored.
#[derive(Debug, Default)]
struct SendQueue {
    writes: VecDeque<PendingStreamWrite>,
    /// Unsent bytes across `writes`: what counts against the stream cap.
    pending: usize,
}

/// Per-stream bookkeeping for half-close tracking.
#[derive(Debug, Default)]
struct StreamRuntimeState {
    /// Whether we have closed our write side.
    local_write_closed: bool,
    /// Whether the remote has closed their write side.
    remote_write_closed: bool,
    /// Whether a StreamClosed event was emitted.
    closed_notified: bool,
    /// Whether a StreamWriteStopped event was emitted.
    write_stopped: bool,
    /// Delivered bytes the reader has not acknowledged (ADR 0012). Reading
    /// stops once they reach the stream receive window, and the state
    /// outlives the stream's close until they are acknowledged: the stream
    /// holds its slot until it settles.
    unacked: usize,
    /// What a WebTransport stream carried while it was held, not yet
    /// delivered for want of receive room, and how its read ended then.
    /// Delivered ahead of anything the engine has behind it.
    held: Option<(Vec<u8>, ReadEnd)>,
    /// A control stream may queue into the connection cap's reserve
    /// ([`Transport::set_control_stream`](minip2p_transport::Transport::set_control_stream)).
    control: bool,
}

impl StreamRuntimeState {
    /// Bytes the stream may still deliver, within `window`, before its
    /// reader acknowledges.
    fn receive_room(&self, window: usize) -> usize {
        window.saturating_sub(self.unacked)
    }

    /// Returns true if both sides have closed their write side.
    fn is_fully_closed(&self) -> bool {
        self.local_write_closed && self.remote_write_closed
    }
}

/// A local stream handed out by `open_stream` but not yet opened in the
/// engine, which opens streams only within the peer's credit.
#[derive(Debug)]
struct PendingOpen {
    /// The id it was given; the engine assigns the same one when it opens.
    id: u64,
    /// Reset before it was opened: reset and stop it on the wire once it is.
    reset_on_bind: bool,
}

/// How one stream scan ended, beyond the data it read.
enum ScanEnd {
    /// No more contiguous data for now.
    Waiting,
    /// The budget is spent with data (or a gap) still waiting behind it.
    Gated,
    /// The peer's FIN was read.
    Finished,
    /// The peer reset the stream.
    Reset,
}

pub(crate) struct QuicConnection {
    /// Logical connection id assigned by the transport.
    id: ConnectionId,
    /// The engine's handle, for routing endpoint events.
    handle: ConnectionHandle,
    conn: quinn_proto::Connection,
    /// Connection endpoint metadata (transport address + optional peer id).
    endpoint: ConnectionEndpoint,
    state: ConnectionState,
    /// Whether stream events reach the caller: from authentication
    /// (`Connected`) until a local close or a failed authentication. Outside
    /// it, new peer streams are refused and data on existing ones is
    /// discarded without events.
    surfaces_streams: bool,
    /// Why the connection is ending: the first cause seen, reported on its
    /// `Closed`.
    close_reason: Option<ConnectionCloseReason>,
    /// Per-stream runtime state keyed by raw QUIC stream id.
    stream_states: HashMap<u64, StreamRuntimeState>,
    /// Outbound write queues keyed by raw QUIC stream id. Only streams with
    /// pending output have an entry, so a drain visits nothing else.
    send_queues: HashMap<u64, SendQueue>,
    /// The keys of `send_queues` in round-robin order: the front stream has
    /// the next turn, and the order persists between drains.
    send_order: VecDeque<u64>,
    /// Next local bidirectional stream id `open_stream` hands out.
    next_local_bidi_stream_id: u64,
    /// Streams handed out but not yet opened in the engine, in id order.
    /// Each holds one reservation against the local stream limit.
    pending_opens: VecDeque<PendingOpen>,
    /// Local bidirectional streams opened in the engine whose state the
    /// adapter still holds.
    bound_local_bidi_streams: u64,
    /// Stream limit per direction: it caps local opens, and the peer's open
    /// and unsettled streams.
    max_streams: u64,
    /// Each stream's receive budget: its receive window.
    stream_window: usize,
    /// Total application bytes queued but not yet accepted by the engine:
    /// always the sum of every queue's `pending`, so subtracting a queue's
    /// share cannot underflow.
    pending_write_bytes: usize,
    /// How much may queue per stream and per connection.
    caps: SendCaps,
    /// Streams whose last write was Full and that want a `StreamWritable`.
    writable_armed: BTreeSet<u64>,
    /// Streams that spent their receive budget with input still waiting in
    /// the engine. The engine raises `Readable` only when data arrives, so
    /// `ack_stream` rescans these.
    gated: BTreeSet<u64>,
    /// Scratch for one scan's chunks before they are copied out.
    read_chunks: Vec<Bytes>,
    /// The engine's next timeout, cached after every service.
    timeout: Option<Instant>,
    /// The last service stopped with work left: output the socket pushed
    /// back on, or engine passes still producing events.
    unfinished: bool,
    /// Diagnostic hooks; empty unless the `diagnostics` feature is on.
    counters: ConnectionCounters,
    /// Set for connections to a WebTransport-serving socket: what an `h3`
    /// handshake needs to authenticate.
    webtransport: Option<Arc<WebTransportContext>>,
    /// The WebTransport session, once the handshake negotiated `h3`.
    wt: Option<WtSession>,
    /// How long an `h3` connection may take to authenticate.
    wt_handshake_timeout: Duration,
    /// When an `h3` connection that has not authenticated yet is closed.
    wt_deadline: Option<Instant>,
    /// In a WebTransport session's Closing phase: when QUIC closes with
    /// `H3_NO_ERROR` at the latest, if the peer has not ended its CONNECT
    /// stream before.
    wt_close_at: Option<Instant>,
    /// Whether the Closing phase may end before `wt_close_at`, once the
    /// session's end is delivered: not when we closed the session.
    wt_close_early: bool,
}

/// The engine's id for a raw stream id the adapter tracks.
fn engine_stream(raw: u64) -> quinn_proto::StreamId {
    VarInt::from_u64(raw)
        .expect("tracked stream ids come from the engine or follow its sequence")
        .into()
}

impl QuicConnection {
    pub(crate) fn new(
        id: ConnectionId,
        handle: ConnectionHandle,
        conn: quinn_proto::Connection,
        endpoint: ConnectionEndpoint,
        limits: &crate::QuicLimits,
        counters: ConnectionCounters,
        webtransport: Option<Arc<WebTransportContext>>,
    ) -> Self {
        let next_local_bidi_stream_id = u64::from(conn.side().is_server());
        Self {
            id,
            handle,
            conn,
            endpoint,
            state: ConnectionState::Connecting,
            surfaces_streams: false,
            close_reason: None,
            stream_states: HashMap::new(),
            send_queues: HashMap::new(),
            send_order: VecDeque::new(),
            next_local_bidi_stream_id,
            pending_opens: VecDeque::new(),
            bound_local_bidi_streams: 0,
            max_streams: limits.max_streams_per_connection,
            stream_window: limits.stream_receive_window,
            pending_write_bytes: 0,
            caps: SendCaps::new(
                limits.max_pending_bytes_per_stream,
                limits.max_pending_connection_bytes,
                limits.control_stream_reserve_bytes,
            ),
            writable_armed: BTreeSet::new(),
            gated: BTreeSet::new(),
            read_chunks: Vec::new(),
            timeout: None,
            unfinished: false,
            counters,
            webtransport,
            wt: None,
            wt_handshake_timeout: Duration::from_millis(limits.webtransport_handshake_timeout_ms),
            wt_deadline: None,
            wt_close_at: None,
            wt_close_early: false,
        }
    }

    pub(crate) fn endpoint(&self) -> &ConnectionEndpoint {
        &self.endpoint
    }

    pub(crate) fn is_server(&self) -> bool {
        self.conn.side().is_server()
    }

    /// Every stream holding delivered bytes not yet acknowledged, with how
    /// many: what the transport keeps counting once the connection is gone.
    pub(crate) fn unsettled_streams(&self) -> impl Iterator<Item = (StreamId, usize)> + '_ {
        self.stream_states
            .iter()
            .map(|(&raw, state)| (StreamId::new(raw), state.unacked))
    }

    /// Why the connection ended, for its `Closed`.
    pub(crate) fn close_reason(&self) -> ConnectionCloseReason {
        // Every cause records itself; a connection drained without one was
        // ended on our side.
        self.close_reason
            .clone()
            .unwrap_or(ConnectionCloseReason::Local)
    }

    /// Whether the engine is done with this connection, which the transport
    /// then removes and reports `Closed`.
    pub(crate) fn is_drained(&self) -> bool {
        self.conn.is_drained()
    }

    /// The engine's handle for this connection.
    pub(crate) fn handle(&self) -> ConnectionHandle {
        self.handle
    }

    /// Runs a closed connection's close period out at once, so the engine
    /// drains it without waiting.
    pub(crate) fn expire(&mut self) {
        // Closing stops every other timer, so the one left is the close.
        if let Some(close) = self.conn.poll_timeout() {
            self.conn.handle_timeout(close);
        }
    }

    /// Whether a close has begun, ending every write side.
    pub(crate) fn is_closing(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Closed
        )
    }

    /// The engine's next timeout, as of the last service.
    pub(crate) fn timeout(&self) -> Option<Instant> {
        self.timeout
    }

    /// Whether the last service left work that needs another without any
    /// packet or timer to prompt it.
    pub(crate) fn is_unfinished(&self) -> bool {
        self.unfinished
    }

    /// Feeds a datagram (or new connection ids) the endpoint routed here.
    pub(crate) fn handle_event(&mut self, event: quinn_proto::ConnectionEvent) {
        self.counters.datagram_received();
        self.conn.handle_event(event);
    }

    /// This connection's diagnostic counters so far.
    #[cfg(feature = "diagnostics")]
    pub(crate) fn diagnostics(&self) -> crate::ConnectionDiagnostics {
        self.counters.snapshot(&self.conn.stats())
    }

    #[cfg(test)]
    pub(crate) fn pending_write_bytes(&self) -> usize {
        self.pending_write_bytes
    }

    #[cfg(test)]
    pub(crate) fn writable_armed_count(&self) -> usize {
        self.writable_armed.len()
    }

    #[cfg(test)]
    pub(crate) fn queued_stream_count(&self) -> usize {
        self.send_queues.len()
    }

    /// Local stream slots in use: opened streams still held plus pending
    /// opens.
    #[cfg(test)]
    pub(crate) fn local_slots_used(&self) -> u64 {
        self.bound_local_bidi_streams + self.pending_opens.len() as u64
    }

    #[cfg(test)]
    pub(crate) fn is_gated(&self, stream_id: StreamId) -> bool {
        self.gated.contains(&stream_id.as_u64())
    }

    #[cfg(test)]
    pub(crate) fn engine(&mut self) -> &mut quinn_proto::Connection {
        &mut self.conn
    }

    /// Runs the engine: due timers, application events, queued writes and
    /// pending opens, endpoint events, then output. Returns the first hard
    /// socket error the output hit, whose datagram was dropped as lost.
    pub(crate) fn service(&mut self, now: Instant, cx: &mut Cx<'_>) -> Option<io::Error> {
        self.unfinished = true;
        if self.is_closing() {
            self.wt_deadline = None;
        } else if self.wt_deadline.is_some_and(|deadline| deadline <= now) {
            self.close_reason
                .get_or_insert(ConnectionCloseReason::TimedOut);
            self.close_with(
                now,
                minip2p_webtransport::h3::code::H3_EXCESSIVE_LOAD,
                "the WebTransport handshake timed out".into(),
            );
        }
        for _ in 0..MAX_SERVICE_PASSES {
            if self
                .conn
                .poll_timeout()
                .is_some_and(|timeout| timeout <= now)
            {
                self.conn.handle_timeout(now);
            }
            let mut progressed = false;
            while let Some(event) = self.conn.poll() {
                progressed = true;
                self.on_event(event, now, cx);
            }
            if let Some(wt) = self.wt.as_mut() {
                wt.open_control(&mut self.conn);
                wt.flush(&mut self.conn);
                self.after_wt(now, cx.events);
                self.finish_wt_closing(now);
            }
            self.bind_pending_opens(now);
            self.drain_send_queues(now, cx.events);
            // Endpoint events (new connection ids, retirements, the final
            // `Drained`) go out before the transmit below, so their output
            // leaves in this service.
            while let Some(event) = self.conn.poll_endpoint_events() {
                progressed = true;
                if let Some(event) = cx.endpoint.handle_event(self.handle, event) {
                    self.conn.handle_event(event);
                }
            }
            if !progressed {
                self.unfinished = false;
                break;
            }
        }
        let failure = self.transmit(now, cx);
        // The engine's timer, or an earlier WebTransport one.
        self.timeout = [self.conn.poll_timeout(), self.wt_deadline, self.wt_close_at]
            .into_iter()
            .flatten()
            .min();
        self.gc_closed_streams();
        failure
    }

    /// Sends the engine's output until it has none, the socket pushes back,
    /// or the retry queue has no room left for another datagram.
    fn transmit(&mut self, now: Instant, cx: &mut Cx<'_>) -> Option<io::Error> {
        self.counters.flush();
        loop {
            // Recomputed for every transmit: retained datagrams shrink it.
            let allowance = cx
                .sockets
                .for_addr(self.conn.remote_address())
                .map_or(0, |socket| socket.allowance());
            if allowance == 0 {
                self.unfinished = true;
                break;
            }
            cx.send_buf.clear();
            let Some(transmit) = self.conn.poll_transmit(now, allowance, cx.send_buf) else {
                break;
            };
            let (Some(contents), Some(socket)) = (
                cx.send_buf.get(..transmit.size),
                cx.sockets.for_addr(transmit.destination),
            ) else {
                // No socket of that family: lost, like any unroutable packet.
                continue;
            };
            match socket.send(&transmit, contents) {
                Ok(true) => {}
                Ok(false) => {
                    self.unfinished = true;
                    break;
                }
                // Stop rather than hammer a dead route within one service.
                Err(error) => return Some(error),
            }
        }
        None
    }

    fn on_event(&mut self, event: Event, now: Instant, cx: &mut Cx<'_>) {
        match event {
            Event::Connected => self.on_connected(now, cx),
            Event::ConnectionLost { reason } => self.on_lost(&reason),
            Event::Stream(StreamEvent::Opened { dir }) => self.accept_streams(dir, now, cx.events),
            Event::Stream(StreamEvent::Readable { id }) => {
                let raw = u64::from(id);
                match self.wt.as_mut().filter(|wt| wt.owns(raw)) {
                    Some(wt) => {
                        wt.on_readable(&mut self.conn, raw);
                        self.after_wt(now, cx.events);
                    }
                    None => self.scan(raw, cx.events),
                }
            }
            // New credit: the scheduler that runs after these events hands
            // it out in turn, rather than to the stream it names.
            Event::Stream(StreamEvent::Writable { .. }) => {}
            Event::Stream(StreamEvent::Finished { id }) => {
                if let Some(wt) = self.wt.as_mut() {
                    wt.on_send_done(u64::from(id));
                }
            }
            Event::Stream(StreamEvent::Stopped { id, error_code }) => {
                let raw = u64::from(id);
                if let Some(wt) = self.wt.as_mut()
                    && wt.on_stopped(&mut self.conn, raw, error_code)
                {
                    self.after_wt(now, cx.events);
                } else if self.surfaces_streams {
                    self.on_stopped(raw, error_code, cx.events);
                }
            }
            Event::Stream(StreamEvent::Available { dir: Dir::Bi }) => {
                self.bind_pending_opens(now);
            }
            // Only WebTransport-serving sockets advertise DATAGRAM, and
            // datagrams are not served there: drained and dropped.
            Event::DatagramReceived => while self.conn.datagrams().recv().is_some() {},
            // Local unidirectional streams are never opened, and half-close
            // is the adapter's own bookkeeping.
            Event::Stream(_) | Event::HandshakeDataReady | Event::DatagramsUnblocked => {}
        }
    }

    /// The ALPN protocol the handshake negotiated.
    fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.conn
            .crypto_session()
            .handshake_data()?
            .downcast::<HandshakeData>()
            .ok()?
            .protocol
    }

    /// The handshake completed. A `libp2p` connection must have verified
    /// the peer's certificate inside TLS (client certificates are optional
    /// on WebTransport-serving sockets): record who it is and the token both
    /// ends derive, then report the connection and the peer streams that
    /// waited for it. An `h3` connection starts its WebTransport session,
    /// which reports it once Noise authenticates the client. Anything else
    /// fails before `Connected`.
    fn on_connected(&mut self, now: Instant, cx: &mut Cx<'_>) {
        if self.negotiated_alpn().as_deref() == Some(crate::tls::H3_ALPN) {
            let Some(context) = self.webtransport.clone() else {
                self.fail_connection(
                    now,
                    "h3 on a socket that does not serve WebTransport".into(),
                );
                return;
            };
            // A browser's address: never a hole-punching candidate.
            let mut transport = self.endpoint.transport().clone();
            transport.push(Protocol::WebTransport);
            self.endpoint = ConnectionEndpoint::new(transport);
            // The CONNECT and Noise streams are the session's own, not
            // application streams: the engine's peer bidi credit gets room
            // for both on top of `max_streams_per_connection`, which the
            // adapter goes on enforcing for application streams.
            self.reserve_wt_streams(2);
            let mut wt = WtSession::new(context);
            wt.open_control(&mut self.conn);
            self.wt = Some(wt);
            self.wt_deadline = Some(now + self.wt_handshake_timeout);
            self.accept_streams(Dir::Uni, now, cx.events);
            self.accept_streams(Dir::Bi, now, cx.events);
            return;
        }
        let identity = self.conn.crypto_session().peer_identity();
        let Some(peer_id) = crate::tls::peer_id_from_identity(identity) else {
            self.fail_connection(now, "peer identity unavailable after the handshake".into());
            return;
        };
        let mut token = [0u8; 32];
        // Left unset rather than guessed if the exporter fails, as the
        // transport contract asks.
        if self
            .conn
            .crypto_session()
            .export_keying_material(&mut token, TOKEN_LABEL, b"")
            .is_ok()
        {
            self.endpoint.set_token(ConnectionToken::new(token));
        }
        let previous = self.endpoint.peer_id().cloned();
        let changed = previous.as_ref() != Some(&peer_id);
        self.endpoint.set_peer_id(peer_id);
        self.state = ConnectionState::Connected;
        self.surfaces_streams = true;
        cx.events.push(TransportEvent::Connected {
            id: self.id,
            endpoint: self.endpoint.clone(),
        });
        if changed {
            cx.events.push(TransportEvent::PeerIdentityVerified {
                id: self.id,
                endpoint: self.endpoint.clone(),
                previous_peer_id: previous,
            });
        }
        self.accept_streams(Dir::Bi, now, cx.events);
        self.accept_streams(Dir::Uni, now, cx.events);
    }

    /// Acts on what the WebTransport session reported: the authenticated
    /// connection, streams to surface, or a failure.
    fn after_wt(&mut self, now: Instant, events: &mut Vec<TransportEvent>) {
        let Some(wt) = self.wt.as_mut() else {
            return;
        };
        for event in wt.take_events() {
            match event {
                WtEvent::Established { peer, token } => {
                    if self.is_closing() {
                        continue;
                    }
                    self.wt_deadline = None;
                    // Only the CONNECT stream stays the session's.
                    self.reserve_wt_streams(1);
                    self.endpoint.set_peer_id(peer);
                    self.endpoint.set_token(ConnectionToken::new(token));
                    self.state = ConnectionState::Connected;
                    self.surfaces_streams = true;
                    events.push(TransportEvent::Connected {
                        id: self.id,
                        endpoint: self.endpoint.clone(),
                    });
                    events.push(TransportEvent::PeerIdentityVerified {
                        id: self.id,
                        endpoint: self.endpoint.clone(),
                        previous_peer_id: None,
                    });
                }
                WtEvent::Admit {
                    raw,
                    early,
                    end,
                    stopped,
                } => {
                    if !self.surfaces_streams {
                        self.refuse_stream(engine_stream(raw));
                    } else if self.admit_remote_stream(raw, events) {
                        // A stop the session took while it held the stream.
                        if let Some(error_code) = stopped {
                            self.on_stopped(raw, error_code, events);
                        }
                        self.deliver_early(raw, early, end, events);
                    }
                }
                WtEvent::Fail { code, reason } => {
                    if !self.is_closing() {
                        self.close_with(now, code, reason);
                    }
                }
                WtEvent::PeerClosed { code } => {
                    if let Some(wt) = self.wt.as_mut() {
                        wt.finish_connect(&mut self.conn);
                    }
                    if !self.is_closing() {
                        self.enter_wt_closing(
                            now,
                            ConnectionCloseReason::Remote {
                                code: u64::from(code),
                            },
                        );
                    }
                }
                WtEvent::Refused { reason } => {
                    if !self.is_closing() {
                        self.enter_wt_closing(now, ConnectionCloseReason::Error(reason));
                    }
                }
            }
        }
    }

    /// Sets the engine's peer bidi stream credit to the application limit
    /// plus `internal` streams the WebTransport session uses itself.
    fn reserve_wt_streams(&mut self, internal: u64) {
        let count =
            VarInt::from_u64(self.max_streams.saturating_add(internal)).unwrap_or(VarInt::MAX);
        self.conn.set_max_concurrent_streams(Dir::Bi, count);
    }

    /// The engine lost the connection; `Closed` follows once it drains,
    /// carrying the loss as its reason unless an earlier cause was recorded.
    fn on_lost(&mut self, reason: &ConnectionError) {
        let reason = match reason {
            ConnectionError::LocallyClosed => ConnectionCloseReason::Local,
            // HTTP/3's orderly close is minip2p's 0.
            ConnectionError::ApplicationClosed(close)
                if self.wt.is_some() && close.error_code.into_inner() == code::H3_NO_ERROR =>
            {
                ConnectionCloseReason::Remote { code: 0 }
            }
            ConnectionError::ApplicationClosed(close) => ConnectionCloseReason::Remote {
                code: close.error_code.into_inner(),
            },
            ConnectionError::ConnectionClosed(close) => ConnectionCloseReason::Remote {
                code: u64::from(close.error_code),
            },
            ConnectionError::TimedOut => ConnectionCloseReason::TimedOut,
            other => ConnectionCloseReason::Error(other.to_string()),
        };
        self.close_reason.get_or_insert(reason);
        self.end_writes();
        self.wt_close_at = None;
        self.state = ConnectionState::Closed;
    }

    /// Accepts every stream the peer opened in `dir`.
    ///
    /// Before the handshake completes none is accepted: they wait in the
    /// engine for `on_connected`, and go with the connection if it never
    /// authenticates. Bidirectional streams of a connection that surfaces
    /// streams are admitted and scanned at once (a new stream's first frame
    /// raises only `Opened`, never `Readable`). Every other stream is
    /// refused: libp2p uses no unidirectional streams, and a closing
    /// connection takes no new ones.
    ///
    /// On an `h3` connection the WebTransport session takes every stream
    /// until the connection closes: it reads HTTP/3's own streams and hands
    /// back prefixed streams to admit.
    fn accept_streams(&mut self, dir: Dir, now: Instant, events: &mut Vec<TransportEvent>) {
        if self.state == ConnectionState::Connecting && self.wt.is_none() {
            return;
        }
        while let Some(stream) = self.conn.streams().accept(dir) {
            let raw = u64::from(stream);
            let closing = self.is_closing();
            if let Some(wt) = self.wt.as_mut().filter(|_| !closing) {
                wt.on_opened(&mut self.conn, stream);
                self.after_wt(now, events);
            } else if dir == Dir::Bi && self.surfaces_streams {
                if self.admit_remote_stream(raw, events) {
                    self.scan(raw, events);
                }
            } else {
                self.refuse_stream(stream);
            }
        }
    }

    /// Refuses a peer-initiated stream with STOP_SENDING, adding
    /// RESET_STREAM only for a bidirectional one: a peer's unidirectional
    /// stream has no local send half, and quinn-proto asserts on resetting
    /// one, which would let a peer panic the transport.
    fn refuse_stream(&mut self, stream: quinn_proto::StreamId) {
        let code = self.stream_code();
        match self.conn.recv_stream(stream).stop(code) {
            Ok(()) | Err(_) => {}
        }
        if stream.dir() == Dir::Bi {
            match self.conn.send_stream(stream).reset(code) {
                Ok(()) | Err(_) => {}
            }
        }
    }

    /// Emits `IncomingStream` for a new peer stream, or refuses it (both
    /// halves shut down, no event) while open and unsettled peer streams fill
    /// the stream limit: the engine frees a closed stream's slot once it is
    /// read, but its delivered bytes are the reader's until acknowledged
    /// (ADR 0012).
    fn admit_remote_stream(&mut self, raw: u64, events: &mut Vec<TransportEvent>) -> bool {
        let held = self
            .stream_states
            .keys()
            .filter(|id| !self.is_local(**id))
            .count() as u64;
        if held >= self.max_streams {
            self.refuse_stream(engine_stream(raw));
            return false;
        }
        self.stream_states
            .insert(raw, StreamRuntimeState::default());
        events.push(TransportEvent::IncomingStream {
            id: self.id,
            stream_id: StreamId::new(raw),
        });
        true
    }

    /// Reads a stream until it is exhausted or has delivered its receive
    /// budget, then emits the copied data followed by any FIN or reset.
    ///
    /// The budget is the read gate: the engine returns credit as bytes are
    /// read, so a stream whose reader has not acknowledged a whole window is
    /// not read again until it does ([`Self::ack_stream`]). The engine then
    /// buffers at most one more window, since the windows are fixed.
    fn scan(&mut self, raw: u64, events: &mut Vec<TransportEvent>) {
        if !self.surfaces_streams {
            return;
        }
        // Nothing follows a stream's StreamClosed.
        let Some(room) = self
            .stream_states
            .get(&raw)
            .filter(|state| !state.closed_notified)
            .map(|state| state.receive_room(self.stream_window))
        else {
            return;
        };
        let stream = engine_stream(raw);
        // The engine delivers `Opened` ahead of queued stream events, so a
        // scan can meet a reset before the `Stopped` for the same stream.
        if let Ok(Some(error_code)) = self.conn.send_stream(stream).stopped() {
            self.on_stopped(raw, error_code, events);
            if self
                .stream_states
                .get(&raw)
                .is_none_or(|state| state.closed_notified)
            {
                return;
            }
        }

        let mut room = room;
        if let Some(state) = self.stream_states.get_mut(&raw)
            && let Some((mut held, end)) = state.held.take()
        {
            let take = room.min(held.len());
            room -= take;
            if take > 0 {
                // A partial take is copied out, so it never pins the rest.
                let data = if take == held.len() {
                    Bytes::from(mem::take(&mut held))
                } else {
                    let data = Bytes::copy_from_slice(held.get(..take).unwrap_or_default());
                    held.drain(..take);
                    data
                };
                state.unacked += take;
                events.push(TransportEvent::StreamData {
                    id: self.id,
                    stream_id: StreamId::new(raw),
                    data,
                });
            }
            if !held.is_empty() {
                state.held = Some((held, end));
                self.gated.insert(raw);
                return;
            }
            let end = match end {
                ReadEnd::Open => None,
                ReadEnd::Finished => Some(ScanEnd::Finished),
                ReadEnd::Reset => Some(ScanEnd::Reset),
            };
            if let Some(end) = end {
                // The engine's side of the stream ended while it was held.
                self.gated.remove(&raw);
                self.on_scan_end(raw, end, events);
                return;
            }
        }

        let (read, end) = {
            let mut recv = self.conn.recv_stream(stream);
            let Ok(mut chunks) = recv.read(true) else {
                return;
            };
            let mut read = 0;
            let end = loop {
                if room == 0 {
                    // One terminal probe: a FIN or reset right behind the
                    // window still surfaces, and data waiting keeps the
                    // stream gated. Nothing is read.
                    break match chunks.next(0) {
                        Ok(Some(_)) | Err(ReadError::Blocked) => ScanEnd::Gated,
                        Ok(None) => ScanEnd::Finished,
                        Err(ReadError::Reset(_)) => ScanEnd::Reset,
                    };
                }
                match chunks.next(room) {
                    Ok(Some(chunk)) => {
                        room -= chunk.bytes.len();
                        read += chunk.bytes.len();
                        self.read_chunks.push(chunk.bytes);
                    }
                    Ok(None) => break ScanEnd::Finished,
                    Err(ReadError::Reset(_)) => break ScanEnd::Reset,
                    Err(ReadError::Blocked) => break ScanEnd::Waiting,
                }
            };
            // Credit for what was read goes out with the service that
            // follows every scan.
            let _credit_follows = chunks.finalize();
            (read, end)
        };

        if matches!(end, ScanEnd::Gated) {
            self.gated.insert(raw);
        } else {
            self.gated.remove(&raw);
        }
        if read > 0 {
            if let Some(state) = self.stream_states.get_mut(&raw) {
                state.unacked += read;
            }
            events.push(TransportEvent::StreamData {
                id: self.id,
                stream_id: StreamId::new(raw),
                data: copy_chunks(&mut self.read_chunks, read),
            });
        }
        self.on_scan_end(raw, end, events);
    }

    /// Delivers what a WebTransport stream carried while it was held, then
    /// whatever the engine has behind it, through the read gate like any
    /// read: past the receive room, the rest waits for acknowledgements.
    fn deliver_early(
        &mut self,
        raw: u64,
        early: Vec<u8>,
        end: ReadEnd,
        events: &mut Vec<TransportEvent>,
    ) {
        if let Some(state) = self.stream_states.get_mut(&raw) {
            state.held = Some((early, end));
        }
        self.scan(raw, events);
    }

    /// Acts on how a read of a surfaced stream ended: FIN, reset, or not
    /// yet.
    fn on_scan_end(&mut self, raw: u64, end: ScanEnd, events: &mut Vec<TransportEvent>) {
        let stream = engine_stream(raw);
        match end {
            ScanEnd::Waiting | ScanEnd::Gated => {}
            ScanEnd::Finished => {
                if let Some(state) = self.stream_states.get_mut(&raw) {
                    state.remote_write_closed = true;
                }
                events.push(TransportEvent::StreamRemoteWriteClosed {
                    id: self.id,
                    stream_id: StreamId::new(raw),
                });
                self.note_stream_closed_if_finished(raw, events);
            }
            ScanEnd::Reset => {
                // Reading the reset frees only the receive half; the peer's
                // stream credit needs the send half freed too.
                let code = self.stream_code();
                match self.conn.send_stream(stream).reset(code) {
                    Ok(()) | Err(_) => {}
                }
                self.note_stream_reset(raw, events);
            }
        }
    }

    /// The peer sent STOP_SENDING. The engine only records it, so reset the
    /// send half here, which discards buffered sends and sends RESET_STREAM;
    /// then report the stop.
    ///
    /// On a WebTransport connection a code in the WebTransport range is
    /// reported as the WebTransport code it carries; any other passes
    /// through unchanged.
    fn on_stopped(&mut self, raw: u64, error_code: VarInt, events: &mut Vec<TransportEvent>) {
        match self.conn.send_stream(engine_stream(raw)).reset(error_code) {
            Ok(()) | Err(_) => {}
        }
        let mut code = error_code.into_inner();
        if self.wt.is_some() {
            code = h3_code_to_webtransport(code).map_or(code, u64::from);
        }
        self.note_write_stopped(raw, code, events);
    }

    /// The wire code for minip2p's stream reset and stop code 0: plain 0 on
    /// libp2p QUIC, WebTransport application error 0 on WebTransport.
    fn stream_code(&self) -> VarInt {
        if self.wt.is_some() {
            VarInt::from_u64(webtransport_code_to_h3(0)).unwrap_or(VarInt::from_u32(0))
        } else {
            VarInt::from_u32(0)
        }
    }

    /// Opens pending streams in the engine, in order, as peer credit allows.
    fn bind_pending_opens(&mut self, now: Instant) {
        // A closing connection opens nothing more.
        while !self.pending_opens.is_empty() && !self.is_closing() {
            // A WebTransport session may also wait on the client's credit.
            if self.wt.as_ref().is_some_and(|wt| !wt.may_open_stream()) {
                return;
            }
            let Some(stream) = self.conn.streams().open(Dir::Bi) else {
                return;
            };
            if let Some(wt) = self.wt.as_mut() {
                wt.note_opened();
            }
            let Some(open) = self.pending_opens.pop_front() else {
                return;
            };
            let raw = u64::from(stream);
            if raw != open.id {
                // The adapter is the only opener, so ids follow its sequence.
                self.fail_connection(
                    now,
                    format!("engine opened stream {raw} where {} was expected", open.id),
                );
                return;
            }
            if open.reset_on_bind {
                self.reset_on_wire(raw);
            } else {
                self.bound_local_bidi_streams += 1;
            }
        }
    }

    /// The first local stream id the engine has not opened yet.
    fn first_unbound(&self) -> u64 {
        self.pending_opens
            .front()
            .map_or(self.next_local_bidi_stream_id, |open| open.id)
    }

    /// Whether `raw` is a local stream still waiting for peer credit.
    fn is_unbound(&self, raw: u64) -> bool {
        self.is_local(raw) && raw >= self.first_unbound()
    }

    /// Hands out a new local stream.
    pub(crate) fn open_stream(&mut self) -> Result<StreamId, TransportError> {
        if self.state != ConnectionState::Connected {
            return Err(TransportError::InvalidState {
                id: self.id,
                state: self.state,
                expected: ConnectionState::Connected,
            });
        }
        if self.bound_local_bidi_streams + self.pending_opens.len() as u64 >= self.max_streams {
            return Err(TransportError::ResourceExhausted {
                resource: "local QUIC bidirectional streams",
            });
        }
        // Handed out now, opened in the engine by the next service once the
        // peer grants credit; writes and FIN queue until then.
        let raw = self.next_local_bidi_stream_id;
        self.next_local_bidi_stream_id += 4;
        self.stream_states
            .insert(raw, StreamRuntimeState::default());
        self.pending_opens.push_back(PendingOpen {
            id: raw,
            reset_on_bind: false,
        });
        if let Some(session_id) = self.wt.as_ref().and_then(WtSession::session_id) {
            let mut prefix = Vec::new();
            minip2p_webtransport::h3::encode_webtransport_bidi_header(session_id, &mut prefix)
                .map_err(|_too_large| TransportError::InvalidState {
                    id: self.id,
                    state: self.state,
                    expected: ConnectionState::Connected,
                })?;
            self.queue_mut(raw)
                .writes
                .push_back(PendingStreamWrite::prefix(prefix));
        }
        Ok(StreamId::new(raw))
    }

    /// Accepts as much of `data` as the engine takes now plus what fits the
    /// stream's and the connection's queues, whatever the peer's credit
    /// (ADR 0012).
    ///
    /// Returns [`TransportError::Full`] with the exact unsent suffix when the
    /// queues cannot hold the rest, and arms a `StreamWritable` that fires
    /// once the stream can queue half the smaller cap again.
    pub(crate) fn send_stream(
        &mut self,
        stream_id: StreamId,
        data: Bytes,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), TransportError> {
        if data.is_empty() {
            return Ok(());
        }
        let raw = stream_id.as_u64();
        let closing = self.is_closing();
        let state = self.stream_state_mut(stream_id)?;
        if closing || state.local_write_closed {
            return Err(TransportError::StreamSendFailed {
                id: self.id,
                stream_id,
                reason: if closing {
                    "connection is closing".into()
                } else {
                    "local stream write side is already closed".into()
                },
            });
        }
        let control = state.control;

        // While any stream has bytes queued, this write takes its turn in the
        // scheduler behind them, which also keeps the stream's own bytes in
        // order; a stream not opened yet queues it all.
        let direct = if !self.send_queues.is_empty() || self.is_unbound(raw) {
            0
        } else {
            // `write` copies only what the engine accepts: handing it a slice
            // would pin the caller's whole allocation behind a small prefix.
            // A WebTransport session's credit may cap it further.
            let room = self.wt.as_ref().map_or(usize::MAX, WtSession::data_room);
            let offer = data.get(..room).unwrap_or(&data);
            match self.conn.send_stream(engine_stream(raw)).write(offer) {
                Ok(written) => {
                    if let Some(wt) = self.wt.as_mut() {
                        wt.note_sent(written);
                    }
                    written
                }
                Err(WriteError::Blocked) => 0,
                Err(WriteError::Stopped(error_code)) => {
                    self.on_stopped(raw, error_code, events);
                    return Err(TransportError::StreamSendFailed {
                        id: self.id,
                        stream_id,
                        reason: format!("stream stopped by peer: code {error_code}"),
                    });
                }
                Err(WriteError::ClosedStream) => {
                    return Err(TransportError::StreamSendFailed {
                        id: self.id,
                        stream_id,
                        reason: "stream is closed".into(),
                    });
                }
            }
        };

        let queued = (data.len() - direct).min(self.send_room(raw, control));
        let accepted = direct + queued;
        if queued != 0 {
            self.pending_write_bytes += queued;
            let queue = self.queue_mut(raw);
            queue.pending += queued;
            queue.writes.push_back(PendingStreamWrite::data(
                data.slice(direct..accepted),
                data.len(),
            ));
        }
        if accepted < data.len() {
            self.writable_armed.insert(raw);
            return Err(TransportError::Full {
                id: self.id,
                stream_id,
                unsent: data.slice(accepted..),
            });
        }
        Ok(())
    }

    /// Bytes stream `raw` may still queue: the smaller of what is left of
    /// its own cap and of the connection cap it may fill.
    fn send_room(&self, raw: u64, control: bool) -> usize {
        let stream_pending = self.send_queues.get(&raw).map_or(0, |queue| queue.pending);
        self.caps
            .room(stream_pending, self.pending_write_bytes, control)
    }

    /// The stream's queue, created at the back of the round-robin order.
    fn queue_mut(&mut self, raw: u64) -> &mut SendQueue {
        let order = &mut self.send_order;
        self.send_queues.entry(raw).or_insert_with(|| {
            order.push_back(raw);
            SendQueue::default()
        })
    }

    /// Marks a stream as a control stream, which may queue into the
    /// connection cap's reserve, or back as an application stream.
    pub(crate) fn set_control_stream(
        &mut self,
        stream_id: StreamId,
        control: bool,
        events: &mut Vec<TransportEvent>,
    ) {
        if let Some(state) = self.stream_states.get_mut(&stream_id.as_u64()) {
            state.control = control;
            // A control stream may have room an application one lacked.
            self.wake_writable(events);
        }
    }

    /// Queues the stream's FIN behind its queued writes.
    pub(crate) fn close_stream_write(&mut self, stream_id: StreamId) -> Result<(), TransportError> {
        let state = self.stream_state_mut(stream_id)?;
        if state.local_write_closed {
            return Err(TransportError::StreamCloseWriteFailed {
                id: self.id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        }
        state.local_write_closed = true;
        self.writable_armed.remove(&stream_id.as_u64());
        self.queue_mut(stream_id.as_u64())
            .writes
            .push_back(PendingStreamWrite::fin());
        Ok(())
    }

    /// Acknowledges `bytes` of the stream's delivered data (ADR 0012).
    ///
    /// The engine returned their credit when they were read, so what this
    /// releases is the read gate: a stream that had spent its budget is
    /// rescanned at once, with no packet and no event. A settled or unknown
    /// stream has nothing to acknowledge.
    pub(crate) fn ack_stream(
        &mut self,
        stream_id: StreamId,
        bytes: usize,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), TransportError> {
        let raw = stream_id.as_u64();
        let Some(state) = self.stream_states.get_mut(&raw) else {
            return Ok(());
        };
        if bytes > state.unacked {
            return Err(TransportError::AckExceedsDelivered {
                id: self.id,
                stream_id,
                acked: bytes,
                unacked: state.unacked,
            });
        }
        state.unacked -= bytes;
        if bytes != 0 && self.gated.contains(&raw) {
            self.scan(raw, events);
        }
        Ok(())
    }

    /// Resets a stream, abandoning its unacknowledged bytes: it settles at
    /// once.
    pub(crate) fn reset_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), TransportError> {
        let raw = stream_id.as_u64();
        self.stream_state_mut(stream_id)?;
        self.drop_send_queue(raw);
        self.writable_armed.remove(&raw);
        self.gated.remove(&raw);
        // The freed queue may unblock streams waiting on the shared cap.
        self.wake_writable(events);

        if self.is_unbound(raw) {
            // Not on the wire yet: done for the caller now, and reset in the
            // engine when it opens, so the id sequence never diverges.
            if let Some(open) = self.pending_opens.iter_mut().find(|open| open.id == raw) {
                open.reset_on_bind = true;
            }
            if let Some(state) = self.stream_states.remove(&raw)
                && !state.closed_notified
            {
                events.push(TransportEvent::StreamClosed {
                    id: self.id,
                    stream_id,
                });
            }
            return Ok(());
        }

        // A closed half is already done.
        self.reset_on_wire(raw);

        let state = self.stream_state_mut(stream_id)?;
        state.local_write_closed = true;
        state.remote_write_closed = true;
        state.unacked = 0;
        if !state.closed_notified {
            state.closed_notified = true;
            events.push(TransportEvent::StreamClosed {
                id: self.id,
                stream_id,
            });
        }
        Ok(())
    }

    /// Starts an orderly close; `Closed` follows once the engine drains.
    ///
    /// An accepted WebTransport session first enters its Closing phase: it
    /// sends the close capsule and FIN on the CONNECT stream, and QUIC
    /// closes once the phase's deadline passes.
    pub(crate) fn close(&mut self, now: Instant) {
        if self.is_closing() {
            return;
        }
        let code = match self.wt.as_mut().map(|wt| wt.close(&mut self.conn, 0)) {
            Some(true) => {
                self.enter_wt_closing(now, ConnectionCloseReason::Local);
                return;
            }
            Some(false) => code::H3_NO_ERROR,
            None => 0,
        };
        self.conn.close(
            now,
            VarInt::from_u64(code).unwrap_or(VarInt::from_u32(0)),
            Bytes::from_static(b"bye"),
        );
        self.close_reason
            .get_or_insert(ConnectionCloseReason::Local);
        self.state = ConnectionState::Closing;
        self.surfaces_streams = false;
        self.end_writes();
    }

    /// Starts a WebTransport session's Closing phase: no more stream events,
    /// every open stream reset, and a deadline for the peer to end its
    /// CONNECT stream. [`Self::finish_wt_closing`] closes QUIC.
    fn enter_wt_closing(&mut self, now: Instant, reason: ConnectionCloseReason) {
        self.state = ConnectionState::Closing;
        self.surfaces_streams = false;
        self.end_writes();
        let first_unbound = self.first_unbound();
        let bound: Vec<u64> = self
            .stream_states
            .keys()
            .copied()
            .filter(|&raw| !(self.is_local(raw) && raw >= first_unbound))
            .collect();
        for raw in bound {
            self.reset_on_wire(raw);
        }
        let wait = (self.conn.rtt() * 3).clamp(WT_CLOSE_MIN, WT_CLOSE_MAX);
        self.wt_close_early = reason != ConnectionCloseReason::Local;
        self.close_reason.get_or_insert(reason);
        self.wt_close_at = Some(now + wait);
        self.finish_wt_closing(now);
    }

    /// Ends the Closing phase once the deadline passed, or sooner for a
    /// session the peer ended, once it ended its CONNECT stream and
    /// acknowledged ours: QUIC closes with `H3_NO_ERROR`. Closing before
    /// that would discard our FIN and resets, which the engine drops with a
    /// close.
    ///
    /// A session we closed always waits out the deadline: Chrome ends its
    /// CONNECT stream and acknowledges ours in its network stack, before the
    /// page's `closed` settles, and a QUIC close in that window rejects
    /// `closed` with "Connection lost" instead of fulfilling it.
    fn finish_wt_closing(&mut self, now: Instant) {
        let Some(at) = self.wt_close_at else {
            return;
        };
        let delivered =
            self.wt_close_early && self.wt.as_ref().is_some_and(WtSession::ended_and_delivered);
        if now < at && !delivered {
            return;
        }
        self.wt_close_at = None;
        self.conn.close(
            now,
            VarInt::from_u64(code::H3_NO_ERROR).unwrap_or(VarInt::from_u32(0)),
            Bytes::new(),
        );
    }

    /// Ends a WebTransport session's Closing phase now, for a transport that
    /// will not be polled again: QUIC closes with `H3_NO_ERROR` without
    /// waiting for the deadline. Anything else is left as it is.
    pub(crate) fn cut_wt_closing(&mut self, now: Instant) {
        if self.wt_close_at.is_some() {
            self.wt_close_at = Some(now);
            self.finish_wt_closing(now);
        }
    }

    /// Resets a stream's send half and stops its receive half with
    /// minip2p's code 0; a half already closed is left alone.
    fn reset_on_wire(&mut self, raw: u64) {
        let (stream, code) = (engine_stream(raw), self.stream_code());
        match self.conn.send_stream(stream).reset(code) {
            Ok(()) | Err(_) => {}
        }
        match self.conn.recv_stream(stream).stop(code) {
            Ok(()) | Err(_) => {}
        }
    }

    /// Every write side ends with the connection: queued writes go and no
    /// Writable fires.
    fn end_writes(&mut self) {
        self.send_queues.clear();
        self.send_order.clear();
        self.pending_write_bytes = 0;
        self.writable_armed.clear();
    }

    /// Pushes queued writes into the engine, round-robin: each stream in turn
    /// hands it up to [`SEND_QUANTUM`] bytes, and rounds repeat while any
    /// stream makes progress. The pass ends once every stream in a row has
    /// made none, so the next pass starts with the stream after the last one
    /// that did: scarce connection credit goes to each stream in turn.
    fn drain_send_queues(&mut self, now: Instant, events: &mut Vec<TransportEvent>) {
        let mut idle = 0;
        while idle < self.send_order.len() {
            let Some(raw) = self.send_order.pop_front() else {
                break;
            };
            let progressed = self.drain_stream(raw, now, events);
            if self.send_queues.contains_key(&raw) {
                self.send_order.push_back(raw);
            }
            idle = if progressed { 0 } else { idle + 1 };
        }
        self.wake_writable(events);
    }

    /// Gives one stream its turn: pushes up to [`SEND_QUANTUM`] queued bytes
    /// into the engine, then any FIN they reach. Returns whether anything
    /// went in. The caller has taken the stream out of the round-robin order
    /// and puts it back if its queue remains.
    ///
    /// Never fails the caller: a stopped stream loses only its own queue, a
    /// write still waiting on peer credit stays queued, and any other engine
    /// error closes only this connection.
    fn drain_stream(&mut self, raw: u64, now: Instant, events: &mut Vec<TransportEvent>) -> bool {
        if self.is_unbound(raw) {
            return false;
        }
        let stream = engine_stream(raw);
        let mut budget = SEND_QUANTUM;
        let mut progressed = false;
        while let Some(queue) = self.send_queues.get_mut(&raw) {
            let Some(front) = queue.writes.front_mut() else {
                break;
            };
            if front.fin {
                match self.conn.send_stream(stream).finish() {
                    Ok(()) => {}
                    Err(FinishError::Stopped(error_code)) => {
                        self.on_stopped(raw, error_code, events);
                        return progressed;
                    }
                    Err(FinishError::ClosedStream) => {
                        self.fail_connection(
                            now,
                            format!("finish failed on {}: closed stream", StreamId::new(raw)),
                        );
                        return progressed;
                    }
                }
            } else {
                // At most this turn's budget, and for caller bytes on a
                // WebTransport session its credit; the whole write when it
                // fits.
                let room = match self.wt.as_ref() {
                    Some(wt) if !front.internal => budget.min(wt.data_room()),
                    _ => budget,
                };
                let offer = front.bytes.get(..room).unwrap_or(&front.bytes);
                let len = offer.len();
                if len == 0 {
                    return progressed;
                }
                // Copies the accepted prefix, as in `send_stream`.
                match self.conn.send_stream(stream).write(offer) {
                    Ok(0) => return progressed,
                    Ok(written) => {
                        if !front.internal {
                            queue.pending -= written;
                            self.pending_write_bytes -= written;
                            if let Some(wt) = self.wt.as_mut() {
                                wt.note_sent(written);
                            }
                        }
                        front.advance(written);
                        budget -= written;
                        progressed = true;
                        if !front.bytes.is_empty() {
                            // Out of credit, or out of this turn's budget.
                            if written < len {
                                return progressed;
                            }
                            continue;
                        }
                    }
                    // Out of flow-control credit or send window: the peer's
                    // next MAX_* frame raises `Writable`, and a drain follows.
                    Err(WriteError::Blocked) => return progressed,
                    Err(WriteError::Stopped(error_code)) => {
                        self.on_stopped(raw, error_code, events);
                        return progressed;
                    }
                    Err(WriteError::ClosedStream) => {
                        self.fail_connection(
                            now,
                            format!("write failed on {}: closed stream", StreamId::new(raw)),
                        );
                        return progressed;
                    }
                }
            }
            progressed = true;
            if let Some(queue) = self.send_queues.get_mut(&raw) {
                queue.writes.pop_front();
                if queue.writes.is_empty() {
                    self.send_queues.remove(&raw);
                }
            }
            self.note_stream_closed_if_finished(raw, events);
        }
        progressed
    }

    /// Drops a stream's queued writes and their byte accounting.
    fn drop_send_queue(&mut self, raw: u64) {
        if let Some(queue) = self.send_queues.remove(&raw) {
            self.pending_write_bytes -= queue.pending;
            self.send_order.retain(|&queued| queued != raw);
        }
    }

    /// The write side ended: no Writable for it, not even one an earlier wake
    /// already queued in these events.
    fn disarm_writable(&mut self, raw: u64, events: &mut Vec<TransportEvent>) {
        self.writable_armed.remove(&raw);
        let (id, stream_id) = (self.id, StreamId::new(raw));
        events.retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
    }

    /// Emits `StreamWritable` for every armed stream that can again queue
    /// half the smaller of its stream cap and the connection cap it may fill
    /// ([`SendCaps::writable_threshold`]). The connection cap is shared, so
    /// freeing it wakes every stream it blocked.
    fn wake_writable(&mut self, events: &mut Vec<TransportEvent>) {
        if self.writable_armed.is_empty() || self.is_closing() {
            return;
        }
        for raw in mem::take(&mut self.writable_armed) {
            // A write side that ended since never gets a Writable.
            let Some(state) = self
                .stream_states
                .get(&raw)
                .filter(|state| !state.local_write_closed)
            else {
                continue;
            };
            let control = state.control;
            if self.send_room(raw, control) < self.caps.writable_threshold(control) {
                self.writable_armed.insert(raw);
                continue;
            }
            events.push(TransportEvent::StreamWritable {
                id: self.id,
                stream_id: StreamId::new(raw),
            });
        }
    }

    /// Our write half is gone for good, so queued writes are dropped. The
    /// read half stays open until the peer finishes. The event is emitted
    /// once, and never after the stream's StreamClosed; the queue is dropped
    /// either way, since a stream closed with writes still queued (FIN read,
    /// write side closed locally) would otherwise keep retrying a reset half.
    fn note_write_stopped(&mut self, raw: u64, error_code: u64, events: &mut Vec<TransportEvent>) {
        let Some(state) = self.stream_states.get_mut(&raw) else {
            return;
        };
        if state.write_stopped {
            return;
        }
        state.write_stopped = true;
        state.local_write_closed = true;
        let closed = state.closed_notified;
        self.drop_send_queue(raw);
        self.disarm_writable(raw, events);
        self.wake_writable(events);
        if closed {
            return;
        }
        events.push(TransportEvent::StreamWriteStopped {
            id: self.id,
            stream_id: StreamId::new(raw),
            error_code,
        });
        self.note_stream_closed_if_finished(raw, events);
    }

    /// Closes this connection after an error the engine did not scope to a
    /// single stream. `Closed` follows once the engine drains, with the
    /// error as its reason.
    ///
    /// Every queued write is dropped so later drains cannot hit the same
    /// error again.
    fn fail_connection(&mut self, now: Instant, message: String) {
        self.end_writes();
        self.close_reason
            .get_or_insert(ConnectionCloseReason::Error(message));
        // 1 is QUIC's INTERNAL_ERROR.
        self.conn.close(
            now,
            VarInt::from_u32(1),
            Bytes::from_static(b"stream send failed"),
        );
        self.state = ConnectionState::Closing;
        self.surfaces_streams = false;
    }

    /// Closes an `h3` connection with an HTTP/3 error code; `Closed`
    /// follows with `message` as its reason.
    fn close_with(&mut self, now: Instant, code: u64, message: String) {
        self.wt_deadline = None;
        self.end_writes();
        let code = VarInt::from_u64(code).unwrap_or(VarInt::from_u32(1));
        self.conn
            .close(now, code, Bytes::from(message.clone().into_bytes()));
        self.close_reason
            .get_or_insert(ConnectionCloseReason::Error(message));
        self.state = ConnectionState::Closing;
        self.surfaces_streams = false;
    }

    /// Emits StreamClosed if both sides are closed and not yet notified.
    fn note_stream_closed_if_finished(&mut self, raw: u64, events: &mut Vec<TransportEvent>) {
        if let Some(state) = self.stream_states.get_mut(&raw)
            && state.is_fully_closed()
            && !state.closed_notified
        {
            state.closed_notified = true;
            events.push(TransportEvent::StreamClosed {
                id: self.id,
                stream_id: StreamId::new(raw),
            });
        }
    }

    /// A peer reset terminates both halves and discards writes that can no
    /// longer be delivered.
    fn note_stream_reset(&mut self, raw: u64, events: &mut Vec<TransportEvent>) {
        self.drop_send_queue(raw);
        self.disarm_writable(raw, events);
        self.gated.remove(&raw);
        // The freed queue may unblock streams waiting on the shared cap.
        self.wake_writable(events);
        let Some(state) = self.stream_states.get_mut(&raw) else {
            return;
        };
        state.local_write_closed = true;
        state.remote_write_closed = true;
        if !state.closed_notified {
            state.closed_notified = true;
            events.push(TransportEvent::StreamClosed {
                id: self.id,
                stream_id: StreamId::new(raw),
            });
        }
    }

    /// Removes closed, drained and settled streams, releasing their slots.
    fn gc_closed_streams(&mut self) {
        let first_unbound = self.first_unbound();
        let side_bit = u64::from(self.is_server());
        let mut freed_local = 0;
        let (send_queues, gated) = (&self.send_queues, &mut self.gated);
        self.stream_states.retain(|&raw, state| {
            let local = raw & 1 == side_bit;
            let settled = state.closed_notified
                && state.unacked == 0
                && !send_queues.contains_key(&raw)
                && !(local && raw >= first_unbound);
            if settled {
                gated.remove(&raw);
                freed_local += u64::from(local);
            }
            !settled
        });
        self.bound_local_bidi_streams = self.bound_local_bidi_streams.saturating_sub(freed_local);
    }

    /// Returns state for a stream previously opened or discovered.
    fn stream_state_mut(
        &mut self,
        stream_id: StreamId,
    ) -> Result<&mut StreamRuntimeState, TransportError> {
        self.stream_states
            .get_mut(&stream_id.as_u64())
            .ok_or(TransportError::StreamNotFound {
                id: self.id,
                stream_id,
            })
    }

    /// Whether this side initiated the stream (QUIC's initiator bit).
    fn is_local(&self, raw: u64) -> bool {
        raw & 1 == u64::from(self.is_server())
    }
}

/// Copies one scan's chunks into a buffer of exactly `len` bytes.
///
/// Chunks may be slices of larger packet allocations; handing them on would
/// pin memory ADR 0012's receive budget does not count.
fn copy_chunks(chunks: &mut Vec<Bytes>, len: usize) -> Bytes {
    let mut data = Vec::with_capacity(len);
    for chunk in chunks.drain(..) {
        data.extend_from_slice(&chunk);
    }
    Bytes::from(data)
}

/// Reports the connection's diagnostic totals, so a host can compare runs
/// without reading them through the transport.
#[cfg(feature = "diagnostics")]
impl Drop for QuicConnection {
    fn drop(&mut self) {
        std::eprintln!(
            "minip2p-quic diagnostics {}: {}",
            self.id,
            self.diagnostics()
        );
    }
}
