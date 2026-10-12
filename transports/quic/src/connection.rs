//! One QUIC connection: the quinn-proto engine plus the adapter's stream
//! bookkeeping (half-close tracking, write queues, the read gate of ADR 0012,
//! and stream-slot accounting).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io;
use std::mem;
use std::time::Instant;

use bytes::Bytes;
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionState, ConnectionToken, StreamId, TransportError,
    TransportEvent,
};
use quinn_proto::{
    ConnectionError, ConnectionHandle, Dir, Event, FinishError, ReadError, StreamEvent, VarInt,
    WriteError,
};

use crate::STREAM_RECEIVE_WINDOW;
use crate::diagnostics::ConnectionCounters;
use crate::socket::Sockets;

/// TLS exporter label for the connection token both ends derive.
const TOKEN_LABEL: &[u8] = b"minip2p quic connection token";

/// Upper bound on engine passes per service: each pass handles what the
/// previous one's events and endpoint events produced.
const MAX_SERVICE_PASSES: usize = 4;

/// Most queued bytes one stream hands the engine per turn of the send
/// scheduler, so backlogged streams share the peer's connection credit.
const SEND_QUANTUM: usize = 64 * 1024;

/// The send caps of ADR 0012, from [`crate::QuicLimits`]: how much each stream
/// and the whole connection may queue beyond what the engine accepted, and
/// the part of the connection cap only control streams may fill.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SendCaps {
    stream: usize,
    connection: usize,
    control_reserve: usize,
}

impl SendCaps {
    /// The caps of validated limits: the reserve is below the connection cap.
    pub(crate) fn new(limits: &crate::QuicLimits) -> Self {
        Self {
            stream: limits.max_pending_bytes_per_stream,
            connection: limits.max_pending_connection_bytes,
            control_reserve: limits.control_stream_reserve_bytes,
        }
    }

    /// The connection cap a stream may fill: all of it for a control
    /// stream, all but the reserve otherwise.
    fn connection_for(&self, control: bool) -> usize {
        if control {
            self.connection
        } else {
            self.connection.saturating_sub(self.control_reserve)
        }
    }

    /// Room a Full stream needs on both caps before its Writable fires:
    /// half the smaller one it may fill.
    fn writable_threshold(&self, control: bool) -> usize {
        (self.stream.min(self.connection_for(control)) / 2).max(1)
    }
}

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
}

impl PendingStreamWrite {
    /// A data write retaining `bytes`, sliced from a payload counted at
    /// `counted` bytes.
    fn data(bytes: Bytes, counted: usize) -> Self {
        let mut write = Self {
            bytes,
            counted,
            fin: false,
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
    /// stops once they reach [`STREAM_RECEIVE_WINDOW`], and the state outlives
    /// the stream's close until they are acknowledged: the stream holds its
    /// slot until it settles.
    unacked: usize,
    /// A control stream may queue into the connection cap's reserve
    /// ([`Transport::set_control_stream`](minip2p_transport::Transport::set_control_stream)).
    control: bool,
}

impl StreamRuntimeState {
    /// Bytes the stream may still deliver before its reader acknowledges.
    fn receive_room(&self) -> usize {
        STREAM_RECEIVE_WINDOW.saturating_sub(self.unacked)
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
    /// Total application bytes queued but not yet accepted by the engine.
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
        max_streams: u64,
        caps: SendCaps,
        counters: ConnectionCounters,
    ) -> Self {
        let next_local_bidi_stream_id = u64::from(conn.side().is_server());
        Self {
            id,
            handle,
            conn,
            endpoint,
            state: ConnectionState::Connecting,
            stream_states: HashMap::new(),
            send_queues: HashMap::new(),
            send_order: VecDeque::new(),
            next_local_bidi_stream_id,
            pending_opens: VecDeque::new(),
            bound_local_bidi_streams: 0,
            max_streams,
            pending_write_bytes: 0,
            caps,
            writable_armed: BTreeSet::new(),
            gated: BTreeSet::new(),
            read_chunks: Vec::new(),
            timeout: None,
            unfinished: false,
            counters,
        }
    }

    pub(crate) fn endpoint(&self) -> &ConnectionEndpoint {
        &self.endpoint
    }

    pub(crate) fn is_server(&self) -> bool {
        self.conn.side().is_server()
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
            self.bind_pending_opens(now, cx.events);
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
        self.timeout = self.conn.poll_timeout();
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
            Event::ConnectionLost { reason } => self.on_lost(&reason, cx.events),
            Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => self.accept_streams(cx.events),
            Event::Stream(StreamEvent::Readable { id }) => self.scan(u64::from(id), cx.events),
            // New credit: the scheduler that runs after these events hands
            // it out in turn, rather than to the stream it names.
            Event::Stream(StreamEvent::Writable { .. }) => {}
            Event::Stream(StreamEvent::Stopped { id, error_code }) => {
                self.on_stopped(u64::from(id), error_code, cx.events);
            }
            Event::Stream(StreamEvent::Available { dir: Dir::Bi }) => {
                self.bind_pending_opens(now, cx.events);
            }
            // Unidirectional streams are never granted, half-close is the
            // adapter's own bookkeeping, and DATAGRAM is not advertised.
            Event::Stream(_)
            | Event::HandshakeDataReady
            | Event::DatagramReceived
            | Event::DatagramsUnblocked => {}
        }
    }

    /// The handshake verified the peer inside TLS; record who it is and the
    /// token both ends derive, then report the connection.
    fn on_connected(&mut self, now: Instant, cx: &mut Cx<'_>) {
        let identity = self.conn.crypto_session().peer_identity();
        let Some(peer_id) = crate::tls::peer_id_from_identity(identity) else {
            self.fail_connection(
                now,
                "peer identity unavailable after the handshake".into(),
                cx.events,
            );
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
    }

    /// The engine lost the connection; `Closed` follows once it drains.
    ///
    /// Orderly closes report no `Error`, and neither do an idle timeout or a
    /// stateless reset of an established connection: those are routine ends
    /// that the swarm would otherwise surface as errors. While handshaking
    /// every reason is reported, so a failed dial carries it.
    fn on_lost(&mut self, reason: &ConnectionError, events: &mut Vec<TransportEvent>) {
        let established = self.state == ConnectionState::Connected;
        let orderly = match reason {
            ConnectionError::LocallyClosed => true,
            ConnectionError::ApplicationClosed(close) => close.error_code == VarInt::from_u32(0),
            ConnectionError::ConnectionClosed(close) => u64::from(close.error_code) == 0,
            ConnectionError::TimedOut | ConnectionError::Reset => established,
            _ => false,
        };
        if !orderly {
            events.push(TransportEvent::Error {
                id: self.id,
                message: reason.to_string(),
            });
        }
        self.end_writes();
        self.state = ConnectionState::Closed;
    }

    /// Accepts every stream the peer opened, scanning each at once: a new
    /// stream's first frame raises only `Opened`, never `Readable`.
    fn accept_streams(&mut self, events: &mut Vec<TransportEvent>) {
        while let Some(stream) = self.conn.streams().accept(Dir::Bi) {
            let raw = u64::from(stream);
            if self.admit_remote_stream(raw, events) {
                self.scan(raw, events);
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
            let stream = engine_stream(raw);
            match self.conn.recv_stream(stream).stop(VarInt::from_u32(0)) {
                Ok(()) | Err(_) => {}
            }
            match self.conn.send_stream(stream).reset(VarInt::from_u32(0)) {
                Ok(()) | Err(_) => {}
            }
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
        // Nothing follows a stream's StreamClosed.
        let Some(room) = self
            .stream_states
            .get(&raw)
            .filter(|state| !state.closed_notified)
            .map(StreamRuntimeState::receive_room)
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

        let (read, end) = {
            let mut recv = self.conn.recv_stream(stream);
            let Ok(mut chunks) = recv.read(true) else {
                return;
            };
            let mut room = room;
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
                match self.conn.send_stream(stream).reset(VarInt::from_u32(0)) {
                    Ok(()) | Err(_) => {}
                }
                self.note_stream_reset(raw, events);
            }
        }
    }

    /// The peer sent STOP_SENDING. The engine only records it, so reset the
    /// send half here, which discards buffered sends and sends RESET_STREAM;
    /// then report the stop.
    fn on_stopped(&mut self, raw: u64, error_code: VarInt, events: &mut Vec<TransportEvent>) {
        match self.conn.send_stream(engine_stream(raw)).reset(error_code) {
            Ok(()) | Err(_) => {}
        }
        self.note_write_stopped(raw, error_code.into_inner(), events);
    }

    /// Opens pending streams in the engine, in order, as peer credit allows.
    fn bind_pending_opens(&mut self, now: Instant, events: &mut Vec<TransportEvent>) {
        while !self.pending_opens.is_empty() {
            let Some(stream) = self.conn.streams().open(Dir::Bi) else {
                return;
            };
            let Some(open) = self.pending_opens.pop_front() else {
                return;
            };
            let raw = u64::from(stream);
            if raw != open.id {
                // The adapter is the only opener, so ids follow its sequence.
                self.fail_connection(
                    now,
                    format!("engine opened stream {raw} where {} was expected", open.id),
                    events,
                );
                return;
            }
            if open.reset_on_bind {
                match self.conn.send_stream(stream).reset(VarInt::from_u32(0)) {
                    Ok(()) | Err(_) => {}
                }
                match self.conn.recv_stream(stream).stop(VarInt::from_u32(0)) {
                    Ok(()) | Err(_) => {}
                }
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
            match self.conn.send_stream(engine_stream(raw)).write(&data) {
                Ok(written) => written,
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
        let stream_room = self.caps.stream.saturating_sub(stream_pending);
        let connection_room = self
            .caps
            .connection_for(control)
            .saturating_sub(self.pending_write_bytes);
        stream_room.min(connection_room)
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
        let stream = engine_stream(raw);
        match self.conn.send_stream(stream).reset(VarInt::from_u32(0)) {
            Ok(()) | Err(_) => {}
        }
        match self.conn.recv_stream(stream).stop(VarInt::from_u32(0)) {
            Ok(()) | Err(_) => {}
        }

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
    pub(crate) fn close(&mut self, now: Instant) {
        if self.is_closing() {
            return;
        }
        self.conn
            .close(now, VarInt::from_u32(0), Bytes::from_static(b"bye"));
        self.state = ConnectionState::Closing;
        self.end_writes();
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
                            events,
                        );
                        return progressed;
                    }
                }
            } else {
                let len = front.bytes.len().min(budget);
                if len == 0 {
                    return progressed;
                }
                // Copies the accepted prefix, as in `send_stream`.
                match self.conn.send_stream(stream).write(&front.bytes[..len]) {
                    Ok(0) => return progressed,
                    Ok(written) => {
                        front.advance(written);
                        queue.pending -= written;
                        self.pending_write_bytes -= written;
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
                            events,
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
    /// single stream. `Closed` follows once the engine drains.
    ///
    /// Every queued write is dropped so later drains cannot hit the same
    /// error again.
    fn fail_connection(&mut self, now: Instant, message: String, events: &mut Vec<TransportEvent>) {
        self.end_writes();
        events.push(TransportEvent::Error {
            id: self.id,
            message,
        });
        // 1 is QUIC's INTERNAL_ERROR.
        self.conn.close(
            now,
            VarInt::from_u32(1),
            Bytes::from_static(b"stream send failed"),
        );
        self.state = ConnectionState::Closing;
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
