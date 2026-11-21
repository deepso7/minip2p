use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::ops::Bound;

use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Bytes, retain_slice};

use crate::yamux::{
    DEFAULT_RECEIVE_WINDOW, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Frame, FrameDecoder, FrameRoom,
    FrameType, KEEPALIVE_ACK_TIMEOUT_MS, KEEPALIVE_HANDOFF_TIMEOUT_MS, KEEPALIVE_INTERVAL_MS,
    YamuxConfig, YamuxError, YamuxOutput, YamuxRole,
};

/// Who queued a control frame, which decides what pulling it settles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    /// This side decided to send it (a GoAway, a local reset).
    Local,
    /// The peer provoked it; counted against the control reserve.
    Peer,
    /// The outstanding keepalive ping; pulling it hands the probe off.
    Probe,
}

/// The outstanding keepalive ping.
#[derive(Clone, Copy, Debug)]
struct Probe {
    /// Only an acknowledgement carrying this nonce answers the probe.
    nonce: u32,
    phase: ProbePhase,
}

/// Where an outstanding keepalive ping is. Each timed phase is bounded:
/// running out fails the session with [`YamuxError::KeepaliveTimeout`].
#[derive(Clone, Copy, Debug)]
enum ProbePhase {
    /// Queued at `since`, waiting to be pulled within
    /// [`KEEPALIVE_HANDOFF_TIMEOUT_MS`].
    Queued { since: u64 },
    /// Pulled since the last poll; the next poll starts the ACK clock.
    HandedOff,
    /// Handed off at `since`, waiting up to [`KEEPALIVE_ACK_TIMEOUT_MS`] for
    /// its acknowledgement.
    AwaitingAck { since: u64 },
}

/// How far a stream's opening handshake has got.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Open {
    /// Opened locally; the next frame for it carries `SYN`.
    SynPending,
    /// Opened locally; `SYN` sent, the peer's `ACK` not yet seen.
    SynSent,
    /// Opened by the peer; the next frame for it carries `ACK`.
    AckPending,
    /// Both sides know the stream.
    Acknowledged,
}

/// The local write side of a stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteSide {
    Open,
    /// Closed by [`YamuxSession::close_write`]; `FIN` goes out once the send
    /// buffer has been framed.
    FinPending,
    /// `FIN` sent.
    Closed,
}

/// Whether the session is active, and if not, why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Active,
    /// This side sent GoAway (possibly in answer to the peer's).
    LocalGoAway,
    /// The peer sent GoAway.
    RemoteGoAway,
    /// A protocol error or keepalive timeout ended the session.
    Failed,
}

/// Bytes accepted by [`YamuxSession::send`] but not yet framed.
///
/// Framing a chunk in part slices it, so the unsent tail shares the caller's
/// allocation. `original_len` is the length that allocation was counted at:
/// once the tail is shorter than half of it, the tail moves to a right-sized
/// buffer (ADR 0012), so retained memory stays within twice the counted bytes.
#[derive(Debug)]
struct QueuedChunk {
    bytes: Bytes,
    original_len: usize,
}

impl QueuedChunk {
    fn new(bytes: Bytes, original_len: usize) -> Self {
        let mut chunk = Self {
            bytes,
            original_len,
        };
        chunk.bound_retained();
        chunk
    }

    /// Drops the first `len` bytes, which were just framed.
    fn advance(&mut self, len: usize) {
        self.bytes = self.bytes.slice(len..);
        self.bound_retained();
    }

    fn bound_retained(&mut self) {
        retain_slice(&mut self.bytes, &mut self.original_len);
    }
}

#[derive(Debug)]
struct StreamState {
    open: Open,
    send_window: u32,
    /// Credit the peer still has: the window less what it has sent us and
    /// we have not returned.
    receive_window: u32,
    /// Delivered bytes the reader has not acknowledged (ADR 0012). They
    /// count against the stream's receive budget.
    unacked: u32,
    /// Acknowledged bytes not yet returned to the peer as credit.
    acked_since_update: u32,
    pending_credit: u64,
    /// Accepted, unframed bytes. They count against the send caps until a
    /// frame carrying them is pulled by [`YamuxSession::poll_frame`].
    send_buffer: VecDeque<QueuedChunk>,
    buffered_send: usize,
    write: WriteSide,
    remote_write_closed: bool,
    /// May queue into [`YamuxConfig::control_stream_reserve`].
    control: bool,
}

impl StreamState {
    fn outbound(config: &YamuxConfig) -> Self {
        Self::new(config, Open::SynPending, DEFAULT_RECEIVE_WINDOW)
    }

    fn inbound(config: &YamuxConfig, send_window: u32) -> Self {
        Self::new(config, Open::AckPending, send_window)
    }

    fn new(config: &YamuxConfig, open: Open, send_window: u32) -> Self {
        Self {
            open,
            send_window,
            receive_window: DEFAULT_RECEIVE_WINDOW,
            unacked: 0,
            acked_since_update: 0,
            pending_credit: u64::from(config.receive_window - DEFAULT_RECEIVE_WINDOW),
            send_buffer: VecDeque::new(),
            buffered_send: 0,
            write: WriteSide::Open,
            remote_write_closed: false,
            control: false,
        }
    }

    /// The open flag the next frame for this stream carries, marking it sent.
    fn take_open_flag(&mut self) -> u16 {
        match self.open {
            Open::SynPending => {
                self.open = Open::SynSent;
                FLAG_SYN
            }
            Open::AckPending => {
                self.open = Open::Acknowledged;
                FLAG_ACK
            }
            Open::SynSent | Open::Acknowledged => 0,
        }
    }

    fn open_flag_pending(&self) -> bool {
        matches!(self.open, Open::SynPending | Open::AckPending)
    }

    /// Notes the flags of a frame received for this stream.
    fn on_peer_flags(&mut self, flags: u16) {
        if flags & FLAG_ACK != 0 && self.open == Open::SynSent {
            self.open = Open::Acknowledged;
        }
    }

    /// Whether this stream needs a standalone window update: returned credit,
    /// or an open flag that no data frame is about to carry.
    fn needs_control_frame(&self) -> bool {
        self.pending_credit != 0 || (self.open_flag_pending() && !self.has_sendable_data())
    }

    /// Whether a data or `FIN` frame can be pulled for this stream now.
    fn has_sendable_data(&self) -> bool {
        (self.send_window != 0 && !self.send_buffer.is_empty())
            || (self.write == WriteSide::FinPending && self.send_buffer.is_empty())
    }
}

/// The aggregate send cap a stream may fill: all of it for a control stream,
/// all but the control reserve otherwise.
fn total_cap_for(config: &YamuxConfig, control: bool) -> usize {
    if control {
        config.max_total_buffered_send
    } else {
        config.max_total_buffered_send - config.control_stream_reserve
    }
}

/// Room a Full stream needs on both caps before its Writable fires: half the
/// smaller of its stream cap and the total cap it may fill. A control stream
/// may be left only the reserve once application streams fill their share,
/// so a non-zero reserve bounds its threshold too.
fn writable_threshold(config: &YamuxConfig, control: bool) -> usize {
    let mut smallest = config.max_buffered_send.min(total_cap_for(config, control));
    if control && config.control_stream_reserve != 0 {
        smallest = smallest.min(config.control_stream_reserve);
    }
    (smallest / 2).max(1)
}

/// Caller-driven Yamux stream-multiplexing session.
///
/// # Output
///
/// Inbound stream events and outbound frames leave through separate queues,
/// so received data never waits behind outbound frames:
///
/// - [`poll_event`](Self::poll_event) yields stream events.
/// - [`poll_frame`](Self::poll_frame) yields encoded frames. Data frames are
///   built only when pulled, so the caller should pull only while its
///   downstream (socket or circuit bridge) has room; that is what bounds the
///   bytes in flight below this session.
///
/// [`poll_output`](Self::poll_output) merges both, events first, for callers
/// that do not care.
///
/// # Backpressure (ADR 0012)
///
/// [`send`](Self::send) accepts as much as the stream's caps allow and hands
/// back the unsent tail in [`YamuxError::Full`]. Peer credit does not decide
/// acceptance. Accepted bytes count against
/// [`YamuxConfig::max_buffered_send`] and
/// [`YamuxConfig::max_total_buffered_send`] until a frame carrying them is
/// pulled. A Full arms [`YamuxOutput::Writable`] for the stream; see its docs
/// for when it fires.
///
/// Control frames (pings, acknowledgements, resets) queue separately and are
/// pulled first. Replies the peer provokes are bounded by
/// [`YamuxConfig::max_pending_control`]: a peer that keeps provoking replies
/// it never reads fails the session with
/// [`YamuxError::ControlReserveExhausted`].
///
/// Reading is credit-driven: a stream's window update goes out only for
/// bytes the reader acknowledged with [`ack`](Self::ack), so a stream holds
/// at most [`YamuxConfig::receive_window`] unacknowledged bytes and a reader
/// that never acknowledges stalls its sender. A stream that closes with
/// unacknowledged bytes stays **unsettled**: it keeps its slot against
/// [`YamuxConfig::max_streams`] until they are acknowledged, or abandoned by
/// a local [`reset`](Self::reset), so stream churn cannot grow retained data
/// past the stream limit times the window. Input never has to stop. The
/// counts outlive the session itself, for its host to take over: see
/// [`unsettled_streams`](Self::unsettled_streams).
pub struct YamuxSession {
    role: YamuxRole,
    config: YamuxConfig,
    decoder: FrameDecoder,
    streams: BTreeMap<u32, StreamState>,
    /// Closed streams still holding unacknowledged bytes, by stream id. Each
    /// keeps a stream slot until those bytes are acknowledged.
    unsettled: BTreeMap<u32, u32>,
    next_stream_id: Option<u32>,
    /// Stream events for [`poll_event`](Self::poll_event).
    events: VecDeque<YamuxOutput>,
    /// Encoded control frames, pulled ahead of data frames, each with who
    /// queued it.
    control: VecDeque<(Vec<u8>, Origin)>,
    /// Peer-provoked frames in `control`: what the reserve bounds.
    peer_control: usize,
    /// Streams whose last `send` was Full and that want a Writable.
    writable_armed: BTreeSet<u32>,
    /// Streams that owe a standalone window update
    /// ([`StreamState::needs_control_frame`]), so output polling never scans
    /// idle streams. Kept in sync by [`Self::index_work`].
    control_due: BTreeSet<u32>,
    /// Streams with a data or `FIN` frame to pull
    /// ([`StreamState::has_sendable_data`]). Kept in sync by
    /// [`Self::index_work`].
    sendable: BTreeSet<u32>,
    /// Round-robin position for data frames: the last stream framed.
    send_cursor: u32,
    total_buffered_send: usize,
    lifecycle: Lifecycle,
    /// Monotonic milliseconds of the first poll after the peer last showed
    /// it was alive (a received frame, or [`Self::note_peer_acked`]), or of
    /// the first poll if it has not yet. `None` until the host supplies a
    /// time sample.
    last_alive_ms: Option<u64>,
    /// The peer showed it was alive since `last_alive_ms` was stamped.
    alive: bool,
    /// The keepalive ping in flight, if any.
    probe: Option<Probe>,
    /// Nonce for the next keepalive ping; never zero.
    next_ping_nonce: u32,
}

impl YamuxSession {
    /// Creates a session with [`YamuxConfig::default`].
    pub fn new(role: YamuxRole) -> Self {
        Self::from_validated_config(role, YamuxConfig::default())
    }

    /// Creates a session with explicit resource limits.
    pub fn with_config(role: YamuxRole, config: YamuxConfig) -> Result<Self, YamuxError> {
        config.validate().map_err(YamuxError::InvalidConfig)?;
        Ok(Self::from_validated_config(role, config))
    }

    /// Builds the session state from a config that already passed (or, for
    /// the default config, statically satisfies) the limit checks.
    fn from_validated_config(role: YamuxRole, config: YamuxConfig) -> Self {
        let next_stream_id = Some(match role {
            YamuxRole::Client => 1,
            YamuxRole::Server => 2,
        });
        Self {
            role,
            decoder: FrameDecoder::new(config.receive_window),
            config,
            streams: BTreeMap::new(),
            unsettled: BTreeMap::new(),
            next_stream_id,
            events: VecDeque::new(),
            control: VecDeque::new(),
            peer_control: 0,
            writable_armed: BTreeSet::new(),
            control_due: BTreeSet::new(),
            sendable: BTreeSet::new(),
            send_cursor: 0,
            total_buffered_send: 0,
            lifecycle: Lifecycle::Active,
            last_alive_ms: None,
            alive: false,
            probe: None,
            next_ping_nonce: 1,
        }
    }

    /// Advances keepalive using the host's time sample.
    ///
    /// Once [`KEEPALIVE_INTERVAL_MS`] passes without a received frame or a
    /// [`note_peer_acked`](Self::note_peer_acked), this queues a ping;
    /// outbound traffic alone does not postpone it. The ping must
    /// then be pulled by [`poll_frame`](Self::poll_frame) within
    /// [`KEEPALIVE_HANDOFF_TIMEOUT_MS`], and acknowledged with its nonce
    /// within [`KEEPALIVE_ACK_TIMEOUT_MS`] of the first poll after that.
    /// Either bound running out fails the session with
    /// [`YamuxError::KeepaliveTimeout`]; its streams end with it, without
    /// per-stream events, as on a protocol failure, but no GoAway is queued
    /// for a peer presumed dead.
    ///
    /// Frames received and acknowledgements noted between polls are dated by
    /// the next poll's sample.
    pub fn poll(&mut self, now: Now) -> Result<(), YamuxError> {
        self.ensure_active()?;
        let now = now.monotonic_ms;
        let quiet_since = match self.last_alive_ms {
            Some(since) if !self.alive => since,
            _ => {
                self.last_alive_ms = Some(now);
                self.alive = false;
                now
            }
        };
        let Some(probe) = &mut self.probe else {
            if now.saturating_sub(quiet_since) >= KEEPALIVE_INTERVAL_MS {
                let nonce = self.next_ping_nonce;
                self.next_ping_nonce = nonce.wrapping_add(1).max(1);
                let ping = Frame::ping(FLAG_SYN, nonce)?.encode();
                self.control.push_back((ping, Origin::Probe));
                self.probe = Some(Probe {
                    nonce,
                    phase: ProbePhase::Queued { since: now },
                });
            }
            return Ok(());
        };
        let expired = match probe.phase {
            ProbePhase::Queued { since } => {
                now.saturating_sub(since) >= KEEPALIVE_HANDOFF_TIMEOUT_MS
            }
            ProbePhase::HandedOff => {
                probe.phase = ProbePhase::AwaitingAck { since: now };
                false
            }
            ProbePhase::AwaitingAck { since } => {
                now.saturating_sub(since) >= KEEPALIVE_ACK_TIMEOUT_MS
            }
        };
        if expired {
            self.fail();
            return Err(YamuxError::KeepaliveTimeout);
        }
        Ok(())
    }

    /// When this session next wants a [`poll`](Self::poll) for keepalive:
    /// the end of the quiet interval, or of the outstanding ping's current
    /// phase. [`Deadline::IMMEDIATE`] right after the ping is pulled, so a
    /// poll can date its hand-off.
    ///
    /// `None` until the first poll supplies a timeline, and once the session
    /// has failed or gone away.
    pub fn next_deadline(&self) -> Option<Deadline> {
        if self.lifecycle != Lifecycle::Active {
            return None;
        }
        let at = match self.probe.map(|probe| probe.phase) {
            None => self.last_alive_ms?.saturating_add(KEEPALIVE_INTERVAL_MS),
            Some(ProbePhase::Queued { since }) => {
                since.saturating_add(KEEPALIVE_HANDOFF_TIMEOUT_MS)
            }
            Some(ProbePhase::HandedOff) => return Some(Deadline::IMMEDIATE),
            Some(ProbePhase::AwaitingAck { since }) => {
                since.saturating_add(KEEPALIVE_ACK_TIMEOUT_MS)
            }
        };
        Some(Deadline::from_millis(at))
    }

    /// Tells keepalive the peer acknowledged bytes this session sent, which
    /// shows it is alive as a received frame does: the quiet interval
    /// restarts at the next [`poll`](Self::poll). An outstanding ping is
    /// unaffected; only its own acknowledgement answers it.
    ///
    /// Call it only on evidence that needs the peer, such as a TCP socket
    /// that refused bytes and later accepted more: a full send buffer frees
    /// room only as the peer's TCP acknowledges data. A write the socket took
    /// straight away is no such evidence, because a send buffer with room
    /// takes bytes for a dead peer too, the keepalive ping included.
    pub fn note_peer_acked(&mut self) {
        self.alive = true;
    }

    /// Opens a local stream and returns its role-partitioned identifier.
    ///
    /// The first data/control frame carries `SYN`; if nothing is sent before
    /// the caller pulls frames, [`YamuxSession::poll_frame`] emits a
    /// standalone window-update frame carrying `SYN`.
    pub fn open_stream(&mut self) -> Result<u32, YamuxError> {
        self.ensure_active()?;
        if self.slots_full() {
            return Err(YamuxError::TooManyStreams);
        }
        let stream = self.next_stream_id.ok_or(YamuxError::StreamsExhausted)?;
        self.next_stream_id = stream.checked_add(2);
        self.streams
            .insert(stream, StreamState::outbound(&self.config));
        self.index_work(stream);
        Ok(stream)
    }

    /// Accepts as much of `data` as the stream's send caps allow.
    ///
    /// Returns [`YamuxError::Full`] carrying the exact unsent suffix when not
    /// every byte fit, and arms [`YamuxOutput::Writable`] for the stream. The
    /// accepted prefix is framed lazily by [`poll_frame`](Self::poll_frame),
    /// as remote credit allows. Empty data is a no-op.
    pub fn send(&mut self, stream: u32, data: Bytes) -> Result<(), YamuxError> {
        self.ensure_active()?;
        let config = &self.config;
        let total_buffered_send = self.total_buffered_send;
        let state = self
            .streams
            .get_mut(&stream)
            .ok_or(YamuxError::UnknownStream(stream))?;
        let total_room = total_cap_for(config, state.control).saturating_sub(total_buffered_send);
        if state.write != WriteSide::Open {
            return Err(YamuxError::StreamWriteClosed(stream));
        }
        if data.is_empty() {
            return Ok(());
        }
        let room = self
            .config
            .max_buffered_send
            .saturating_sub(state.buffered_send)
            .min(total_room);
        let accepted = data.len().min(room);
        if accepted != 0 {
            state
                .send_buffer
                .push_back(QueuedChunk::new(data.slice(..accepted), data.len()));
            state.buffered_send += accepted;
            self.total_buffered_send += accepted;
            self.index_work(stream);
        }
        if accepted == data.len() {
            return Ok(());
        }
        self.writable_armed.insert(stream);
        Err(YamuxError::Full {
            stream,
            unsent: data.slice(accepted..),
        })
    }

    /// Marks a stream as a control stream, which may queue into
    /// [`YamuxConfig::control_stream_reserve`], or back as an application
    /// stream. Streams start as application streams; an unknown stream is
    /// ignored.
    pub fn set_control(&mut self, stream: u32, control: bool) {
        if let Some(state) = self.streams.get_mut(&stream) {
            state.control = control;
            self.wake_writable();
        }
    }

    /// Gracefully half-closes a stream after all accepted data.
    ///
    /// The `FIN` is framed once every accepted byte has been, and a pending
    /// [`YamuxOutput::Writable`] is disarmed: the write side has ended.
    pub fn close_write(&mut self, stream: u32) -> Result<(), YamuxError> {
        self.ensure_active()?;
        let state = self
            .streams
            .get_mut(&stream)
            .ok_or(YamuxError::UnknownStream(stream))?;
        if state.write == WriteSide::Open {
            state.write = WriteSide::FinPending;
        }
        self.index_work(stream);
        self.disarm_writable(stream);
        Ok(())
    }

    /// Immediately resets a stream and emits [`YamuxOutput::StreamClosed`].
    ///
    /// The reset abandons the stream's unacknowledged bytes, so it settles
    /// at once. Resetting a stream that is closed but unsettled only settles
    /// it, also after the session ended.
    ///
    /// Resetting a stream the peer opened spends the control reserve: a peer
    /// can open (and provoke the reset of) streams without bound, so a peer
    /// that never reads the resets fails the session with
    /// [`YamuxError::ControlReserveExhausted`].
    pub fn reset(&mut self, stream: u32) -> Result<(), YamuxError> {
        if self.unsettled.remove(&stream).is_some() {
            return Ok(());
        }
        self.ensure_active()?;
        let unannounced = match self.streams.get(&stream) {
            Some(state) => state.open == Open::SynPending,
            None => return Err(YamuxError::UnknownStream(stream)),
        };
        let peer_opened = self.valid_remote_stream_id(stream);
        self.remove_stream(stream, true);
        self.unsettled.remove(&stream);
        if unannounced {
            return Ok(());
        }
        let rst = Frame::data(stream, FLAG_RST, Vec::new())?;
        if !peer_opened {
            self.push_control(rst);
            return Ok(());
        }
        self.queue_peer_control(rst)
            .or_else(|error| self.fail_protocol(error))
    }

    /// Acknowledges `bytes` of the stream's delivered data as consumed.
    ///
    /// Acknowledged bytes return to the peer as credit once at least a quarter
    /// of the window has been acknowledged since the last update; the window
    /// update is then pulled by [`poll_frame`](Self::poll_frame). On a closed,
    /// unsettled stream the bytes are released, and its slot with the last
    /// of them. Acknowledging a settled or unknown stream does nothing.
    ///
    /// Fails with [`YamuxError::AckExceedsDelivered`], acknowledging nothing,
    /// when `bytes` exceeds the stream's unacknowledged bytes.
    pub fn ack(&mut self, stream: u32, bytes: usize) -> Result<(), YamuxError> {
        let unacked = match (self.streams.get(&stream), self.unsettled.get(&stream)) {
            (Some(state), _) => state.unacked,
            (None, Some(unacked)) => *unacked,
            (None, None) => return Ok(()),
        };
        let acked = u32::try_from(bytes)
            .ok()
            .filter(|acked| *acked <= unacked)
            .ok_or(YamuxError::AckExceedsDelivered {
                stream,
                acked: bytes,
                unacked: unacked as usize,
            })?;
        let Some(state) = self.streams.get_mut(&stream) else {
            if acked == unacked {
                self.unsettled.remove(&stream);
            } else if let Some(unacked) = self.unsettled.get_mut(&stream) {
                *unacked -= acked;
            }
            return Ok(());
        };
        state.unacked -= acked;
        state.acked_since_update += acked;
        if state.acked_since_update >= self.config.receive_window / 4 {
            state.pending_credit += u64::from(state.acked_since_update);
            state.acked_since_update = 0;
            self.index_work(stream);
        }
        Ok(())
    }

    /// Gracefully terminates the whole Yamux session with `code`.
    pub fn go_away(&mut self, code: u32) {
        if matches!(self.lifecycle, Lifecycle::LocalGoAway | Lifecycle::Failed) {
            return;
        }
        self.lifecycle = Lifecycle::LocalGoAway;
        self.close_all_streams();
        self.decoder.clear();
        self.push_control(Frame::go_away(code));
    }

    /// Feeds ordered bytes received from the underlying connection.
    ///
    /// A protocol error fails the session closed: queued frames are replaced
    /// by a protocol GoAway and queued events are dropped. No per-stream
    /// terminal events follow; every stream ends with the session.
    pub fn handle_data(&mut self, bytes: &[u8]) -> Result<(), YamuxError> {
        self.ensure_active()?;
        self.decoder.push(bytes);
        loop {
            let frame = match self.decoder.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(()),
                Err(error) => return self.fail_protocol(error),
            };
            if let Err(error) = self.process_frame(frame) {
                return self.fail_protocol(error);
            }
            self.alive = true;
            if self.lifecycle == Lifecycle::RemoteGoAway {
                self.decoder.clear();
                return Ok(());
            }
        }
    }

    /// Returns the next stream event.
    pub fn poll_event(&mut self) -> Option<YamuxOutput> {
        self.events.pop_front()
    }

    /// Returns the next encoded frame to write, if any.
    ///
    /// Control frames come first, then deferred stream control (open flags,
    /// window updates), then data frames round-robin across streams with
    /// remote credit. Pulling a data frame releases its bytes from the send
    /// caps, which may queue [`YamuxOutput::Writable`] events.
    pub fn poll_frame(&mut self) -> Option<Vec<u8>> {
        self.poll_frame_with_room(FrameRoom::default())
    }

    /// [`poll_frame`](Self::poll_frame), with every frame returned in a buffer
    /// that carries `room`. Data frames are encoded straight into it; the
    /// small control frames are moved in.
    pub(crate) fn poll_frame_with_room(&mut self, room: FrameRoom) -> Option<Vec<u8>> {
        if let Some((frame, origin)) = self.control.pop_front() {
            match origin {
                Origin::Local => {}
                Origin::Peer => self.peer_control -= 1,
                Origin::Probe => {
                    if let Some(probe) = &mut self.probe {
                        probe.phase = ProbePhase::HandedOff;
                    }
                }
            }
            return Some(room.wrap(frame));
        }
        if self.lifecycle != Lifecycle::Active {
            return None;
        }
        debug_assert!(self.work_indexed(), "stream work index out of sync");
        if let Some(frame) = self.deferred_control_frame() {
            return Some(room.wrap(frame));
        }
        let frame = self.data_frame(room)?;
        self.wake_writable();
        Some(frame)
    }

    /// Returns the next event, or else the next frame as
    /// [`YamuxOutput::Outbound`].
    ///
    /// Drain until `None` after every input, before waiting on the
    /// connection, the clock, or the application again.
    pub fn poll_output(&mut self) -> Option<YamuxOutput> {
        self.poll_event()
            .or_else(|| self.poll_frame().map(YamuxOutput::Outbound))
    }

    /// Whether [`poll_frame`](Self::poll_frame) would return a frame now.
    pub fn has_frames(&self) -> bool {
        if !self.control.is_empty() {
            return true;
        }
        if self.lifecycle != Lifecycle::Active {
            return false;
        }
        !self.control_due.is_empty() || !self.sendable.is_empty()
    }

    /// Whether accepted stream bytes or a `FIN` are still waiting to be
    /// framed: a frame [`has_frames`](Self::has_frames) would hand out now,
    /// or bytes held back by the peer's window. What a host drains before
    /// closing the session.
    pub fn has_unsent(&self) -> bool {
        self.total_buffered_send != 0 || self.has_frames()
    }

    /// Returns the number of currently tracked streams.
    #[cfg(test)]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Drains every queued stream event.
    #[cfg(test)]
    pub fn poll_events(&mut self) -> Vec<YamuxOutput> {
        core::iter::from_fn(|| self.poll_event()).collect()
    }

    /// Every stream still holding delivered bytes that are not acknowledged,
    /// open or closed, with how many.
    ///
    /// A host tearing the connection down takes these over so the bytes stay
    /// counted until they are acknowledged or abandoned (ADR 0012). They
    /// survive the session ending: a GoAway or protocol failure leaves
    /// [`ack`](Self::ack) and [`reset`](Self::reset) settling them here.
    pub fn unsettled_streams(&self) -> impl Iterator<Item = (u32, usize)> + '_ {
        self.streams
            .iter()
            .map(|(&stream, state)| (stream, state.unacked))
            .chain(self.unsettled.iter().map(|(&stream, &n)| (stream, n)))
            .filter(|(_, unacked)| *unacked != 0)
            .map(|(stream, unacked)| (stream, unacked as usize))
    }

    /// Whether open and unsettled streams fill every stream slot.
    fn slots_full(&self) -> bool {
        self.streams.len() + self.unsettled.len() >= self.config.max_streams
    }

    /// Returns aggregate accepted bytes not yet pulled as frames.
    #[cfg(test)]
    pub fn total_buffered_send(&self) -> usize {
        self.total_buffered_send
    }

    /// Returns whether the stream-opening `SYN` has been acknowledged.
    #[cfg(test)]
    pub fn is_acknowledged(&self, stream: u32) -> Result<bool, YamuxError> {
        self.streams
            .get(&stream)
            .map(|state| state.open == Open::Acknowledged)
            .ok_or(YamuxError::UnknownStream(stream))
    }

    fn ensure_active(&self) -> Result<(), YamuxError> {
        match self.lifecycle {
            Lifecycle::Active => Ok(()),
            Lifecycle::Failed => Err(YamuxError::Failed),
            Lifecycle::LocalGoAway | Lifecycle::RemoteGoAway => Err(YamuxError::SessionClosed),
        }
    }

    fn process_frame(&mut self, frame: Frame) -> Result<(), YamuxError> {
        match frame.frame_type() {
            FrameType::Data => self.on_data(frame),
            FrameType::WindowUpdate => self.on_window_update(frame),
            FrameType::Ping => self.on_ping(frame),
            FrameType::GoAway => {
                self.lifecycle = Lifecycle::RemoteGoAway;
                self.events.push_back(YamuxOutput::GoAwayReceived {
                    code: frame.value(),
                });
                self.close_all_streams();
                Ok(())
            }
        }
    }

    fn on_data(&mut self, frame: Frame) -> Result<(), YamuxError> {
        let stream = frame.stream_id();
        let flags = frame.flags();
        if flags & FLAG_RST != 0 {
            self.remove_stream(stream, self.streams.contains_key(&stream));
            return Ok(());
        }

        if flags & FLAG_SYN != 0 {
            if !self.valid_remote_stream_id(stream) {
                return Err(YamuxError::Protocol("remote used a local-parity stream id"));
            }
            if self.streams.contains_key(&stream) || self.unsettled.contains_key(&stream) {
                return Err(YamuxError::Protocol("duplicate SYN for an existing stream"));
            }
            if self.slots_full() {
                return self.queue_reset_for_unknown(stream);
            }
            self.streams.insert(
                stream,
                StreamState::inbound(&self.config, DEFAULT_RECEIVE_WINDOW),
            );
            self.index_work(stream);
            self.events
                .push_back(YamuxOutput::IncomingStream { stream });
        } else if !self.streams.contains_key(&stream) {
            return self.queue_reset_for_unknown(stream);
        }

        let mut data_output = None;
        let mut remote_closed = false;
        let fully_closed;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("stream was inserted or checked above");
            state.on_peer_flags(flags);
            if state.remote_write_closed && !frame.payload().is_empty() {
                return Err(YamuxError::Protocol("data after FIN"));
            }
            let payload_len = frame.value();
            if payload_len > state.receive_window {
                return Err(YamuxError::ReceiveWindowExceeded { stream });
            }
            state.receive_window -= payload_len;
            state.unacked = state
                .unacked
                .checked_add(payload_len)
                .ok_or(YamuxError::Protocol("receive accounting overflow"))?;
            if !frame.payload().is_empty() {
                data_output = Some(frame.into_payload());
            }
            if flags & FLAG_FIN != 0 && !state.remote_write_closed {
                state.remote_write_closed = true;
                remote_closed = true;
            }
            fully_closed = state.remote_write_closed && state.write == WriteSide::Closed;
        }
        if let Some(data) = data_output {
            self.events.push_back(YamuxOutput::Data { stream, data });
        }
        if remote_closed {
            self.events
                .push_back(YamuxOutput::RemoteWriteClosed { stream });
        }
        if fully_closed {
            self.remove_stream(stream, true);
        }
        Ok(())
    }

    fn on_window_update(&mut self, frame: Frame) -> Result<(), YamuxError> {
        let stream = frame.stream_id();
        let flags = frame.flags();
        if flags & FLAG_RST != 0 {
            self.remove_stream(stream, self.streams.contains_key(&stream));
            return Ok(());
        }

        if flags & FLAG_SYN != 0 {
            if !self.valid_remote_stream_id(stream) {
                return Err(YamuxError::Protocol("remote used a local-parity stream id"));
            }
            if self.streams.contains_key(&stream) || self.unsettled.contains_key(&stream) {
                return Err(YamuxError::Protocol("duplicate SYN for an existing stream"));
            }
            let send_window = DEFAULT_RECEIVE_WINDOW
                .checked_add(frame.value())
                .ok_or(YamuxError::WindowOverflow { stream })?;
            if self.slots_full() {
                return self.queue_reset_for_unknown(stream);
            }
            self.streams
                .insert(stream, StreamState::inbound(&self.config, send_window));
            self.events
                .push_back(YamuxOutput::IncomingStream { stream });
        } else if !self.streams.contains_key(&stream) {
            return self.queue_reset_for_unknown(stream);
        } else {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("stream existence checked above");
            state.send_window = state
                .send_window
                .checked_add(frame.value())
                .ok_or(YamuxError::WindowOverflow { stream })?;
        }
        self.index_work(stream);

        let mut remote_closed = false;
        let fully_closed;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("stream was inserted or checked above");
            state.on_peer_flags(flags);
            if flags & FLAG_FIN != 0 && !state.remote_write_closed {
                state.remote_write_closed = true;
                remote_closed = true;
            }
            fully_closed = state.remote_write_closed && state.write == WriteSide::Closed;
        }
        if remote_closed {
            self.events
                .push_back(YamuxOutput::RemoteWriteClosed { stream });
        }
        if fully_closed {
            self.remove_stream(stream, true);
        }
        Ok(())
    }

    fn on_ping(&mut self, frame: Frame) -> Result<(), YamuxError> {
        if frame.flags() == FLAG_SYN {
            self.queue_peer_control(Frame::ping(FLAG_ACK, frame.value())?)?;
        } else if self.probe.is_some_and(|probe| probe.nonce == frame.value()) {
            self.probe = None;
        }
        Ok(())
    }

    /// The next stream's open flag or returned receive credit, as a
    /// standalone window update.
    fn deferred_control_frame(&mut self) -> Option<Vec<u8>> {
        let stream = *self.control_due.first()?;
        let state = self.streams.get_mut(&stream)?;
        let flags = state.take_open_flag();
        let credit = state.pending_credit.min(u64::from(u32::MAX)) as u32;
        state.pending_credit -= u64::from(credit);
        state.receive_window = state.receive_window.saturating_add(credit);
        self.index_work(stream);
        Some(Frame::window_update(stream, flags, credit).ok()?.encode())
    }

    /// Frames the next stream's data, round-robin from `send_cursor`, or its
    /// `FIN` once its accepted bytes have all gone, in a buffer with `room`.
    fn data_frame(&mut self, room: FrameRoom) -> Option<Vec<u8>> {
        let after = self.send_cursor;
        let stream = *self
            .sendable
            .range((Bound::Excluded(after), Bound::Unbounded))
            .chain(self.sendable.range(..=after))
            .next()?;
        self.send_cursor = stream;
        let max_frame_len = self.config.max_frame_len as usize;
        let state = self.streams.get_mut(&stream)?;
        let mut flags = state.take_open_flag();
        let last_chunk = state.send_buffer.len() == 1;
        let frame = match state.send_buffer.front_mut() {
            Some(chunk) if state.send_window != 0 => {
                let sent = chunk
                    .bytes
                    .len()
                    .min(state.send_window as usize)
                    .min(max_frame_len);
                let drained = sent == chunk.bytes.len();
                if drained && last_chunk && state.write == WriteSide::FinPending {
                    flags |= FLAG_FIN;
                }
                let payload = chunk.bytes.get(..sent).unwrap_or_default();
                let frame = Frame::encode_data_with_room(stream, flags, payload, room)
                    .expect("payload length is bounded by the u32 send window");
                if drained {
                    state.send_buffer.pop_front();
                } else {
                    chunk.advance(sent);
                }
                state.send_window -= sent as u32;
                state.buffered_send -= sent;
                self.total_buffered_send -= sent;
                frame
            }
            _ => {
                flags |= FLAG_FIN;
                Frame::encode_data_with_room(stream, flags, &[], room)
                    .expect("empty FIN frame is valid")
            }
        };
        if flags & FLAG_FIN != 0 {
            state.write = WriteSide::Closed;
            if state.remote_write_closed {
                self.remove_stream(stream, true);
            }
        }
        self.index_work(stream);
        Some(frame)
    }

    /// Queues [`YamuxOutput::Writable`] for every armed stream that can now
    /// queue at least [`writable_threshold`] on both its stream cap and the
    /// total cap it may fill ([`total_cap_for`]).
    fn wake_writable(&mut self) {
        if self.writable_armed.is_empty() {
            return;
        }
        let config = &self.config;
        let total_buffered_send = self.total_buffered_send;
        let streams = &self.streams;
        let events = &mut self.events;
        self.writable_armed.retain(|stream| {
            let Some(state) = streams.get(stream) else {
                return false;
            };
            let threshold = writable_threshold(config, state.control);
            if config.max_buffered_send.saturating_sub(state.buffered_send) < threshold
                || total_cap_for(config, state.control).saturating_sub(total_buffered_send)
                    < threshold
            {
                return true;
            }
            events.push_back(YamuxOutput::Writable { stream: *stream });
            false
        });
    }

    /// Files `stream` in the work indexes by its current state. Every change
    /// that can flip [`StreamState::needs_control_frame`] or
    /// [`StreamState::has_sendable_data`] calls this; a removed stream leaves
    /// both.
    fn index_work(&mut self, stream: u32) {
        let (control, data) = self.streams.get(&stream).map_or((false, false), |state| {
            (state.needs_control_frame(), state.has_sendable_data())
        });
        for (index, member) in [(&mut self.control_due, control), (&mut self.sendable, data)] {
            if member {
                index.insert(stream);
            } else {
                index.remove(&stream);
            }
        }
    }

    /// Whether the work indexes match a scan of every stream; checked by
    /// debug builds (tests and fuzzing) on each output poll.
    fn work_indexed(&self) -> bool {
        let scanned = |test: fn(&StreamState) -> bool| {
            self.streams
                .iter()
                .filter(|(_, state)| test(state))
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
        };
        scanned(StreamState::needs_control_frame) == self.control_due
            && scanned(StreamState::has_sendable_data) == self.sendable
    }

    fn queue_reset_for_unknown(&mut self, stream: u32) -> Result<(), YamuxError> {
        self.queue_peer_control(Frame::data(stream, FLAG_RST, Vec::new())?)
    }

    /// Queues a reply the peer provoked (a ping acknowledgement, a reset for
    /// an unknown or peer-opened stream) within the control reserve. A peer that keeps
    /// provoking replies without reading them exhausts it, which is a
    /// protocol violation that fails the session.
    fn queue_peer_control(&mut self, frame: Frame) -> Result<(), YamuxError> {
        if self.peer_control >= self.config.max_pending_control {
            return Err(YamuxError::ControlReserveExhausted {
                limit: self.config.max_pending_control,
            });
        }
        self.peer_control += 1;
        self.control.push_back((frame.encode(), Origin::Peer));
        Ok(())
    }

    /// Queues a control frame this side decided to send. Local frames are
    /// bounded by local behaviour, not by the reserve.
    fn push_control(&mut self, frame: Frame) {
        self.control.push_back((frame.encode(), Origin::Local));
    }

    /// Ends the stream's claim to a Writable, including one already queued:
    /// its write side is over.
    fn disarm_writable(&mut self, stream: u32) {
        self.writable_armed.remove(&stream);
        self.events
            .retain(|event| *event != YamuxOutput::Writable { stream });
    }

    /// Drops a stream's state. One still holding unacknowledged bytes stays
    /// unsettled, keeping its slot; a local reset settles it afterwards.
    fn remove_stream(&mut self, stream: u32, emit: bool) {
        self.disarm_writable(stream);
        self.control_due.remove(&stream);
        self.sendable.remove(&stream);
        if let Some(state) = self.streams.remove(&stream) {
            if state.unacked != 0 {
                self.unsettled.insert(stream, state.unacked);
            }
            self.total_buffered_send -= state.buffered_send;
            if emit {
                self.events.push_back(YamuxOutput::StreamClosed { stream });
            }
            if state.buffered_send != 0 {
                self.wake_writable();
            }
        }
    }

    /// Ends every stream with the session. Streams still holding
    /// unacknowledged bytes stay unsettled for the host to settle.
    fn close_all_streams(&mut self) {
        let streams = self.streams.keys().copied().collect::<Vec<_>>();
        self.unsettle_all();
        self.writable_armed.clear();
        self.control_due.clear();
        self.sendable.clear();
        self.events
            .retain(|event| !matches!(event, YamuxOutput::Writable { .. }));
        self.total_buffered_send = 0;
        for stream in streams {
            self.events.push_back(YamuxOutput::StreamClosed { stream });
        }
    }

    fn valid_remote_stream_id(&self, stream: u32) -> bool {
        stream != 0
            && match self.role {
                YamuxRole::Client => stream.is_multiple_of(2),
                YamuxRole::Server => !stream.is_multiple_of(2),
            }
    }

    /// Moves every open stream's unacknowledged count into `unsettled` and
    /// drops the open streams.
    fn unsettle_all(&mut self) {
        for (stream, state) in core::mem::take(&mut self.streams) {
            if state.unacked != 0 {
                self.unsettled.insert(stream, state.unacked);
            }
        }
    }

    /// Fails the session for a protocol error, telling the peer with a
    /// protocol GoAway.
    fn fail_protocol<T>(&mut self, error: YamuxError) -> Result<T, YamuxError> {
        self.fail();
        self.push_control(Frame::go_away(1));
        Err(error)
    }

    /// Whether the session failed: a protocol error or keepalive timeout
    /// ended it, and every stream with it.
    pub(crate) fn has_failed(&self) -> bool {
        self.lifecycle == Lifecycle::Failed
    }

    /// Fails the session for good: queued frames and events are dropped,
    /// and no stream gets a terminal event of its own; the failure ends them.
    fn fail(&mut self) {
        self.lifecycle = Lifecycle::Failed;
        for event in &self.events {
            if let YamuxOutput::Data { stream, data } = event {
                let len = data.len() as u32;
                if let Some(state) = self.streams.get_mut(stream) {
                    state.unacked = state.unacked.saturating_sub(len);
                } else if let Some(unacked) = self.unsettled.get_mut(stream) {
                    *unacked = unacked.saturating_sub(len);
                }
            }
        }
        self.unsettled.retain(|_, unacked| *unacked != 0);
        self.unsettle_all();
        self.writable_armed.clear();
        self.control_due.clear();
        self.sendable.clear();
        self.total_buffered_send = 0;
        self.decoder.clear();
        self.events.clear();
        self.control.clear();
        self.peer_control = 0;
        self.probe = None;
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
