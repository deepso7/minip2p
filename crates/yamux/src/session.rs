use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use minip2p_core::{Bytes, retain_slice};
use minip2p_platform::{Deadline, Now};

use crate::{
    DEFAULT_RECEIVE_WINDOW, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Frame, FrameDecoder, FrameType,
    KEEPALIVE_INTERVAL_MS, YamuxConfig, YamuxError, YamuxOutput, YamuxRole,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenFlag {
    Syn,
    Ack,
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
    locally_opened: bool,
    pending_open: Option<OpenFlag>,
    acknowledged: bool,
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
    /// The local write side was closed; `FIN` goes out once `send_buffer`
    /// has been framed.
    close_pending: bool,
    local_write_closed: bool,
    remote_write_closed: bool,
}

impl StreamState {
    fn outbound(config: &YamuxConfig) -> Self {
        Self::new(config, true, Some(OpenFlag::Syn), DEFAULT_RECEIVE_WINDOW)
    }

    fn inbound(config: &YamuxConfig, send_window: u32) -> Self {
        Self::new(config, false, Some(OpenFlag::Ack), send_window)
    }

    fn new(
        config: &YamuxConfig,
        locally_opened: bool,
        pending_open: Option<OpenFlag>,
        send_window: u32,
    ) -> Self {
        Self {
            locally_opened,
            pending_open,
            acknowledged: false,
            send_window,
            receive_window: DEFAULT_RECEIVE_WINDOW,
            unacked: 0,
            acked_since_update: 0,
            pending_credit: u64::from(config.receive_window - DEFAULT_RECEIVE_WINDOW),
            send_buffer: VecDeque::new(),
            buffered_send: 0,
            close_pending: false,
            local_write_closed: false,
            remote_write_closed: false,
        }
    }

    fn take_open_flag(&mut self) -> u16 {
        match self.pending_open.take() {
            Some(OpenFlag::Syn) => FLAG_SYN,
            Some(OpenFlag::Ack) => {
                self.acknowledged = true;
                FLAG_ACK
            }
            None => 0,
        }
    }

    /// Whether this stream needs a standalone window update: returned credit,
    /// or an open flag that no data frame is about to carry.
    fn needs_control_frame(&self) -> bool {
        self.pending_credit != 0 || (self.pending_open.is_some() && !self.has_sendable_data())
    }

    /// Whether a data or `FIN` frame can be pulled for this stream now.
    fn has_sendable_data(&self) -> bool {
        (self.send_window != 0 && !self.send_buffer.is_empty())
            || (self.close_pending && self.send_buffer.is_empty())
    }
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
/// past the stream limit times the window. Input never has to stop.
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
    /// Encoded control frames, pulled ahead of data frames, each marked
    /// whether the peer provoked it.
    control: VecDeque<(Vec<u8>, bool)>,
    /// Peer-provoked frames in `control`: what the reserve bounds.
    peer_control: usize,
    /// Streams whose last `send` was Full and that want a Writable.
    writable_armed: BTreeSet<u32>,
    /// Round-robin position for data frames: the last stream framed.
    send_cursor: u32,
    total_buffered_send: usize,
    failed: bool,
    local_go_away: bool,
    remote_go_away: bool,
    /// Monotonic milliseconds of the last poll that observed traffic, or the
    /// first poll if none has arrived yet. `None` until the host supplies a
    /// time sample.
    last_activity_ms: Option<u64>,
    /// A frame was queued or consumed since `last_activity_ms` was stamped.
    dirty: bool,
    /// Nonce for the next locally originated keepalive ping.
    next_ping_nonce: u32,
}

impl YamuxSession {
    /// Creates a session with [`YamuxConfig::default`].
    pub fn new(role: YamuxRole) -> Self {
        Self::from_validated_config(role, YamuxConfig::default())
    }

    /// Creates a session with explicit resource limits.
    pub fn with_config(role: YamuxRole, config: YamuxConfig) -> Result<Self, YamuxError> {
        if config.receive_window < DEFAULT_RECEIVE_WINDOW {
            return Err(YamuxError::InvalidConfig(
                "receive_window is below Yamux's initial 256 KiB credit",
            ));
        }
        if config.max_frame_len == 0 {
            return Err(YamuxError::InvalidConfig(
                "max_frame_len must be greater than zero",
            ));
        }
        if config.max_buffered_send == 0 || config.max_total_buffered_send == 0 {
            return Err(YamuxError::InvalidConfig(
                "send caps must be greater than zero",
            ));
        }
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
            decoder: FrameDecoder::new(config.max_frame_len),
            config,
            streams: BTreeMap::new(),
            unsettled: BTreeMap::new(),
            next_stream_id,
            events: VecDeque::new(),
            control: VecDeque::new(),
            peer_control: 0,
            writable_armed: BTreeSet::new(),
            send_cursor: 0,
            total_buffered_send: 0,
            failed: false,
            local_go_away: false,
            remote_go_away: false,
            last_activity_ms: None,
            dirty: false,
            next_ping_nonce: 1,
        }
    }

    /// Advances keepalive using the host's time sample.
    ///
    /// A quiet session queues a ping once [`KEEPALIVE_INTERVAL_MS`] has elapsed
    /// since the last inbound or outbound frame. Traffic observed since the
    /// previous sample restamps the timer, so a busy session never pings.
    pub fn poll(&mut self, now: Now) -> Result<(), YamuxError> {
        self.ensure_active()?;
        if self.dirty || self.last_activity_ms.is_none() {
            self.last_activity_ms = Some(now.monotonic_ms);
            self.dirty = false;
        }
        let last = self.last_activity_ms.expect("stamped above");
        if now.monotonic_ms.saturating_sub(last) >= KEEPALIVE_INTERVAL_MS {
            let nonce = self.next_ping_nonce;
            self.next_ping_nonce = self.next_ping_nonce.wrapping_add(1);
            // A session with control frames still unpulled is not quiet on
            // the wire, and the ping would only queue behind them.
            if self.control.is_empty() {
                self.push_control(Frame::ping(FLAG_SYN, nonce)?);
            }
            self.last_activity_ms = Some(now.monotonic_ms);
            self.dirty = false;
        }
        Ok(())
    }

    /// When this session next wants a [`poll`](Self::poll) for keepalive.
    ///
    /// `None` until the first poll supplies a timeline, and once the session
    /// has failed or gone away.
    pub fn next_deadline(&self) -> Option<Deadline> {
        if self.failed || self.local_go_away || self.remote_go_away {
            return None;
        }
        Some(Deadline::from_millis(
            self.last_activity_ms?.saturating_add(KEEPALIVE_INTERVAL_MS),
        ))
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
        let total_room = self
            .config
            .max_total_buffered_send
            .saturating_sub(self.total_buffered_send);
        let state = self
            .streams
            .get_mut(&stream)
            .ok_or(YamuxError::UnknownStream(stream))?;
        if state.local_write_closed || state.close_pending {
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
        if !state.local_write_closed {
            state.close_pending = true;
        }
        self.disarm_writable(stream);
        Ok(())
    }

    /// Immediately resets a stream and emits [`YamuxOutput::StreamClosed`].
    ///
    /// The reset abandons the stream's unacknowledged bytes, so it settles
    /// at once. Resetting a stream that is closed but unsettled only settles
    /// it.
    ///
    /// Resetting a stream the peer opened spends the control reserve: a peer
    /// can open (and provoke the reset of) streams without bound, so a peer
    /// that never reads the resets fails the session with
    /// [`YamuxError::ControlReserveExhausted`].
    pub fn reset(&mut self, stream: u32) -> Result<(), YamuxError> {
        self.ensure_active()?;
        if self.unsettled.remove(&stream).is_some() {
            return Ok(());
        }
        let unannounced = match self.streams.get(&stream) {
            Some(state) => state.pending_open == Some(OpenFlag::Syn),
            None => return Err(YamuxError::UnknownStream(stream)),
        };
        let peer_opened = self.valid_remote_stream_id(stream);
        self.remove_stream(stream, true);
        self.unsettled.remove(&stream);
        // A stream whose SYN never went out is unknown to the peer.
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
    /// Acknowledged bytes return to the peer as credit once more than half
    /// the window has been acknowledged since the last update; the window
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
        if state.acked_since_update > self.config.receive_window / 2 {
            state.pending_credit += u64::from(state.acked_since_update);
            state.acked_since_update = 0;
        }
        Ok(())
    }

    /// Gracefully terminates the whole Yamux session with `code`.
    pub fn go_away(&mut self, code: u32) {
        if self.local_go_away || self.failed {
            return;
        }
        self.local_go_away = true;
        self.close_all_streams();
        self.decoder.clear();
        self.push_control(Frame::go_away(code));
    }

    /// Feeds ordered bytes received from the underlying connection.
    ///
    /// A protocol error fails the session closed: queued frames are replaced
    /// by a protocol GoAway, queued events are dropped, and terminal events
    /// follow for tracked streams. A caller must therefore tolerate
    /// [`YamuxOutput::StreamClosed`] for a stream whose queued
    /// [`YamuxOutput::IncomingStream`] was discarded.
    pub fn handle_data(&mut self, bytes: &[u8]) -> Result<(), YamuxError> {
        if self.failed {
            return Err(YamuxError::Failed);
        }
        if self.local_go_away || self.remote_go_away {
            return Err(YamuxError::SessionClosed);
        }
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
            self.dirty = true;
            if self.remote_go_away {
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
        if let Some((frame, provoked)) = self.control.pop_front() {
            self.peer_control -= usize::from(provoked);
            return Some(frame);
        }
        if self.failed || self.local_go_away || self.remote_go_away {
            return None;
        }
        if let Some(frame) = self.deferred_control_frame() {
            self.dirty = true;
            return Some(frame);
        }
        let frame = self.data_frame()?;
        self.dirty = true;
        self.wake_writable();
        Some(frame)
    }

    /// Returns the next event, or else the next frame as
    /// [`YamuxOutput::Outbound`].
    pub fn poll_output(&mut self) -> Option<YamuxOutput> {
        self.poll_event()
            .or_else(|| self.poll_frame().map(YamuxOutput::Outbound))
    }

    /// Whether [`poll_frame`](Self::poll_frame) would return a frame now.
    pub fn has_frames(&self) -> bool {
        if !self.control.is_empty() {
            return true;
        }
        if self.failed || self.local_go_away || self.remote_go_away {
            return false;
        }
        self.streams
            .values()
            .any(|state| state.needs_control_frame() || state.has_sendable_data())
    }

    /// Returns true when no event or frame is pending.
    pub fn is_idle(&self) -> bool {
        self.events.is_empty() && !self.has_frames()
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
            .map(|state| state.acknowledged)
            .ok_or(YamuxError::UnknownStream(stream))
    }

    fn ensure_active(&self) -> Result<(), YamuxError> {
        if self.failed {
            Err(YamuxError::Failed)
        } else if self.local_go_away || self.remote_go_away {
            Err(YamuxError::SessionClosed)
        } else {
            Ok(())
        }
    }

    fn process_frame(&mut self, frame: Frame) -> Result<(), YamuxError> {
        match frame.frame_type() {
            FrameType::Data => self.on_data(frame),
            FrameType::WindowUpdate => self.on_window_update(frame),
            FrameType::Ping => self.on_ping(frame),
            FrameType::GoAway => {
                self.remote_go_away = true;
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
            if self.streams.contains_key(&stream) {
                return Err(YamuxError::Protocol("duplicate SYN for an existing stream"));
            }
            if self.slots_full() {
                return self.queue_reset_for_unknown(stream);
            }
            self.streams.insert(
                stream,
                StreamState::inbound(&self.config, DEFAULT_RECEIVE_WINDOW),
            );
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
            if flags & FLAG_ACK != 0 && state.locally_opened {
                state.acknowledged = true;
            }
            if state.remote_write_closed && !frame.payload().is_empty() {
                return Err(YamuxError::Protocol("data after FIN"));
            }
            let payload_len = frame.value();
            if payload_len > state.receive_window {
                return Err(YamuxError::ReceiveWindowExceeded { stream });
            }
            state.receive_window -= payload_len;
            // Credit returns only as the reader acknowledges these bytes.
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
            fully_closed = state.remote_write_closed && state.local_write_closed;
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
            if self.streams.contains_key(&stream) {
                return Err(YamuxError::Protocol("duplicate SYN for an existing stream"));
            }
            if self.slots_full() {
                return self.queue_reset_for_unknown(stream);
            }
            let send_window = DEFAULT_RECEIVE_WINDOW
                .checked_add(frame.value())
                .ok_or(YamuxError::WindowOverflow { stream })?;
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

        let mut remote_closed = false;
        let fully_closed;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("stream was inserted or checked above");
            if flags & FLAG_ACK != 0 && state.locally_opened {
                state.acknowledged = true;
            }
            if flags & FLAG_FIN != 0 && !state.remote_write_closed {
                state.remote_write_closed = true;
                remote_closed = true;
            }
            fully_closed = state.remote_write_closed && state.local_write_closed;
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
        }
        Ok(())
    }

    /// The next stream's open flag or returned receive credit, as a
    /// standalone window update.
    fn deferred_control_frame(&mut self) -> Option<Vec<u8>> {
        let (&stream, state) = self
            .streams
            .iter_mut()
            .find(|(_, state)| state.needs_control_frame())?;
        let flags = state.take_open_flag();
        let credit = state.pending_credit.min(u64::from(u32::MAX)) as u32;
        state.pending_credit -= u64::from(credit);
        // Pending credit is only ever what the window gave up, so this never
        // saturates.
        state.receive_window = state.receive_window.saturating_add(credit);
        Some(Frame::window_update(stream, flags, credit).ok()?.encode())
    }

    /// Frames the next stream's data, round-robin from `send_cursor`, or its
    /// `FIN` once its accepted bytes have all gone.
    fn data_frame(&mut self) -> Option<Vec<u8>> {
        let after = self.send_cursor;
        let stream = self
            .streams
            .range(after.saturating_add(1)..)
            .chain(self.streams.range(..=after))
            .find_map(|(id, state)| state.has_sendable_data().then_some(*id))?;
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
                if drained && last_chunk && state.close_pending {
                    flags |= FLAG_FIN;
                }
                let payload = chunk.bytes.get(..sent).unwrap_or_default();
                let frame = Frame::encode_data(stream, flags, payload)
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
            // Only a pending close is sendable with nothing buffered.
            _ => {
                flags |= FLAG_FIN;
                Frame::encode_data(stream, flags, &[]).expect("empty FIN frame is valid")
            }
        };
        if flags & FLAG_FIN != 0 {
            state.close_pending = false;
            state.local_write_closed = true;
            if state.remote_write_closed {
                self.remove_stream(stream, true);
            }
        }
        Some(frame)
    }

    /// Queues [`YamuxOutput::Writable`] for every armed stream that can now
    /// queue at least half of the smaller send cap.
    fn wake_writable(&mut self) {
        if self.writable_armed.is_empty() {
            return;
        }
        let threshold = (self
            .config
            .max_buffered_send
            .min(self.config.max_total_buffered_send)
            / 2)
        .max(1);
        let total_room = self
            .config
            .max_total_buffered_send
            .saturating_sub(self.total_buffered_send);
        if total_room < threshold {
            return;
        }
        let max_buffered_send = self.config.max_buffered_send;
        let streams = &self.streams;
        let events = &mut self.events;
        self.writable_armed.retain(|stream| {
            let Some(state) = streams.get(stream) else {
                return false;
            };
            if max_buffered_send.saturating_sub(state.buffered_send) < threshold {
                return true;
            }
            events.push_back(YamuxOutput::Writable { stream: *stream });
            false
        });
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
        self.dirty = true;
        self.control.push_back((frame.encode(), true));
        Ok(())
    }

    /// Queues a control frame this side decided to send. Local frames are
    /// bounded by local behaviour, not by the reserve.
    fn push_control(&mut self, frame: Frame) {
        self.dirty = true;
        self.control.push_back((frame.encode(), false));
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
        if let Some(state) = self.streams.remove(&stream) {
            if state.unacked != 0 {
                self.unsettled.insert(stream, state.unacked);
            }
            self.total_buffered_send -= state.buffered_send;
            if emit {
                self.events.push_back(YamuxOutput::StreamClosed { stream });
            }
            // Its unframed bytes left the shared cap without a frame being
            // pulled, so streams blocked on that cap must hear about it here.
            if state.buffered_send != 0 {
                self.wake_writable();
            }
        }
    }

    /// Ends every stream with the session; nothing is left to settle.
    fn close_all_streams(&mut self) {
        let streams = self.streams.keys().copied().collect::<Vec<_>>();
        self.streams.clear();
        self.unsettled.clear();
        self.writable_armed.clear();
        // Every write side ended: no Writable, not even one already queued.
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

    fn fail_protocol<T>(&mut self, error: YamuxError) -> Result<T, YamuxError> {
        let streams = self.streams.keys().copied().collect::<Vec<_>>();
        self.failed = true;
        self.streams.clear();
        self.unsettled.clear();
        self.writable_armed.clear();
        self.total_buffered_send = 0;
        self.decoder.clear();
        self.events.clear();
        self.control.clear();
        self.peer_control = 0;
        self.push_control(Frame::go_away(1));
        for stream in streams {
            self.events.push_back(YamuxOutput::StreamClosed { stream });
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KEEPALIVE_INTERVAL_MS;
    use minip2p_platform::{Deadline, Now};

    fn outbound(session: &mut YamuxSession) -> Vec<u8> {
        session.poll_frame().expect("outbound Yamux frame")
    }

    fn decode(bytes: &[u8]) -> Frame {
        let mut decoder = FrameDecoder::new(u32::MAX);
        decoder.push(bytes);
        decoder.next_frame().unwrap().unwrap()
    }

    fn config() -> YamuxConfig {
        YamuxConfig {
            max_streams: 8,
            max_buffered_send: DEFAULT_RECEIVE_WINDOW as usize,
            max_total_buffered_send: DEFAULT_RECEIVE_WINDOW as usize * 2,
            ..YamuxConfig::default()
        }
    }

    #[test]
    fn clients_use_odd_ids_and_servers_use_even_ids() {
        let mut client = YamuxSession::new(YamuxRole::Client);
        let mut server = YamuxSession::new(YamuxRole::Server);
        assert_eq!(client.open_stream().unwrap(), 1);
        assert_eq!(client.open_stream().unwrap(), 3);
        assert_eq!(server.open_stream().unwrap(), 2);
        assert_eq!(server.open_stream().unwrap(), 4);
    }

    #[test]
    fn remote_stream_ids_exclude_the_reserved_session_id() {
        let client = YamuxSession::new(YamuxRole::Client);
        let server = YamuxSession::new(YamuxRole::Server);

        assert!(!client.valid_remote_stream_id(0));
        assert!(client.valid_remote_stream_id(2));
        assert!(!client.valid_remote_stream_id(1));
        assert!(!server.valid_remote_stream_id(0));
        assert!(server.valid_remote_stream_id(1));
        assert!(!server.valid_remote_stream_id(2));
    }

    #[test]
    fn syn_and_ack_piggyback_on_first_data_frames() {
        let mut client = YamuxSession::new(YamuxRole::Client);
        let mut server = YamuxSession::new(YamuxRole::Server);
        let stream = client.open_stream().unwrap();
        client.send(stream, Bytes::from(b"hello".to_vec())).unwrap();
        let opening = outbound(&mut client);
        assert_eq!(decode(&opening).flags(), FLAG_SYN);
        server.handle_data(&opening).unwrap();
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::IncomingStream { stream })
        );
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::Data {
                stream,
                data: b"hello".to_vec()
            })
        );
        server.send(stream, Bytes::from(b"world".to_vec())).unwrap();
        let response = outbound(&mut server);
        assert_eq!(decode(&response).flags(), FLAG_ACK);
        client.handle_data(&response).unwrap();
        assert!(client.is_acknowledged(stream).unwrap());
        assert_eq!(
            client.poll_output(),
            Some(YamuxOutput::Data {
                stream,
                data: b"world".to_vec()
            })
        );
    }

    #[test]
    fn server_opened_stream_completes_a_bidirectional_lifecycle() {
        let mut client = YamuxSession::new(YamuxRole::Client);
        let mut server = YamuxSession::new(YamuxRole::Server);
        let stream = server.open_stream().unwrap();
        server
            .send(stream, Bytes::from(b"request".to_vec()))
            .unwrap();
        client.handle_data(&outbound(&mut server)).unwrap();
        assert_eq!(
            client.poll_output(),
            Some(YamuxOutput::IncomingStream { stream })
        );
        assert_eq!(
            client.poll_output(),
            Some(YamuxOutput::Data {
                stream,
                data: b"request".to_vec()
            })
        );

        client
            .send(stream, Bytes::from(b"response".to_vec()))
            .unwrap();
        server.handle_data(&outbound(&mut client)).unwrap();
        assert!(server.is_acknowledged(stream).unwrap());
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::Data {
                stream,
                data: b"response".to_vec()
            })
        );

        server.close_write(stream).unwrap();
        client.handle_data(&outbound(&mut server)).unwrap();
        assert_eq!(
            client.poll_output(),
            Some(YamuxOutput::RemoteWriteClosed { stream })
        );
        client.close_write(stream).unwrap();
        server.handle_data(&outbound(&mut client)).unwrap();
        assert_eq!(
            client.poll_output(),
            Some(YamuxOutput::StreamClosed { stream })
        );
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::RemoteWriteClosed { stream })
        );
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::StreamClosed { stream })
        );
    }

    #[test]
    fn idle_open_and_accept_emit_standalone_control_frames() {
        let mut client = YamuxSession::new(YamuxRole::Client);
        let mut server = YamuxSession::new(YamuxRole::Server);
        let stream = client.open_stream().unwrap();
        let syn = outbound(&mut client);
        let frame = decode(&syn);
        assert_eq!(frame.frame_type(), FrameType::WindowUpdate);
        assert_eq!(frame.flags(), FLAG_SYN);
        server.handle_data(&syn).unwrap();
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::IncomingStream { stream })
        );
        let ack = outbound(&mut server);
        assert_eq!(decode(&ack).flags(), FLAG_ACK);
        client.handle_data(&ack).unwrap();
        assert!(client.is_acknowledged(stream).unwrap());
    }

    #[test]
    fn accepted_bytes_count_until_pulled_and_queue_past_the_window() {
        let mut limits = config();
        limits.max_buffered_send *= 2;
        let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let stream = client.open_stream().unwrap();
        let data = Bytes::from(alloc::vec![7; DEFAULT_RECEIVE_WINDOW as usize + 5]);
        // Peer credit does not decide acceptance; only the caps do.
        client.send(stream, data).unwrap();
        assert_eq!(
            client.total_buffered_send(),
            DEFAULT_RECEIVE_WINDOW as usize + 5
        );
        let first = outbound(&mut client);
        assert_eq!(
            decode(&first).payload().len(),
            DEFAULT_RECEIVE_WINDOW as usize
        );
        assert_eq!(client.total_buffered_send(), 5);
        assert_eq!(client.poll_frame(), None, "no credit, no frame");

        let update = Frame::window_update(stream, FLAG_ACK, 5).unwrap().encode();
        client.handle_data(&update).unwrap();
        assert_eq!(decode(&outbound(&mut client)).payload(), &[7; 5]);
        assert_eq!(client.total_buffered_send(), 0);
    }

    #[test]
    fn partial_windows_frame_queued_bytes_in_order() {
        let mut limits = config();
        limits.max_frame_len = 4;
        let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let stream = client.open_stream().unwrap();
        client.streams.get_mut(&stream).unwrap().send_window = 10;
        client
            .send(stream, Bytes::from(b"abcdefghijkl".to_vec()))
            .unwrap();
        client
            .send(stream, Bytes::from(b"mnopqrstu".to_vec()))
            .unwrap();
        let payloads = |client: &mut YamuxSession| {
            core::iter::from_fn(|| client.poll_output())
                .map(|output| match output {
                    YamuxOutput::Outbound(bytes) => decode(&bytes).payload().to_vec(),
                    output => panic!("expected outbound bytes, got {output:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(payloads(&mut client), [&b"abcd"[..], b"efgh", b"ij"]);

        for (credit, expected) in [
            (1, &[&b"k"[..]][..]),
            (3, &[b"l", b"mn"]),
            (9, &[b"opqr", b"stu"]),
        ] {
            let update = Frame::window_update(stream, 0, credit).unwrap().encode();
            client.handle_data(&update).unwrap();
            assert_eq!(payloads(&mut client), expected);
        }
        assert_eq!(client.total_buffered_send(), 0);
    }

    #[test]
    fn queued_chunks_retain_at_most_twice_their_unsent_bytes() {
        let mut client = YamuxSession::with_config(YamuxRole::Client, config()).unwrap();
        let stream = client.open_stream().unwrap();
        let source = Bytes::from(alloc::vec![1; 100]);
        let retains_source = |client: &YamuxSession| {
            client.streams[&stream].send_buffer.iter().any(|chunk| {
                chunk.bytes.as_ptr() >= source.as_ptr()
                    && chunk.bytes.as_ptr() < source.as_ptr().wrapping_add(100)
            })
        };
        client.streams.get_mut(&stream).unwrap().send_window = 40;
        client.send(stream, source.clone()).unwrap();
        while client.poll_frame().is_some() {}
        assert_eq!(client.total_buffered_send(), 60);
        assert!(retains_source(&client), "a tail of 60/100 stays a slice");

        let update = Frame::window_update(stream, 0, 20).unwrap().encode();
        client.handle_data(&update).unwrap();
        while client.poll_frame().is_some() {}
        assert_eq!(client.total_buffered_send(), 40);
        assert!(
            !retains_source(&client),
            "a tail under half its counted length is copied out"
        );
    }

    #[test]
    fn a_write_past_the_caps_returns_the_exact_unsent_suffix() {
        let mut limits = config();
        limits.max_buffered_send = 4;
        limits.max_total_buffered_send = 6;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let first = session.open_stream().unwrap();
        let second = session.open_stream().unwrap();

        let unsent = |result| match result {
            Err(YamuxError::Full { unsent, .. }) => unsent,
            other => panic!("expected Full, got {other:?}"),
        };
        assert_eq!(
            unsent(session.send(first, Bytes::from_static(b"abcde"))),
            &b"e"[..]
        );
        assert_eq!(session.total_buffered_send(), 4);
        // The shared cap leaves two bytes for the second stream.
        assert_eq!(
            unsent(session.send(second, Bytes::from_static(b"xyz"))),
            &b"z"[..]
        );
        assert_eq!(
            unsent(session.send(second, Bytes::from_static(b"!"))),
            &b"!"[..],
            "nothing fits: the whole payload comes back"
        );
        assert_eq!(session.total_buffered_send(), 6);
    }

    #[test]
    fn resending_tails_after_writable_reproduces_the_byte_stream() {
        let mut limits = config();
        limits.max_buffered_send = 8;
        limits.max_frame_len = 3;
        let mut client = YamuxSession::with_config(YamuxRole::Client, limits.clone()).unwrap();
        let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
        let stream = client.open_stream().unwrap();
        let payload: Vec<u8> = (0..100).collect();
        let mut pending = Some(Bytes::from(payload.clone()));
        let mut received = Vec::new();
        let mut writable_count = 0;
        while pending.is_some() || client.has_frames() {
            if let Some(data) = pending.take() {
                match client.send(stream, data) {
                    Ok(()) => {}
                    Err(YamuxError::Full { unsent, .. }) => pending = Some(unsent),
                    Err(error) => panic!("{error}"),
                }
            }
            while let Some(frame) = client.poll_frame() {
                server.handle_data(&frame).unwrap();
            }
            while let Some(event) = client.poll_event() {
                assert_eq!(event, YamuxOutput::Writable { stream });
                writable_count += 1;
            }
            while let Some(output) = server.poll_output() {
                match output {
                    YamuxOutput::Data { data, .. } => received.extend(data),
                    YamuxOutput::Outbound(frame) => client.handle_data(&frame).unwrap(),
                    _ => {}
                }
            }
        }
        assert_eq!(received, payload);
        assert!(writable_count > 0);
    }

    #[test]
    fn writable_fires_once_per_full_and_for_shared_cap_blocks() {
        let mut limits = config();
        limits.max_buffered_send = 8;
        limits.max_total_buffered_send = 8;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let busy = session.open_stream().unwrap();
        let starved = session.open_stream().unwrap();
        session.send(busy, Bytes::from(alloc::vec![1; 8])).unwrap();
        // `starved` has nothing queued; only the shared cap blocks it.
        assert!(matches!(
            session.send(starved, Bytes::from_static(b"x")),
            Err(YamuxError::Full { .. })
        ));
        assert!(matches!(
            session.send(busy, Bytes::from_static(b"y")),
            Err(YamuxError::Full { .. })
        ));
        while session.poll_frame().is_some() {}
        let mut woken = Vec::new();
        while let Some(event) = session.poll_event() {
            if let YamuxOutput::Writable { stream } = event {
                woken.push(stream);
            }
        }
        woken.sort_unstable();
        assert_eq!(woken, [busy, starved]);

        session.send(busy, Bytes::from_static(b"z")).unwrap();
        while session.poll_frame().is_some() {}
        assert_eq!(
            session.poll_event(),
            None,
            "no second Writable without a Full"
        );
    }

    #[test]
    fn a_reset_that_frees_the_shared_cap_wakes_blocked_streams() {
        let mut limits = config();
        limits.max_buffered_send = 8;
        limits.max_total_buffered_send = 8;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let hog = session.open_stream().unwrap();
        let blocked = session.open_stream().unwrap();
        // No remote credit, so nothing is ever framed from `hog`.
        session.streams.get_mut(&hog).unwrap().send_window = 0;
        session.send(hog, Bytes::from(alloc::vec![1; 8])).unwrap();
        assert!(matches!(
            session.send(blocked, Bytes::from_static(b"x")),
            Err(YamuxError::Full { .. })
        ));

        session.reset(hog).unwrap();
        let events: Vec<_> = core::iter::from_fn(|| session.poll_event()).collect();
        assert!(
            events.contains(&YamuxOutput::Writable { stream: blocked }),
            "freeing the shared cap must wake the blocked stream: {events:?}"
        );
    }

    #[test]
    fn a_writable_already_queued_is_dropped_when_the_write_side_closes() {
        let mut limits = config();
        limits.max_buffered_send = 4;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let stream = session.open_stream().unwrap();
        assert!(matches!(
            session.send(stream, Bytes::from_static(b"abcdef")),
            Err(YamuxError::Full { .. })
        ));
        while session.poll_frame().is_some() {}
        session.close_write(stream).unwrap();
        assert_eq!(session.poll_event(), None);
    }

    #[test]
    fn a_writable_already_queued_is_dropped_when_the_session_goes_away() {
        let mut limits = config();
        limits.max_buffered_send = 4;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let stream = session.open_stream().unwrap();
        assert!(matches!(
            session.send(stream, Bytes::from_static(b"abcdef")),
            Err(YamuxError::Full { .. })
        ));
        while session.poll_frame().is_some() {}
        session.go_away(0);
        let events: Vec<_> = core::iter::from_fn(|| session.poll_event()).collect();
        assert_eq!(events, [YamuxOutput::StreamClosed { stream }]);
    }

    #[test]
    fn local_resets_do_not_spend_the_peer_control_reserve() {
        let mut limits = config();
        limits.max_pending_control = 1;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        for _ in 0..3 {
            let stream = session.open_stream().unwrap();
            assert!(session.poll_frame().is_some(), "announce the stream");
            session.reset(stream).unwrap();
        }
        session
            .handle_data(&Frame::ping(FLAG_SYN, 1).unwrap().encode())
            .expect("one peer ping fits the reserve");
    }

    #[test]
    fn writable_never_fires_after_the_write_side_ends() {
        let mut limits = config();
        limits.max_buffered_send = 4;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let closed = session.open_stream().unwrap();
        let reset = session.open_stream().unwrap();
        for stream in [closed, reset] {
            assert!(matches!(
                session.send(stream, Bytes::from_static(b"abcdef")),
                Err(YamuxError::Full { .. })
            ));
        }
        session.close_write(closed).unwrap();
        assert!(matches!(
            session.send(closed, Bytes::from_static(b"late")),
            Err(YamuxError::StreamWriteClosed(_))
        ));
        session.reset(reset).unwrap();
        while session.poll_frame().is_some() {}
        while let Some(event) = session.poll_event() {
            assert!(
                !matches!(event, YamuxOutput::Writable { .. }),
                "unexpected {event:?}"
            );
        }
    }

    #[test]
    fn resets_of_peer_opened_streams_spend_the_control_reserve() {
        let mut limits = config();
        limits.max_pending_control = 2;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        // The peer opens a stream, we reset it, and the slot is free again:
        // only the reserve bounds the RSTs a non-reading peer piles up.
        let mut reset_inbound = |stream: u32| {
            session
                .handle_data(&Frame::window_update(stream, FLAG_SYN, 0).unwrap().encode())
                .unwrap();
            session.reset(stream)
        };
        reset_inbound(2).unwrap();
        reset_inbound(4).unwrap();
        assert!(matches!(
            reset_inbound(6),
            Err(YamuxError::ControlReserveExhausted { limit: 2 })
        ));
        let frames: Vec<_> = core::iter::from_fn(|| session.poll_frame()).collect();
        assert_eq!(frames.len(), 1, "only the protocol GoAway remains");
        assert_eq!(decode(&frames[0]).frame_type(), FrameType::GoAway);
    }

    #[test]
    fn a_peer_flooding_pings_cannot_grow_control_past_the_reserve() {
        let mut limits = config();
        limits.max_pending_control = 4;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let ping = Frame::ping(FLAG_SYN, 1).unwrap().encode();
        for _ in 0..4 {
            session.handle_data(&ping).unwrap();
        }
        assert!(matches!(
            session.handle_data(&ping),
            Err(YamuxError::ControlReserveExhausted { limit: 4 })
        ));
        let frames: Vec<_> = core::iter::from_fn(|| session.poll_frame()).collect();
        assert_eq!(frames.len(), 1, "only the protocol GoAway remains");
        assert_eq!(decode(&frames[0]).frame_type(), FrameType::GoAway);
    }

    #[test]
    fn inbound_events_do_not_wait_behind_unpulled_frames() {
        let mut client = YamuxSession::new(YamuxRole::Client);
        let mut server = YamuxSession::new(YamuxRole::Server);
        let stream = client.open_stream().unwrap();
        client.send(stream, Bytes::from_static(b"hi")).unwrap();
        server.handle_data(&outbound(&mut client)).unwrap();
        server
            .send(stream, Bytes::from(alloc::vec![0; 1000]))
            .unwrap();
        server
            .handle_data(&Frame::ping(FLAG_SYN, 7).unwrap().encode())
            .unwrap();
        // Frames are queued, yet events come out without pulling any.
        assert_eq!(
            server.poll_event(),
            Some(YamuxOutput::IncomingStream { stream })
        );
        assert!(matches!(
            server.poll_event(),
            Some(YamuxOutput::Data { .. })
        ));
        assert!(server.has_frames());
    }

    #[test]
    fn close_waits_for_buffered_data_and_reset_is_immediate() {
        let mut session = YamuxSession::with_config(YamuxRole::Client, config()).unwrap();
        let stream = session.open_stream().unwrap();
        session.streams.get_mut(&stream).unwrap().send_window = 0;
        session.send(stream, Bytes::from_static(b"queued")).unwrap();
        session.close_write(stream).unwrap();
        assert!(session.streams[&stream].close_pending);
        // Only the standalone SYN can go before credit arrives.
        assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_SYN);
        assert_eq!(session.poll_frame(), None);
        session
            .handle_data(&Frame::window_update(stream, FLAG_ACK, 6).unwrap().encode())
            .unwrap();
        let data = decode(&outbound(&mut session));
        assert_eq!(data.payload(), b"queued");
        assert_eq!(data.flags(), FLAG_FIN, "FIN rides on the last data frame");

        let reset_stream = session.open_stream().unwrap();
        assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_SYN);
        session.reset(reset_stream).unwrap();
        assert_eq!(
            session.poll_output(),
            Some(YamuxOutput::StreamClosed {
                stream: reset_stream
            })
        );
        assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_RST);
    }

    /// A server whose peer opened stream 1 and sent `len` bytes on it.
    fn server_with_delivered(limits: YamuxConfig, len: usize, flags: u16) -> YamuxSession {
        let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
        let frame = Frame::encode_data(1, FLAG_SYN | flags, &alloc::vec![7; len]).unwrap();
        server.handle_data(&frame).unwrap();
        // The SYN's ACK is not credit; take it so only window updates remain.
        assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_ACK);
        server
    }

    #[test]
    fn window_credit_returns_only_for_acknowledged_bytes() {
        let window = DEFAULT_RECEIVE_WINDOW as usize;
        let mut server = server_with_delivered(config(), window, 0);
        while server.poll_event().is_some() {}
        assert_eq!(server.poll_frame(), None, "unread bytes return no credit");
        // A peer past the budget is violating the window it was given.
        let more = Frame::encode_data(1, 0, &[0]).unwrap();
        assert_eq!(
            server_with_delivered(config(), window, 0).handle_data(&more),
            Err(YamuxError::ReceiveWindowExceeded { stream: 1 })
        );

        server.ack(1, window / 2).unwrap();
        assert_eq!(server.poll_frame(), None, "credit returns in half windows");
        server.ack(1, 1).unwrap();
        let update = decode(&outbound(&mut server));
        assert_eq!(update.frame_type(), FrameType::WindowUpdate);
        assert_eq!(update.value() as usize, window / 2 + 1);
        server.handle_data(&more).unwrap();
    }

    #[test]
    fn an_over_ack_names_the_stream_and_both_counts_and_acks_nothing() {
        let mut server = server_with_delivered(config(), 10, 0);
        assert_eq!(
            server.ack(1, 11),
            Err(YamuxError::AckExceedsDelivered {
                stream: 1,
                acked: 11,
                unacked: 10,
            })
        );
        server.ack(1, 10).unwrap();
        assert_eq!(
            server.ack(1, 1),
            Err(YamuxError::AckExceedsDelivered {
                stream: 1,
                acked: 1,
                unacked: 0,
            })
        );
        // Unknown streams have nothing to acknowledge.
        server.ack(9, 1_000).unwrap();
    }

    #[test]
    fn a_closed_stream_keeps_its_slot_until_its_bytes_are_acknowledged() {
        let mut limits = config();
        limits.max_streams = 1;
        let mut server = server_with_delivered(limits, 10, FLAG_FIN);
        server.close_write(1).unwrap();
        while server.poll_frame().is_some() {}
        assert!(
            server
                .poll_events()
                .contains(&YamuxOutput::StreamClosed { stream: 1 })
        );
        let open = |stream| Frame::window_update(stream, FLAG_SYN, 0).unwrap().encode();

        // Unsettled: the next stream is refused, locally and from the peer.
        assert_eq!(server.open_stream(), Err(YamuxError::TooManyStreams));
        server.handle_data(&open(3)).unwrap();
        assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_RST);

        server.ack(1, 4).unwrap();
        server.handle_data(&open(5)).unwrap();
        assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_RST);
        assert_eq!(
            server.ack(1, 7),
            Err(YamuxError::AckExceedsDelivered {
                stream: 1,
                acked: 7,
                unacked: 6,
            })
        );

        // The last acknowledged byte frees the slot.
        server.ack(1, 6).unwrap();
        server.handle_data(&open(7)).unwrap();
        assert_eq!(
            server.poll_events(),
            alloc::vec![YamuxOutput::IncomingStream { stream: 7 }]
        );
        server.ack(1, 1).unwrap();
    }

    #[test]
    fn stream_churn_with_an_unread_reader_stays_within_max_streams_times_the_window() {
        let mut limits = config();
        limits.max_streams = 4;
        let window = limits.receive_window as usize;
        let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
        let mut delivered = 0;
        // The peer opens a stream, fills its window, and resets it, over and
        // over; the reader never acknowledges anything.
        for stream in (1..200).step_by(2) {
            let frame = Frame::encode_data(stream, FLAG_SYN, &alloc::vec![7; window]).unwrap();
            server.handle_data(&frame).unwrap();
            server
                .handle_data(&Frame::data(stream, FLAG_RST, Vec::new()).unwrap().encode())
                .unwrap();
            while server.poll_frame().is_some() {}
            for event in server.poll_events() {
                if let YamuxOutput::Data { data, .. } = event {
                    delivered += data.len();
                }
            }
        }
        assert_eq!(delivered, 4 * window, "refused streams deliver nothing");
    }

    #[test]
    fn a_local_reset_abandons_unacknowledged_bytes() {
        let mut limits = config();
        limits.max_streams = 1;
        let mut server = server_with_delivered(limits.clone(), 10, 0);
        server.reset(1).unwrap();
        assert_eq!(server.open_stream(), Ok(2), "the reset settled stream 1");

        // A stream the peer reset stays unsettled until our own reset.
        let mut server = server_with_delivered(limits, 10, 0);
        server
            .handle_data(&Frame::data(1, FLAG_RST, Vec::new()).unwrap().encode())
            .unwrap();
        assert_eq!(server.open_stream(), Err(YamuxError::TooManyStreams));
        server.reset(1).unwrap();
        assert_eq!(server.open_stream(), Ok(2));
    }

    #[test]
    fn inbound_capacity_resets_only_excess_stream() {
        let mut limits = config();
        limits.max_streams = 1;
        let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
        server
            .handle_data(&Frame::window_update(1, FLAG_SYN, 0).unwrap().encode())
            .unwrap();
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::IncomingStream { stream: 1 })
        );
        server
            .handle_data(&Frame::window_update(3, FLAG_SYN, 0).unwrap().encode())
            .unwrap();
        assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_RST);
        assert_eq!(server.stream_count(), 1);
    }

    #[test]
    fn local_capacity_and_id_exhaustion_do_not_damage_existing_streams() {
        let mut limits = config();
        limits.max_streams = 1;
        let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        assert_eq!(client.open_stream().unwrap(), 1);
        assert_eq!(client.open_stream(), Err(YamuxError::TooManyStreams));
        client.config.max_streams = 2;
        client.next_stream_id = Some(u32::MAX);
        assert_eq!(client.open_stream().unwrap(), u32::MAX);
        client.config.max_streams = 3;
        assert_eq!(client.open_stream(), Err(YamuxError::StreamsExhausted));
        assert_eq!(client.stream_count(), 2);
    }

    #[test]
    fn receive_window_violation_emits_protocol_go_away() {
        let mut server = YamuxSession::new(YamuxRole::Server);
        let oversized = Frame::data(
            1,
            FLAG_SYN,
            alloc::vec![0; DEFAULT_RECEIVE_WINDOW as usize + 1],
        )
        .unwrap()
        .encode();
        assert_eq!(
            server.handle_data(&oversized),
            Err(YamuxError::ReceiveWindowExceeded { stream: 1 })
        );
        let go_away = decode(&outbound(&mut server));
        assert_eq!(go_away.frame_type(), FrameType::GoAway);
        assert_eq!(go_away.value(), 1);
        assert_eq!(server.handle_data(&[]), Err(YamuxError::Failed));
    }

    #[test]
    fn non_empty_data_after_remote_fin_is_a_protocol_error() {
        let mut server = YamuxSession::new(YamuxRole::Server);
        server
            .handle_data(
                &Frame::data(1, FLAG_SYN | FLAG_FIN, b"final".to_vec())
                    .unwrap()
                    .encode(),
            )
            .unwrap();
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::IncomingStream { stream: 1 })
        );
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::Data {
                stream: 1,
                data: b"final".to_vec()
            })
        );
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::RemoteWriteClosed { stream: 1 })
        );

        server
            .handle_data(&Frame::data(1, 0, Vec::new()).unwrap().encode())
            .unwrap();
        server
            .handle_data(&Frame::window_update(1, 0, 1).unwrap().encode())
            .unwrap();

        assert_eq!(
            server.handle_data(&Frame::data(1, 0, b"late".to_vec()).unwrap().encode()),
            Err(YamuxError::Protocol("data after FIN"))
        );
        let go_away = decode(&outbound(&mut server));
        assert_eq!(go_away.frame_type(), FrameType::GoAway);
        assert_eq!(go_away.value(), 1);
        assert_eq!(
            server.poll_output(),
            Some(YamuxOutput::StreamClosed { stream: 1 })
        );
    }

    #[test]
    fn coalesced_data_cannot_spend_unadvertised_window_credit() {
        let mut server = YamuxSession::new(YamuxRole::Server);
        let first_len = DEFAULT_RECEIVE_WINDOW / 2 + 1;
        let second_len = DEFAULT_RECEIVE_WINDOW - first_len + 1;
        let mut coalesced = Frame::data(1, FLAG_SYN, alloc::vec![1; first_len as usize])
            .unwrap()
            .encode();
        coalesced.extend(
            Frame::data(1, 0, alloc::vec![2; second_len as usize])
                .unwrap()
                .encode(),
        );

        assert_eq!(
            server.handle_data(&coalesced),
            Err(YamuxError::ReceiveWindowExceeded { stream: 1 })
        );
        let go_away = decode(&outbound(&mut server));
        assert_eq!(go_away.frame_type(), FrameType::GoAway);
        assert_eq!(go_away.value(), 1);
    }

    #[test]
    fn ping_is_echoed_and_go_away_closes_streams() {
        let mut session = YamuxSession::new(YamuxRole::Client);
        let stream = session.open_stream().unwrap();
        session
            .handle_data(&Frame::ping(FLAG_SYN, 42).unwrap().encode())
            .unwrap();
        let pong = decode(&outbound(&mut session));
        assert_eq!(pong.flags(), FLAG_ACK);
        assert_eq!(pong.value(), 42);

        session.handle_data(&Frame::go_away(0).encode()).unwrap();
        assert_eq!(
            session.poll_output(),
            Some(YamuxOutput::GoAwayReceived { code: 0 })
        );
        assert_eq!(
            session.poll_output(),
            Some(YamuxOutput::StreamClosed { stream })
        );
        assert_eq!(session.open_stream(), Err(YamuxError::SessionClosed));
    }

    #[test]
    fn quiet_session_sends_ping_after_keepalive_interval() {
        let mut session = YamuxSession::new(YamuxRole::Client);
        session.poll(Now::from_millis(0)).unwrap();
        assert_eq!(session.poll_output(), None, "nothing is due at t=0");

        session
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS - 1))
            .unwrap();
        assert_eq!(
            session.poll_output(),
            None,
            "a ping one millisecond early would be early"
        );

        session
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .unwrap();
        let ping = decode(&outbound(&mut session));
        assert_eq!(ping.frame_type(), FrameType::Ping);
        assert_eq!(ping.flags(), FLAG_SYN);
        assert_ne!(ping.value(), 0, "the nonce is an opaque non-zero value");
        assert_eq!(session.poll_output(), None);
    }

    #[test]
    fn inbound_traffic_defers_the_keepalive_ping() {
        let mut session = YamuxSession::new(YamuxRole::Server);
        session.poll(Now::from_millis(0)).unwrap();

        session
            .handle_data(&Frame::ping(FLAG_SYN, 7).unwrap().encode())
            .unwrap();
        let pong = decode(&outbound(&mut session));
        assert_eq!(pong.flags(), FLAG_ACK);
        assert_eq!(pong.value(), 7);

        session
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .unwrap();
        assert_eq!(
            session.poll_output(),
            None,
            "the echoed ping was traffic; the next keepalive is another interval out"
        );

        session
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS * 2))
            .unwrap();
        let ping = decode(&outbound(&mut session));
        assert_eq!(ping.frame_type(), FrameType::Ping);
        assert_eq!(ping.flags(), FLAG_SYN);
    }

    #[test]
    fn outbound_traffic_defers_the_keepalive_ping() {
        let mut session = YamuxSession::new(YamuxRole::Client);
        session.poll(Now::from_millis(0)).unwrap();
        let stream = session.open_stream().unwrap();
        session
            .send(stream, Bytes::from(b"hello".to_vec()))
            .unwrap();
        assert_eq!(decode(&outbound(&mut session)).payload(), b"hello");

        session
            .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
            .unwrap();
        assert_eq!(
            session.poll_output(),
            None,
            "sending on a stream is traffic; keepalive waits another interval"
        );
    }

    #[test]
    fn next_deadline_is_the_keepalive_interval_after_the_first_poll() {
        let mut session = YamuxSession::new(YamuxRole::Client);
        assert_eq!(
            session.next_deadline(),
            None,
            "no sample yet means no timeline to answer on"
        );

        session.poll(Now::from_millis(10)).unwrap();
        assert_eq!(
            session.next_deadline(),
            Some(Deadline::from_millis(10 + KEEPALIVE_INTERVAL_MS))
        );

        session
            .poll(Now::from_millis(10 + KEEPALIVE_INTERVAL_MS))
            .unwrap();
        let _ = outbound(&mut session);
        assert_eq!(
            session.next_deadline(),
            Some(Deadline::from_millis(10 + KEEPALIVE_INTERVAL_MS * 2))
        );
    }

    #[test]
    fn a_closed_session_does_not_keepalive() {
        let mut session = YamuxSession::new(YamuxRole::Client);
        session.poll(Now::from_millis(0)).unwrap();
        session.go_away(0);
        let _ = outbound(&mut session);

        assert_eq!(
            session.poll(Now::from_millis(KEEPALIVE_INTERVAL_MS)),
            Err(YamuxError::SessionClosed)
        );
        assert_eq!(session.poll_output(), None);
        assert_eq!(session.next_deadline(), None);
    }

    #[test]
    fn rst_before_ack_surfaces_stream_closed() {
        let mut client = YamuxSession::new(YamuxRole::Client);
        let stream = client.open_stream().unwrap();
        client
            .handle_data(&Frame::data(stream, FLAG_RST, Vec::new()).unwrap().encode())
            .unwrap();
        assert_eq!(
            client.poll_output(),
            Some(YamuxOutput::StreamClosed { stream })
        );
    }
}
