use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::{
    DEFAULT_RECEIVE_WINDOW, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Frame, FrameDecoder, FrameType,
    YamuxConfig, YamuxError, YamuxOutput, YamuxRole,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenFlag {
    Syn,
    Ack,
}

#[derive(Debug)]
struct StreamState {
    locally_opened: bool,
    pending_open: Option<OpenFlag>,
    acknowledged: bool,
    send_window: u32,
    receive_window: u32,
    delivered_since_update: u32,
    pending_credit: u64,
    send_buffer: VecDeque<Vec<u8>>,
    buffered_send: usize,
    close_pending: bool,
    local_write_closed: bool,
    remote_write_closed: bool,
}

impl StreamState {
    fn outbound(config: &YamuxConfig) -> Self {
        Self {
            locally_opened: true,
            pending_open: Some(OpenFlag::Syn),
            acknowledged: false,
            send_window: DEFAULT_RECEIVE_WINDOW,
            receive_window: DEFAULT_RECEIVE_WINDOW,
            delivered_since_update: 0,
            pending_credit: u64::from(config.receive_window - DEFAULT_RECEIVE_WINDOW),
            send_buffer: VecDeque::new(),
            buffered_send: 0,
            close_pending: false,
            local_write_closed: false,
            remote_write_closed: false,
        }
    }

    fn inbound(config: &YamuxConfig, send_window: u32) -> Self {
        Self {
            locally_opened: false,
            pending_open: Some(OpenFlag::Ack),
            acknowledged: false,
            send_window,
            receive_window: DEFAULT_RECEIVE_WINDOW,
            delivered_since_update: 0,
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

    fn has_deferred_control(&self) -> bool {
        self.pending_open.is_some() || self.pending_credit != 0
    }
}

/// Caller-driven Yamux stream-multiplexing session.
pub struct YamuxSession {
    role: YamuxRole,
    config: YamuxConfig,
    decoder: FrameDecoder,
    streams: BTreeMap<u32, StreamState>,
    next_stream_id: Option<u32>,
    pending: VecDeque<YamuxOutput>,
    total_buffered_send: usize,
    failed: bool,
    local_go_away: bool,
    remote_go_away: bool,
}

impl YamuxSession {
    /// Creates a session with [`YamuxConfig::default`].
    pub fn new(role: YamuxRole) -> Self {
        Self::with_config(role, YamuxConfig::default())
            .expect("the default Yamux configuration is valid")
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
        let next_stream_id = Some(match role {
            YamuxRole::Client => 1,
            YamuxRole::Server => 2,
        });
        Ok(Self {
            role,
            decoder: FrameDecoder::new(config.max_frame_len),
            config,
            streams: BTreeMap::new(),
            next_stream_id,
            pending: VecDeque::new(),
            total_buffered_send: 0,
            failed: false,
            local_go_away: false,
            remote_go_away: false,
        })
    }

    /// Opens a local stream and returns its role-partitioned identifier.
    ///
    /// The first data/control frame carries `SYN`; if the caller drains output
    /// before sending, [`YamuxSession::poll_output`] emits a standalone
    /// window-update frame carrying `SYN`.
    pub fn open_stream(&mut self) -> Result<u32, YamuxError> {
        self.ensure_active()?;
        if self.streams.len() >= self.config.max_streams {
            return Err(YamuxError::TooManyStreams);
        }
        let stream = self.next_stream_id.ok_or(YamuxError::StreamsExhausted)?;
        self.next_stream_id = stream.checked_add(2);
        self.streams
            .insert(stream, StreamState::outbound(&self.config));
        Ok(stream)
    }

    /// Sends bytes on a stream, queueing the portion beyond remote credit.
    ///
    /// Queue-cap checks are atomic: on [`YamuxError::SendBufferFull`] no part
    /// of this call was queued or framed, and the stream remains usable.
    pub fn send(&mut self, stream: u32, data: Vec<u8>) -> Result<(), YamuxError> {
        self.ensure_active()?;
        let max_frame_len = self.config.max_frame_len as usize;
        let total_before = self.total_buffered_send;
        let mut frames = Vec::new();
        let buffered_added;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .ok_or(YamuxError::UnknownStream(stream))?;
            if state.local_write_closed || state.close_pending {
                return Err(YamuxError::StreamWriteClosed(stream));
            }

            let immediate_len = data.len().min(state.send_window as usize);
            let queued_len = data.len() - immediate_len;
            let per_stream_after = state.buffered_send.checked_add(queued_len);
            let total_after = total_before.checked_add(queued_len);
            if per_stream_after.is_none_or(|value| value > self.config.max_buffered_send)
                || total_after.is_none_or(|value| value > self.config.max_total_buffered_send)
            {
                return Err(YamuxError::SendBufferFull {
                    stream,
                    attempted: queued_len,
                    per_stream_limit: self.config.max_buffered_send,
                    total_limit: self.config.max_total_buffered_send,
                });
            }

            state.send_window -= immediate_len as u32;
            if data.is_empty() && state.pending_open.is_some() {
                let flags = state.take_open_flag();
                frames.push(Frame::data(stream, flags, Vec::new())?);
            } else if immediate_len != 0 {
                let mut immediate = data[..immediate_len].to_vec();
                let mut first = true;
                while !immediate.is_empty() {
                    let rest = if immediate.len() > max_frame_len {
                        immediate.split_off(max_frame_len)
                    } else {
                        Vec::new()
                    };
                    let flags = if first { state.take_open_flag() } else { 0 };
                    frames.push(Frame::data(stream, flags, immediate)?);
                    immediate = rest;
                    first = false;
                }
            }
            if queued_len != 0 {
                state.send_buffer.push_back(data[immediate_len..].to_vec());
                state.buffered_send += queued_len;
            }
            buffered_added = queued_len;
        }
        self.total_buffered_send += buffered_added;
        self.queue_frames(frames);
        Ok(())
    }

    /// Gracefully half-closes a stream after all accepted buffered data.
    pub fn close_write(&mut self, stream: u32) -> Result<(), YamuxError> {
        self.ensure_active()?;
        let frame;
        let close_stream;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .ok_or(YamuxError::UnknownStream(stream))?;
            if state.local_write_closed || state.close_pending {
                return Ok(());
            }
            if state.buffered_send != 0 {
                state.close_pending = true;
                return Ok(());
            }
            let flags = state.take_open_flag() | FLAG_FIN;
            frame = Frame::data(stream, flags, Vec::new())?;
            state.local_write_closed = true;
            close_stream = state.remote_write_closed;
        }
        self.queue_frame(frame);
        if close_stream {
            self.remove_stream(stream, true);
        }
        Ok(())
    }

    /// Immediately resets a stream and emits [`YamuxOutput::StreamClosed`].
    pub fn reset(&mut self, stream: u32) -> Result<(), YamuxError> {
        self.ensure_active()?;
        let mut state = self
            .streams
            .remove(&stream)
            .ok_or(YamuxError::UnknownStream(stream))?;
        self.total_buffered_send -= state.buffered_send;
        let flags = state.take_open_flag() | FLAG_RST;
        self.queue_frame(Frame::data(stream, flags, Vec::new())?);
        self.pending.push_back(YamuxOutput::StreamClosed { stream });
        Ok(())
    }

    /// Gracefully terminates the whole Yamux session with `code`.
    pub fn go_away(&mut self, code: u32) {
        if self.local_go_away || self.failed {
            return;
        }
        self.local_go_away = true;
        self.queue_frame(Frame::go_away(code));
        self.close_all_streams();
        self.decoder.clear();
    }

    /// Feeds ordered bytes received from the underlying connection.
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
            if self.remote_go_away {
                self.decoder.clear();
                return Ok(());
            }
        }
    }

    /// Returns the next encoded frame or stream event.
    pub fn poll_output(&mut self) -> Option<YamuxOutput> {
        if let Some(output) = self.pending.pop_front() {
            return Some(output);
        }
        if !self.failed && !self.local_go_away && !self.remote_go_away {
            self.materialize_deferred_control();
        }
        self.pending.pop_front()
    }

    /// Returns true when no output or deferred control frame is pending.
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
            && self
                .streams
                .values()
                .all(|stream| !stream.has_deferred_control())
    }

    /// Returns the number of currently tracked streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Returns aggregate bytes queued behind remote flow-control windows.
    pub fn total_buffered_send(&self) -> usize {
        self.total_buffered_send
    }

    /// Returns whether the stream-opening `SYN` has been acknowledged.
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
                self.pending.push_back(YamuxOutput::GoAwayReceived {
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
            if self.streams.len() >= self.config.max_streams {
                self.queue_reset_for_unknown(stream)?;
                return Ok(());
            }
            self.streams.insert(
                stream,
                StreamState::inbound(&self.config, DEFAULT_RECEIVE_WINDOW),
            );
            self.pending
                .push_back(YamuxOutput::IncomingStream { stream });
        } else if !self.streams.contains_key(&stream) {
            self.queue_reset_for_unknown(stream)?;
            return Ok(());
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
            let payload_len = frame.value();
            if payload_len > state.receive_window {
                return Err(YamuxError::ReceiveWindowExceeded { stream });
            }
            state.receive_window -= payload_len;
            state.delivered_since_update = state
                .delivered_since_update
                .checked_add(payload_len)
                .ok_or(YamuxError::Protocol("receive accounting overflow"))?;
            if !frame.payload().is_empty() {
                data_output = Some(frame.payload().to_vec());
            }
            if state.delivered_since_update > self.config.receive_window / 2 {
                let credit = state.delivered_since_update;
                state.pending_credit += u64::from(credit);
                state.delivered_since_update = 0;
            }
            if flags & FLAG_FIN != 0 && !state.remote_write_closed {
                state.remote_write_closed = true;
                remote_closed = true;
            }
            fully_closed = state.remote_write_closed && state.local_write_closed;
        }
        if let Some(data) = data_output {
            self.pending.push_back(YamuxOutput::Data { stream, data });
        }
        if remote_closed {
            self.pending
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
            if self.streams.len() >= self.config.max_streams {
                self.queue_reset_for_unknown(stream)?;
                return Ok(());
            }
            let send_window = DEFAULT_RECEIVE_WINDOW
                .checked_add(frame.value())
                .ok_or(YamuxError::WindowOverflow { stream })?;
            self.streams
                .insert(stream, StreamState::inbound(&self.config, send_window));
            self.pending
                .push_back(YamuxOutput::IncomingStream { stream });
        } else if !self.streams.contains_key(&stream) {
            self.queue_reset_for_unknown(stream)?;
            return Ok(());
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

        {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("stream was inserted or checked above");
            if flags & FLAG_ACK != 0 && state.locally_opened {
                state.acknowledged = true;
            }
        }
        self.flush_buffered(stream)?;
        if !self.streams.contains_key(&stream) {
            return Ok(());
        }

        let mut remote_closed = false;
        let fully_closed;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("stream remains after flushing");
            if flags & FLAG_FIN != 0 && !state.remote_write_closed {
                state.remote_write_closed = true;
                remote_closed = true;
            }
            fully_closed = state.remote_write_closed && state.local_write_closed;
        }
        if remote_closed {
            self.pending
                .push_back(YamuxOutput::RemoteWriteClosed { stream });
        }
        if fully_closed {
            self.remove_stream(stream, true);
        }
        Ok(())
    }

    fn on_ping(&mut self, frame: Frame) -> Result<(), YamuxError> {
        if frame.flags() == FLAG_SYN {
            self.queue_frame(Frame::ping(FLAG_ACK, frame.value())?);
        }
        Ok(())
    }

    fn flush_buffered(&mut self, stream: u32) -> Result<(), YamuxError> {
        let max_frame_len = self.config.max_frame_len as usize;
        let mut frames = Vec::new();
        let mut drained = 0usize;
        let mut close_after_flush = false;
        let fully_closed;
        {
            let state = self
                .streams
                .get_mut(&stream)
                .ok_or(YamuxError::UnknownStream(stream))?;
            while state.send_window != 0 {
                let Some(mut chunk) = state.send_buffer.pop_front() else {
                    break;
                };
                let send_len = chunk
                    .len()
                    .min(state.send_window as usize)
                    .min(max_frame_len);
                let remainder = chunk.split_off(send_len);
                state.send_window -= send_len as u32;
                state.buffered_send -= send_len;
                drained += send_len;
                let flags = state.take_open_flag();
                frames.push(Frame::data(stream, flags, chunk)?);
                if !remainder.is_empty() {
                    state.send_buffer.push_front(remainder);
                }
            }
            if state.send_buffer.is_empty() && state.close_pending {
                state.close_pending = false;
                state.local_write_closed = true;
                let flags = state.take_open_flag() | FLAG_FIN;
                frames.push(Frame::data(stream, flags, Vec::new())?);
                close_after_flush = true;
            }
            fully_closed = close_after_flush && state.remote_write_closed;
        }
        self.total_buffered_send -= drained;
        self.queue_frames(frames);
        if fully_closed {
            self.remove_stream(stream, true);
        }
        Ok(())
    }

    fn materialize_deferred_control(&mut self) {
        let Some(stream) = self
            .streams
            .iter()
            .find_map(|(id, state)| state.has_deferred_control().then_some(*id))
        else {
            return;
        };
        let frame = {
            let state = self
                .streams
                .get_mut(&stream)
                .expect("selected stream exists");
            let flags = state.take_open_flag();
            let credit = state.pending_credit.min(u64::from(u32::MAX)) as u32;
            state.pending_credit -= u64::from(credit);
            state.receive_window = state
                .receive_window
                .checked_add(credit)
                .expect("pending receive credit stays within the configured window");
            Frame::window_update(stream, flags, credit)
                .expect("deferred control frame has valid stream and flags")
        };
        self.queue_frame(frame);
    }

    fn queue_reset_for_unknown(&mut self, stream: u32) -> Result<(), YamuxError> {
        self.queue_frame(Frame::data(stream, FLAG_RST, Vec::new())?);
        Ok(())
    }

    fn queue_frame(&mut self, frame: Frame) {
        self.pending
            .push_back(YamuxOutput::Outbound(frame.encode()));
    }

    fn queue_frames(&mut self, frames: Vec<Frame>) {
        for frame in frames {
            self.queue_frame(frame);
        }
    }

    fn remove_stream(&mut self, stream: u32, emit: bool) {
        if let Some(state) = self.streams.remove(&stream) {
            self.total_buffered_send -= state.buffered_send;
            if emit {
                self.pending.push_back(YamuxOutput::StreamClosed { stream });
            }
        }
    }

    fn close_all_streams(&mut self) {
        let streams = self.streams.keys().copied().collect::<Vec<_>>();
        self.streams.clear();
        self.total_buffered_send = 0;
        for stream in streams {
            self.pending.push_back(YamuxOutput::StreamClosed { stream });
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
        self.total_buffered_send = 0;
        self.decoder.clear();
        self.pending.clear();
        self.queue_frame(Frame::go_away(1));
        for stream in streams {
            self.pending.push_back(YamuxOutput::StreamClosed { stream });
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(session: &mut YamuxSession) -> Vec<u8> {
        match session.poll_output().expect("outbound Yamux frame") {
            YamuxOutput::Outbound(bytes) => bytes,
            output => panic!("expected outbound bytes, got {output:?}"),
        }
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
        client.send(stream, b"hello".to_vec()).unwrap();
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
        server.send(stream, b"world".to_vec()).unwrap();
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
        server.send(stream, b"request".to_vec()).unwrap();
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

        client.send(stream, b"response".to_vec()).unwrap();
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
    fn window_exhaustion_buffers_then_drains() {
        let mut client = YamuxSession::with_config(YamuxRole::Client, config()).unwrap();
        let stream = client.open_stream().unwrap();
        let data = alloc::vec![7; DEFAULT_RECEIVE_WINDOW as usize + 5];
        client.send(stream, data).unwrap();
        assert_eq!(client.total_buffered_send(), 5);
        let first = outbound(&mut client);
        assert_eq!(
            decode(&first).payload().len(),
            DEFAULT_RECEIVE_WINDOW as usize
        );

        let update = Frame::window_update(stream, FLAG_ACK, 5).unwrap().encode();
        client.handle_data(&update).unwrap();
        assert_eq!(client.total_buffered_send(), 0);
        assert_eq!(decode(&outbound(&mut client)).payload(), &[7; 5]);
    }

    #[test]
    fn buffer_caps_reject_atomically_and_session_survives() {
        let mut limits = config();
        limits.max_buffered_send = 4;
        limits.max_total_buffered_send = 6;
        let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
        let first = session.open_stream().unwrap();
        let second = session.open_stream().unwrap();
        session.streams.get_mut(&first).unwrap().send_window = 0;
        session.streams.get_mut(&second).unwrap().send_window = 0;

        assert!(matches!(
            session.send(first, alloc::vec![1; 5]),
            Err(YamuxError::SendBufferFull { .. })
        ));
        assert_eq!(session.total_buffered_send(), 0);
        session.send(first, alloc::vec![1; 4]).unwrap();
        assert!(matches!(
            session.send(second, alloc::vec![2; 3]),
            Err(YamuxError::SendBufferFull { .. })
        ));
        assert_eq!(session.total_buffered_send(), 4);
        session.send(second, alloc::vec![2; 2]).unwrap();
        assert_eq!(session.total_buffered_send(), 6);

        session
            .handle_data(&Frame::window_update(first, 0, 4).unwrap().encode())
            .unwrap();
        assert_eq!(session.total_buffered_send(), 2);
        session.send(second, alloc::vec![3; 2]).unwrap();
        assert_eq!(session.total_buffered_send(), 4);
    }

    #[test]
    fn close_waits_for_buffered_data_and_reset_is_immediate() {
        let mut session = YamuxSession::with_config(YamuxRole::Client, config()).unwrap();
        let stream = session.open_stream().unwrap();
        session.streams.get_mut(&stream).unwrap().send_window = 0;
        session.send(stream, b"queued".to_vec()).unwrap();
        session.close_write(stream).unwrap();
        assert!(session.streams.get(&stream).unwrap().close_pending);
        session
            .handle_data(&Frame::window_update(stream, FLAG_ACK, 6).unwrap().encode())
            .unwrap();
        let data = decode(&outbound(&mut session));
        assert_eq!(data.payload(), b"queued");
        let fin = decode(&outbound(&mut session));
        assert_eq!(fin.flags(), FLAG_FIN);

        let reset_stream = session.open_stream().unwrap();
        session.reset(reset_stream).unwrap();
        assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_SYN | FLAG_RST);
        assert_eq!(
            session.poll_output(),
            Some(YamuxOutput::StreamClosed {
                stream: reset_stream
            })
        );
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
