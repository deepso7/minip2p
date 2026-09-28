//! Per-connection state management for the QUIC transport.
//!
//! Handles the QUIC connection lifecycle, stream multiplexing, send queue
//! draining, and event emission.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use minip2p_platform::{Deadline, Now};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionState, StreamId, TransportError, TransportEvent,
};

use crate::PendingDatagram;

const SEND_BUF_SIZE: usize = 1350;

/// A queued write operation for a QUIC stream.
#[derive(Debug)]
struct PendingStreamWrite {
    /// Payload bytes to send.
    bytes: Vec<u8>,
    /// Number of bytes already sent from this write.
    offset: usize,
    /// If true, this write closes the stream's write side.
    fin: bool,
}

impl PendingStreamWrite {
    /// Creates a data write whose first `offset` bytes were already accepted
    /// by quiche.
    fn data(bytes: Vec<u8>, offset: usize) -> Self {
        Self {
            bytes,
            offset,
            fin: false,
        }
    }

    /// Creates a FIN-only write (empty payload, closes write side).
    fn fin() -> Self {
        Self {
            bytes: Vec::new(),
            offset: 0,
            fin: true,
        }
    }
}

/// Per-stream bookkeeping for half-close tracking and pending writes.
#[derive(Debug, Default)]
struct StreamRuntimeState {
    /// Outbound write queue.
    pending_writes: VecDeque<PendingStreamWrite>,
    /// Whether we have closed our write side.
    local_write_closed: bool,
    /// Whether the remote has closed their write side.
    remote_write_closed: bool,
    /// Whether an IncomingStream event was emitted for this stream.
    incoming_notified: bool,
    /// Whether a StreamClosed event was emitted.
    closed_notified: bool,
    /// Whether a StreamWriteStopped event was emitted.
    write_stopped: bool,
}

impl StreamRuntimeState {
    /// Drops every queued write, returning how many unsent bytes it held.
    fn drop_pending_writes(&mut self) -> usize {
        self.pending_writes
            .drain(..)
            .map(|write| write.bytes.len().saturating_sub(write.offset))
            .sum()
    }

    /// Returns true if both sides have closed their write side.
    fn is_fully_closed(&self) -> bool {
        self.local_write_closed && self.remote_write_closed
    }
}

pub struct QuicConnection {
    /// Logical connection id assigned by the transport.
    id: ConnectionId,
    /// The underlying quiche QUIC connection.
    conn: quiche::Connection,
    /// Connection endpoint metadata (transport address + optional peer id).
    endpoint: ConnectionEndpoint,
    /// Current connection lifecycle state.
    state: ConnectionState,
    /// Per-stream runtime state keyed by raw QUIC stream id.
    stream_states: HashMap<u64, StreamRuntimeState>,
    /// Next stream id to allocate (increments by 4 per QUIC spec).
    next_local_bidi_stream_id: u64,
    /// Number of active locally initiated bidirectional streams.
    active_local_bidi_streams: u64,
    /// Maximum local bidirectional streams allowed by configuration.
    max_local_bidi_streams: u64,
    /// Total application bytes queued but not yet accepted by quiche.
    pending_write_bytes: usize,
    /// Maximum queued application bytes for this connection.
    max_pending_write_bytes: usize,
    /// Source CIDs the transport has entered into its routing table, so
    /// reindexing and unindexing never scan the whole table.
    indexed_cids: Vec<Vec<u8>>,
    /// Peer's stateless reset token, once entered into the transport's reset
    /// routing table.
    indexed_reset_token: Option<u128>,
    /// Host time of the last packet this connection received.
    last_recv_ms: Option<u64>,
    /// An ack-eliciting keepalive has been sent since `last_recv_ms`.
    ///
    /// Further pings would restart the idle timer without evidence the peer
    /// is still there, so one unanswered ping is enough; idle timeout then
    /// closes a dead path.
    sent_keepalive_since_recv: bool,
}

impl QuicConnection {
    pub fn new(
        id: ConnectionId,
        conn: quiche::Connection,
        endpoint: ConnectionEndpoint,
        max_local_bidi_streams: u64,
        max_pending_write_bytes: usize,
    ) -> Self {
        let next_local_bidi_stream_id = if conn.is_server() { 1 } else { 0 };

        Self {
            id,
            conn,
            endpoint,
            state: ConnectionState::Connecting,
            stream_states: HashMap::new(),
            next_local_bidi_stream_id,
            active_local_bidi_streams: 0,
            max_local_bidi_streams,
            pending_write_bytes: 0,
            max_pending_write_bytes,
            indexed_cids: Vec::new(),
            indexed_reset_token: None,
            last_recv_ms: None,
            sent_keepalive_since_recv: false,
        }
    }

    /// Returns quiche source CIDs not yet in the transport's routing table,
    /// recording them as indexed.
    pub fn take_unindexed_source_cids(&mut self) -> Vec<Vec<u8>> {
        let mut new_cids: Vec<Vec<u8>> = Vec::new();
        for cid in self.conn.source_ids() {
            let cid = cid.as_ref();
            if !self.indexed_cids.iter().any(|known| known == cid) {
                new_cids.push(cid.to_vec());
            }
        }
        self.indexed_cids.extend(new_cids.iter().cloned());
        new_cids
    }

    /// Returns source CIDs quiche has retired since the last call, dropping
    /// them from the indexed set so the transport can unroute them.
    ///
    /// The transport never issues extra source CIDs (`new_scid`), so peers
    /// have nothing to rotate onto today; this keeps the table exact if it
    /// ever does.
    pub fn take_retired_source_cids(&mut self) -> Vec<Vec<u8>> {
        let mut retired = Vec::new();
        while let Some(cid) = self.conn.retired_scid_next() {
            self.indexed_cids.retain(|known| known != cid.as_ref());
            retired.push(cid.to_vec());
        }
        retired
    }

    /// Returns the peer's stateless reset token the first time it is known
    /// (after the peer's transport parameters arrive), recording it as indexed.
    ///
    /// Only servers advertise one, and it is the only token quiche checks when
    /// deciding whether an undecryptable packet is a reset.
    pub fn take_unindexed_reset_token(&mut self) -> Option<u128> {
        if self.indexed_reset_token.is_some() {
            return None;
        }
        self.indexed_reset_token = self.conn.peer_transport_params()?.stateless_reset_token;
        self.indexed_reset_token
    }

    /// The reset token the transport routes to this connection, if any.
    pub fn indexed_reset_token(&self) -> Option<u128> {
        self.indexed_reset_token
    }

    /// Records a CID the transport indexed outside of quiche's source-id set
    /// (e.g. the client-chosen destination CID on an accepted connection).
    pub fn note_indexed_cid(&mut self, cid: Vec<u8>) {
        if !self.indexed_cids.contains(&cid) {
            self.indexed_cids.push(cid);
        }
    }

    /// All CIDs the transport currently routes to this connection.
    pub fn indexed_cids(&self) -> &[Vec<u8>] {
        &self.indexed_cids
    }

    /// Application bytes queued but not yet accepted by quiche.
    #[cfg(test)]
    pub(crate) fn pending_write_bytes(&self) -> usize {
        self.pending_write_bytes
    }

    pub fn endpoint(&self) -> &ConnectionEndpoint {
        &self.endpoint
    }

    pub fn is_server(&self) -> bool {
        self.conn.is_server()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Returns the duration until quiche next needs timer service.
    pub(crate) fn timeout(&self) -> Option<Duration> {
        self.conn.timeout()
    }

    /// When this connection next wants a keepalive poll, if it is quiet.
    pub(crate) fn keepalive_deadline(&self, interval_ms: u64) -> Option<Deadline> {
        if self.state != ConnectionState::Connected || self.sent_keepalive_since_recv {
            return None;
        }
        Some(Deadline::from_millis(
            self.last_recv_ms?.saturating_add(interval_ms),
        ))
    }

    /// Sends an ack-eliciting packet if the connection has been quiet long
    /// enough. One ping per receive; a dead peer is then left to idle-timeout.
    pub fn maybe_keepalive(
        &mut self,
        now: Now,
        interval_ms: u64,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        if self.state != ConnectionState::Connected || self.sent_keepalive_since_recv {
            return Ok(());
        }
        let Some(last) = self.last_recv_ms else {
            return Ok(());
        };
        if now.monotonic_ms.saturating_sub(last) < interval_ms {
            return Ok(());
        }
        if self.conn.send_ack_eliciting().is_ok() {
            self.sent_keepalive_since_recv = true;
        }
        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)
    }

    /// Advances quiche's loss-recovery and idle timers when they are due.
    pub fn handle_timeout(
        &mut self,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        if !self.timeout().is_some_and(|timeout| timeout.is_zero()) {
            return Ok(());
        }

        self.conn.on_timeout();
        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)
    }

    // These arguments are the complete I/O context for a single datagram.
    // Keeping them explicit makes this adapter easy to embed and avoids a
    // second mutable runtime object on the packet hot path.
    #[expect(
        clippy::too_many_arguments,
        reason = "a packet needs the complete explicit I/O context in this sans-runtime adapter"
    )]
    pub fn recv_packet(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        local: SocketAddr,
        now: Now,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        let recv_info = quiche::RecvInfo { from, to: local };

        match self.conn.recv(buf, recv_info) {
            Ok(_) => {
                self.last_recv_ms = Some(now.monotonic_ms);
                self.sent_keepalive_since_recv = false;
            }
            Err(quiche::Error::Done) => {
                self.last_recv_ms = Some(now.monotonic_ms);
                self.sent_keepalive_since_recv = false;
            }
            Err(e) => {
                events.push(TransportEvent::Error {
                    id: self.id,
                    message: format!("recv error: {e}"),
                });
                return Ok(());
            }
        }

        if self.state == ConnectionState::Connecting && self.conn.is_established() {
            self.state = ConnectionState::Connected;
            self.drain_send_queue(events);
            self.flush(socket, pending_datagrams, max_pending_datagrams)?;

            // Auto-verify the remote peer's identity from their TLS certificate.
            let Some(peer_cert_der) = self.conn.peer_cert() else {
                events.push(TransportEvent::Error {
                    id: self.id,
                    message: "peer TLS certificate missing".into(),
                });
                if let Err(error) = self.conn.close(true, 0x03, b"peer certificate missing") {
                    events.push(TransportEvent::Error {
                        id: self.id,
                        message: format!("failed to close after missing peer certificate: {error}"),
                    });
                }
                self.state = ConnectionState::Closing;
                self.flush(socket, pending_datagrams, max_pending_datagrams)?;
                return Ok(());
            };

            match minip2p_tls::verify_libp2p_certificate(peer_cert_der) {
                Ok(verified_peer_id) => {
                    // If the dialer specified an expected PeerId (via PeerAddr),
                    // reject the connection if the verified identity doesn't match.
                    if let Some(expected) = self.endpoint.peer_id()
                        && *expected != verified_peer_id
                    {
                        events.push(TransportEvent::Error {
                            id: self.id,
                            message: format!(
                                "peer id mismatch: dialed {expected} but server certificate proves {verified_peer_id}"
                            ),
                        });
                        // Close the connection — the peer is not who we expected.
                        if let Err(error) = self.conn.close(true, 0x01, b"peer id mismatch") {
                            events.push(TransportEvent::Error {
                                id: self.id,
                                message: format!("failed to close after peer id mismatch: {error}"),
                            });
                        }
                        self.state = ConnectionState::Closing;
                        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
                        return Ok(());
                    }
                    self.endpoint.set_peer_id(verified_peer_id);
                }
                Err(e) => {
                    events.push(TransportEvent::Error {
                        id: self.id,
                        message: format!("peer TLS certificate verification failed: {e}"),
                    });
                    if let Err(error) =
                        self.conn
                            .close(true, 0x02, b"certificate verification failed")
                    {
                        events.push(TransportEvent::Error {
                            id: self.id,
                            message: format!(
                                "failed to close after certificate verification: {error}"
                            ),
                        });
                    }
                    self.state = ConnectionState::Closing;
                    self.flush(socket, pending_datagrams, max_pending_datagrams)?;
                    return Ok(());
                }
            }

            events.push(TransportEvent::Connected {
                id: self.id,
                endpoint: self.endpoint.clone(),
            });
        } else {
            self.drain_send_queue(events);
            self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        }

        Ok(())
    }

    pub fn open_stream(&mut self) -> Result<StreamId, TransportError> {
        if self.state != ConnectionState::Connected {
            return Err(TransportError::InvalidState {
                id: self.id,
                state: self.state,
                expected: ConnectionState::Connected,
            });
        }

        if self.active_local_bidi_streams >= self.max_local_bidi_streams {
            return Err(TransportError::ResourceExhausted {
                resource: "local QUIC bidirectional streams",
            });
        }

        let raw_stream_id = self.next_local_bidi_stream_id;
        self.next_local_bidi_stream_id = self.next_local_bidi_stream_id.wrapping_add(4);

        if self.stream_states.contains_key(&raw_stream_id) {
            return Err(TransportError::StreamExists {
                id: self.id,
                stream_id: StreamId::new(raw_stream_id),
            });
        }

        self.stream_states
            .insert(raw_stream_id, StreamRuntimeState::default());
        self.active_local_bidi_streams += 1;
        Ok(StreamId::new(raw_stream_id))
    }

    pub fn send_stream(
        &mut self,
        stream_id: StreamId,
        data: Vec<u8>,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        if data.is_empty() {
            return Ok(());
        }

        let raw_stream_id = stream_id.as_u64();
        let has_queued_writes = {
            let state = self.stream_state_mut(stream_id)?;
            if state.local_write_closed {
                return Err(TransportError::StreamSendFailed {
                    id: self.id,
                    stream_id,
                    reason: "local stream write side is already closed".into(),
                });
            }
            !state.pending_writes.is_empty()
        };

        let queue_capacity = self
            .max_pending_write_bytes
            .saturating_sub(self.pending_write_bytes);

        let offset = if has_queued_writes {
            // Earlier bytes are still queued; queue behind them so the direct
            // send below cannot reorder the stream.
            if data.len() > queue_capacity {
                return Err(TransportError::ResourceExhausted {
                    resource: "queued QUIC stream bytes",
                });
            }
            0
        } else {
            // Touch the stream so quiche reports its send capacity, then
            // reject up front when the unsendable remainder would not fit the
            // queue. This keeps oversized writes all-or-nothing: no bytes are
            // committed to quiche before the write is known to fit.
            // `StreamLimit` means the peer has not yet granted this stream;
            // it has no capacity, so the whole write queues until it does.
            match self.conn.stream_send(raw_stream_id, &[], false) {
                Ok(_) | Err(quiche::Error::Done | quiche::Error::StreamLimit) => {}
                Err(e) => return Err(self.direct_send_failed(stream_id, e, events)),
            }
            let capacity = self.conn.stream_capacity(raw_stream_id).unwrap_or(0);
            if data.len().saturating_sub(capacity) > queue_capacity {
                return Err(TransportError::ResourceExhausted {
                    resource: "queued QUIC stream bytes",
                });
            }

            match self.conn.stream_send(raw_stream_id, &data, false) {
                Ok(written) => written,
                Err(quiche::Error::Done | quiche::Error::StreamLimit) => 0,
                Err(e) => return Err(self.direct_send_failed(stream_id, e, events)),
            }
        };

        if offset < data.len() {
            self.pending_write_bytes += data.len() - offset;
            self.stream_states
                .entry(raw_stream_id)
                .or_default()
                .pending_writes
                .push_back(PendingStreamWrite::data(data, offset));
        }

        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        Ok(())
    }

    /// Maps a quiche error from `send_stream`'s direct write to the caller's
    /// error. A STOP_SENDING seen here is also recorded like one seen by the
    /// drain, so the stream still reports `StreamWriteStopped`.
    fn direct_send_failed(
        &mut self,
        stream_id: StreamId,
        error: quiche::Error,
        events: &mut Vec<TransportEvent>,
    ) -> TransportError {
        if let quiche::Error::StreamStopped(error_code) = error {
            self.note_write_stopped(stream_id, error_code, events);
        }
        TransportError::StreamSendFailed {
            id: self.id,
            stream_id,
            reason: format!("stream_send error: {error}"),
        }
    }

    pub fn close_stream_write(
        &mut self,
        stream_id: StreamId,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        let state = self.stream_state_mut(stream_id)?;

        if state.local_write_closed {
            return Err(TransportError::StreamCloseWriteFailed {
                id: self.id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        }

        state.local_write_closed = true;
        state.pending_writes.push_back(PendingStreamWrite::fin());

        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        Ok(())
    }

    pub fn reset_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), TransportError> {
        let state = self.stream_states.get_mut(&stream_id.as_u64()).ok_or(
            TransportError::StreamNotFound {
                id: self.id,
                stream_id,
            },
        )?;

        let dropped = state.drop_pending_writes();
        self.pending_write_bytes = self.pending_write_bytes.saturating_sub(dropped);

        // `Done` means quiche already shut that half down or collected the
        // stream (e.g. after the peer's STOP_SENDING and FIN), so there is
        // nothing left to reset.
        for (direction, side) in [
            (quiche::Shutdown::Write, "write"),
            (quiche::Shutdown::Read, "read"),
        ] {
            match self
                .conn
                .stream_shutdown(stream_id.as_u64(), direction, 0x00)
            {
                Ok(()) | Err(quiche::Error::Done) => {}
                Err(e) => {
                    return Err(TransportError::StreamResetFailed {
                        id: self.id,
                        stream_id,
                        reason: format!("failed to shutdown stream {side} side: {e}"),
                    });
                }
            }
        }

        state.local_write_closed = true;
        state.remote_write_closed = true;

        if !state.closed_notified {
            state.closed_notified = true;
            events.push(TransportEvent::StreamClosed {
                id: self.id,
                stream_id,
            });
        }

        Ok(())
    }

    pub fn close(
        &mut self,
        socket: &UdpSocket,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Closed
        ) {
            self.flush(socket, pending_datagrams, max_pending_datagrams)?;
            return Ok(());
        }

        match self.conn.close(true, 0x00, b"bye") {
            Ok(()) | Err(quiche::Error::Done) => {}
            Err(e) => {
                return Err(TransportError::CloseFailed {
                    id: self.id,
                    reason: format!("close error: {e}"),
                });
            }
        }

        self.state = ConnectionState::Closing;
        let mut drain_events = Vec::new();
        self.drain_send_queue(&mut drain_events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        Ok(())
    }

    pub fn poll_streams(
        &mut self,
        events: &mut Vec<TransportEvent>,
        socket: &UdpSocket,
        stream_read_buffer: &mut [u8],
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        if !self.conn.is_established() {
            return Ok(());
        }

        // Catch STOP_SENDING before reading: once the peer's FIN is read,
        // quiche may collect the stream and every later write would only
        // report `Done`. quiche marks a stopped stream writable, but lists no
        // writable streams while connection credit is exhausted, so readable
        // streams (the ones a FIN could collect) are checked as well.
        let candidates: Vec<u64> = self.conn.writable().chain(self.conn.readable()).collect();
        for raw_stream_id in candidates {
            if let Err(quiche::Error::StreamStopped(error_code)) =
                self.conn.stream_capacity(raw_stream_id)
            {
                let stream_id = StreamId::new(raw_stream_id);
                self.ensure_stream_discovered(stream_id, events);
                self.note_write_stopped(stream_id, error_code, events);
            }
        }

        for raw_stream_id in self.conn.readable() {
            let stream_id = StreamId::new(raw_stream_id);
            self.ensure_stream_discovered(stream_id, events);

            loop {
                match self.conn.stream_recv(raw_stream_id, stream_read_buffer) {
                    Ok((read, fin)) => {
                        if read > 0 {
                            events.push(TransportEvent::StreamData {
                                id: self.id,
                                stream_id,
                                data: stream_read_buffer
                                    .get(..read)
                                    .expect("quiche stream reads fit the supplied buffer")
                                    .to_vec(),
                            });
                        }

                        if fin {
                            if let Some(state) = self.stream_states.get_mut(&raw_stream_id) {
                                state.remote_write_closed = true;
                            }

                            events.push(TransportEvent::StreamRemoteWriteClosed {
                                id: self.id,
                                stream_id,
                            });

                            self.note_stream_closed_if_finished(stream_id, events);
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(quiche::Error::StreamReset(_)) => {
                        self.note_stream_reset(stream_id, events);
                        break;
                    }
                    Err(e) => {
                        events.push(TransportEvent::Error {
                            id: self.id,
                            message: format!("stream_recv error on {stream_id}: {e}"),
                        });
                        break;
                    }
                }
            }
        }

        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        self.gc_closed_streams();
        Ok(())
    }

    /// Sends all pending quiche output packets via the UDP socket.
    fn flush(
        &mut self,
        socket: &UdpSocket,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        let mut out = [0u8; SEND_BUF_SIZE];
        loop {
            // `quiche::Connection::send()` advances congestion and loss state.
            // Do not consume another packet unless we can retain it if the
            // non-blocking UDP socket reports `WouldBlock`.
            if pending_datagrams.len() >= max_pending_datagrams {
                break;
            }
            let (written, send_info) = match self.conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    return Err(TransportError::CloseFailed {
                        id: self.id,
                        reason: format!("quiche send error: {e}"),
                    });
                }
            };

            let packet = out
                .get(..written)
                .expect("quiche reports packet lengths within the supplied buffer");
            match socket.send_to(packet, send_info.to) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    pending_datagrams.push_back(PendingDatagram {
                        bytes: packet.to_vec(),
                        destination: send_info.to,
                    });
                    break;
                }
                // Any other send error (EHOSTUNREACH after a route flap,
                // ICMP-driven ECONNREFUSED, ...) affects only this
                // connection's path, so it must not abort the whole
                // endpoint's poll. Treat the packet as lost -- quiche's
                // loss recovery retransmits it, and a path that stays dead
                // ends in this connection's idle timeout. Stop draining so
                // a dead route is not hammered within one flush.
                Err(_) => break,
            }
        }
        Ok(())
    }

    /// Pushes queued stream writes into quiche, handling partial writes.
    ///
    /// Never fails the caller: a stopped stream loses only its own queue, a
    /// write still waiting on peer credit stays queued for a later drain, and
    /// any other quiche error closes only this connection.
    fn drain_send_queue(&mut self, events: &mut Vec<TransportEvent>) {
        let stream_ids: Vec<u64> = self.stream_states.keys().copied().collect();

        for raw_stream_id in stream_ids {
            loop {
                let stream_id = StreamId::new(raw_stream_id);
                let result = {
                    let (conn, stream_states) = (&mut self.conn, &mut self.stream_states);
                    let Some(state) = stream_states.get_mut(&raw_stream_id) else {
                        break;
                    };
                    let Some(front) = state.pending_writes.front_mut() else {
                        break;
                    };
                    let payload = front
                        .bytes
                        .get(front.offset..)
                        .expect("pending write offsets advance only within their buffers");
                    let fin = front.fin && payload.is_empty();
                    conn.stream_send(raw_stream_id, payload, fin)
                };
                let written = match result {
                    Ok(written) => written,
                    // Out of flow-control or stream-count credit: the peer's
                    // next MAX_* frame lets a later drain continue.
                    Err(quiche::Error::Done | quiche::Error::StreamLimit) => break,
                    Err(quiche::Error::StreamStopped(error_code)) => {
                        self.note_write_stopped(stream_id, error_code, events);
                        break;
                    }
                    Err(e) => {
                        self.fail_connection(
                            format!("stream_send error on {stream_id}: {e}"),
                            events,
                        );
                        return;
                    }
                };

                if let Some(state) = self.stream_states.get_mut(&raw_stream_id)
                    && let Some(front) = state.pending_writes.front_mut()
                {
                    if front.fin && front.bytes.is_empty() {
                        state.pending_writes.pop_front();
                    } else {
                        if written == 0 {
                            break;
                        }

                        front.offset = front.offset.saturating_add(written);
                        self.pending_write_bytes = self.pending_write_bytes.saturating_sub(written);
                        if front.offset >= front.bytes.len() {
                            state.pending_writes.pop_front();
                        }
                    }
                }

                self.note_stream_closed_if_finished(stream_id, events);
            }
        }
    }

    /// The peer sent STOP_SENDING: our write half is gone for good, so queued
    /// writes are dropped. The read half stays open until the peer finishes.
    ///
    /// The stop can surface from the drain, from `send_stream`, or from the
    /// stream scan in `poll_streams`; `StreamWriteStopped` is emitted once.
    fn note_write_stopped(
        &mut self,
        stream_id: StreamId,
        error_code: u64,
        events: &mut Vec<TransportEvent>,
    ) {
        let Some(state) = self.stream_states.get_mut(&stream_id.as_u64()) else {
            return;
        };
        if state.write_stopped {
            return;
        }
        state.write_stopped = true;
        let dropped = state.drop_pending_writes();
        self.pending_write_bytes = self.pending_write_bytes.saturating_sub(dropped);
        state.local_write_closed = true;
        events.push(TransportEvent::StreamWriteStopped {
            id: self.id,
            stream_id,
            error_code,
        });
        self.note_stream_closed_if_finished(stream_id, events);
    }

    /// Closes this connection after an error quiche did not scope to a single
    /// stream. The transport reports `Closed` once quiche finishes draining.
    ///
    /// Every queued write is dropped so later drains cannot hit the same error
    /// again while quiche drains the connection.
    fn fail_connection(&mut self, message: String, events: &mut Vec<TransportEvent>) {
        for state in self.stream_states.values_mut() {
            state.drop_pending_writes();
        }
        self.pending_write_bytes = 0;
        events.push(TransportEvent::Error {
            id: self.id,
            message,
        });
        // 0x1 is QUIC's INTERNAL_ERROR. `Done` means quiche is already closing.
        if let Err(error) = self.conn.close(false, 0x1, b"stream send failed")
            && error != quiche::Error::Done
        {
            events.push(TransportEvent::Error {
                id: self.id,
                message: format!("failed to close after stream send error: {error}"),
            });
        }
        self.state = ConnectionState::Closing;
    }

    /// Emits IncomingStream for remote-initiated streams not yet notified.
    fn ensure_stream_discovered(&mut self, stream_id: StreamId, events: &mut Vec<TransportEvent>) {
        let is_remote = self.is_remote_initiated_stream(stream_id.as_u64());
        let state = self.stream_states.entry(stream_id.as_u64()).or_default();

        if is_remote && !state.incoming_notified {
            state.incoming_notified = true;
            events.push(TransportEvent::IncomingStream {
                id: self.id,
                stream_id,
            });
        }
    }

    /// Emits StreamClosed if both sides are closed and not yet notified.
    fn note_stream_closed_if_finished(
        &mut self,
        stream_id: StreamId,
        events: &mut Vec<TransportEvent>,
    ) {
        if let Some(state) = self.stream_states.get_mut(&stream_id.as_u64())
            && state.is_fully_closed()
            && !state.closed_notified
        {
            state.closed_notified = true;
            events.push(TransportEvent::StreamClosed {
                id: self.id,
                stream_id,
            });
        }
    }

    /// A peer reset terminates both halves and discards writes that can no
    /// longer be delivered.
    fn note_stream_reset(&mut self, stream_id: StreamId, events: &mut Vec<TransportEvent>) {
        let Some(state) = self.stream_states.get_mut(&stream_id.as_u64()) else {
            return;
        };
        let dropped = state.drop_pending_writes();
        self.pending_write_bytes = self.pending_write_bytes.saturating_sub(dropped);
        state.local_write_closed = true;
        state.remote_write_closed = true;
        if !state.closed_notified {
            state.closed_notified = true;
            events.push(TransportEvent::StreamClosed {
                id: self.id,
                stream_id,
            });
        }
    }

    /// Removes stream state entries that are fully closed and drained.
    fn gc_closed_streams(&mut self) {
        let to_remove: Vec<u64> = self
            .stream_states
            .iter()
            .filter_map(|(stream_id, state)| {
                if state.closed_notified && state.pending_writes.is_empty() {
                    Some(*stream_id)
                } else {
                    None
                }
            })
            .collect();

        let removed_local_bidi = to_remove
            .iter()
            .filter(|stream_id| self.is_local_bidi_stream(**stream_id))
            .count() as u64;
        for stream_id in to_remove {
            self.stream_states.remove(&stream_id);
        }
        self.active_local_bidi_streams = self
            .active_local_bidi_streams
            .saturating_sub(removed_local_bidi);
    }

    /// Returns state for a stream previously opened or discovered by the transport.
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

    /// Checks if a stream id was initiated by this side (QUIC parity bit check).
    fn is_local_initiated_stream(&self, stream_id: u64) -> bool {
        let local_initiator_bit = if self.conn.is_server() { 1 } else { 0 };
        (stream_id & 0x1) == local_initiator_bit
    }

    /// Checks if a stream is bidirectional and was initiated by this side.
    fn is_local_bidi_stream(&self, stream_id: u64) -> bool {
        self.is_local_initiated_stream(stream_id) && (stream_id & 0x2) == 0
    }

    /// Checks if a stream id was initiated by the remote side.
    fn is_remote_initiated_stream(&self, stream_id: u64) -> bool {
        !self.is_local_initiated_stream(stream_id)
    }
}
