//! Per-connection state management for the QUIC transport.
//!
//! Handles the QUIC connection lifecycle, stream multiplexing, send queue
//! draining, and event emission.

use std::collections::{HashMap, VecDeque};
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use minip2p_core::PeerId;
use minip2p_platform::{Deadline, Now};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionState, ConnectionToken, StreamId, TransportError,
    TransportEvent,
};

use sha2::{Digest, Sha256};

use crate::PendingDatagram;
use crate::diagnostics::{ConnectionCounters, DatagramTally};

const SEND_BUF_SIZE: usize = 1350;

/// Why a handshaken peer's identity was rejected: the QUIC close code and
/// reason sent to the peer, and the message reported to the local caller.
struct PeerRejection {
    code: u64,
    reason: &'static [u8],
    message: String,
}

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

/// Queued writes for one stream, never empty while stored.
type SendQueue = VecDeque<PendingStreamWrite>;

/// Unsent bytes held by a dropped queue.
fn unsent_bytes(queue: SendQueue) -> usize {
    queue
        .into_iter()
        .map(|write| write.bytes.len().saturating_sub(write.offset))
        .sum()
}

/// Per-stream bookkeeping for half-close tracking.
#[derive(Debug, Default)]
struct StreamRuntimeState {
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
    /// Outbound write queues keyed by raw QUIC stream id. Only streams with
    /// pending output have an entry, so a drain visits nothing else.
    send_queues: HashMap<u64, SendQueue>,
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
    /// A packet quiche paced into the future (`SendInfo::at`), held until its
    /// send time. While one is held, `flush` generates nothing further for
    /// this connection, so packets leave in order and never early.
    paced: Option<PacedPacket>,
    /// Something may have left stream input for `poll_streams` to find:
    /// readable data, or a peer's STOP_SENDING.
    ///
    /// Set before every `conn.recv` (even a failing one: quiche may apply
    /// some frames before erroring) and before a local reset, which returns
    /// unsent credit and can re-list a stopped stream as writable while no
    /// packet arrives. Idle polls skip the scans while it is clear.
    streams_dirty: bool,
    /// Diagnostic hooks; empty unless the `diagnostics` feature is on.
    counters: ConnectionCounters,
}

/// Whether a flush waits for quiche's pacing send times.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pacing {
    Honour,
    Ignore,
}

/// An encoded packet waiting for its pacing send time.
struct PacedPacket {
    datagram: PendingDatagram,
    /// quiche's intended send time, on its own `Instant` clock.
    at: Instant,
}

impl QuicConnection {
    pub fn new(
        id: ConnectionId,
        conn: quiche::Connection,
        endpoint: ConnectionEndpoint,
        max_local_bidi_streams: u64,
        max_pending_write_bytes: usize,
        tally: DatagramTally,
    ) -> Self {
        let next_local_bidi_stream_id = if conn.is_server() { 1 } else { 0 };

        Self {
            id,
            conn,
            endpoint,
            state: ConnectionState::Connecting,
            stream_states: HashMap::new(),
            send_queues: HashMap::new(),
            next_local_bidi_stream_id,
            active_local_bidi_streams: 0,
            max_local_bidi_streams,
            pending_write_bytes: 0,
            max_pending_write_bytes,
            indexed_cids: Vec::new(),
            indexed_reset_token: None,
            last_recv_ms: None,
            sent_keepalive_since_recv: false,
            paced: None,
            streams_dirty: false,
            counters: ConnectionCounters::new(tally),
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

    /// This connection's diagnostic counters so far.
    #[cfg(feature = "diagnostics")]
    pub(crate) fn diagnostics(&self) -> crate::ConnectionDiagnostics {
        self.counters.snapshot()
    }

    /// Application bytes queued but not yet accepted by quiche.
    #[cfg(test)]
    pub(crate) fn pending_write_bytes(&self) -> usize {
        self.pending_write_bytes
    }

    /// Number of streams with queued writes.
    #[cfg(test)]
    pub(crate) fn queued_stream_count(&self) -> usize {
        self.send_queues.len()
    }

    /// Drops `raw_stream_id`'s queued writes and their byte accounting.
    fn drop_send_queue(&mut self, raw_stream_id: u64) {
        if let Some(queue) = self.send_queues.remove(&raw_stream_id) {
            self.pending_write_bytes = self.pending_write_bytes.saturating_sub(unsent_bytes(queue));
        }
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

    /// Time until a held paced packet is due, if one is held.
    pub(crate) fn pacing_delay(&self) -> Option<Duration> {
        self.paced
            .as_ref()
            .map(|paced| paced.at.saturating_duration_since(Instant::now()))
    }

    /// The held paced packet's bytes and send time.
    #[cfg(test)]
    pub(crate) fn paced_packet(&self) -> Option<(&[u8], Instant)> {
        self.paced
            .as_ref()
            .map(|paced| (paced.datagram.bytes.as_slice(), paced.at))
    }

    /// Moves the held paced packet's send time to `at`.
    #[cfg(test)]
    pub(crate) fn repace_held_packet(&mut self, at: Instant) {
        self.paced.as_mut().expect("a held packet").at = at;
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
        let timer_due = self.timeout().is_some_and(|timeout| timeout.is_zero());
        // A due paced packet counts too: before the handshake completes no
        // other per-poll path flushes, and `next_deadline` would report it due
        // on every poll.
        let paced_due = self.pacing_delay().is_some_and(|delay| delay.is_zero());
        if !timer_due && !paced_due {
            return Ok(());
        }

        if timer_due {
            self.conn.on_timeout();
            self.drain_send_queue(events);
        }
        self.flush(socket, pending_datagrams, max_pending_datagrams)
    }

    /// Feeds one received datagram to quiche.
    ///
    /// Flushes only while the handshake is in progress, on the transition to
    /// established, and on peer rejection. An established connection's
    /// output is left for the caller's `poll_streams` after the receive
    /// batch, which must run for every connection that received datagrams.
    //
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

        self.counters.datagram_received();
        self.streams_dirty = true;
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
            self.counters.receive_flush();
            self.flush(socket, pending_datagrams, max_pending_datagrams)?;

            // Auto-verify the remote peer's identity from their TLS certificate.
            // Prefer the caller's wall-clock sample; fall back to the system
            // clock when the caller's platform supplied none.
            let unix_now = now
                .unix_seconds
                .map_or_else(crate::unix_time, Duration::from_secs);
            match self.verify_peer_identity(unix_now) {
                Ok(verified_peer_id) => {
                    self.endpoint.set_peer_id(verified_peer_id);
                    self.endpoint.set_token(self.shared_token());
                }
                Err(rejection) => {
                    events.push(TransportEvent::Error {
                        id: self.id,
                        message: rejection.message,
                    });
                    if let Err(error) = self.conn.close(true, rejection.code, rejection.reason) {
                        events.push(TransportEvent::Error {
                            id: self.id,
                            message: format!("failed to close rejected peer connection: {error}"),
                        });
                    }
                    self.state = ConnectionState::Closing;
                    self.counters.receive_flush();
                    self.flush(socket, pending_datagrams, max_pending_datagrams)?;
                    return Ok(());
                }
            }

            events.push(TransportEvent::Connected {
                id: self.id,
                endpoint: self.endpoint.clone(),
            });
        } else if !self.conn.is_established() {
            self.drain_send_queue(events);
            self.counters.receive_flush();
            self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        }
        // Once established, output waits for the `poll_streams` that follows
        // the receive batch: quiche has no delayed-ACK timer, so flushing per
        // datagram sends an ACK per packet and squeezes packets into slivers
        // of free congestion window. `poll_streams` flushes exactly when
        // `is_established` holds, so nothing deferred here is stranded.

        Ok(())
    }

    /// Derives the connection's token from its two connection IDs.
    ///
    /// Once the handshake completes, each end's source CID is the other's
    /// destination CID: the listener takes the dialer's CID from its first
    /// Initial, and quiche replaces the dialer's random initial destination
    /// with the listener's CID from the listener's first Initial (or Retry).
    /// Hashing the pair in sorted order therefore gives both ends the same
    /// token. This transport never issues extra CIDs (`new_scid`) and nothing
    /// migrates before establishment, so the pair is the one the handshake
    /// set; the token is read once, here, and kept.
    fn shared_token(&self) -> ConnectionToken {
        let (source, destination) = (self.conn.source_id(), self.conn.destination_id());
        let (low, high) = if source.as_ref() <= destination.as_ref() {
            (source, destination)
        } else {
            (destination, source)
        };
        let mut hash = Sha256::new();
        for cid in [low.as_ref(), high.as_ref()] {
            // CIDs are at most 20 bytes, so one length byte keeps the
            // encoding unambiguous.
            hash.update([u8::try_from(cid.len()).unwrap_or(u8::MAX)]);
            hash.update(cid);
        }
        ConnectionToken::new(hash.finalize().into())
    }

    /// Checks the handshaken peer's libp2p identity: exactly one certificate
    /// (the libp2p TLS spec forbids chains), a valid libp2p certificate at
    /// `now` (wall-clock time since the Unix epoch), and the expected
    /// `PeerId` when the dialer named one.
    fn verify_peer_identity(&self, now: Duration) -> Result<PeerId, PeerRejection> {
        // quiche lists the leaf first on both the dialer and listener sides.
        let chain = self.conn.peer_cert_chain().unwrap_or_default();
        let leaf = match chain.as_slice() {
            [] => {
                return Err(PeerRejection {
                    code: 0x03,
                    reason: b"peer certificate missing",
                    message: "peer TLS certificate missing".into(),
                });
            }
            [leaf] => *leaf,
            certs => {
                return Err(PeerRejection {
                    code: 0x04,
                    reason: b"peer certificate chain rejected",
                    message: format!(
                        "peer presented {} certificates; libp2p TLS requires exactly one",
                        certs.len()
                    ),
                });
            }
        };

        let verified =
            minip2p_tls::verify_libp2p_certificate(leaf, now).map_err(|e| PeerRejection {
                code: 0x02,
                reason: b"certificate verification failed",
                message: format!("peer TLS certificate verification failed: {e}"),
            })?;

        // If the dialer specified an expected PeerId (via PeerAddr), the
        // peer must be exactly that identity.
        if let Some(expected) = self.endpoint.peer_id()
            && *expected != verified
        {
            return Err(PeerRejection {
                code: 0x01,
                reason: b"peer id mismatch",
                message: format!(
                    "peer id mismatch: dialed {expected} but server certificate proves {verified}"
                ),
            });
        }
        Ok(verified)
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
        if self.stream_state_mut(stream_id)?.local_write_closed {
            return Err(TransportError::StreamSendFailed {
                id: self.id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        }
        let has_queued_writes = self.send_queues.contains_key(&raw_stream_id);

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
            self.send_queues
                .entry(raw_stream_id)
                .or_default()
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
        self.send_queues
            .entry(stream_id.as_u64())
            .or_default()
            .push_back(PendingStreamWrite::fin());

        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        Ok(())
    }

    pub fn reset_stream(
        &mut self,
        stream_id: StreamId,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), TransportError> {
        // Fail with `StreamNotFound` before touching quiche.
        self.stream_state_mut(stream_id)?;
        self.drop_send_queue(stream_id.as_u64());
        self.streams_dirty = true;

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

        let state = self.stream_state_mut(stream_id)?;
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

        if mem::take(&mut self.streams_dirty) {
            self.scan_stream_input(events, stream_read_buffer);
        }

        self.drain_send_queue(events);
        self.flush(socket, pending_datagrams, max_pending_datagrams)?;
        self.gc_closed_streams();
        Ok(())
    }

    /// Reports peer STOP_SENDINGs, then reads every readable stream to
    /// exhaustion. Only runs while `streams_dirty` is set.
    fn scan_stream_input(
        &mut self,
        events: &mut Vec<TransportEvent>,
        stream_read_buffer: &mut [u8],
    ) {
        // Catch STOP_SENDING before reading: once the peer's FIN is read,
        // quiche may collect the stream and every later write would only
        // report `Done`. quiche marks a stopped stream writable, but lists no
        // writable streams while connection credit is exhausted, so readable
        // streams (the ones a FIN could collect) are checked as well.
        // Both iterators own a snapshot of ids, so the loop may mutate `conn`.
        for raw_stream_id in self.conn.writable().chain(self.conn.readable()) {
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
    }

    /// Sends quiche's output packets via the UDP socket, honouring pacing.
    ///
    /// A packet whose `SendInfo::at` is still in the future is held rather
    /// than sent, and flushing stops there; a later flush sends it first once
    /// it is due. quiche's clock is `Instant`, so due-ness is judged on it.
    fn flush(
        &mut self,
        socket: &UdpSocket,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        self.send_output(
            socket,
            pending_datagrams,
            max_pending_datagrams,
            Pacing::Honour,
        )
    }

    /// Sends everything left, held packet first, ignoring pacing.
    ///
    /// For a transport being dropped: no later poll would send held packets,
    /// and a `close` stopped behind one would never tell the peer.
    pub(crate) fn flush_ignoring_pacing(
        &mut self,
        socket: &UdpSocket,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
    ) -> Result<(), TransportError> {
        self.send_output(
            socket,
            pending_datagrams,
            max_pending_datagrams,
            Pacing::Ignore,
        )
    }

    /// Shared body of `flush` and `flush_ignoring_pacing`: sends any held
    /// packet, then pulls from quiche until it is done, a packet must wait for
    /// its send time (under `Pacing::Honour`), or the socket pushes back.
    fn send_output(
        &mut self,
        socket: &UdpSocket,
        pending_datagrams: &mut VecDeque<PendingDatagram>,
        max_pending_datagrams: usize,
        pacing: Pacing,
    ) -> Result<(), TransportError> {
        let not_due = |at: Instant| pacing == Pacing::Honour && at > Instant::now();
        self.counters.flush();
        if let Some(paced) = self.paced.take() {
            // Not due yet, or nowhere to retain it on `WouldBlock`.
            if not_due(paced.at) || pending_datagrams.len() >= max_pending_datagrams {
                self.paced = Some(paced);
                return Ok(());
            }
            let PendingDatagram { bytes, destination } = &paced.datagram;
            if !send_or_retain(socket, bytes, *destination, pending_datagrams) {
                return Ok(());
            }
            self.counters.sent(bytes.len());
        }

        let full_packet = self.conn.max_send_udp_payload_size();
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
                Err(quiche::Error::Done) => {
                    self.counters.quiche_done(!self.send_queues.is_empty());
                    break;
                }
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
            self.counters.packet(written, full_packet);
            if not_due(send_info.at) {
                self.paced = Some(PacedPacket {
                    datagram: PendingDatagram {
                        bytes: packet.to_vec(),
                        destination: send_info.to,
                    },
                    at: send_info.at,
                });
                break;
            }
            if !send_or_retain(socket, packet, send_info.to, pending_datagrams) {
                break;
            }
            self.counters.sent(written);
        }
        Ok(())
    }

    /// Pushes queued stream writes into quiche, handling partial writes.
    ///
    /// Never fails the caller: a stopped stream loses only its own queue, a
    /// write still waiting on peer credit stays queued for a later drain, and
    /// any other quiche error closes only this connection.
    fn drain_send_queue(&mut self, events: &mut Vec<TransportEvent>) {
        // Only streams with pending output; collecting none allocates nothing.
        let stream_ids: Vec<u64> = self.send_queues.keys().copied().collect();

        for raw_stream_id in stream_ids {
            let stream_id = StreamId::new(raw_stream_id);
            while let Some(front) = self
                .send_queues
                .get(&raw_stream_id)
                .and_then(VecDeque::front)
            {
                let payload = front
                    .bytes
                    .get(front.offset..)
                    .expect("pending write offsets advance only within their buffers");
                let fin = front.fin && payload.is_empty();
                let written = match self.conn.stream_send(raw_stream_id, payload, fin) {
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

                // Only the error arms above drop a queue, and they leave the loop.
                let queue = self
                    .send_queues
                    .get_mut(&raw_stream_id)
                    .expect("a successful send leaves the stream's queue in place");
                let front = queue
                    .front_mut()
                    .expect("stored send queues are never empty");
                if !front.fin || !front.bytes.is_empty() {
                    if written == 0 {
                        break;
                    }
                    front.offset = front.offset.saturating_add(written);
                    self.pending_write_bytes = self.pending_write_bytes.saturating_sub(written);
                }
                if front.offset >= front.bytes.len() {
                    queue.pop_front();
                    if queue.is_empty() {
                        self.send_queues.remove(&raw_stream_id);
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
        state.local_write_closed = true;
        self.drop_send_queue(stream_id.as_u64());
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
        self.send_queues.clear();
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
        self.drop_send_queue(stream_id.as_u64());
        let Some(state) = self.stream_states.get_mut(&stream_id.as_u64()) else {
            return;
        };
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
                if state.closed_notified && !self.send_queues.contains_key(stream_id) {
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

/// Reports the connection's diagnostic totals, so a host can compare runs
/// without reading them through the transport.
#[cfg(feature = "diagnostics")]
impl Drop for QuicConnection {
    fn drop(&mut self) {
        std::eprintln!(
            "minip2p-quic diagnostics {}: {}",
            self.id,
            self.counters.snapshot()
        );
    }
}

/// Sends one packet, retaining it on `WouldBlock` or behind datagrams already
/// retained, so it never overtakes them. Returns whether the caller should
/// keep flushing.
fn send_or_retain(
    socket: &UdpSocket,
    packet: &[u8],
    destination: SocketAddr,
    pending_datagrams: &mut VecDeque<PendingDatagram>,
) -> bool {
    let retain = |pending_datagrams: &mut VecDeque<PendingDatagram>| {
        pending_datagrams.push_back(PendingDatagram {
            bytes: packet.to_vec(),
            destination,
        });
        false
    };
    if !pending_datagrams.is_empty() {
        return retain(pending_datagrams);
    }
    match socket.send_to(packet, destination) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => retain(pending_datagrams),
        // Any other send error (EHOSTUNREACH after a route flap,
        // ICMP-driven ECONNREFUSED, ...) affects only this connection's path,
        // so it must not abort the whole endpoint's poll. Treat the packet as
        // lost -- quiche's loss recovery retransmits it, and a path that stays
        // dead ends in this connection's idle timeout. Stop draining so a dead
        // route is not hammered within one flush.
        Err(_) => false,
    }
}
