//! [`WebTransportClient`]: libp2p WebTransport dialing over a
//! [`WebTransportIo`], as a [`Transport`].
//!
//! A dial opens a session to the server's `/.well-known/libp2p-webtransport`
//! URL, trusting only the certificates its address names, then runs Noise XX
//! as initiator on the session's first stream. The server must prove the
//! dialed peer id and list every dialed certhash in its Noise extensions;
//! then the Noise stream is finished and the connection is up. Every later
//! stream is a plain libp2p stream, mapped 1:1 onto a WebTransport stream.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem;
use core::net::{Ipv4Addr, Ipv6Addr};

use minip2p_core::platform::{Deadline, EntropySource, IoErrorKind, Now};
use minip2p_core::{Bytes, Multiaddr, Multihash, PeerAddr, Protocol, retain_slice};
use minip2p_identity::Ed25519Keypair;
use minip2p_secure_mux::noise::{NoiseConfig, NoiseOutput, NoiseRole, NoiseSession};
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, ConnectionIdAllocator,
    ConnectionNamespace, ConnectionState, ConnectionToken, InvalidLimit, SendCaps, StreamId,
    Transport, TransportError, TransportEvent, UnsettledConnections,
};

use crate::io::{IoEvent, SessionHandle, StreamHandle, WebTransportIo};
use crate::limits::WebTransportLimits;

/// The path and query of every libp2p WebTransport session.
pub const LIBP2P_WEBTRANSPORT_PATH: &str = "/.well-known/libp2p-webtransport?type=noise";

/// Read grant on the Noise stream; handshake messages are far smaller.
const NOISE_READ_GRANT: usize = 64 * 1024;

/// Why a dial fails when the platform refuses a write on the Noise stream.
const NOISE_REFUSED: &str = "the platform refused the Noise stream";

/// The `https://` URL a libp2p WebTransport address is served at.
///
/// `addr` is `/<host>/udp/<port>/quic-v1/webtransport[/certhash/…]`. IPv6
/// hosts are bracketed and DNS names pass through for the platform to
/// resolve.
pub fn webtransport_url(addr: &Multiaddr) -> Result<String, TransportError> {
    if !addr.is_webtransport() {
        return Err(TransportError::InvalidAddress {
            context: "dial target",
            reason: format!("{addr} is not /<host>/udp/<port>/quic-v1/webtransport/certhash/…"),
        });
    }
    let (host, port) = match addr.protocols() {
        [host, Protocol::Udp(port), ..] => (host, *port),
        _ => {
            return Err(TransportError::InvalidAddress {
                context: "dial target",
                reason: format!("{addr} has no /udp port"),
            });
        }
    };
    let host = match host {
        Protocol::Ip4(octets) => Ipv4Addr::from(*octets).to_string(),
        Protocol::Ip6(octets) => format!("[{}]", Ipv6Addr::from(*octets)),
        Protocol::Dns(name) | Protocol::Dns4(name) | Protocol::Dns6(name) => name.clone(),
        other => {
            return Err(TransportError::InvalidAddress {
                context: "dial target",
                reason: format!("{other:?} is not a host"),
            });
        }
    };
    Ok(format!("https://{host}:{port}{LIBP2P_WEBTRANSPORT_PATH}"))
}

/// A libp2p WebTransport dialer over the platform's WebTransport API.
///
/// Dial-only: [`listen`](Transport::listen) is unsupported (a browser cannot
/// accept connections), and so are addresses without a `/certhash` (there
/// is no CA-certificate mode). Connection ids come from
/// [`ConnectionNamespace::WEBTRANSPORT`].
///
/// It honours the full transport contract within [`WebTransportLimits`].
/// Every byte it is responsible for sits in exactly one bounded place:
///
/// - **Pending writes**: from `send_stream` until the platform's
///   [`WriteCompleted`](IoEvent::WriteCompleted), whether still queued in
///   Rust or copied into the platform's in-flight writes, counted against
///   the stream and connection send caps ([`SendCaps`]). That is where
///   `Full` and `StreamWritable` come from. A queued tail never pins more
///   than twice its bytes of the caller's payload ([`retain_slice`]).
/// - **Granted reads**: [`grant_read`](WebTransportIo::grant_read) is only
///   ever issued for `window − unacked − outstanding grant`.
/// - **Delivered, unacknowledged bytes**: held per stream until
///   `ack_stream`, and when a connection ends, in [`UnsettledConnections`]
///   until `ack_stream` or `reset_stream` settles them.
///
/// A reset, a `SessionClosed` or `close` frees a stream's or session's
/// queues and grants at once. Handles are never reused, so platform events
/// for a handle that is gone are ignored.
pub struct WebTransportClient<Io, E> {
    io: Io,
    identity: Ed25519Keypair,
    entropy: E,
    limits: WebTransportLimits,
    caps: SendCaps,
    ids: ConnectionIdAllocator,
    connections: BTreeMap<ConnectionId, Session>,
    /// Ended connections whose delivered bytes are not all acknowledged yet;
    /// each still holds a connection slot.
    unsettled: UnsettledConnections,
    by_session: BTreeMap<SessionHandle, ConnectionId>,
    by_stream: BTreeMap<StreamHandle, ConnectionId>,
    events: Vec<TransportEvent>,
}

/// One dialed session.
struct Session {
    handle: SessionHandle,
    endpoint: ConnectionEndpoint,
    /// The dialed certhashes: the server's Noise extensions must list each.
    certhashes: Vec<Multihash>,
    /// The Noise stream and its session, until the handshake completes.
    noise_stream: Option<StreamHandle>,
    noise: Option<NoiseSession>,
    connected: bool,
    /// When an unconnected session times out, in monotonic ms, stamped at
    /// the first poll that sees it.
    handshake_deadline: Option<u64>,
    streams: BTreeMap<StreamHandle, Stream>,
    /// Pending write bytes across every stream (see [`Stream::pending`]).
    pending: usize,
    /// Streams that returned `Full` and wait for a `StreamWritable`.
    writable_armed: BTreeSet<StreamHandle>,
}

/// One stream's half-close state, write queue and read accounting.
#[derive(Default)]
struct Stream {
    /// We opened it (as opposed to the server).
    local: bool,
    /// The platform reported it writable.
    opened: bool,
    /// May fill the connection cap's control reserve.
    control: bool,
    /// Bytes the platform has not accepted yet.
    writes: VecDeque<QueuedWrite>,
    /// Bytes accepted from the caller and not yet reported written: those
    /// in `writes` plus `in_flight`.
    pending: usize,
    /// Bytes the platform accepted whose `WriteCompleted` has not arrived.
    in_flight: usize,
    /// A FIN goes out once `writes` drains.
    fin_queued: bool,
    /// Our write side is done: finished, stopped by the peer, or reset.
    local_closed: bool,
    remote_closed: bool,
    write_stopped: bool,
    closed_notified: bool,
    /// Delivered bytes the reader has not acknowledged.
    unacked: usize,
    /// Bytes granted to the platform and not yet delivered.
    granted: usize,
}

/// A queued write: a slice of a caller's payload, and the length its
/// allocation is counted at, so a shrinking tail pins at most twice its
/// bytes ([`retain_slice`]).
struct QueuedWrite {
    bytes: Bytes,
    counted: usize,
}

impl QueuedWrite {
    /// `bytes`, sliced from a payload `counted` bytes long.
    fn new(mut bytes: Bytes, mut counted: usize) -> Self {
        retain_slice(&mut bytes, &mut counted);
        Self { bytes, counted }
    }

    /// Drops the first `len` bytes, which the platform accepted.
    fn advance(&mut self, len: usize) {
        self.bytes = self.bytes.slice(len..);
        retain_slice(&mut self.bytes, &mut self.counted);
    }
}

impl Stream {
    /// Grants what is left of `window` after unacknowledged and still
    /// granted bytes.
    fn top_up(&mut self, io: &mut impl WebTransportIo, handle: StreamHandle, window: usize) {
        let room = window.saturating_sub(self.unacked + self.granted);
        if room > 0 {
            self.granted += room;
            io.grant_read(handle, room);
        }
    }

    /// Whether the stream is finished with and can be forgotten: both
    /// halves closed and reported, every delivered byte acknowledged, and
    /// every write reported.
    fn settled(&self) -> bool {
        self.closed_notified && self.unacked == 0 && self.pending == 0
    }
}

impl Session {
    /// Queues `write` on a stream, counted as pending.
    fn queue(&mut self, handle: StreamHandle, write: QueuedWrite) {
        if let Some(state) = self.streams.get_mut(&handle) {
            state.pending += write.bytes.len();
            self.pending += write.bytes.len();
            state.writes.push_back(write);
        }
    }

    /// Hands queued writes, then a queued FIN, to the platform as far as it
    /// takes them. Returns whether the platform refused the stream: its
    /// writes are then dropped and its write side stopped, for the caller to
    /// report.
    #[must_use]
    fn flush(&mut self, io: &mut impl WebTransportIo, handle: StreamHandle) -> bool {
        let Some(state) = self.streams.get_mut(&handle).filter(|state| state.opened) else {
            return false;
        };
        while let Some(front) = state.writes.front_mut() {
            match io.write(handle, &front.bytes) {
                Ok(written) if written >= front.bytes.len() => {
                    state.in_flight += front.bytes.len();
                    state.writes.pop_front();
                }
                // The rest waits for a WriteCompleted.
                Ok(written) => {
                    state.in_flight += written;
                    front.advance(written);
                    return false;
                }
                // The platform refused the stream: nothing more goes out.
                Err(_) => {
                    state.local_closed = true;
                    state.write_stopped = true;
                    self.drop_writes(handle);
                    return true;
                }
            }
        }
        if mem::take(&mut state.fin_queued) {
            io.close_write(handle);
        }
        false
    }

    /// Releases `bytes` of a stream's in-flight writes, which the platform
    /// reported written. A completion for writes already dropped releases
    /// nothing, and the Noise stream's own writes were never counted.
    fn complete(&mut self, handle: StreamHandle, bytes: usize) {
        if let Some(state) = self.streams.get_mut(&handle) {
            let released = bytes.min(state.in_flight);
            state.in_flight -= released;
            let counted = released.min(state.pending);
            state.pending -= counted;
            self.pending -= counted;
        }
    }

    /// The write side ended for good: queued and in-flight writes are gone
    /// (the platform drops its own), and so is any pending `StreamWritable`.
    fn drop_writes(&mut self, handle: StreamHandle) {
        self.writable_armed.remove(&handle);
        if let Some(state) = self.streams.get_mut(&handle) {
            state.writes.clear();
            state.fin_queued = false;
            state.in_flight = 0;
            self.pending -= mem::take(&mut state.pending);
        }
    }

    /// Streams held in one direction, the Noise stream aside.
    fn stream_count(&self, local: bool) -> usize {
        self.app_streams()
            .filter(|(_, state)| state.local == local)
            .count()
    }

    /// Every stream but the Noise stream.
    fn app_streams(&self) -> impl Iterator<Item = (&StreamHandle, &Stream)> {
        let noise = self.noise_stream;
        self.streams
            .iter()
            .filter(move |(handle, _)| Some(**handle) != noise)
    }
}

impl<Io: WebTransportIo, E: EntropySource> WebTransportClient<Io, E> {
    /// A client that dials as `identity` over `io`, drawing Noise keys from
    /// `entropy`, within the default [`WebTransportLimits`].
    pub fn new(io: Io, identity: Ed25519Keypair, entropy: E) -> Self {
        Self::build(io, identity, entropy, WebTransportLimits::default())
    }

    /// A client within `limits`, once they [validate](WebTransportLimits::validate).
    pub fn with_limits(
        io: Io,
        identity: Ed25519Keypair,
        entropy: E,
        limits: WebTransportLimits,
    ) -> Result<Self, InvalidLimit> {
        limits.validate()?;
        Ok(Self::build(io, identity, entropy, limits))
    }

    fn build(io: Io, identity: Ed25519Keypair, entropy: E, limits: WebTransportLimits) -> Self {
        Self {
            io,
            identity,
            entropy,
            caps: SendCaps::new(
                limits.max_pending_bytes_per_stream,
                limits.max_pending_connection_bytes,
                limits.control_stream_reserve_bytes,
            ),
            limits,
            ids: ConnectionIdAllocator::new(ConnectionNamespace::WEBTRANSPORT),
            connections: BTreeMap::new(),
            unsettled: UnsettledConnections::new(),
            by_session: BTreeMap::new(),
            by_stream: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// The platform I/O, for hosts that drive it.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Ends a connection that failed: the session is closed and `Closed`
    /// carries `reason`.
    fn fail(&mut self, id: ConnectionId, reason: String) {
        if let Some(session) = self.remove(id) {
            self.io.close(session.handle, 0, &reason);
            self.events.push(TransportEvent::Closed {
                id,
                reason: ConnectionCloseReason::Error(reason),
            });
        }
    }

    /// Forgets a connection and its handles, keeping its streams'
    /// unacknowledged counts as an unsettled connection, and dropping any
    /// `StreamWritable` it still had queued: nothing writes after `Closed`.
    fn remove(&mut self, id: ConnectionId) -> Option<Session> {
        let session = self.connections.remove(&id)?;
        self.by_session.remove(&session.handle);
        for handle in session.streams.keys() {
            self.by_stream.remove(handle);
        }
        self.unsettled.insert(
            id,
            session
                .app_streams()
                .map(|(handle, state)| (stream_id(*handle), state.unacked)),
        );
        self.events.retain(
            |event| !matches!(event, TransportEvent::StreamWritable { id: owner, .. } if *owner == id),
        );
        Some(session)
    }

    /// Drops a queued `StreamWritable` for a stream whose write side just
    /// ended.
    fn drop_writable(&mut self, id: ConnectionId, handle: StreamHandle) {
        let stream_id = stream_id(handle);
        self.events
            .retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
    }

    /// Emits `StreamWritable` for every armed stream of `id` that can again
    /// queue [`SendCaps::writable_threshold`]. The connection cap is shared,
    /// so freeing it wakes every stream it blocked.
    fn wake_writable(&mut self, id: ConnectionId) {
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
        for handle in mem::take(&mut conn.writable_armed) {
            let Some(state) = conn
                .streams
                .get(&handle)
                .filter(|state| !state.local_closed)
            else {
                continue;
            };
            let room = self.caps.room(state.pending, conn.pending, state.control);
            if room < self.caps.writable_threshold(state.control) {
                conn.writable_armed.insert(handle);
                continue;
            }
            self.events.push(TransportEvent::StreamWritable {
                id,
                stream_id: stream_id(handle),
            });
        }
    }

    fn on_io_event(&mut self, event: IoEvent) {
        match event {
            IoEvent::SessionReady { session } => self.on_session_ready(session),
            IoEvent::SessionClosed {
                session,
                code,
                reason,
            } => {
                let Some(&id) = self.by_session.get(&session) else {
                    return;
                };
                let Some(session) = self.remove(id) else {
                    return;
                };
                let reason = if session.connected {
                    ConnectionCloseReason::Remote {
                        code: u64::from(code),
                    }
                } else {
                    ConnectionCloseReason::Error(format!("WebTransport session failed: {reason}"))
                };
                self.events.push(TransportEvent::Closed { id, reason });
            }
            IoEvent::StreamOpened { stream } => self.on_stream_opened(stream),
            IoEvent::IncomingStream { session, stream } => self.on_incoming_stream(session, stream),
            IoEvent::Data { stream, bytes } => self.on_data(stream, bytes),
            IoEvent::Fin { stream } => self.on_fin(stream),
            IoEvent::Reset { stream, .. } => self.on_reset(stream),
            IoEvent::StopSending { stream, code } => self.on_stop_sending(stream, code),
            IoEvent::WriteCompleted { stream, bytes } => {
                let Some((id, noise)) = self.owner(stream) else {
                    return;
                };
                let refused = self.connections.get_mut(&id).is_some_and(|conn| {
                    conn.complete(stream, bytes);
                    conn.flush(&mut self.io, stream)
                });
                if refused && noise {
                    // The Noise stream is the client's own: no stream event,
                    // the handshake fails.
                    self.fail(id, NOISE_REFUSED.into());
                    return;
                }
                if refused {
                    self.on_write_refused(id, stream);
                }
                self.close_if_done(id, stream);
                self.wake_writable(id);
            }
        }
    }

    /// A stream's state, with the platform I/O beside it.
    fn stream_mut(&mut self, handle: StreamHandle) -> Option<(&mut Stream, &mut Io)> {
        let id = self.by_stream.get(&handle)?;
        let state = self.connections.get_mut(id)?.streams.get_mut(&handle)?;
        Some((state, &mut self.io))
    }

    /// The connection a handle belongs to, and whether it is the Noise
    /// stream.
    fn owner(&self, handle: StreamHandle) -> Option<(ConnectionId, bool)> {
        let id = *self.by_stream.get(&handle)?;
        let noise = self.connections.get(&id)?.noise_stream == Some(handle);
        Some((id, noise))
    }

    /// The CONNECT succeeded: open the Noise stream.
    fn on_session_ready(&mut self, session: SessionHandle) {
        let Some(&id) = self.by_session.get(&session) else {
            return;
        };
        match self.io.open_stream(session) {
            Ok(stream) => {
                if let Some(conn) = self.connections.get_mut(&id) {
                    conn.noise_stream = Some(stream);
                    conn.streams.insert(stream, Stream::default());
                    self.by_stream.insert(stream, id);
                }
            }
            Err(error) => self.fail(id, format!("opening the Noise stream failed: {error}")),
        }
    }

    /// The server opened a stream: admitted within the stream limit, reset
    /// with no event past it or before `Connected`.
    fn on_incoming_stream(&mut self, session: SessionHandle, stream: StreamHandle) {
        let max = self.limits.max_streams_per_connection;
        let admitted = self.by_session.get(&session).and_then(|&id| {
            let conn = self.connections.get_mut(&id)?;
            (conn.connected && conn.stream_count(false) < max).then_some((id, conn))
        });
        let Some((id, conn)) = admitted else {
            self.io.reset(stream, 0);
            return;
        };
        let mut state = Stream {
            opened: true,
            ..Stream::default()
        };
        state.top_up(&mut self.io, stream, self.limits.stream_receive_window);
        conn.streams.insert(stream, state);
        self.by_stream.insert(stream, id);
        self.events.push(TransportEvent::IncomingStream {
            id,
            stream_id: stream_id(stream),
        });
    }

    fn on_stream_opened(&mut self, handle: StreamHandle) {
        let Some((id, noise)) = self.owner(handle) else {
            return;
        };
        if !noise {
            let refused = self.connections.get_mut(&id).is_some_and(|conn| {
                if let Some(state) = conn.streams.get_mut(&handle) {
                    state.opened = true;
                }
                conn.flush(&mut self.io, handle)
            });
            if refused {
                self.on_write_refused(id, handle);
                self.wake_writable(id);
            }
            self.close_if_done(id, handle);
            return;
        }
        let mut secrets = [[0u8; 32]; 2];
        for secret in &mut secrets {
            if let Err(error) = self.entropy.fill_bytes(secret) {
                self.fail(id, format!("no entropy for Noise keys: {error}"));
                return;
            }
        }
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
        let [static_secret, ephemeral_secret] = secrets;
        let mut noise = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Initiator,
            identity: self.identity.clone(),
            static_secret,
            ephemeral_secret,
            expected_peer: conn.endpoint.peer_id().cloned(),
            local_extensions: None,
        });
        if let Err(error) = noise.start() {
            self.fail(id, format!("Noise start failed: {error}"));
            return;
        }
        conn.noise = Some(noise);
        if let Some(state) = conn.streams.get_mut(&handle) {
            state.opened = true;
            state.granted = NOISE_READ_GRANT;
            self.io.grant_read(handle, NOISE_READ_GRANT);
        }
        self.drive_noise(id, handle);
    }

    fn on_data(&mut self, handle: StreamHandle, bytes: Bytes) {
        let Some((id, noise)) = self.owner(handle) else {
            return;
        };
        if noise {
            let Some(conn) = self.connections.get_mut(&id) else {
                return;
            };
            let Some(session) = conn.noise.as_mut() else {
                // Anything after the handshake is ignored.
                return;
            };
            if let Err(error) = session.on_data(bytes.to_vec()) {
                self.fail(id, format!("Noise handshake failed: {error}"));
                return;
            }
            if let Some(state) = conn.streams.get_mut(&handle) {
                state.granted = state.granted.saturating_sub(bytes.len());
                state.top_up(&mut self.io, handle, NOISE_READ_GRANT);
            }
            self.drive_noise(id, handle);
            return;
        }
        let Some((state, _)) = self.stream_mut(handle) else {
            return;
        };
        if state.remote_closed {
            // Late: the read side already ended.
            return;
        }
        state.granted = state.granted.saturating_sub(bytes.len());
        state.unacked += bytes.len();
        self.events.push(TransportEvent::StreamData {
            id,
            stream_id: stream_id(handle),
            data: bytes,
        });
    }

    /// Writes the Noise session's output and, once the handshake is done,
    /// checks the server's certhashes and reports the connection.
    fn drive_noise(&mut self, id: ConnectionId, handle: StreamHandle) {
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
        let Some(noise) = conn.noise.as_mut() else {
            return;
        };
        let mut frames = Vec::new();
        let mut offered = None;
        while let Some(output) = noise.poll_output() {
            match output {
                NoiseOutput::Outbound(frame) => frames.push(Bytes::from(frame)),
                NoiseOutput::HandshakeComplete {
                    remote_extensions, ..
                } => {
                    offered = Some(
                        remote_extensions
                            .map(|extensions| extensions.webtransport_certhashes)
                            .unwrap_or_default(),
                    );
                }
                NoiseOutput::Decrypted(_) => {}
            }
        }
        let hash = noise.handshake_hash();
        // Handshake bytes are the client's own, not counted against the caps.
        if let Some(state) = conn.streams.get_mut(&handle) {
            state
                .writes
                .extend(frames.into_iter().map(|frame| QueuedWrite {
                    counted: frame.len(),
                    bytes: frame,
                }));
        }
        let Some(offered) = offered else {
            if conn.flush(&mut self.io, handle) {
                self.fail(id, NOISE_REFUSED.into());
            }
            return;
        };
        if let Some(&missing) = conn.certhashes.iter().find(|hash| !offered.contains(hash)) {
            let reason = format!(
                "the server's Noise extensions do not list the dialed certhash {}",
                Multiaddr::from_protocols(alloc::vec![Protocol::Certhash(missing)])
            );
            self.fail(id, reason);
            return;
        }
        // Message three goes out, then the Noise stream is finished.
        if let Some(state) = conn.streams.get_mut(&handle) {
            state.fin_queued = true;
            state.local_closed = true;
        }
        if conn.flush(&mut self.io, handle) {
            self.fail(id, NOISE_REFUSED.into());
            return;
        }
        if let Some(hash) = hash {
            conn.endpoint.set_token(ConnectionToken::new(hash));
        }
        conn.noise = None;
        conn.connected = true;
        conn.handshake_deadline = None;
        self.events.push(TransportEvent::Connected {
            id,
            endpoint: conn.endpoint.clone(),
        });
    }

    fn on_fin(&mut self, handle: StreamHandle) {
        let Some((id, noise)) = self.owner(handle) else {
            return;
        };
        if noise {
            if self
                .connections
                .get(&id)
                .is_some_and(|conn| !conn.connected)
            {
                self.fail(
                    id,
                    "the server finished the Noise stream mid-handshake".into(),
                );
            }
            return;
        }
        let Some((state, _)) = self.stream_mut(handle) else {
            return;
        };
        if state.remote_closed {
            return;
        }
        state.remote_closed = true;
        state.granted = 0;
        self.events.push(TransportEvent::StreamRemoteWriteClosed {
            id,
            stream_id: stream_id(handle),
        });
        self.close_if_done(id, handle);
    }

    fn on_reset(&mut self, handle: StreamHandle) {
        let Some((id, noise)) = self.owner(handle) else {
            return;
        };
        if noise {
            if self
                .connections
                .get(&id)
                .is_some_and(|conn| !conn.connected)
            {
                self.fail(id, "the server reset the Noise stream".into());
            }
            return;
        }
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
        // The peer reset only its sending side: reset ours too, as the QUIC
        // server does, so the platform stream is freed.
        self.io.reset(handle, 0);
        conn.drop_writes(handle);
        if let Some(state) = conn.streams.get_mut(&handle) {
            state.granted = 0;
            state.local_closed = true;
            state.remote_closed = true;
        }
        self.drop_writable(id, handle);
        self.close_if_done(id, handle);
        self.wake_writable(id);
    }

    fn on_stop_sending(&mut self, handle: StreamHandle, code: u8) {
        let Some((id, false)) = self.owner(handle) else {
            return;
        };
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
        let Some(state) = conn.streams.get_mut(&handle) else {
            return;
        };
        if state.write_stopped {
            return;
        }
        // After StreamClosed nothing more is reported, but writes still in
        // the platform are released: a stopped stream never completes them.
        let notify = !state.closed_notified;
        state.write_stopped = true;
        state.local_closed = true;
        conn.drop_writes(handle);
        self.drop_writable(id, handle);
        if notify {
            self.events.push(TransportEvent::StreamWriteStopped {
                id,
                stream_id: stream_id(handle),
                error_code: u64::from(code),
            });
        }
        self.close_if_done(id, handle);
        self.wake_writable(id);
    }

    /// The platform refused a stream's queued writes: its write side is
    /// stopped as if the peer had stopped it, with code 0.
    fn on_write_refused(&mut self, id: ConnectionId, handle: StreamHandle) {
        self.drop_writable(id, handle);
        self.events.push(TransportEvent::StreamWriteStopped {
            id,
            stream_id: stream_id(handle),
            error_code: 0,
        });
    }

    /// Emits `StreamClosed` once both halves are done, and forgets the
    /// stream once it [settled](Stream::settled).
    fn close_if_done(&mut self, id: ConnectionId, handle: StreamHandle) {
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
        if conn.noise_stream == Some(handle) {
            return;
        }
        let Some(state) = conn.streams.get_mut(&handle) else {
            return;
        };
        let finished = state.local_closed && state.writes.is_empty() && !state.fin_queued;
        if finished && state.remote_closed && !state.closed_notified {
            state.closed_notified = true;
            self.events.push(TransportEvent::StreamClosed {
                id,
                stream_id: stream_id(handle),
            });
        }
        if state.settled() {
            conn.streams.remove(&handle);
            self.by_stream.remove(&handle);
        }
    }

    /// The connection of a caller's ids, checked to hold the stream (the
    /// Noise stream is not the caller's).
    fn caller_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(&mut Session, &mut Io, StreamHandle), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let handle = StreamHandle(stream_id.as_u64());
        if conn.noise_stream == Some(handle) || !conn.streams.contains_key(&handle) {
            return Err(TransportError::StreamNotFound { id, stream_id });
        }
        Ok((conn, &mut self.io, handle))
    }

    /// Times out every session that has not connected by its deadline,
    /// stamping deadlines on sessions this poll sees first.
    fn expire_handshakes(&mut self, now: Now) {
        let timeout = self.limits.handshake_timeout_ms;
        let expired: Vec<ConnectionId> = self
            .connections
            .iter_mut()
            .filter(|(_, conn)| !conn.connected)
            .filter_map(|(id, conn)| {
                let at = *conn
                    .handshake_deadline
                    .get_or_insert(now.monotonic_ms.saturating_add(timeout));
                (now.monotonic_ms >= at).then_some(*id)
            })
            .collect();
        for id in expired {
            if let Some(session) = self.remove(id) {
                self.io
                    .close(session.handle, 0, "the WebTransport handshake timed out");
                self.events.push(TransportEvent::Closed {
                    id,
                    reason: ConnectionCloseReason::TimedOut,
                });
            }
        }
    }
}

/// The caller-facing id of a stream handle.
fn stream_id(handle: StreamHandle) -> StreamId {
    StreamId::new(handle.0)
}

impl<Io: WebTransportIo, E: EntropySource> Transport for WebTransportClient<Io, E> {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        if !addr.transport().is_webtransport() {
            return Err(TransportError::Unsupported {
                operation: "dialing anything but /webtransport/certhash addresses",
            });
        }
        let certhashes: Vec<Multihash> = addr.transport().certhashes().copied().collect();
        if certhashes.is_empty() {
            return Err(TransportError::Unsupported {
                operation: "WebTransport dials without a /certhash (CA certificates)",
            });
        }
        let url = webtransport_url(addr.transport())?;
        if self.connections.len() + self.unsettled.len() >= self.limits.max_connections {
            return Err(TransportError::ResourceExhausted {
                resource: "WebTransport connections",
            });
        }
        let id = self.ids.allocate()?;
        let handle =
            self.io
                .connect(&url, &certhashes)
                .map_err(|error| TransportError::DialFailed {
                    id,
                    reason: error.to_string(),
                })?;
        self.by_session.insert(handle, id);
        self.connections.insert(
            id,
            Session {
                handle,
                endpoint: ConnectionEndpoint::from_peer_addr(addr),
                certhashes,
                noise_stream: None,
                noise: None,
                connected: false,
                handshake_deadline: None,
                streams: BTreeMap::new(),
                pending: 0,
                writable_armed: BTreeSet::new(),
            },
        );
        Ok(id)
    }

    fn listen(&mut self, _addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listening on WebTransport from a client; use a relay reservation to be reachable",
        })
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        if !conn.connected {
            return Err(TransportError::InvalidState {
                id,
                state: ConnectionState::Connecting,
                expected: ConnectionState::Connected,
            });
        }
        if conn.stream_count(true) >= self.limits.max_streams_per_connection {
            return Err(TransportError::ResourceExhausted {
                resource: "local WebTransport streams",
            });
        }
        let handle = self
            .io
            .open_stream(conn.handle)
            .map_err(|error| TransportError::Io {
                operation: "opening a WebTransport stream",
                kind: IoErrorKind::Other,
                detail: error.to_string(),
            })?;
        let mut state = Stream {
            local: true,
            ..Stream::default()
        };
        state.top_up(&mut self.io, handle, self.limits.stream_receive_window);
        conn.streams.insert(handle, state);
        self.by_stream.insert(handle, id);
        let stream_id = stream_id(handle);
        self.events
            .push(TransportEvent::StreamOpened { id, stream_id });
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        if data.is_empty() {
            return Ok(());
        }
        let caps = self.caps;
        let (conn, io, handle) = self.caller_stream(id, stream_id)?;
        let Some(state) = conn
            .streams
            .get(&handle)
            .filter(|state| !state.local_closed)
        else {
            return Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        };
        let room = caps.room(state.pending, conn.pending, state.control);
        let accepted = data.len().min(room);
        if accepted != 0 {
            conn.queue(handle, QueuedWrite::new(data.slice(..accepted), data.len()));
            if conn.flush(io, handle) {
                self.drop_writable(id, handle);
                self.close_if_done(id, handle);
                self.wake_writable(id);
                return Err(TransportError::StreamSendFailed {
                    id,
                    stream_id,
                    reason: "the platform refused the write".into(),
                });
            }
        }
        if accepted < data.len() {
            conn.writable_armed.insert(handle);
            return Err(TransportError::Full {
                id,
                stream_id,
                unsent: data.slice(accepted..),
            });
        }
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let (conn, io, handle) = self.caller_stream(id, stream_id)?;
        let Some(state) = conn
            .streams
            .get_mut(&handle)
            .filter(|state| !state.local_closed)
        else {
            return Err(TransportError::StreamCloseWriteFailed {
                id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        };
        state.local_closed = true;
        state.fin_queued = true;
        conn.writable_armed.remove(&handle);
        let refused = conn.flush(io, handle);
        self.drop_writable(id, handle);
        self.close_if_done(id, handle);
        if refused {
            self.wake_writable(id);
            return Err(TransportError::StreamCloseWriteFailed {
                id,
                stream_id,
                reason: "the platform refused the stream's queued writes".into(),
            });
        }
        Ok(())
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if !self.connections.contains_key(&id) {
            // Abandoning a stream of an ended connection only settles it.
            return if self.unsettled.abandon(id, stream_id) {
                Ok(())
            } else {
                Err(TransportError::ConnectionNotFound { id })
            };
        }
        let (conn, io, handle) = self.caller_stream(id, stream_id)?;
        io.reset(handle, 0);
        conn.drop_writes(handle);
        let notified = conn
            .streams
            .remove(&handle)
            .is_some_and(|state| state.closed_notified);
        self.by_stream.remove(&handle);
        self.drop_writable(id, handle);
        if !notified {
            self.events
                .push(TransportEvent::StreamClosed { id, stream_id });
        }
        self.wake_writable(id);
        Ok(())
    }

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        if !self.connections.contains_key(&id) {
            // An ended connection's bytes are released without credit.
            return self.unsettled.ack(id, stream_id, bytes).map(|_held| ());
        }
        let window = self.limits.stream_receive_window;
        let Ok((conn, io, handle)) = self.caller_stream(id, stream_id) else {
            // A settled or unknown stream has nothing to acknowledge.
            return Ok(());
        };
        let Some(state) = conn.streams.get_mut(&handle) else {
            return Ok(());
        };
        if bytes > state.unacked {
            return Err(TransportError::AckExceedsDelivered {
                id,
                stream_id,
                acked: bytes,
                unacked: state.unacked,
            });
        }
        state.unacked -= bytes;
        if !state.remote_closed {
            state.top_up(io, handle, window);
        }
        self.close_if_done(id, handle);
        Ok(())
    }

    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        if let Ok((conn, _, handle)) = self.caller_stream(id, stream_id)
            && let Some(state) = conn.streams.get_mut(&handle)
        {
            state.control = control;
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let session = self
            .remove(id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        self.io.close(session.handle, 0, "");
        self.events.push(TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        });
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        while let Some(event) = self.io.poll_event() {
            self.on_io_event(event);
        }
        self.expire_handshakes(now);
        Ok(mem::take(&mut self.events))
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.events.is_empty() {
            return Some(Deadline::IMMEDIATE);
        }
        self.connections
            .values()
            .filter_map(|conn| conn.handshake_deadline)
            .min()
            .map(Deadline::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";

    fn url(addr: &str) -> Result<String, TransportError> {
        webtransport_url(&parse(addr))
    }

    fn parse(addr: &str) -> Multiaddr {
        addr.parse().expect("multiaddr")
    }

    #[test]
    fn urls_bracket_ipv6_and_pass_names_through() {
        assert_eq!(
            url(&format!(
                "/ip4/192.0.2.1/udp/4001/quic-v1/webtransport/{HASH}"
            )),
            Ok("https://192.0.2.1:4001/.well-known/libp2p-webtransport?type=noise".into())
        );
        assert_eq!(
            url(&format!(
                "/ip6/2001:db8::1/udp/443/quic-v1/webtransport/{HASH}"
            )),
            Ok("https://[2001:db8::1]:443/.well-known/libp2p-webtransport?type=noise".into())
        );
        assert_eq!(
            url(&format!(
                "/dns4/relay.example/udp/443/quic-v1/webtransport/{HASH}"
            )),
            Ok("https://relay.example:443/.well-known/libp2p-webtransport?type=noise".into())
        );
        assert!(matches!(
            url("/ip4/192.0.2.1/udp/4001/quic-v1"),
            Err(TransportError::InvalidAddress { .. })
        ));
    }
}
