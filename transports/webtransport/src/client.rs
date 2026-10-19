//! [`WebTransportClient`]: libp2p WebTransport dialing over a
//! [`WebTransportIo`], as a [`Transport`].
//!
//! A dial opens a session to the server's `/.well-known/libp2p-webtransport`
//! URL, trusting only the certificates its address names, then runs Noise XX
//! as initiator on the session's first stream. The server must prove the
//! dialed peer id and list every dialed certhash in its Noise extensions;
//! then the Noise stream is finished and the connection is up. Every later
//! stream is a plain libp2p stream, mapped 1:1 onto a WebTransport stream.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem;
use core::net::{Ipv4Addr, Ipv6Addr};

use minip2p_core::platform::{Deadline, EntropySource, IoErrorKind, Now};
use minip2p_core::{Bytes, Multiaddr, Multihash, PeerAddr, Protocol};
use minip2p_identity::Ed25519Keypair;
use minip2p_secure_mux::noise::{NoiseConfig, NoiseOutput, NoiseRole, NoiseSession};
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, ConnectionIdAllocator,
    ConnectionNamespace, ConnectionState, ConnectionToken, StreamId, Transport, TransportError,
    TransportEvent,
};

use crate::io::{IoEvent, SessionHandle, StreamHandle, WebTransportIo};

/// The path and query of every libp2p WebTransport session.
pub const LIBP2P_WEBTRANSPORT_PATH: &str = "/.well-known/libp2p-webtransport?type=noise";

/// Bytes each stream may deliver before its reader acknowledges them.
const STREAM_RECEIVE_WINDOW: usize = 256 * 1024;

/// Read grant on the Noise stream; handshake messages are far smaller.
const NOISE_READ_GRANT: usize = 64 * 1024;

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
pub struct WebTransportClient<Io, E> {
    io: Io,
    identity: Ed25519Keypair,
    entropy: E,
    ids: ConnectionIdAllocator,
    connections: BTreeMap<ConnectionId, Session>,
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
    streams: BTreeMap<StreamHandle, Stream>,
}

/// One stream's half-close state, write queue and read accounting.
#[derive(Default)]
struct Stream {
    /// The platform reported it writable.
    opened: bool,
    /// Bytes the platform has not accepted yet.
    writes: VecDeque<Bytes>,
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

impl Stream {
    fn opened() -> Self {
        Self {
            opened: true,
            ..Self::default()
        }
    }

    /// Grants what is left of `window` after unacknowledged and still
    /// granted bytes.
    fn top_up(&mut self, io: &mut impl WebTransportIo, handle: StreamHandle, window: usize) {
        let room = window.saturating_sub(self.unacked + self.granted);
        if room > 0 {
            self.granted += room;
            io.grant_read(handle, room);
        }
    }

    /// Hands queued writes, then a queued FIN, to the platform as far as it
    /// takes them.
    fn flush(&mut self, io: &mut impl WebTransportIo, handle: StreamHandle) {
        if !self.opened {
            return;
        }
        while let Some(front) = self.writes.front_mut() {
            match io.write(handle, front) {
                Ok(written) if written >= front.len() => {
                    self.writes.pop_front();
                }
                // The rest waits for a WriteCompleted.
                Ok(written) => {
                    *front = front.slice(written..);
                    return;
                }
                // The platform refused the stream: nothing more goes out.
                Err(_) => {
                    self.writes.clear();
                    self.fin_queued = false;
                    return;
                }
            }
        }
        if mem::take(&mut self.fin_queued) {
            io.close_write(handle);
        }
    }
}

impl<Io: WebTransportIo, E: EntropySource> WebTransportClient<Io, E> {
    /// A client that dials as `identity` over `io`, drawing Noise keys from
    /// `entropy`.
    pub fn new(io: Io, identity: Ed25519Keypair, entropy: E) -> Self {
        Self {
            io,
            identity,
            entropy,
            ids: ConnectionIdAllocator::new(ConnectionNamespace::WEBTRANSPORT),
            connections: BTreeMap::new(),
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

    /// Forgets a connection and its handles.
    fn remove(&mut self, id: ConnectionId) -> Option<Session> {
        let session = self.connections.remove(&id)?;
        self.by_session.remove(&session.handle);
        for handle in session.streams.keys() {
            self.by_stream.remove(handle);
        }
        Some(session)
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
            IoEvent::IncomingStream { session, stream } => {
                let Some(&id) = self.by_session.get(&session) else {
                    self.io.reset(stream, 0);
                    return;
                };
                let Some(conn) = self.connections.get_mut(&id).filter(|conn| conn.connected) else {
                    // Nothing precedes Connected.
                    self.io.reset(stream, 0);
                    return;
                };
                let mut state = Stream::opened();
                state.top_up(&mut self.io, stream, STREAM_RECEIVE_WINDOW);
                conn.streams.insert(stream, state);
                self.by_stream.insert(stream, id);
                self.events.push(TransportEvent::IncomingStream {
                    id,
                    stream_id: stream_id(stream),
                });
            }
            IoEvent::Data { stream, bytes } => self.on_data(stream, bytes),
            IoEvent::Fin { stream } => self.on_fin(stream),
            IoEvent::Reset { stream, .. } => self.on_reset(stream),
            IoEvent::StopSending { stream, code } => self.on_stop_sending(stream, code),
            IoEvent::WriteCompleted { stream, .. } => {
                if let Some((state, io)) = self.stream_mut(stream) {
                    state.flush(io, stream);
                }
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

    fn on_stream_opened(&mut self, handle: StreamHandle) {
        let Some((id, noise)) = self.owner(handle) else {
            return;
        };
        if !noise {
            if let Some((state, io)) = self.stream_mut(handle) {
                state.opened = true;
                state.flush(io, handle);
            }
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
        if state.closed_notified {
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
        let (Some(noise), Some(state)) = (conn.noise.as_mut(), conn.streams.get_mut(&handle))
        else {
            return;
        };
        let mut offered = None;
        while let Some(output) = noise.poll_output() {
            match output {
                NoiseOutput::Outbound(frame) => state.writes.push_back(Bytes::from(frame)),
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
        let Some(offered) = offered else {
            state.flush(&mut self.io, handle);
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
        state.fin_queued = true;
        state.local_closed = true;
        state.flush(&mut self.io, handle);
        if let Some(hash) = noise.handshake_hash() {
            conn.endpoint.set_token(ConnectionToken::new(hash));
        }
        conn.noise = None;
        conn.connected = true;
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
        if state.remote_closed || state.closed_notified {
            return;
        }
        state.remote_closed = true;
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
        let Some((state, _)) = self.stream_mut(handle) else {
            return;
        };
        state.writes.clear();
        state.fin_queued = false;
        state.local_closed = true;
        state.remote_closed = true;
        self.close_if_done(id, handle);
    }

    fn on_stop_sending(&mut self, handle: StreamHandle, code: u8) {
        let Some((id, false)) = self.owner(handle) else {
            return;
        };
        let Some((state, _)) = self.stream_mut(handle) else {
            return;
        };
        if state.write_stopped || state.closed_notified {
            return;
        }
        state.write_stopped = true;
        state.local_closed = true;
        state.writes.clear();
        state.fin_queued = false;
        self.events.push(TransportEvent::StreamWriteStopped {
            id,
            stream_id: stream_id(handle),
            error_code: u64::from(code),
        });
        self.close_if_done(id, handle);
    }

    /// Emits `StreamClosed` once both halves are done, and forgets the
    /// stream once its delivered bytes are acknowledged too.
    fn close_if_done(&mut self, id: ConnectionId, handle: StreamHandle) {
        let Some(conn) = self.connections.get_mut(&id) else {
            return;
        };
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
        if state.closed_notified && state.unacked == 0 {
            conn.streams.remove(&handle);
            self.by_stream.remove(&handle);
        }
    }

    /// The connection and stream state for a caller's ids.
    fn caller_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(&mut Stream, &mut Io), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let handle = StreamHandle(stream_id.as_u64());
        let state = conn
            .streams
            .get_mut(&handle)
            .filter(|_| conn.noise_stream != Some(handle))
            .ok_or(TransportError::StreamNotFound { id, stream_id })?;
        Ok((state, &mut self.io))
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
                streams: BTreeMap::new(),
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
        let handle = self
            .io
            .open_stream(conn.handle)
            .map_err(|error| TransportError::Io {
                operation: "opening a WebTransport stream",
                kind: IoErrorKind::Other,
                detail: error.to_string(),
            })?;
        let mut state = Stream::default();
        state.top_up(&mut self.io, handle, STREAM_RECEIVE_WINDOW);
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
        let (state, io) = self.caller_stream(id, stream_id)?;
        if state.local_closed {
            return Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        }
        state.writes.push_back(data);
        state.flush(io, StreamHandle(stream_id.as_u64()));
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let (state, io) = self.caller_stream(id, stream_id)?;
        if state.local_closed {
            return Err(TransportError::StreamCloseWriteFailed {
                id,
                stream_id,
                reason: "local stream write side is already closed".into(),
            });
        }
        state.local_closed = true;
        state.fin_queued = true;
        let handle = StreamHandle(stream_id.as_u64());
        state.flush(io, handle);
        self.close_if_done(id, handle);
        Ok(())
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let handle = StreamHandle(stream_id.as_u64());
        let (state, io) = self.caller_stream(id, stream_id)?;
        io.reset(handle, 0);
        let notified = state.closed_notified;
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.streams.remove(&handle);
        }
        self.by_stream.remove(&handle);
        if !notified {
            self.events
                .push(TransportEvent::StreamClosed { id, stream_id });
        }
        Ok(())
    }

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        let handle = StreamHandle(stream_id.as_u64());
        let Ok((state, io)) = self.caller_stream(id, stream_id) else {
            // A settled or unknown stream has nothing to acknowledge.
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
            state.top_up(io, handle, STREAM_RECEIVE_WINDOW);
        }
        self.close_if_done(id, handle);
        Ok(())
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

    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        while let Some(event) = self.io.poll_event() {
            self.on_io_event(event);
        }
        Ok(mem::take(&mut self.events))
    }

    fn next_deadline(&self) -> Option<Deadline> {
        (!self.events.is_empty()).then_some(Deadline::IMMEDIATE)
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
