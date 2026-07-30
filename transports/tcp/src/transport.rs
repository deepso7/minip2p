use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_platform::{Deadline, EntropySource, Now};
use minip2p_secure_mux::{
    SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole,
};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionIdAllocator, ConnectionState, StreamId, Transport,
    TransportError, TransportEvent,
};

use crate::config::TcpConfig;
use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider};

/// Why a connection is being torn down.
struct Teardown {
    /// Text for the public [`TransportEvent::Error`], if one is emitted.
    message: String,
    /// The remote ended an established session cleanly rather than failing.
    graceful: bool,
}

impl Teardown {
    fn fault(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            graceful: false,
        }
    }
}

impl From<SessionError> for Teardown {
    fn from(error: SessionError) -> Self {
        Self {
            graceful: matches!(error, SessionError::GoAway { code: 0 }),
            message: error.to_string(),
        }
    }
}

impl From<TcpError> for Teardown {
    fn from(error: TcpError) -> Self {
        Self::fault(error.to_string())
    }
}

struct Connection {
    id: ConnectionId,
    socket: SocketHandle,
    /// The remote transport address, refined to the concrete one once the
    /// socket reports it.
    remote: Multiaddr,
    /// Accepted rather than dialed, which is what
    /// [`Transport::active_inbound_connection_sources`] reports on.
    inbound: bool,
    /// Whether the byte stream is up. A dialed socket is not writable until
    /// then, so its session cannot start.
    linked: bool,
    session: SecureMuxSession,
    /// Bytes the session has produced that the socket has not accepted yet.
    outbound: VecDeque<u8>,
}

impl Connection {
    fn endpoint(&self, peer: Option<PeerId>) -> ConnectionEndpoint {
        match peer {
            Some(peer) => ConnectionEndpoint::with_peer_id(self.remote.clone(), peer),
            None => ConnectionEndpoint::new(self.remote.clone()),
        }
    }
}

/// A libp2p TCP transport over any [`TcpProvider`].
///
/// See the [crate docs](crate) for how the pieces fit and what a provider owes
/// the transport.
pub struct TcpTransport<P, E> {
    provider: P,
    entropy: E,
    identity: Ed25519Keypair,
    config: TcpConfig,
    ids: ConnectionIdAllocator,
    connections: BTreeMap<ConnectionId, Connection>,
    by_socket: BTreeMap<SocketHandle, ConnectionId>,
    pending: VecDeque<TransportEvent>,
}

impl<P, E> TcpTransport<P, E> {
    /// Creates a transport with explicit configuration.
    pub fn with_config(
        provider: P,
        identity: Ed25519Keypair,
        entropy: E,
        config: TcpConfig,
    ) -> Self {
        Self {
            provider,
            entropy,
            identity,
            ids: ConnectionIdAllocator::new(config.namespace),
            config,
            connections: BTreeMap::new(),
            by_socket: BTreeMap::new(),
            pending: VecDeque::new(),
        }
    }

    /// Creates a transport with [`TcpConfig::default`].
    pub fn new(provider: P, identity: Ed25519Keypair, entropy: E) -> Self {
        Self::with_config(provider, identity, entropy, TcpConfig::default())
    }

    /// Borrows the provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Mutably borrows the provider.
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    /// The local peer identity this transport proves during the upgrade.
    pub fn local_peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// The active connection identifiers.
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.keys().copied().collect()
    }
}

impl<P: TcpProvider, E: EntropySource> TcpTransport<P, E> {
    /// Runs `operation` with the connection taken out of the map, so it can
    /// borrow the provider and the event queue at the same time.
    fn with_connection<R>(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut Self, &mut Connection) -> Result<R, Teardown>,
    ) -> Result<R, Teardown> {
        let mut connection = self
            .connections
            .remove(&id)
            .ok_or_else(|| Teardown::fault(format!("connection {id} is unknown")))?;
        let result = operation(self, &mut connection);
        self.connections.insert(id, connection);
        result
    }

    /// Builds a session for one connection.
    fn new_session(
        &mut self,
        role: SessionRole,
        expected_peer: Option<PeerId>,
    ) -> Result<SecureMuxSession, TransportError> {
        let mut static_secret = [0u8; 32];
        let mut ephemeral_secret = [0u8; 32];
        let mut draw = |target: &mut [u8; 32]| {
            self.entropy
                .fill_bytes(target)
                .map_err(|error| TransportError::PollError {
                    reason: format!("entropy unavailable: {error}"),
                })
        };
        draw(&mut static_secret)?;
        draw(&mut ephemeral_secret)?;

        Ok(SecureMuxSession::new(SessionConfig {
            role,
            identity: self.identity.clone(),
            static_secret,
            ephemeral_secret,
            expected_peer,
            yamux: self.config.yamux.clone(),
        }))
    }

    /// Drains session outputs into buffered writes and public events.
    ///
    /// The session queues both in one ordered stream, so a single pass keeps
    /// the wire and the event feed in step. Bytes only reach the socket in
    /// [`flush`](Self::flush), which is what absorbs a socket that is not
    /// accepting writes right now.
    fn pump(&mut self, connection: &mut Connection) -> Result<(), Teardown> {
        while let Some(output) = connection.session.poll_output() {
            match output {
                SessionOutput::Write(bytes) => {
                    if connection.outbound.len() + bytes.len() > self.config.max_buffered_send {
                        return Err(Teardown::fault(format!(
                            "outbound buffer exceeded {} bytes; peer is not reading",
                            self.config.max_buffered_send
                        )));
                    }
                    connection.outbound.extend(bytes);
                }
                SessionOutput::Established { peer } => {
                    self.pending.push_back(TransportEvent::Connected {
                        id: connection.id,
                        endpoint: connection.endpoint(Some(peer)),
                    });
                }
                SessionOutput::IncomingStream { stream } => {
                    self.pending.push_back(TransportEvent::IncomingStream {
                        id: connection.id,
                        stream_id: stream,
                    });
                }
                SessionOutput::StreamData { stream, data } => {
                    self.pending.push_back(TransportEvent::StreamData {
                        id: connection.id,
                        stream_id: stream,
                        data,
                    });
                }
                SessionOutput::StreamRemoteWriteClosed { stream } => {
                    self.pending
                        .push_back(TransportEvent::StreamRemoteWriteClosed {
                            id: connection.id,
                            stream_id: stream,
                        });
                }
                SessionOutput::StreamClosed { stream } => {
                    self.pending.push_back(TransportEvent::StreamClosed {
                        id: connection.id,
                        stream_id: stream,
                    });
                }
            }
        }
        Ok(())
    }

    /// Writes as much of the outbound buffer as the socket takes.
    ///
    /// Stops at the first write the socket does not fully accept and keeps the
    /// remainder, which a later `Writable` or `poll` retries. A dialed socket
    /// that has not linked yet holds everything, since writing before the
    /// stream is up is not allowed.
    fn flush(&mut self, connection: &mut Connection) -> Result<(), Teardown> {
        if !connection.linked {
            return Ok(());
        }
        while !connection.outbound.is_empty() {
            let accepted = {
                let pending = connection.outbound.make_contiguous();
                self.provider.send(connection.socket, pending)?
            };
            if accepted == 0 {
                break;
            }
            connection.outbound.drain(..accepted);
        }
        Ok(())
    }

    /// Pumps then flushes, the pairing every session interaction needs.
    fn pump_and_flush(&mut self, connection: &mut Connection) -> Result<(), Teardown> {
        self.pump(connection)?;
        self.flush(connection)
    }

    /// Tears a connection down, emitting `Closed` and optionally `Error`.
    ///
    /// Aborting the socket is what makes this final: a provider emits nothing
    /// further for an aborted handle, so no late event can resurrect the id.
    fn fail_connection(&mut self, id: ConnectionId, message: String, emit_error: bool) {
        let Some(connection) = self.connections.remove(&id) else {
            return;
        };
        self.by_socket.remove(&connection.socket);
        self.provider.abort(connection.socket);
        if emit_error {
            self.pending
                .push_back(TransportEvent::Error { id, message });
        }
        self.pending.push_back(TransportEvent::Closed { id });
    }

    /// Feeds a session and flushes, tearing the connection down on failure.
    fn drive_connection(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut SecureMuxSession) -> Result<(), SessionError>,
    ) {
        // A failed session is unusable, so `is_established` reads false
        // afterwards: capture it first. A normal remote GoAway on an
        // established connection must close without being reported as a
        // failed handshake.
        let pre_established = self
            .connections
            .get(&id)
            .is_some_and(|connection| !connection.session.is_established());
        let result = self.with_connection(id, |this, connection| {
            let fed = operation(&mut connection.session);
            // Pump either way: bytes the session queued before failing, and
            // events it already produced, are the host's regardless.
            let pumped = this.pump_and_flush(connection);
            fed.map_err(Teardown::from).and(pumped)
        });
        if let Err(teardown) = result {
            self.fail_connection(id, teardown.message, pre_established || !teardown.graceful);
        }
    }

    /// Runs one stream operation against a connection's session and flushes
    /// whatever it queued.
    ///
    /// A failure that kills the session closes the connection before
    /// returning. No `Error` event goes out: the caller already learns why
    /// from the returned error, exactly as for a locally requested
    /// [`Transport::close`].
    fn operate_session<R>(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut SecureMuxSession) -> Result<R, SessionError>,
    ) -> Result<R, TransportError> {
        let mut connection = self
            .connections
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let result = operation(&mut connection.session);
        let pumped = self.pump_and_flush(&mut connection);
        self.connections.insert(id, connection);

        if let Err(teardown) = pumped {
            self.fail_connection(id, teardown.message.clone(), false);
            return Err(TransportError::PollError {
                reason: teardown.message,
            });
        }
        match result {
            Ok(value) => Ok(value),
            Err(SessionError::NotEstablished) => Err(TransportError::InvalidState {
                id,
                state: ConnectionState::Connecting,
                expected: ConnectionState::Connected,
            }),
            Err(SessionError::UnknownStream { stream }) => Err(TransportError::StreamNotFound {
                id,
                stream_id: stream,
            }),
            // Yamux refused the operation -- a full send buffer, an unknown
            // substream -- but the session itself is still healthy.
            Err(SessionError::Yamux(error)) => Err(TransportError::PollError {
                reason: error.to_string(),
            }),
            // Defensive: today a session only fails fatally while handling
            // input, so a local operation cannot land here. Dropping the arm
            // would leave a dead session in the map if that ever changed.
            Err(fatal) => {
                let reason = fatal.to_string();
                self.fail_connection(id, reason.clone(), false);
                Err(TransportError::PollError { reason })
            }
        }
    }

    fn handle_provider_event(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Accepted { socket, remote } => self.accept(socket, remote),
            TcpEvent::Connected { socket, remote } => {
                let Some(id) = self.by_socket.get(&socket).copied() else {
                    // A handle we never dialed, or one already torn down.
                    self.provider.abort(socket);
                    return;
                };
                if let Some(connection) = self.connections.get_mut(&id) {
                    connection.remote = remote;
                    connection.linked = true;
                }
                self.drive_connection(id, SecureMuxSession::start);
            }
            TcpEvent::Received { socket, data } => {
                if let Some(id) = self.by_socket.get(&socket).copied() {
                    self.drive_connection(id, move |session| session.handle_input(data));
                }
            }
            // Nothing to do beyond having been polled: `poll` retries every
            // buffered write before it returns, so readiness needs no separate
            // path. One flush point is one thing to get right.
            TcpEvent::Writable { .. } => {}
            TcpEvent::RemoteWriteClosed { socket } => {
                // libp2p needs the stream in both directions, so a remote FIN
                // ends the connection. Yamux carries its own orderly shutdown
                // and would have surfaced it before this.
                self.close_from_provider(socket, "remote closed its write side".to_string(), false);
            }
            TcpEvent::Closed { socket, reason } => {
                let graceful = reason.is_none();
                let message = reason.unwrap_or_else(|| "byte stream closed".to_string());
                self.close_from_provider(socket, message, graceful);
            }
        }
    }

    fn accept(&mut self, socket: SocketHandle, remote: Multiaddr) {
        // Name the connection up front, even though what follows may reject it.
        // The id is what an `Error` would refer to, so it has to be spent
        // either way: reusing it later would point two outcomes at one id.
        // An exhausted namespace leaves nothing to report against, so the
        // socket just goes.
        let Ok(id) = self.ids.allocate() else {
            self.provider.abort(socket);
            return;
        };
        let session = match self.new_session(SessionRole::Responder, None) {
            Ok(session) => session,
            Err(error) => {
                self.provider.abort(socket);
                self.pending.push_back(TransportEvent::Error {
                    id,
                    message: format!("inbound connection rejected: {error}"),
                });
                return;
            }
        };

        self.by_socket.insert(socket, id);
        self.connections.insert(
            id,
            Connection {
                id,
                socket,
                remote: remote.clone(),
                inbound: true,
                // Accepted sockets are already up.
                linked: true,
                session,
                outbound: VecDeque::new(),
            },
        );
        self.pending.push_back(TransportEvent::IncomingConnection {
            id,
            endpoint: ConnectionEndpoint::new(remote),
        });
        self.drive_connection(id, SecureMuxSession::start);
    }

    fn close_from_provider(&mut self, socket: SocketHandle, message: String, graceful: bool) {
        let Some(id) = self.by_socket.get(&socket).copied() else {
            return;
        };
        let pre_established = self
            .connections
            .get(&id)
            .is_some_and(|connection| !connection.session.is_established());
        self.fail_connection(id, message, pre_established || !graceful);
    }

    fn drain_pending_events(&mut self) -> Vec<TransportEvent> {
        self.pending.drain(..).collect()
    }
}

impl<P: TcpProvider, E: EntropySource> Transport for TcpTransport<P, E> {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let target = addr.transport();
        if !target.is_tcp_transport() {
            return Err(TransportError::InvalidAddress {
                context: "tcp dial",
                reason: format!("{target} is not a /tcp transport address"),
            });
        }
        // Peek before anything with a side effect, so an exhausted namespace
        // cannot leave a connected socket with no id to name it.
        let id = self.ids.peek().ok_or(TransportError::ResourceExhausted {
            resource: "tcp connection ids",
        })?;
        let session = self.new_session(SessionRole::Initiator, Some(addr.peer_id().clone()))?;
        let socket = self
            .provider
            .connect(target)
            .map_err(|error| TransportError::DialFailed {
                id,
                reason: error.to_string(),
            })?;

        let consumed = self.ids.allocate();
        debug_assert_eq!(consumed, Ok(id), "peeked id must match the allocated one");

        self.by_socket.insert(socket, id);
        self.connections.insert(
            id,
            Connection {
                id,
                socket,
                remote: target.clone(),
                inbound: false,
                // Nothing may be written until the provider reports the link.
                linked: false,
                session,
                outbound: VecDeque::new(),
            },
        );
        Ok(id)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        if !addr.is_tcp_transport() {
            return Err(TransportError::InvalidAddress {
                context: "tcp listen",
                reason: format!("{addr} is not a /tcp transport address"),
            });
        }
        let bound = self
            .provider
            .listen(addr)
            .map_err(|error| TransportError::ListenFailed {
                reason: error.to_string(),
            })?;
        self.pending.push_back(TransportEvent::Listening {
            addr: bound.clone(),
        });
        Ok(bound)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        let stream_id = self.operate_session(id, SecureMuxSession::open_stream)?;
        self.pending
            .push_back(TransportEvent::StreamOpened { id, stream_id });
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        if data.is_empty() {
            // The contract makes an empty write a no-op, but not a way to
            // address a connection that does not exist -- the same order the
            // QUIC adapter applies.
            return if self.connections.contains_key(&id) {
                Ok(())
            } else {
                Err(TransportError::ConnectionNotFound { id })
            };
        }
        self.operate_session(id, |session| session.send(stream_id, data))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamSendFailed {
                    id,
                    stream_id,
                    reason,
                })
            })
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.operate_session(id, |session| session.close_stream_write(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamCloseWriteFailed {
                    id,
                    stream_id,
                    reason,
                })
            })
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.operate_session(id, |session| session.reset_stream(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamResetFailed {
                    id,
                    stream_id,
                    reason,
                })
            })
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let mut connection = self
            .connections
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        self.by_socket.remove(&connection.socket);

        // A connection still negotiating has no Yamux session to shut down, so
        // `go_away` refuses and the socket is aborted instead.
        let announced = connection.session.go_away(0).is_ok();
        let flushed = announced && self.pump_and_flush(&mut connection).is_ok();
        // Anything still buffered would be discarded by the FIN, so only a
        // fully drained socket can be closed gracefully.
        let graceful = flushed
            && connection.outbound.is_empty()
            && self.provider.close_write(connection.socket).is_ok();
        if !graceful {
            self.provider.abort(connection.socket);
        }
        self.pending.push_back(TransportEvent::Closed { id });
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        // Hand back what is already queued before doing more work, so a host
        // that acts between polls -- opening a stream on a fresh `Connected`,
        // say -- does so against the state those events described.
        if !self.pending.is_empty() {
            return Ok(self.drain_pending_events());
        }
        let events = self
            .provider
            .poll(now)
            .map_err(|error| TransportError::PollError {
                reason: error.to_string(),
            })?;
        for event in events {
            self.handle_provider_event(event);
        }
        // Retry buffered writes even without a `Writable` event, so a provider
        // that only reports readiness coarsely still drains.
        for id in self.connections.keys().copied().collect::<Vec<_>>() {
            let buffered = self
                .connections
                .get(&id)
                .is_some_and(|connection| !connection.outbound.is_empty());
            if !buffered {
                continue;
            }
            if let Err(teardown) =
                self.with_connection(id, |this, connection| this.flush(connection))
            {
                self.fail_connection(id, teardown.message, true);
            }
        }
        Ok(self.drain_pending_events())
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() {
            // Buffered events are due regardless of what the host's clock
            // reads, so this needs no retained time sample.
            return Some(Deadline::IMMEDIATE);
        }
        if self
            .connections
            .values()
            .any(|connection| !connection.outbound.is_empty())
        {
            // Queued writes are waiting on socket writability; keep the driver
            // coming back until they drain.
            return Some(Deadline::IMMEDIATE);
        }
        self.provider.next_deadline()
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.provider.local_addresses()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.connections
            .values()
            .filter(|connection| connection.inbound)
            .map(|connection| connection.remote.clone())
            .collect()
    }
}

/// Wraps a session failure as the stream error the transport contract expects.
///
/// Identifier and state errors pass through: they describe the request rather
/// than the stream operation, and callers match on them.
fn stream_error(
    error: TransportError,
    wrap: impl FnOnce(String) -> TransportError,
) -> TransportError {
    match error {
        error @ (TransportError::ConnectionNotFound { .. }
        | TransportError::StreamNotFound { .. }
        | TransportError::InvalidState { .. }) => error,
        error => wrap(error.to_string()),
    }
}
