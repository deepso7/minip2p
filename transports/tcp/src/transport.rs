use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::platform::{Deadline, EntropySource, Now};
use minip2p_core::{Bytes, Multiaddr, PeerAddr};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_secure_mux::{
    SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole, YamuxError,
};
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, ConnectionIdAllocator,
    ConnectionNamespace, ConnectionState, ConnectionToken, InvalidLimit, StreamId, Transport,
    TransportError, TransportEvent, UnsettledConnections,
};

use crate::config::TcpConfig;
use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider};

/// Longest a gracefully closed socket waits for the peer to close its side
/// before it is aborted. See [`TcpTransport::closing`].
const CLOSE_LINGER_MS: u64 = 10_000;

/// Why a connection is being torn down.
struct Teardown(ConnectionCloseReason);

impl Teardown {
    fn fault(message: impl Into<String>) -> Self {
        Self(ConnectionCloseReason::Error(message.into()))
    }
}

impl From<SessionError> for Teardown {
    fn from(error: SessionError) -> Self {
        Self(error.close_reason())
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
    /// Bytes pulled from the session that the socket has not accepted yet.
    /// The session is pulled only while this is below
    /// [`TcpConfig::max_buffered_send`].
    outbound: VecDeque<u8>,
    /// When the socket last refused everything, while bytes were still queued.
    ///
    /// `None` means the last flush made progress. Cleared the moment the
    /// socket accepts anything again.
    stalled_since: Option<u64>,
    /// The socket refused bytes and has not accepted any since. Its next
    /// acceptance shows the peer is alive: a full send buffer frees room only
    /// as the peer's TCP acknowledges data.
    refused: bool,
    /// When this connection stops being given time to authenticate.
    ///
    /// Stamped by the first poll to see it rather than by the call that made
    /// it: a transport owns no clock, so between polls the only time it holds
    /// is the last poll's sample, and after an idle spell that is arbitrarily
    /// long ago. Dating a dial from it would start it already expired. `None`
    /// once the session is established, or if the host set no timeout.
    authenticate_by: Option<u64>,
    /// This connection's entry in [`TcpTransport::timers`], so it can be
    /// found again to move or drop.
    wake_at: Option<u64>,
}

impl Connection {
    fn new(
        id: ConnectionId,
        socket: SocketHandle,
        remote: Multiaddr,
        inbound: bool,
        session: SecureMuxSession,
    ) -> Self {
        Self {
            id,
            socket,
            remote,
            inbound,
            linked: inbound,
            session,
            outbound: VecDeque::new(),
            stalled_since: None,
            refused: false,
            authenticate_by: None,
            wake_at: None,
        }
    }

    /// Bytes still to move from the session to the socket.
    ///
    /// Such a connection is retried on every poll, so a provider that only
    /// reports writability coarsely still drains it.
    fn has_backlog(&self) -> bool {
        !self.outbound.is_empty() || (self.linked && self.session.has_pending_write())
    }

    /// When this connection next needs a poll, [`Deadline::IMMEDIATE`] as 0.
    fn wake_at(&self, stall_timeout: Option<u64>) -> Option<u64> {
        let mut at = self.authenticate_by;
        let mut fold = |deadline: u64| at = Some(at.map_or(deadline, |at| at.min(deadline)));
        if let Some(keepalive) = self.session.next_deadline() {
            fold(keepalive.as_millis());
        }
        if self.outbound.is_empty() {
            if self.linked && self.session.has_pending_write() {
                return Some(0);
            }
        } else if let Some(since) = self.stalled_since {
            if let Some(timeout) = stall_timeout {
                fold(since.saturating_add(timeout));
            }
        } else {
            return Some(0);
        }
        at
    }

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
    /// Ended connections whose delivered bytes are not settled yet. Each
    /// still holds a slot against [`TcpConfig::max_connections`] (ADR 0012).
    unsettled: UnsettledConnections,
    by_socket: BTreeMap<SocketHandle, ConnectionId>,
    pending: VecDeque<TransportEvent>,
    /// Connections the next poll services regardless of time: new ones, which
    /// the poll stamps with an authentication deadline; ones whose session
    /// was driven since, whose keepalive the poll restarts; and ones with a
    /// backlog to retry. Everything else waits for a provider event or its
    /// entry in `timers`, so a poll costs what has work rather than every
    /// connection.
    work: BTreeSet<ConnectionId>,
    /// Each connection's next wake-up -- authentication, keepalive, or stall
    /// deadline, or 0 for straight away -- ordered so the earliest is first.
    timers: BTreeSet<(u64, ConnectionId)>,
    /// Sockets of gracefully closed connections, kept until the peer closes
    /// its side too, with when to give up on that (`None` until the next poll
    /// stamps it). Dropping a socket while the peer still sends -- a window
    /// update for bytes it is reading, say -- makes the kernel answer with a
    /// reset, and a reset discards whatever the peer had not read yet. The
    /// provider reads and discards what arrives meanwhile, and its `Closed`
    /// ends the wait.
    closing: BTreeMap<SocketHandle, Option<u64>>,
}

impl<P, E> TcpTransport<P, E> {
    /// Creates a transport with explicit configuration, or the limit that
    /// cannot work ([`TcpConfig::validate`]).
    pub fn with_config(
        provider: P,
        identity: Ed25519Keypair,
        entropy: E,
        config: TcpConfig,
    ) -> Result<Self, InvalidLimit> {
        config.validate()?;
        Ok(Self::from_valid(provider, identity, entropy, config))
    }

    /// Creates a transport with [`TcpConfig::default`], which is valid.
    pub fn new(provider: P, identity: Ed25519Keypair, entropy: E) -> Self {
        Self::from_valid(provider, identity, entropy, TcpConfig::default())
    }

    /// Builds the transport from a config that passed
    /// [`TcpConfig::validate`].
    fn from_valid(provider: P, identity: Ed25519Keypair, entropy: E, config: TcpConfig) -> Self {
        Self {
            provider,
            entropy,
            identity,
            ids: ConnectionIdAllocator::new(config.namespace),
            config,
            connections: BTreeMap::new(),
            unsettled: UnsettledConnections::new(),
            by_socket: BTreeMap::new(),
            pending: VecDeque::new(),
            work: BTreeSet::new(),
            timers: BTreeSet::new(),
            closing: BTreeMap::new(),
        }
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

    /// The namespace this transport's connection ids carry.
    ///
    /// A host routing several transports needs this to say which ids are
    /// TCP's -- see [`TransportSet`](minip2p_transport::TransportSet). It is
    /// [`TcpConfig::namespace`], read back from the allocator that actually
    /// mints the ids.
    pub fn namespace(&self) -> ConnectionNamespace {
        self.ids.namespace()
    }

    /// The active connection identifiers.
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.keys().copied().collect()
    }

    /// Whether every connection slot is taken, by live connections and by
    /// ended ones whose delivered bytes are not settled yet.
    fn at_capacity(&self) -> bool {
        self.connections.len() + self.unsettled.len() >= self.config.max_connections
    }

    /// Takes a connection out of the map for good, handing its unsettled
    /// streams' counts to [`Self::unsettled`].
    fn retire(&mut self, id: ConnectionId) -> Option<Connection> {
        let connection = self.connections.remove(&id)?;
        self.unsettled
            .insert(id, connection.session.unsettled_streams());
        Some(connection)
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
        self.touch(id);
        result
    }

    /// Re-files a connection after its session was driven: it joins the next
    /// poll's work, and its wake-up moves to whatever it now waits for.
    fn touch(&mut self, id: ConnectionId) {
        self.work.insert(id);
        self.reschedule(id);
    }

    /// Moves a connection's `timers` entry to its current wake-up.
    fn reschedule(&mut self, id: ConnectionId) {
        let timeout = self.config.send_stall_timeout_ms;
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        let wake_at = connection.wake_at(timeout);
        if connection.wake_at == wake_at {
            return;
        }
        if let Some(old) = core::mem::replace(&mut connection.wake_at, wake_at) {
            self.timers.remove(&(old, id));
        }
        if let Some(new) = wake_at {
            self.timers.insert((new, id));
        }
    }

    /// Drops a connection that is leaving the map from the scheduling sets.
    fn forget(&mut self, connection: &Connection) {
        self.work.remove(&connection.id);
        if let Some(at) = connection.wake_at {
            self.timers.remove(&(at, connection.id));
        }
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
                .map_err(TransportError::from)
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

    /// Drains session events into public events.
    ///
    /// Events leave the session separately from its bytes, so they are never
    /// held back by a socket that is not taking writes.
    fn pump(&mut self, connection: &mut Connection) {
        while let Some(output) = connection.session.poll_output() {
            let id = connection.id;
            let event = match output {
                SessionOutput::Established {
                    peer,
                    handshake_hash,
                } => {
                    let mut endpoint = connection.endpoint(Some(peer));
                    endpoint.set_token(ConnectionToken::new(handshake_hash));
                    TransportEvent::Connected {
                        id,
                        endpoint: Box::new(endpoint),
                    }
                }
                SessionOutput::IncomingStream { stream } => TransportEvent::IncomingStream {
                    id,
                    stream_id: stream,
                },
                SessionOutput::StreamData { stream, data } => TransportEvent::StreamData {
                    id,
                    stream_id: stream,
                    data,
                },
                SessionOutput::StreamRemoteWriteClosed { stream } => {
                    TransportEvent::StreamRemoteWriteClosed {
                        id,
                        stream_id: stream,
                    }
                }
                SessionOutput::StreamClosed { stream } => TransportEvent::StreamClosed {
                    id,
                    stream_id: stream,
                },
                SessionOutput::StreamWritable { stream } => TransportEvent::StreamWritable {
                    id,
                    stream_id: stream,
                },
            };
            self.pending.push_back(event);
        }
    }

    /// Pulls session bytes into the outbound buffer while it has room.
    ///
    /// This is the only place ciphertext is produced, so a socket that stops
    /// taking bytes stops the session from framing more: stream writes then
    /// queue inside Yamux, against its send caps, and come back to the caller
    /// as Full instead of growing this buffer (ADR 0012).
    fn fill(&mut self, connection: &mut Connection) -> Result<(), Teardown> {
        while connection.outbound.len() < self.config.max_buffered_send.max(1) {
            let Some(bytes) = connection.session.poll_write()? else {
                break;
            };
            connection.outbound.extend(bytes);
        }
        Ok(())
    }

    /// Writes as much of the outbound buffer as the socket takes.
    ///
    /// Stops at the first write the socket refuses and keeps the remainder,
    /// which the next [`poll`](Transport::poll) retries -- that is the only
    /// flush point, so no separate readiness path can miss it. A dialed socket
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
                connection.refused = true;
                break;
            }
            if core::mem::take(&mut connection.refused) {
                connection.session.note_peer_acked();
            }
            connection.outbound.drain(..accepted);
            connection.stalled_since = None;
        }
        Ok(())
    }

    /// Moves bytes from the session to the socket until one of them stops,
    /// then publishes the session's events.
    ///
    /// Flushing first frees buffer room for the session; filling may in turn
    /// free Yamux send capacity, which is what queues `StreamWritable`, so
    /// events are drained last.
    fn pump_and_flush(&mut self, connection: &mut Connection) -> Result<(), Teardown> {
        let result = loop {
            if let Err(teardown) = self.flush(connection) {
                break Err(teardown);
            }
            let before = connection.outbound.len();
            if let Err(teardown) = self.fill(connection) {
                break Err(teardown);
            }
            if connection.outbound.len() == before || !connection.linked {
                break Ok(());
            }
        };
        self.pump(connection);
        result
    }

    /// Tears a connection down, emitting `Closed` with `reason`.
    ///
    /// Aborting the socket is what makes this final: a provider emits nothing
    /// further for an aborted handle, so no late event can resurrect the id.
    fn fail_connection(&mut self, id: ConnectionId, reason: ConnectionCloseReason) {
        let Some(connection) = self.retire(id) else {
            return;
        };
        self.forget(&connection);
        self.by_socket.remove(&connection.socket);
        self.provider.abort(connection.socket);
        self.pending
            .push_back(TransportEvent::Closed { id, reason });
    }

    /// Feeds a session and flushes, tearing the connection down on failure.
    fn drive_connection(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut SecureMuxSession) -> Result<(), SessionError>,
    ) {
        let result = self.with_connection(id, |this, connection| {
            let fed = operation(&mut connection.session);
            let pumped = this.pump_and_flush(connection);
            fed.map_err(Teardown::from).and(pumped)
        });
        if let Err(teardown) = result {
            self.fail_connection(id, teardown.0);
        }
    }

    /// Runs one stream operation against a connection's session and flushes
    /// whatever it queued.
    ///
    /// A failure that kills the session closes the connection before
    /// returning, with the failure as its close reason, and returns
    /// [`TransportError::ConnectionClosed`] so the caller can tell its
    /// operation ended the connection.
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
        self.touch(id);

        if let Err(Teardown(reason)) = pumped {
            let message = reason.to_string();
            self.fail_connection(id, reason);
            return Err(TransportError::ConnectionClosed {
                id,
                reason: message,
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
            Err(SessionError::Yamux(YamuxError::Full { stream, unsent })) => {
                Err(TransportError::Full {
                    id,
                    stream_id: StreamId::new(u64::from(stream)),
                    unsent,
                })
            }
            Err(SessionError::Yamux(YamuxError::TooManyStreams)) => {
                Err(TransportError::ResourceExhausted {
                    resource: "Yamux streams",
                })
            }
            Err(SessionError::Yamux(YamuxError::AckExceedsDelivered {
                stream,
                acked,
                unacked,
            })) => Err(TransportError::AckExceedsDelivered {
                id,
                stream_id: StreamId::new(u64::from(stream)),
                acked,
                unacked,
            }),
            Err(SessionError::Yamux(error)) => Err(TransportError::PollError {
                reason: error.to_string(),
            }),
            Err(fatal) => {
                let reason = fatal.to_string();
                self.fail_connection(id, ConnectionCloseReason::Error(reason.clone()));
                Err(TransportError::ConnectionClosed { id, reason })
            }
        }
    }

    fn handle_provider_event(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Accepted { socket, remote } => self.accept(socket, remote),
            TcpEvent::Connected { socket, remote } => {
                let Some(id) = self.by_socket.get(&socket).copied() else {
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
            TcpEvent::Writable { .. } => {}
            TcpEvent::RemoteWriteClosed { socket } => {
                self.close_from_provider(socket, "remote closed its write side".to_string());
            }
            TcpEvent::Closed { socket, reason } => {
                if self.closing.remove(&socket).is_some() {
                    return;
                }
                let message = reason.unwrap_or_else(|| "byte stream closed".to_string());
                self.close_from_provider(socket, message);
            }
        }
    }

    fn accept(&mut self, socket: SocketHandle, remote: Multiaddr) {
        if self.at_capacity() {
            self.provider.abort(socket);
            return;
        }
        let Ok(session) = self.new_session(SessionRole::Responder, None) else {
            self.provider.abort(socket);
            return;
        };
        let Ok(id) = self.ids.allocate() else {
            self.provider.abort(socket);
            return;
        };

        self.by_socket.insert(socket, id);
        self.connections.insert(
            id,
            Connection::new(id, socket, remote.clone(), true, session),
        );
        self.pending.push_back(TransportEvent::IncomingConnection {
            id,
            endpoint: Box::new(ConnectionEndpoint::new(remote)),
        });
        self.drive_connection(id, SecureMuxSession::start);
    }

    /// One poll's worth of work for one connection: enforce its
    /// authentication deadline, retry its buffered writes, and advance its
    /// keepalive, then file it under whatever it waits for next.
    fn service(&mut self, id: ConnectionId, now: Now) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };

        if connection.session.is_established() {
            connection.authenticate_by = None;
        } else if let Some(limit) = self.config.handshake_timeout_ms {
            let deadline = *connection
                .authenticate_by
                .get_or_insert(now.monotonic_ms.saturating_add(limit));
            if now.monotonic_ms >= deadline {
                self.fail_connection(id, ConnectionCloseReason::TimedOut);
                return;
            }
        }

        connection.stalled_since.get_or_insert(now.monotonic_ms);
        if let Err(teardown) =
            self.with_connection(id, |this, connection| this.pump_and_flush(connection))
        {
            self.fail_connection(id, teardown.0);
            return;
        }
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        if connection.outbound.is_empty() {
            connection.stalled_since = None;
        } else if let Some(since) = connection.stalled_since {
            let stalled_for = now.saturating_millis_since(Now::from_millis(since));
            if let Some(limit) = self.config.send_stall_timeout_ms
                && stalled_for >= limit
            {
                self.fail_connection(id, ConnectionCloseReason::Stalled);
                return;
            }
        }
        if self
            .connections
            .get(&id)
            .is_some_and(|connection| connection.session.is_established())
        {
            self.drive_connection(id, |session| session.poll(now));
        }

        if !self
            .connections
            .get(&id)
            .is_some_and(Connection::has_backlog)
        {
            self.work.remove(&id);
        }
        self.reschedule(id);
    }

    /// Stamps new lingering sockets with their deadline and aborts those
    /// whose peer never closed in time.
    fn linger(&mut self, now: Now) {
        let provider = &mut self.provider;
        self.closing.retain(|&socket, deadline| {
            let at = *deadline.get_or_insert(now.monotonic_ms.saturating_add(CLOSE_LINGER_MS));
            if now.monotonic_ms < at {
                return true;
            }
            provider.abort(socket);
            false
        });
    }

    /// Ends the connection on `socket` after the byte stream under it ended
    /// without a Yamux `GoAway`.
    fn close_from_provider(&mut self, socket: SocketHandle, message: String) {
        if let Some(id) = self.by_socket.get(&socket).copied() {
            self.fail_connection(id, ConnectionCloseReason::Error(message));
        }
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
        if self.at_capacity() {
            return Err(TransportError::ResourceExhausted {
                resource: "tcp connections",
            });
        }
        let id = self.ids.peek().ok_or(TransportError::ResourceExhausted {
            resource: "tcp connection ids",
        })?;
        let session = self.new_session(SessionRole::Initiator, Some(*addr.peer_id()))?;

        let consumed = self.ids.allocate();
        debug_assert_eq!(consumed, Ok(id), "peeked id must match the allocated one");

        let socket = self.provider.connect(target).map_err(|error| match error {
            TcpError::Address { context, reason } => {
                TransportError::InvalidAddress { context, reason }
            }
            error => TransportError::DialFailed {
                id,
                reason: error.to_string(),
            },
        })?;

        self.by_socket.insert(socket, id);
        self.connections.insert(
            id,
            Connection::new(id, socket, target.clone(), false, session),
        );
        self.work.insert(id);
        Ok(id)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        if !addr.is_tcp_transport() {
            return Err(TransportError::InvalidAddress {
                context: "tcp listen",
                reason: format!("{addr} is not a /tcp transport address"),
            });
        }
        if self.provider.local_addresses().iter().any(|a| a == addr) {
            return Ok(addr.clone());
        }
        let bound = self.provider.listen(addr).map_err(|error| match error {
            TcpError::Io { kind, detail, .. } => TransportError::ListenFailed {
                addr: addr.clone(),
                kind,
                detail,
            },
            other => other.into(),
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
        data: Bytes,
    ) -> Result<(), TransportError> {
        if data.is_empty() {
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
        let result = self
            .operate_session(id, |session| session.close_stream_write(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamCloseWriteFailed {
                    id,
                    stream_id,
                    reason,
                })
            });
        drop_writable(&mut self.pending, id, stream_id);
        result
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if self.unsettled.abandon(id, stream_id) {
            return Ok(());
        }
        let result = self
            .operate_session(id, |session| session.reset_stream(stream_id))
            .map_err(|error| {
                stream_error(error, |reason| TransportError::StreamResetFailed {
                    id,
                    stream_id,
                    reason,
                })
            });
        drop_writable(&mut self.pending, id, stream_id);
        result
    }

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        if !self.connections.contains_key(&id) {
            return self.unsettled.ack(id, stream_id, bytes).map(|_held| ());
        }
        self.operate_session(id, |session| session.ack_stream(stream_id, bytes))
    }

    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        if self.connections.contains_key(&id) {
            self.drive_connection(id, |session| session.set_control_stream(stream_id, control));
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let mut connection = self
            .retire(id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        self.forget(&connection);
        self.by_socket.remove(&connection.socket);

        let held = connection.session.has_unsent_writes();
        let drained = connection.outbound.is_empty() && !held;
        let announced = connection.session.go_away(0).is_ok();
        let flushed = announced && self.pump_and_flush(&mut connection).is_ok();
        let graceful = flushed
            && !held
            && (drained
                || (connection.outbound.is_empty() && !connection.session.has_pending_write()))
            && self.provider.close_write(connection.socket).is_ok();
        if graceful {
            self.closing.insert(connection.socket, None);
        } else {
            self.provider.abort(connection.socket);
        }
        self.pending
            .retain(|event| !matches!(event, TransportEvent::StreamWritable { id: owner, .. } if *owner == id));
        self.pending.push_back(TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        });
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        if !self.pending.is_empty() {
            return Ok(self.drain_pending_events());
        }
        let events = self.provider.poll(now)?;
        for event in events {
            self.handle_provider_event(event);
        }
        self.linger(now);
        let mut due = core::mem::take(&mut self.work);
        while let Some(&(at, id)) = self.timers.first() {
            if at > now.monotonic_ms {
                break;
            }
            self.timers.pop_first();
            if let Some(connection) = self.connections.get_mut(&id) {
                connection.wake_at = None;
            }
            due.insert(id);
        }
        for id in due {
            self.service(id, now);
        }
        Ok(self.drain_pending_events())
    }

    /// Bytes the socket has not taken yet, or a session still holding
    /// frames or window-blocked stream bytes. What the socket took is the
    /// operating system's (or the provider's stack's) to deliver, so a
    /// gracefully closed socket counts until the peer has closed its side
    /// too: dropping it sooner can reset the stream and lose that tail.
    fn has_pending_writes(&self) -> bool {
        !self.closing.is_empty()
            || self.connections.values().any(|connection| {
                !connection.outbound.is_empty()
                    || (connection.linked && connection.session.has_unsent_writes())
            })
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() {
            return Some(Deadline::IMMEDIATE);
        }
        let own = self
            .timers
            .first()
            .map(|&(at, _)| Deadline::from_millis(at));
        let linger = self
            .closing
            .values()
            .map(|at| at.map_or(Deadline::IMMEDIATE, Deadline::from_millis))
            .min();
        Deadline::earliest_opt(
            Deadline::earliest_opt(own, linger),
            self.provider.next_deadline(),
        )
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.provider.local_addresses()
    }

    fn local_addresses_revision(&self) -> Option<u64> {
        self.provider.local_addresses_revision()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.connections
            .values()
            .filter(|connection| connection.inbound)
            .map(|connection| connection.remote.clone())
            .collect()
    }
}

/// Drops a `StreamWritable` already queued for a stream whose write side
/// just ended: a Full can queue one before its call returns, and Writable
/// never follows the end of a write side.
fn drop_writable(pending: &mut VecDeque<TransportEvent>, id: ConnectionId, stream_id: StreamId) {
    pending.retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
}

/// Wraps a session failure as the stream error the transport contract expects.
///
/// Identifier and state errors pass through: they describe the request rather
/// than the stream operation, and callers match on them. So does Full, which
/// carries the caller's unsent tail, and ConnectionClosed, which tells the
/// swarm the failure already ended the connection and is reported by its
/// `Closed` alone.
fn stream_error(
    error: TransportError,
    wrap: impl FnOnce(String) -> TransportError,
) -> TransportError {
    match error {
        error @ (TransportError::ConnectionNotFound { .. }
        | TransportError::ConnectionClosed { .. }
        | TransportError::StreamNotFound { .. }
        | TransportError::InvalidState { .. }
        | TransportError::Full { .. }) => error,
        error => wrap(error.to_string()),
    }
}
