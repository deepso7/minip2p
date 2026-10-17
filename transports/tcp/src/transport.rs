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
    ConnectionNamespace, ConnectionState, ConnectionToken, InvalidLimit, MemoryLedger, StreamId,
    Transport, TransportError, TransportEvent, UnsettledConnections,
};

use crate::config::TcpConfig;
use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider};

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
            // Accepted sockets are already up; nothing may be written to a
            // dialed one until the provider reports the link.
            linked: inbound,
            session,
            outbound: VecDeque::new(),
            stalled_since: None,
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
        // An unauthenticated connection has to be revisited when its patience
        // runs out, and an established one when its keepalive is due, whether
        // or not it has anything queued: a backed-up write path to a dead
        // peer is exactly what keepalive has to catch.
        let mut at = self.authenticate_by;
        let mut fold = |deadline: u64| at = Some(at.map_or(deadline, |at| at.min(deadline)));
        if let Some(keepalive) = self.session.next_deadline() {
            fold(keepalive.as_millis());
        }
        if self.outbound.is_empty() {
            if self.linked && self.session.has_pending_write() {
                // Framed bytes with room to put them: come straight back.
                return Some(0);
            }
        } else if let Some(since) = self.stalled_since {
            // The socket is refusing bytes, and spinning would not change
            // that. Sleep until the stall becomes fatal; the provider's own
            // readiness reporting is what wakes us sooner if the peer starts
            // reading again.
            if let Some(timeout) = stall_timeout {
                fold(since.saturating_add(timeout));
            }
        } else {
            // The socket is still taking bytes, so coming straight back makes
            // progress.
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
    /// still holds a slot against [`TcpConfig::max_connections`] (ADR 0012),
    /// and each of its streams its reservation (ADR 0021).
    unsettled: UnsettledConnections,
    /// The TCP memory budget's reservations ([`TcpConfig::memory_budget_bytes`]).
    ledger: MemoryLedger,
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
            ledger: MemoryLedger::new(config.memory_budget_bytes),
            config,
            connections: BTreeMap::new(),
            unsettled: UnsettledConnections::new(),
            by_socket: BTreeMap::new(),
            pending: VecDeque::new(),
            work: BTreeSet::new(),
            timers: BTreeSet::new(),
        }
    }

    /// Bytes reserved against the TCP memory budget now, by live
    /// connections and by streams still unsettled, including those of
    /// ended connections.
    pub fn memory_reserved(&self) -> usize {
        self.ledger.reserved()
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
    /// streams' counts to [`Self::unsettled`]. Those keep their stream
    /// reservations; the connection's fixed part and every other stream's
    /// reservation go now.
    fn retire(&mut self, id: ConnectionId) -> Option<Connection> {
        let mut connection = self.connections.remove(&id)?;
        let (unsettled, released) = connection.session.end_streams();
        self.unsettled.insert(id, unsettled);
        self.ledger.release(
            self.config
                .connection_reservation_bytes()
                .saturating_add(released * self.config.stream_reservation_bytes()),
        );
        Some(connection)
    }

    /// Releases the reservations of streams the session reports settled.
    fn release_settled(&mut self, session: &mut SecureMuxSession) {
        let settled = session.take_settled_streams();
        self.ledger
            .release(settled * self.config.stream_reservation_bytes());
    }

    /// Settles streams of ended connections through `settle`, releasing the
    /// reservation of each one that settles.
    fn settle_unsettled<R>(&mut self, settle: impl FnOnce(&mut UnsettledConnections) -> R) -> R {
        let before = self.unsettled.streams();
        let result = settle(&mut self.unsettled);
        let settled = before - self.unsettled.streams();
        self.ledger
            .release(settled * self.config.stream_reservation_bytes());
        result
    }

    /// The refusal for a connection or stream the budget cannot fit.
    fn budget_exhausted() -> TransportError {
        TransportError::ResourceExhausted {
            resource: "TCP memory budget",
        }
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
        self.release_settled(&mut connection.session);
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
                    // Both ends share the Noise handshake hash, so it serves
                    // as the connection's token.
                    let mut endpoint = connection.endpoint(Some(peer));
                    endpoint.set_token(ConnectionToken::new(handshake_hash));
                    TransportEvent::Connected { id, endpoint }
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
        // Zero still pulls one frame at a time, or nothing would ever leave.
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
                break;
            }
            connection.outbound.drain(..accepted);
            // Progress, even if the session refills the buffer right after.
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
        // Events the session already produced are the host's either way.
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
        operation: impl FnOnce(&mut SecureMuxSession, &mut MemoryLedger) -> Result<(), SessionError>,
    ) {
        let result = self.with_connection(id, |this, connection| {
            let fed = operation(&mut connection.session, &mut this.ledger);
            // Pump either way: bytes the session queued before failing, and
            // events it already produced, are the host's regardless.
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
        operation: impl FnOnce(&mut SecureMuxSession, &mut MemoryLedger) -> Result<R, SessionError>,
    ) -> Result<R, TransportError> {
        let mut connection = self
            .connections
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let result = operation(&mut connection.session, &mut self.ledger);
        let pumped = self.pump_and_flush(&mut connection);
        self.release_settled(&mut connection.session);
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
            // Temporary send pressure: retryable, never a fault.
            Err(SessionError::Yamux(YamuxError::Full { stream, unsent })) => {
                Err(TransportError::Full {
                    id,
                    stream_id: StreamId::new(u64::from(stream)),
                    unsent,
                })
            }
            Err(SessionError::Yamux(YamuxError::BudgetExhausted)) => Err(Self::budget_exhausted()),
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
            // Yamux refused the operation -- a closed write side, an unknown
            // substream -- but the session itself is still healthy.
            Err(SessionError::Yamux(error)) => Err(TransportError::PollError {
                reason: error.to_string(),
            }),
            // The session failed: a local reset of a peer-opened stream
            // exhausted the control reserve (see `YamuxSession::reset`).
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
                    // A handle we never dialed, or one already torn down.
                    self.provider.abort(socket);
                    return;
                };
                if let Some(connection) = self.connections.get_mut(&id) {
                    connection.remote = remote;
                    connection.linked = true;
                }
                self.drive_connection(id, |session, _| session.start());
            }
            TcpEvent::Received { socket, data } => {
                if let Some(id) = self.by_socket.get(&socket).copied() {
                    self.drive_connection(id, move |session, ledger| {
                        session.handle_input_within(data, ledger)
                    });
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
                self.close_from_provider(socket, "remote closed its write side".to_string());
            }
            TcpEvent::Closed { socket, reason } => {
                let message = reason.unwrap_or_else(|| "byte stream closed".to_string());
                self.close_from_provider(socket, message);
            }
        }
    }

    fn accept(&mut self, socket: SocketHandle, remote: Multiaddr) {
        // Shed before naming. An inbound connection at the ceiling is refused
        // where it stands: nothing has been announced about it, so there is
        // nobody to report a failure to, and spending an id on it would burn
        // the namespace at whatever rate a peer chose to knock. Ended
        // connections with unsettled bytes still hold their slots.
        // So is one the memory budget cannot fit.
        if self.at_capacity() || !self.ledger.fits(self.config.connection_reservation_bytes()) {
            self.provider.abort(socket);
            return;
        }
        // Build the session before naming the connection. `Error` is an error
        // *on a connection*, and nothing has been announced about this socket
        // yet -- so an `Error` here would name an id the caller never saw, with
        // no `Closed` behind it to end a lifecycle that never began. The same
        // reasoning as the shed above: it goes where it stands. A dial that
        // cannot build a session still reports it, because there the caller
        // asked.
        let Ok(session) = self.new_session(SessionRole::Responder, None) else {
            self.provider.abort(socket);
            return;
        };
        // Named only now that it will exist. An exhausted namespace leaves
        // nothing to report against, so the socket just goes.
        let Ok(id) = self.ids.allocate() else {
            self.provider.abort(socket);
            return;
        };

        let reserved = self
            .ledger
            .reserve(self.config.connection_reservation_bytes());
        debug_assert!(reserved, "checked to fit above");
        self.by_socket.insert(socket, id);
        self.connections.insert(
            id,
            Connection::new(id, socket, remote.clone(), true, session),
        );
        self.pending.push_back(TransportEvent::IncomingConnection {
            id,
            endpoint: ConnectionEndpoint::new(remote),
        });
        self.drive_connection(id, |session, _| session.start());
    }

    /// One poll's worth of work for one connection: enforce its
    /// authentication deadline, retry its buffered writes, and advance its
    /// keepalive, then file it under whatever it waits for next.
    fn service(&mut self, id: ConnectionId, now: Now) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };

        // A connection that has not authenticated is on a clock. The ceiling
        // alone would not hold: a peer that opens a byte stream and then says
        // nothing keeps its slot for as long as the socket lives, so a few
        // silent peers could fill the ceiling and keep it full.
        if connection.session.is_established() {
            // Authenticated, so there is nothing left to time.
            connection.authenticate_by = None;
        } else if let Some(limit) = self.config.handshake_timeout_ms {
            // Stamped here, from this poll's sample, rather than when the
            // connection was made: between polls a transport holds no current
            // time, only the last one it was given.
            let deadline = *connection
                .authenticate_by
                .get_or_insert(now.monotonic_ms.saturating_add(limit));
            if now.monotonic_ms >= deadline {
                self.fail_connection(id, ConnectionCloseReason::TimedOut);
                return;
            }
        }

        // Retry buffered writes even without a `Writable` event, so a provider
        // that only reports readiness coarsely still drains, and pull whatever
        // the session has framed since. Assume this poll stalls, keeping an
        // older mark; `flush` clears it the moment the socket accepts a byte.
        // Comparing buffer lengths instead would miss progress the session
        // refilled.
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
            // Fully drained: nothing is stalled. Leaving a stale mark would
            // make the next socketful look like the tail of an old stall and
            // fail the connection on the spot.
            connection.stalled_since = None;
        } else if let Some(since) = connection.stalled_since {
            // Still set: the socket took nothing this poll.
            let stalled_for = now.saturating_millis_since(Now::from_millis(since));
            if let Some(limit) = self.config.send_stall_timeout_ms
                && stalled_for >= limit
            {
                self.fail_connection(id, ConnectionCloseReason::Stalled);
                return;
            }
        }
        // Yamux keepalive, backlog or not: a ping that cannot get into the
        // outbound buffer is timed too. This runs after the retry, so the
        // poll dates a ping the retry just pulled, and a session whose final
        // upgrade bytes just drained gets its first keepalive deadline here.
        if self
            .connections
            .get(&id)
            .is_some_and(|connection| connection.session.is_established())
        {
            self.drive_connection(id, |session, _| session.poll(now));
        }

        // Driving the session above queued it as work; only a backlog keeps it
        // there, or every serviced connection would be serviced forever.
        if !self
            .connections
            .get(&id)
            .is_some_and(Connection::has_backlog)
        {
            self.work.remove(&id);
        }
        self.reschedule(id);
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
        // Both checks come before anything with a side effect, so a refused
        // dial leaves nothing behind: no spent id, and no connected socket
        // without an id to name it.
        if self.at_capacity() {
            return Err(TransportError::ResourceExhausted {
                resource: "tcp connections",
            });
        }
        if !self.ledger.fits(self.config.connection_reservation_bytes()) {
            return Err(Self::budget_exhausted());
        }
        let id = self.ids.peek().ok_or(TransportError::ResourceExhausted {
            resource: "tcp connection ids",
        })?;
        let session = self.new_session(SessionRole::Initiator, Some(addr.peer_id().clone()))?;

        // Spend the id before the first failure that names it. `DialFailed`
        // carries this id, so handing it back for a later dial to reuse would
        // point two outcomes at one id -- the same reason `accept` allocates up
        // front. Entropy failures above name no id, so they cost nothing.
        let consumed = self.ids.allocate();
        debug_assert_eq!(consumed, Ok(id), "peeked id must match the allocated one");

        let socket = self.provider.connect(target).map_err(|error| match error {
            // A refused address is the caller's to fix, not a dial outcome.
            TcpError::Address { context, reason } => {
                TransportError::InvalidAddress { context, reason }
            }
            error => TransportError::DialFailed {
                id,
                reason: error.to_string(),
            },
        })?;

        let reserved = self
            .ledger
            .reserve(self.config.connection_reservation_bytes());
        debug_assert!(reserved, "checked to fit above");
        self.by_socket.insert(socket, id);
        self.connections.insert(
            id,
            Connection::new(id, socket, target.clone(), false, session),
        );
        // The next poll stamps its authentication deadline.
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
        // Listening again on an address already bound is the same listener,
        // not a second one. Hosts announce what they bound and then listen on
        // it -- the swarm's own bind-then-listen does exactly that -- and
        // binding a fresh socket there would fail with the address in use, on
        // a request that had already been granted.
        //
        // Nothing is announced the second time either: the address was
        // reported when it was bound, and repeating it would have every
        // re-listen add an event the host has already seen -- growing the
        // queue for as long as a caller keeps asking.
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
        let stream_id =
            self.operate_session(id, |session, ledger| session.open_stream_within(ledger))?;
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
            // The contract makes an empty write a no-op, but not a way to
            // address a connection that does not exist -- the same order the
            // QUIC adapter applies.
            return if self.connections.contains_key(&id) {
                Ok(())
            } else {
                Err(TransportError::ConnectionNotFound { id })
            };
        }
        self.operate_session(id, |session, _| session.send(stream_id, data))
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
            .operate_session(id, |session, _| session.close_stream_write(stream_id))
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
        // Abandoning a stream of an ended connection only settles it.
        if self.settle_unsettled(|unsettled| unsettled.abandon(id, stream_id)) {
            return Ok(());
        }
        let result = self
            .operate_session(id, |session, _| session.reset_stream(stream_id))
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
            // An ended connection's bytes are released without credit.
            return self
                .settle_unsettled(|unsettled| unsettled.ack(id, stream_id, bytes))
                .map(|_held| ());
        }
        // Flushed at once, so the window update reaches the peer without
        // waiting for another poll.
        self.operate_session(id, |session, _| session.ack_stream(stream_id, bytes))
    }

    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        // Nothing returns to the caller, so a session the mark's flush fails
        // is torn down with the failure as its close reason.
        if self.connections.contains_key(&id) {
            self.drive_connection(id, |session, _| {
                session.set_control_stream(stream_id, control)
            });
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let mut connection = self
            .retire(id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        self.forget(&connection);
        self.by_socket.remove(&connection.socket);

        // A connection still negotiating has no Yamux session to shut down, so
        // `go_away` refuses and the socket is aborted instead.
        let announced = connection.session.go_away(0).is_ok();
        let flushed = announced && self.pump_and_flush(&mut connection).is_ok();
        // Anything still buffered would be discarded by the FIN, so only a
        // fully drained socket can be closed gracefully.
        let graceful = flushed
            && connection.outbound.is_empty()
            && !connection.session.has_pending_write()
            && self.provider.close_write(connection.socket).is_ok();
        if !graceful {
            self.provider.abort(connection.socket);
        }
        // Every write side ended with the connection.
        self.pending
            .retain(|event| !matches!(event, TransportEvent::StreamWritable { id: owner, .. } if *owner == id));
        self.pending.push_back(TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        });
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        // Hand back what is already queued before doing more work, so a host
        // that acts between polls -- opening a stream on a fresh `Connected`,
        // say -- does so against the state those events described.
        if !self.pending.is_empty() {
            return Ok(self.drain_pending_events());
        }
        let events = self.provider.poll(now)?;
        for event in events {
            self.handle_provider_event(event);
        }
        // Only connections with work: those queued since the last poll --
        // including every one a provider event above just drove -- and those
        // whose wake-up has come.
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

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() {
            // Buffered events are due regardless of what the host's clock
            // reads, so this needs no retained time sample.
            return Some(Deadline::IMMEDIATE);
        }
        let own = self
            .timers
            .first()
            .map(|&(at, _)| Deadline::from_millis(at));
        Deadline::earliest_opt(own, self.provider.next_deadline())
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

/// Wraps a session failure as the stream error the transport contract expects.
///
/// Identifier and state errors pass through: they describe the request rather
/// than the stream operation, and callers match on them. So does Full, which
/// carries the caller's unsent tail.
/// Drops a `StreamWritable` already queued for a stream whose write side
/// just ended: a Full can queue one before its call returns, and Writable
/// never follows the end of a write side.
fn drop_writable(pending: &mut VecDeque<TransportEvent>, id: ConnectionId, stream_id: StreamId) {
    pending.retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
}

fn stream_error(
    error: TransportError,
    wrap: impl FnOnce(String) -> TransportError,
) -> TransportError {
    match error {
        error @ (TransportError::ConnectionNotFound { .. }
        | TransportError::StreamNotFound { .. }
        | TransportError::InvalidState { .. }
        | TransportError::Full { .. }) => error,
        error => wrap(error.to_string()),
    }
}
