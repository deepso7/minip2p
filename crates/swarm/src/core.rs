//! [`SwarmCore`]: the portable swarm, driving its state against a
//! [`Transport`].
//!
//! `no_std + alloc`: no clock, no entropy source of its own, no executor. The
//! caller samples time and passes it in, which is what lets the same swarm run
//! on an embedded board and under the `std` [`Swarm`](crate::Swarm) wrapper.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::platform::{Deadline, EntropySource, Now};
use minip2p_core::{Bytes, Multiaddr, PeerAddr, PeerId};
use minip2p_identify::{IdentifyConfig, IdentifyMessage};
use minip2p_ping::PING_PAYLOAD_LEN;
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

use crate::events::{SwarmError, SwarmErrorKind, SwarmEvent, SwarmRuntimeError};
use crate::state::{Action, ProtocolKind, SwarmState, SwarmTimeouts};

/// Errors returned synchronously by swarm commands.
///
/// Protocol-state rejections remain distinguishable from transport failures;
/// callers no longer need to recover their meaning from a flattened string.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DriverError {
    /// The stream could not accept the whole write. Retryable, never a
    /// fault (ADR 0012): every byte before `unsent` was accepted, the caller
    /// holds `unsent`, and [`SwarmEvent::StreamWritable`] follows for the
    /// stream once it can queue again.
    #[error("stream {stream_id} on connection {conn_id} is full; {} bytes unsent", unsent.len())]
    Full {
        conn_id: ConnectionId,
        stream_id: StreamId,
        unsent: Bytes,
    },
    /// The underlying transport rejected the operation.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The swarm rejected the operation.
    #[error(transparent)]
    Swarm(#[from] SwarmError),
    /// A host built on the swarm found its own internal contract violated.
    #[error("swarm driver invariant violated: {reason}")]
    Invariant { reason: &'static str },
    /// The std-only `Swarm::run_until` set aside its maximum number of
    /// non-matching events without finding a match.
    ///
    /// The skipped events were restored to the event buffer in their
    /// original order; drain them with `Swarm::poll_next` before waiting
    /// again, or use a predicate that matches (and thereby consumes) the
    /// high-volume events.
    #[error(
        "run_until skipped {limit} events without a match; drain the event buffer with poll_next"
    )]
    EventBacklogExceeded { limit: usize },
    /// The injected [`EntropySource`] failed to supply bytes.
    #[error("entropy source failed")]
    Entropy,
}

impl DriverError {
    /// Whether the same operation can succeed later: a `Full` write, whose
    /// stream announces room with a Writable event. The unsent bytes are the
    /// caller's to resend; a `?` on a Full send drops them.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Full { .. }
                | Self::Swarm(SwarmError::Full { .. })
                | Self::Transport(TransportError::Full { .. })
        )
    }

    /// Whether the stream or its connection no longer exists (it ended, the
    /// connection closed or was replaced, or the ids never named one), so no
    /// later operation on it can succeed. A write side that is closing or
    /// closed is not "gone": the stream may still be read. Neither is a
    /// stream still negotiating ([`SwarmError::StreamNotReady`]), which
    /// becomes usable at its `StreamReady`.
    pub fn is_stream_gone(&self) -> bool {
        matches!(
            self,
            Self::Swarm(SwarmError::StreamNotFound { .. } | SwarmError::NotConnected { .. })
        ) || matches!(self, Self::Transport(error) if target_ended(error))
    }
}

/// Whether a transport stream operation failed only because its stream or
/// connection had already ended (or begun closing). The transport reports
/// that end with its own `StreamClosed` or `Closed`.
fn target_ended(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::StreamNotFound { .. }
            | TransportError::ConnectionNotFound { .. }
            | TransportError::ConnectionClosed { .. }
    )
}

/// The swarm: connection and protocol orchestration over a concrete
/// [`Transport`].
///
/// `no_std + alloc`: it owns no clock, no entropy source of its own, and no
/// executor. Every timed operation takes the caller's time sample, and ping
/// nonces come from the injected [`EntropySource`], which is what lets the
/// same swarm run on an embedded board and under the `Swarm` std wrapper.
///
/// Drive it by calling [`poll`](Self::poll) whenever
/// [`next_deadline`](Self::next_deadline) says so (or input arrives).
/// Commands such as [`open_stream`](Self::open_stream) and
/// [`send_stream`](Self::send_stream) run their transport call directly and
/// return its result; protocol work they start, and everything the transport
/// reports later, arrives as [`SwarmEvent`]s.
///
/// Applications on `std` usually want `Swarm`, which adds a clock and
/// blocking drive loops on top of this.
pub struct SwarmCore<T: Transport, E: EntropySource> {
    transport: T,
    pub(crate) state: SwarmState,

    /// Our own `PeerId`. Cached from the [`crate::SwarmBuilder`]'s keypair
    /// so applications don't have to drill into the transport to get it.
    local_peer_id: PeerId,

    /// Externally validated addresses advertised through Identify in
    /// addition to the transport's bound set. See
    /// [`SwarmCore::set_external_addresses`].
    external_addresses: Vec<Multiaddr>,
    external_addresses_revision: u64,

    /// Bumped by every successful `listen*` call so drivers can notice a
    /// moved listened-address set without re-reading the transport each
    /// turn. Binding through [`SwarmCore::transport_mut`] bypasses it.
    listened_addrs_revision: u64,

    /// Resolved addresses every successful `listen*` call returned, deduped.
    /// `Transport::local_addresses` can report bound-but-not-listening
    /// sockets, so this — not that — is the set that accepts inbound.
    listened_addrs: Vec<Multiaddr>,

    /// What the advertised address snapshot was last built from: the
    /// transport's address revision, the external-address revision, and the
    /// listened-address revision. `None` until the first build, and kept
    /// `None` while the transport cannot report a revision, so the snapshot
    /// is rebuilt only when one of its inputs moved.
    local_addresses_key: Option<(u64, u64, u64)>,
    /// How many times [`drive`](Self::drive) rebuilt the address snapshot.
    #[cfg(test)]
    pub(crate) address_rebuilds: usize,

    /// Randomness for ping nonces. Injected so the swarm stays deterministic
    /// and testable, and so `no_std` hosts can supply their own source.
    entropy: E,
}

impl<T: Transport, E: EntropySource> SwarmCore<T, E> {
    /// Creates a swarm around the given transport, identify config, and
    /// protocol deadlines. Fails with [`SwarmError::ZeroTimeout`] if a
    /// deadline is zero.
    ///
    /// Most callers should construct via [`crate::SwarmBuilder`] instead,
    /// which derives `local_peer_id` from the keypair automatically.
    pub fn new(
        transport: T,
        identify_config: IdentifyConfig,
        timeouts: SwarmTimeouts,
        local_peer_id: PeerId,
        entropy: E,
    ) -> Result<Self, SwarmError> {
        timeouts.validate()?;
        Ok(Self {
            transport,
            state: SwarmState::new(identify_config, timeouts),
            local_peer_id,
            external_addresses: Vec::new(),
            external_addresses_revision: 0,
            listened_addrs_revision: 0,
            listened_addrs: Vec::new(),
            local_addresses_key: None,
            #[cfg(test)]
            address_rebuilds: 0,
            entropy,
        })
    }

    // -----------------------------------------------------------------------
    // Addresses and transport access
    // -----------------------------------------------------------------------

    /// Sets externally validated addresses (e.g. AutoNAT-confirmed public
    /// addresses or relay circuit addresses) to advertise through Identify
    /// alongside the transport's bound addresses.
    ///
    /// Replaces the previous external set; pass an empty vector to stop
    /// advertising extras. Duplicates of transport-bound addresses are
    /// dropped. Setting the set it already holds changes nothing, not even
    /// [`external_addresses_revision`](Self::external_addresses_revision).
    pub fn set_external_addresses(&mut self, addrs: Vec<Multiaddr>) {
        if self.external_addresses == addrs {
            return;
        }
        self.external_addresses = addrs;
        self.external_addresses_revision = self.external_addresses_revision.wrapping_add(1);
    }

    /// Returns the externally validated addresses currently contributed to
    /// Identify, excluding transport-bound addresses.
    pub fn external_addresses(&self) -> &[Multiaddr] {
        &self.external_addresses
    }

    /// Returns the wrapping revision of the external-address set.
    ///
    /// It advances only when a replacement actually changed the set.
    pub fn external_addresses_revision(&self) -> u64 {
        self.external_addresses_revision
    }

    /// The address snapshot from the last [`poll`](Self::poll): the
    /// transport's bound set plus the external addresses. Identify
    /// advertises it without wildcard hosts, which stay here.
    pub fn local_addresses(&self) -> &[Multiaddr] {
        self.state.local_addresses()
    }

    /// Returns the wrapping revision of the listened-address set.
    ///
    /// Every successful `listen*` call bumps it, letting drivers refresh
    /// cached listen addresses without asking the transport each turn.
    /// Binding directly through [`SwarmCore::transport_mut`] does not
    /// bump it.
    pub fn listened_addrs_revision(&self) -> u64 {
        self.listened_addrs_revision
    }

    /// Returns the resolved addresses the transport has confirmed it listens
    /// on through this swarm's `listen*` methods, deduped.
    ///
    /// [`Transport::local_addresses`] reports bound sockets, which on some
    /// transports exist before — or without — a successful `listen`. For
    /// "which addresses accept inbound connections", use this set.
    pub fn listened_addrs(&self) -> &[Multiaddr] {
        &self.listened_addrs
    }

    /// Returns a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the underlying transport.
    ///
    /// Listeners bound through this escape hatch are invisible to
    /// [`SwarmCore::listened_addrs_revision`]; prefer the `listen*` methods.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns this node's own `PeerId`.
    ///
    /// This accessor is infallible because the [`crate::SwarmBuilder`] requires
    /// a keypair at construction time.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// How long after a peer's connection takes its slot a racing connection
    /// can still lose to it, in milliseconds. Set with
    /// [`crate::SwarmBuilder::simultaneous_dial_window_ms`]; defaults to
    /// [`crate::SIMULTANEOUS_DIAL_WINDOW_MS`].
    pub fn simultaneous_dial_window_ms(&self) -> u64 {
        self.state.simultaneous_dial_window_ms
    }

    // -----------------------------------------------------------------------
    // Peers and connections
    // -----------------------------------------------------------------------

    /// Returns peers currently surfaced through `ConnectionEstablished` and
    /// not yet closed. A Connection replacement keeps the peer listed.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.state.connected_peers()
    }

    /// Returns whether `peer_id` has been surfaced to the application as
    /// connected. Unlike [`SwarmCore::connection_id`], pending dials and
    /// other pre-established mappings do not count.
    pub fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.state.is_peer_connected(peer_id)
    }

    /// Returns every established connection with its peer, in ascending id
    /// order. Each connected peer holds exactly one: a Connection
    /// replacement retires the old connection immediately. Pending dials
    /// and replaced connections never appear.
    pub fn established_connections(&self) -> impl Iterator<Item = (ConnectionId, &PeerId)> {
        self.state.established_connections()
    }

    /// Returns the peer whose established connection `conn_id` is: `None`
    /// once it was replaced or closed, and for a pending dial or handshake.
    pub fn connection_peer(&self, conn_id: ConnectionId) -> Option<&PeerId> {
        self.state.connection_peer(conn_id)
    }

    /// Returns whether a transport connection is still tracked, including
    /// outbound dials and inbound handshakes that have not yet emitted
    /// [`SwarmEvent::ConnectionEstablished`].
    pub fn has_tracked_connections(&self) -> bool {
        self.state.has_tracked_connections()
    }

    /// Returns every tracked transport connection, pending dials included,
    /// with its peer if known: a dial's is the peer it targets, and an
    /// inbound handshake that has not yet identified one has `None`.
    pub fn tracked_connections(&self) -> impl Iterator<Item = (ConnectionId, Option<&PeerId>)> {
        self.state.tracked_connections()
    }

    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.state.peer_info(peer_id)
    }

    /// Returns whether `peer_id`'s current connection has emitted `PeerReady`.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.state.is_peer_ready(peer_id)
    }

    /// Returns the peer's current connection and its Identify info when that
    /// connection is ready, as one coherent snapshot.
    ///
    /// Ready waits use this instead of separate readiness, connection, and
    /// Identify getters, which could each describe a different connection
    /// around a Connection replacement.
    pub fn peer_readiness(&self, peer_id: &PeerId) -> Option<(ConnectionId, &IdentifyMessage)> {
        self.state.peer_readiness(peer_id)
    }

    /// Returns the active transport connection selected for `peer_id`.
    pub fn connection_id(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.state.connection_id(peer_id)
    }

    /// Whether `conn_id`, while it is some peer's current connection, came
    /// from one of our dials. `None` once it no longer holds a slot (not
    /// "inbound").
    pub fn is_outbound(&self, conn_id: ConnectionId) -> Option<bool> {
        self.state.is_outbound(conn_id)
    }

    /// Whether `event` is a `PeerReady` for a connection that is no longer
    /// the peer's current one.
    ///
    /// A `PeerReady(old)` queued before `old` was replaced is still delivered
    /// in order, but a host processing a batch sees the swarm's state after
    /// it. Hosts pass such an event to the application only: protocol drivers
    /// act peer-scoped and would start work on the not-yet-ready replacement.
    pub fn is_stale_peer_ready(&self, event: &SwarmEvent) -> bool {
        self.state.is_stale_peer_ready(event)
    }

    /// Returns the remote transport address recorded for an exact connection.
    pub fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.state.connection_remote_addr(conn_id)
    }

    // -----------------------------------------------------------------------
    // Protocol registration
    // -----------------------------------------------------------------------

    /// Registers an application protocol id for inbound acceptance and
    /// outbound opens, and advertises it through Identify.
    ///
    /// Built-in ids ([`crate::RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]: inbound routing gives the built-in
    /// handlers precedence, so a user registration under one of those ids
    /// could never receive traffic.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), SwarmError> {
        self.state.add_protocol(protocol_id)
    }

    /// Registers a protocol only for inbound negotiation by a composed service.
    pub fn add_inbound_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), SwarmError> {
        self.state.add_inbound_protocol(protocol_id)
    }

    /// Registers a protocol only for outbound opens by a composed service.
    pub fn add_outbound_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), SwarmError> {
        self.state.add_outbound_protocol(protocol_id)
    }

    /// Adds a protocol only to future Identify responses.
    pub fn add_advertised_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), SwarmError> {
        self.state.add_advertised_protocol(protocol_id)
    }

    // -----------------------------------------------------------------------
    // Listening and dialing
    // -----------------------------------------------------------------------

    /// Bumps the listened-address revision and records `addr` after a
    /// successful `Transport::listen`, in place of the same address with
    /// other certhashes (an older WebTransport certificate's).
    fn record_listen(&mut self, addr: &Multiaddr) {
        self.listened_addrs_revision = self.listened_addrs_revision.wrapping_add(1);
        let base = addr.without_certhashes();
        match self
            .listened_addrs
            .iter_mut()
            .find(|listened| listened.without_certhashes() == base)
        {
            Some(listened) => *listened = addr.clone(),
            None => self.listened_addrs.push(addr.clone()),
        }
    }

    /// Start listening on the given multiaddr and return the resolved local address.
    pub fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, DriverError> {
        let bound = self.transport.listen(addr)?;
        self.record_listen(&bound);
        Ok(bound)
    }

    /// Start listening on the transport's already-bound local addresses.
    ///
    /// Transports that know their bound addresses expose them via
    /// `Transport::local_addresses()`. Multi-socket transports such as a
    /// dual-stack QUIC endpoint can therefore advertise every bound address
    /// without forcing callers to pick one.
    pub fn listen_on_bound_addrs(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        let addrs = self.transport.local_addresses();
        if addrs.is_empty() {
            return Err(TransportError::NotListening.into());
        }

        let mut resolved = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let addr = self.transport.listen(&addr)?;
            // A later bind may still fail, leaving this one bound — record
            // each successful bind, not the batch.
            self.record_listen(&addr);
            resolved.push(self.local_peer_addr(addr)?);
        }
        Ok(resolved)
    }

    /// Start listening on the transport's first already-bound local address.
    ///
    /// Prefer [`SwarmCore::listen_on_bound_addrs`] for transports that may bind
    /// more than one socket.
    pub fn listen_on_bound_addr(&mut self) -> Result<PeerAddr, DriverError> {
        let addr = self
            .transport
            .local_addresses()
            .into_iter()
            .next()
            .ok_or(TransportError::NotListening)?;
        let addr = self.transport.listen(&addr)?;
        self.record_listen(&addr);
        Ok(self.local_peer_addr(addr)?)
    }

    /// `addr` as this node's dialable peer address.
    fn local_peer_addr(&self, addr: Multiaddr) -> Result<PeerAddr, TransportError> {
        PeerAddr::new(addr.clone(), self.local_peer_id)
            .map_err(|error| TransportError::LocalPeerAddr { addr, error })
    }

    /// Dial a remote peer. The transport allocates the connection id.
    ///
    /// The swarm notes the dial so a close before
    /// [`SwarmEvent::ConnectionEstablished`] surfaces as
    /// [`SwarmEvent::DialFailed`].
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, DriverError> {
        let id = self.transport.dial(addr)?;
        self.state.note_dial(id, addr.clone());
        Ok(id)
    }

    /// Closes a dial that has not established. Silent: no
    /// [`SwarmEvent::DialFailed`] follows.
    ///
    /// Returns `Ok(true)` when the dial was still pending and was forgotten.
    /// Returns `Ok(false)` when it was not pending (already established,
    /// already failed, or unknown) — a [`SwarmEvent::DialFailed`] may already
    /// be queued for that id. Never disconnects an established peer.
    ///
    /// If `close` fails, the dial is left exactly as it was (still pending,
    /// with any recorded `last_error` and any veto), so a later close still
    /// surfaces as [`SwarmEvent::DialFailed`] rather than a silent
    /// half-aborted dial.
    pub fn abort_dial(&mut self, conn_id: ConnectionId) -> Result<bool, DriverError> {
        if !self.state.is_pending_dial(conn_id) {
            return Ok(false);
        }
        match self.transport.close(conn_id) {
            Ok(()) | Err(TransportError::ConnectionNotFound { .. }) => {
                self.state.take_pending_dial(conn_id);
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Marks `conn_id` so establish-stage events cannot register or replace.
    ///
    /// Used after a failed [`abort_dial`](Self::abort_dial): the dial stays
    /// pending, but must not displace an existing peer connection
    /// if the transport still completes. The veto stays until the connection
    /// closes, covering both `TransportEvent::Connected` and a later
    /// `TransportEvent::PeerIdentityVerified`.
    pub fn veto_establish(&mut self, conn_id: ConnectionId) {
        self.state.veto_establish(conn_id);
    }

    // -----------------------------------------------------------------------
    // Commands
    // -----------------------------------------------------------------------

    /// The swarm's entropy source, for composed drivers that need random
    /// bytes of their own without holding a second source.
    pub fn entropy_mut(&mut self) -> &mut E {
        &mut self.entropy
    }

    /// Pings a peer, sending a random 32-byte payload and measuring RTT.
    ///
    /// If a ping stream isn't yet negotiated the payload is queued and
    /// fires when the stream becomes ready. The attempt ends in exactly one
    /// [`SwarmEvent::PingRttMeasured`] or [`SwarmEvent::PingFailed`], whose
    /// cause says whether the deadline ([`crate::SwarmTimeouts::ping_ms`],
    /// from this call, covering the open, the negotiation and the echo) ran
    /// out, the open failed, the peer refused ping, or the stream closed. A
    /// connection that closes first ends it with its `ConnectionClosed`. A
    /// call while an attempt is still opening joins it.
    ///
    /// A failed entropy draw refuses the ping with [`DriverError::Entropy`].
    /// There is no fallback: a predictable nonce lets a remote pre-compute the
    /// reply, so a ping that cannot be random must not be sent at all.
    pub fn ping(&mut self, peer_id: &PeerId, now_ms: u64) -> Result<(), DriverError> {
        let mut payload = [0u8; PING_PAYLOAD_LEN];
        #[expect(
            clippy::map_err_ignore,
            reason = "DriverError intentionally keeps entropy backend failures opaque."
        )]
        self.entropy
            .fill_bytes(&mut payload)
            .map_err(|_| DriverError::Entropy)?;
        self.state.ping(peer_id, payload, now_ms)?;
        self.flush();
        Ok(())
    }

    /// Closes the connection to a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId, _now_ms: u64) -> Result<(), DriverError> {
        self.state.disconnect(peer_id)?;
        self.flush();
        Ok(())
    }

    /// Opens a new outbound stream and negotiates `protocol_id` via
    /// multistream-select.
    ///
    /// The protocol must have been registered via
    /// [`SwarmCore::add_protocol`] (or
    /// [`add_outbound_protocol`](Self::add_outbound_protocol)) first. When
    /// negotiation completes [`SwarmEvent::StreamReady`] fires with the
    /// returned stream id; subsequent stream data arrives as
    /// [`SwarmEvent::StreamData`].
    ///
    /// Returns the stream's full identity: stream ids are only unique per
    /// connection, so later stream operations take both. A transport that
    /// refuses the stream fails this call with [`DriverError::Transport`] and
    /// emits no event. Otherwise the open ends in exactly one terminal:
    /// `StreamReady`, or a [`SwarmEvent::Error`] naming the stream when
    /// negotiation fails, the peer closes or resets the stream first, or
    /// the negotiation deadline
    /// ([`SwarmTimeouts::negotiation_ms`](crate::SwarmTimeouts::negotiation_ms))
    /// passes without an answer. That clock starts at the transport's
    /// `StreamOpened`, not at this call: an open QUIC holds for the peer's
    /// stream credit has no deadline until then. A closed or replaced
    /// connection ends it with the connection's own event.
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        _now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), DriverError> {
        // Earlier queued work keeps its place ahead of this open, and its
        // failures keep flowing as events.
        self.flush();
        let conn_id = self.state.admit_user_open(peer_id, protocol_id)?;
        let stream_id = self.open(
            conn_id,
            protocol_id,
            ProtocolKind::User(protocol_id.to_string()),
        )?;
        self.flush();
        Ok((conn_id, stream_id))
    }

    /// Sends raw bytes on a negotiated user stream.
    ///
    /// Accepts as much of `data` as the stream can queue. When not every byte
    /// fit, returns [`DriverError::Full`] with the exact unsent suffix; the
    /// caller holds it and sends it again on [`SwarmEvent::StreamWritable`].
    /// Any other transport failure is returned as [`DriverError::Transport`]
    /// and emits no event.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        _now_ms: u64,
    ) -> Result<(), DriverError> {
        // Earlier queued writes for the stream go out first.
        self.flush();
        let data = self
            .state
            .admit_user_write(peer_id, conn_id, stream_id, data)
            .map_err(|error| match error {
                SwarmError::Full {
                    conn_id,
                    stream_id,
                    unsent,
                } => DriverError::Full {
                    conn_id,
                    stream_id,
                    unsent,
                },
                error => error.into(),
            })?;
        match self.transport.send_stream(conn_id, stream_id, data) {
            Ok(()) => Ok(()),
            Err(TransportError::Full {
                id,
                stream_id,
                unsent,
            }) => Err(DriverError::Full {
                conn_id: id,
                stream_id,
                unsent,
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Half-closes the write side of a user stream.
    ///
    /// The FIN follows every write the transport accepted. A caller holding
    /// an unsent tail of its own must send it before closing. No
    /// [`SwarmEvent::StreamWritable`] for the stream follows, including one
    /// already queued. A transport failure arrives as [`SwarmEvent::Error`],
    /// unless the stream or connection already ended: its `StreamClosed` or
    /// `ConnectionClosed` reports that.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.close_stream_write(peer_id, conn_id, stream_id)?;
        self.flush();
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    ///
    /// No [`SwarmEvent::StreamWritable`] for the stream follows, including
    /// one already queued. A transport failure arrives as
    /// [`SwarmEvent::Error`], and the reset may be retried; a stream or
    /// connection that already ended needs no reset and reports nothing.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.reset_stream(peer_id, conn_id, stream_id)?;
        self.flush();
        Ok(())
    }

    /// Acknowledges `bytes` of a stream's delivered data as consumed,
    /// replenishing its receive budget so the sender can continue (ADR 0012).
    ///
    /// The application owns this for every [`SwarmEvent::StreamData`] it
    /// receives; the swarm acknowledges what it consumes itself. Fails with
    /// [`TransportError::AckExceedsDelivered`] for more than the stream's
    /// unacknowledged bytes; a closed stream releases them, and a settled or
    /// unknown stream is a no-op.
    pub fn ack_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), DriverError> {
        Ok(self.transport.ack_stream(conn_id, stream_id, bytes)?)
    }

    /// Events already produced but not yet handed out, oldest first, such
    /// as ones a blocking wait left undelivered. A host that must act on
    /// events it has not seen yet (a `StreamReady` still in flight, say) can
    /// inspect them.
    pub fn buffered_events(&self) -> impl Iterator<Item = &SwarmEvent> {
        self.state.events.iter()
    }

    /// Forgets swarm bookkeeping for a stream without touching the transport.
    ///
    /// This is used when ownership of a negotiated stream moves to another
    /// protocol layer. Already-queued events are intentionally preserved, and
    /// pending half-close and reset work for the stream is discarded.
    ///
    /// Returns the bytes the swarm still owes the stream, oldest first: tails
    /// held after a Full (a negotiation reply, say), then queued sends. The
    /// new owner must send them before anything of its own.
    pub fn forget_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) -> VecDeque<Bytes> {
        self.state.forget_stream(conn_id, stream_id)
    }

    /// Resets and forgets a stream whose consumer will never read it again.
    ///
    /// A reset is sent at most once, and it settles the queued data this
    /// drops. Already-queued events and all later data, EOF, and close events
    /// for the stream are suppressed.
    ///
    /// A stream the transport has already closed has nothing left to reset, so
    /// its dropped data is acknowledged instead. That case succeeds only while
    /// the stream's [`SwarmEvent::StreamClosed`] is still queued, since that
    /// event is what identifies the stream as one this connection owned. Once
    /// it has been delivered, or dropped by an earlier call, the stream is
    /// indistinguishable from one that never existed and both are
    /// [`SwarmError::StreamNotFound`].
    ///
    /// After the stream's connection ended -- its `ConnectionClosed` or
    /// `ConnectionReplaced` may long have been delivered -- no terminal event
    /// is needed: the swarm drops what it still queues for the stream and the
    /// transport settles it outright, giving up its unacknowledged bytes
    /// (ADR 0012). That always succeeds; a transport holding nothing for the
    /// stream makes it a no-op.
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.abandon_stream(peer_id, conn_id, stream_id)?;
        self.flush();
        Ok(())
    }

    /// Abandons a stream of a connection that already ended, for a caller
    /// that no longer knows its peer because every event naming the stream
    /// was delivered. The transport settles it outright, giving up its
    /// unacknowledged bytes (ADR 0012); one holding nothing for it makes this
    /// a no-op. A connection the swarm still routes is
    /// [`SwarmError::StreamNotFound`]: use
    /// [`abandon_stream`](Self::abandon_stream) there.
    pub fn abandon_ended_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.abandon_ended_stream(conn_id, stream_id)?;
        self.flush();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Driving
    // -----------------------------------------------------------------------

    /// Drive the swarm: poll the transport, run the work each event causes,
    /// advance timers, and return the application's events. Must be called
    /// repeatedly; [`next_deadline`](Self::next_deadline) says when.
    ///
    /// Std event-loop code can instead use `Swarm::poll_next` or
    /// `Swarm::run_until`, which call this in a sleep/poll loop and return one
    /// event at a time.
    pub fn poll(&mut self, now: Now) -> Result<Vec<SwarmEvent>, DriverError> {
        self.drive(now)?;
        Ok(self.take_buffered_events())
    }

    /// Hands out the events already produced without driving the transport,
    /// so a host whose [`poll`](Self::poll) failed can still deliver what
    /// was queued before it (a disconnect's close failure, say).
    pub fn take_buffered_events(&mut self) -> Vec<SwarmEvent> {
        core::iter::from_fn(|| self.state.next_event()).collect()
    }

    /// One drive iteration, leaving its events queued for delivery.
    ///
    /// The std `Swarm` hands queued events out one at a time, which is why
    /// this is visible to the rest of the crate.
    pub(crate) fn drive(&mut self, now: Now) -> Result<(), DriverError> {
        let now_ms = now.monotonic_ms;

        // Closes deferred behind events the caller has since drained are now
        // due. Run them before reading more transport input so replaced
        // connections cannot produce another batch ahead of their close.
        self.flush();

        let events = self.transport.poll(now)?;

        // A transport that moved a listen address on its own (a
        // WebTransport certificate rotation) announces it with `Listening`.
        let listen_changed = self.apply_listen_updates(&events);

        // Refresh the snapshot of our listening addresses so Identify
        // advertises the current bound set plus any validated external
        // addresses -- but only when one of those moved. It runs after the
        // poll, so addresses the poll itself moved are in it before any of
        // its events (an Identify reply, say) are handled.
        self.refresh_local_addresses();
        if listen_changed {
            let addrs = self
                .listened_addrs
                .iter()
                .filter_map(|addr| self.local_peer_addr(addr.clone()).ok())
                .collect();
            self.state
                .events
                .push_back(SwarmEvent::ListenAddressesChanged { addrs });
        }

        // Each transport event's work runs to completion before the next
        // event is ingested: a later event must not observe state that
        // assumes an earlier event's transport actions have already run.
        for event in events {
            self.state.handle_transport_event(event, now_ms);
            self.flush();
        }

        // Timers tick after the transport batch.
        self.state.handle_tick(now_ms);
        self.flush();
        Ok(())
    }

    /// Replaces each listened address a `Listening` event names in a new
    /// form (the same address with other certhashes); returns whether the
    /// listen set changed. Addresses the swarm never listened on are
    /// ignored: `listen*` records those itself.
    fn apply_listen_updates(&mut self, events: &[TransportEvent]) -> bool {
        let mut changed = false;
        for event in events {
            let TransportEvent::Listening { addr } = event else {
                continue;
            };
            let base = addr.without_certhashes();
            for listened in &mut self.listened_addrs {
                if listened != addr && listened.without_certhashes() == base {
                    *listened = addr.clone();
                    changed = true;
                }
            }
        }
        if changed {
            self.listened_addrs_revision = self.listened_addrs_revision.wrapping_add(1);
        }
        changed
    }

    /// Rebuilds the advertised address snapshot when the transport's
    /// addresses, the external set, or the listened set moved since the last
    /// build. A transport without an address revision is re-read every time.
    fn refresh_local_addresses(&mut self) {
        let key = self.transport.local_addresses_revision().map(|transport| {
            (
                transport,
                self.external_addresses_revision,
                self.listened_addrs_revision,
            )
        });
        if key.is_some() && key == self.local_addresses_key {
            return;
        }
        self.local_addresses_key = key;
        #[cfg(test)]
        {
            self.address_rebuilds += 1;
        }
        let mut local_addresses = self.transport.local_addresses();
        for addr in &self.external_addresses {
            if !local_addresses.contains(addr) {
                local_addresses.push(addr.clone());
            }
        }
        self.state.set_local_addresses(local_addresses);
    }

    /// Takes the next queued event, delivering it to the caller.
    #[cfg(feature = "std")]
    pub(crate) fn next_event(&mut self) -> Option<SwarmEvent> {
        self.state.next_event()
    }

    /// Returns when this swarm next needs polling, if it has a timer.
    ///
    /// Folds the transport's deadline together with the swarm's protocol
    /// timers, both on the timeline of the samples passed to
    /// [`poll`](Self::poll). Undelivered events and closes waiting on them
    /// are due immediately. Hosts idle until this deadline rather than
    /// polling on a fixed cadence.
    pub fn next_deadline(&self, now: Now) -> Option<Deadline> {
        if self.state.has_pending_work() {
            return Some(Deadline::IMMEDIATE);
        }
        Deadline::earliest_opt(
            self.transport.next_deadline(),
            self.state.next_deadline(now),
        )
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Dispatches queued transport work until none is due, feeding each
    /// result back into the state (which may queue more).
    fn flush(&mut self) {
        while let Some(action) = self.state.next_action() {
            self.dispatch(action);
        }
    }

    /// Opens a stream on `conn_id` and starts negotiating `protocol` on it.
    ///
    /// The one open path: an application open returns the error, while an
    /// open for the swarm's own protocols reports it as an event.
    fn open(
        &mut self,
        conn_id: ConnectionId,
        protocol: &str,
        target: ProtocolKind,
    ) -> Result<StreamId, TransportError> {
        let stream_id = self.transport.open_stream(conn_id)?;
        self.state
            .start_outbound(conn_id, stream_id, protocol, target);
        Ok(stream_id)
    }

    /// Executes one action against the transport and feeds any result back
    /// into the state.
    ///
    /// A [`TransportError::ConnectionClosed`] is not reported here: the
    /// connection's close reports the failure once. Nor is any stream
    /// operation on a target that already ended ([`target_ended`]): the
    /// transport can emit a stream's last events together with its end and
    /// forget it in the same poll, so actions those events queued find it
    /// gone, and the `StreamClosed` or `Closed` behind them reports the end.
    fn dispatch(&mut self, action: Action) {
        match action {
            Action::OpenStream {
                conn_id,
                protocol,
                target,
            } => match self.open(conn_id, &protocol, target) {
                Ok(_) | Err(TransportError::ConnectionClosed { .. }) => {}
                Err(error) => self
                    .state
                    .open_failed(conn_id, &protocol, &error.to_string()),
            },
            Action::SendStream {
                conn_id,
                stream_id,
                data,
            } => {
                let counted = data.len();
                match self.transport.send_stream(conn_id, stream_id, data) {
                    Ok(()) => {}
                    Err(e) if target_ended(&e) => {}
                    // The state's own write: it holds the tail.
                    Err(TransportError::Full { unsent, .. }) => {
                        self.state
                            .handle_send_full(conn_id, stream_id, unsent, counted);
                    }
                    Err(e) => self.state.record_runtime_error(transport_error(
                        Some(conn_id),
                        Some(stream_id),
                        format!(
                            "send_stream to connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    )),
                }
            }
            Action::CloseStreamWrite { conn_id, stream_id } => {
                match self.transport.close_stream_write(conn_id, stream_id) {
                    Ok(()) => {}
                    Err(e) if target_ended(&e) => {}
                    Err(e) => self.state.record_runtime_error(transport_error(
                        Some(conn_id),
                        Some(stream_id),
                        format!(
                            "close_stream_write on connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    )),
                }
            }
            Action::ResetStream { conn_id, stream_id } => {
                match self.transport.reset_stream(conn_id, stream_id) {
                    Ok(()) => {}
                    // The stream is already gone, which is what the reset
                    // wanted. No terminal event may be left to clear the
                    // pending reset, so drop it here.
                    Err(e) if target_ended(&e) => {
                        self.state.reset_stream_failed(conn_id, stream_id);
                    }
                    Err(e) => {
                        self.state.reset_stream_failed(conn_id, stream_id);
                        self.state.record_runtime_error(transport_error(
                            Some(conn_id),
                            Some(stream_id),
                            format!(
                                "reset_stream on connection {conn_id} stream {stream_id} failed: {e}"
                            ),
                        ));
                    }
                }
            }
            Action::AckStream {
                conn_id,
                stream_id,
                bytes,
            } => match self.transport.ack_stream(conn_id, stream_id, bytes) {
                Ok(()) | Err(TransportError::ConnectionClosed { .. }) => {}
                Err(e) => self.state.record_runtime_error(transport_error(
                    Some(conn_id),
                    Some(stream_id),
                    format!("ack_stream on connection {conn_id} stream {stream_id} failed: {e}"),
                )),
            },
            Action::SettleStream { conn_id, stream_id } => {
                match self.transport.reset_stream(conn_id, stream_id) {
                    Ok(()) => {}
                    // Nothing held is nothing to settle.
                    Err(e) if target_ended(&e) => {}
                    Err(e) => self.state.record_runtime_error(transport_error(
                        Some(conn_id),
                        Some(stream_id),
                        format!("settling connection {conn_id} stream {stream_id} failed: {e}"),
                    )),
                }
            }
            Action::SetControlStream {
                conn_id,
                stream_id,
                control,
            } => self
                .transport
                .set_control_stream(conn_id, stream_id, control),
            Action::CloseConnection { conn_id } => match self.transport.close(conn_id) {
                Ok(()) | Err(TransportError::ConnectionNotFound { .. }) => {}
                Err(e) => self.state.record_runtime_error(transport_error(
                    Some(conn_id),
                    None,
                    format!("close on connection {conn_id} failed: {e}"),
                )),
            },
        }
    }
}

fn transport_error(
    conn_id: Option<ConnectionId>,
    stream_id: Option<StreamId>,
    detail: String,
) -> SwarmRuntimeError {
    SwarmRuntimeError {
        kind: SwarmErrorKind::Transport,
        peer_id: None,
        conn_id,
        stream_id,
        detail,
    }
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
