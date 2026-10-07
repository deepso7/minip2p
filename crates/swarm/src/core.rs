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

use minip2p_core::{Bytes, Multiaddr, PeerAddr, PeerId};
use minip2p_identify::{IdentifyConfig, IdentifyMessage};
use minip2p_ping::{PING_PAYLOAD_LEN, PingConfig};
use minip2p_platform::{Deadline, EntropySource, Now};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

use crate::events::{SwarmError, SwarmErrorKind, SwarmEvent, SwarmRuntimeError};
use crate::state::{Action, ProtocolKind, SwarmState};

/// Errors returned synchronously by swarm commands.
///
/// Protocol-state rejections remain distinguishable from transport failures;
/// callers no longer need to recover their meaning from a flattened string.
#[derive(Debug, thiserror::Error)]
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
    /// The operating system's entropy source failed.
    #[error("system entropy source failed")]
    Entropy,
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

    /// Randomness for ping nonces. Injected so the swarm stays deterministic
    /// and testable, and so `no_std` hosts can supply their own source.
    entropy: E,
}

impl<T: Transport, E: EntropySource> SwarmCore<T, E> {
    /// Creates a swarm around the given transport, identify config, and ping
    /// config.
    ///
    /// Most callers should construct via [`crate::SwarmBuilder`] instead,
    /// which derives `local_peer_id` from the keypair automatically.
    pub fn new(
        transport: T,
        identify_config: IdentifyConfig,
        ping_config: PingConfig,
        local_peer_id: PeerId,
        entropy: E,
    ) -> Self {
        Self {
            transport,
            state: SwarmState::new(identify_config, ping_config),
            local_peer_id,
            external_addresses: Vec::new(),
            external_addresses_revision: 0,
            listened_addrs_revision: 0,
            listened_addrs: Vec::new(),
            entropy,
        }
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
    /// dropped.
    pub fn set_external_addresses(&mut self, addrs: Vec<Multiaddr>) {
        self.external_addresses = addrs;
        self.external_addresses_revision = self.external_addresses_revision.wrapping_add(1);
    }

    /// Returns the externally validated addresses currently contributed to
    /// Identify, excluding transport-bound addresses.
    pub fn external_addresses(&self) -> &[Multiaddr] {
        &self.external_addresses
    }

    /// Returns the wrapping revision of the external-address replacement.
    ///
    /// The revision advances even when a replacement contains the same values,
    /// allowing composed hosts to distinguish address ownership changes.
    pub fn external_addresses_revision(&self) -> u64 {
        self.external_addresses_revision
    }

    /// The addresses Identify advertised at the last [`poll`](Self::poll):
    /// the transport's bound set plus the external addresses.
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

    /// Returns whether a transport connection is still tracked, including
    /// inbound handshakes that have not yet emitted
    /// [`SwarmEvent::ConnectionEstablished`].
    pub fn has_tracked_connections(&self) -> bool {
        self.state.has_tracked_connections()
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

    /// Bumps the listened-address revision and records `addr` (deduped)
    /// after a successful `Transport::listen`.
    fn record_listen(&mut self, addr: &Multiaddr) {
        self.listened_addrs_revision = self.listened_addrs_revision.wrapping_add(1);
        if !self.listened_addrs.contains(addr) {
            self.listened_addrs.push(addr.clone());
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
            return Err(TransportError::InvalidConfig {
                reason: "transport does not expose a bound local address".into(),
            }
            .into());
        }

        let mut resolved = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let addr = self.transport.listen(&addr)?;
            // A later bind may still fail, leaving this one bound — record
            // each successful bind, not the batch.
            self.record_listen(&addr);
            let peer_addr = PeerAddr::new(addr, self.local_peer_id.clone()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to build local PeerAddr: {e}"),
                }
            })?;
            resolved.push(peer_addr);
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
            .ok_or_else(|| TransportError::InvalidConfig {
                reason: "transport does not expose a bound local address".into(),
            })?;
        let addr = self.transport.listen(&addr)?;
        self.record_listen(&addr);
        Ok(
            PeerAddr::new(addr, self.local_peer_id.clone()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to build local PeerAddr: {e}"),
                }
            })?,
        )
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
    /// If `close` fails after the dial was taken off the pending map, the
    /// pending entry is restored (including any recorded `last_error`) so a
    /// later close still surfaces as [`SwarmEvent::DialFailed`] rather than a
    /// silent half-aborted dial.
    pub fn abort_dial(&mut self, conn_id: ConnectionId) -> Result<bool, DriverError> {
        let Some((addr, last_error)) = self.state.take_pending_dial(conn_id) else {
            return Ok(false);
        };
        match self.transport.close(conn_id) {
            Ok(()) | Err(TransportError::ConnectionNotFound { .. }) => Ok(true),
            Err(error) => {
                self.state.restore_pending_dial(conn_id, addr, last_error);
                Err(error.into())
            }
        }
    }

    /// Marks `conn_id` so establish-stage events cannot register or replace.
    ///
    /// Used after a failed [`abort_dial`](Self::abort_dial): the dial is
    /// restored as pending, but must not displace an existing peer connection
    /// if the transport still completes. The veto stays until the connection
    /// closes, covering both `TransportEvent::Connected` and a later
    /// `TransportEvent::PeerIdentityVerified`.
    pub fn veto_establish(&mut self, conn_id: ConnectionId) {
        self.state.veto_establish(conn_id);
    }

    // -----------------------------------------------------------------------
    // Commands
    // -----------------------------------------------------------------------

    /// Pings a peer, sending a random 32-byte payload and measuring RTT.
    ///
    /// If a ping stream isn't yet negotiated the payload is queued and
    /// fires when the stream becomes ready. The resulting RTT is delivered
    /// via [`SwarmEvent::PingRttMeasured`]; a reply that does not arrive in
    /// time is reported as [`SwarmEvent::PingTimeout`].
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
        self.flush(now_ms);
        Ok(())
    }

    /// Closes the connection to a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId, now_ms: u64) -> Result<(), DriverError> {
        self.state.disconnect(peer_id)?;
        self.flush(now_ms);
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
    /// emits no event; a later negotiation failure arrives as
    /// [`SwarmEvent::Error`].
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), DriverError> {
        // Earlier queued work keeps its place ahead of this open, and its
        // failures keep flowing as events.
        self.flush(now_ms);
        let conn_id = self.state.admit_user_open(peer_id, protocol_id)?;
        let stream_id = self.open(
            conn_id,
            protocol_id,
            ProtocolKind::User(protocol_id.to_string()),
        )?;
        self.flush(now_ms);
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
        now_ms: u64,
    ) -> Result<(), DriverError> {
        // Earlier queued writes for the stream go out first.
        self.flush(now_ms);
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
    /// an unsent tail of its own must send it before closing. A transport
    /// failure arrives as [`SwarmEvent::Error`].
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.close_stream_write(peer_id, conn_id, stream_id)?;
        self.flush(now_ms);
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    ///
    /// A transport failure arrives as [`SwarmEvent::Error`], and the reset
    /// may be retried.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.reset_stream(peer_id, conn_id, stream_id)?;
        self.flush(now_ms);
        Ok(())
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
    /// A reset is sent at most once. Already-queued events and all later
    /// data, EOF, and close events for the stream are suppressed.
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.state.abandon_stream(peer_id, conn_id, stream_id)?;
        self.flush(now_ms);
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
        Ok(core::iter::from_fn(|| self.state.next_event()).collect())
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
        self.flush(now_ms);

        // Refresh the snapshot of our listening addresses so Identify
        // advertises the current bound set plus any validated external
        // addresses. Cheap -- a handful of multiaddrs at most.
        let mut local_addresses = self.transport.local_addresses();
        for addr in &self.external_addresses {
            if !local_addresses.contains(addr) {
                local_addresses.push(addr.clone());
            }
        }
        self.state.set_local_addresses(local_addresses);

        // Each transport event's work runs to completion before the next
        // event is ingested: a later event must not observe state that
        // assumes an earlier event's transport actions have already run.
        for event in self.transport.poll(now)? {
            self.state.handle_transport_event(event, now_ms);
            self.flush(now_ms);
        }

        // Timers tick after the transport batch.
        self.state.handle_tick(now_ms);
        self.flush(now_ms);
        Ok(())
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
        fold_deadlines(
            now,
            self.transport.next_deadline(),
            self.state.next_timeout(now.monotonic_ms),
        )
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Dispatches queued transport work until none is due, feeding each
    /// result back into the state (which may queue more).
    ///
    /// `_now_ms` is the caller's sample for this step. Every command takes
    /// one so timed work never needs an API change; no dispatched action
    /// reads time today.
    fn flush(&mut self, _now_ms: u64) {
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
    fn dispatch(&mut self, action: Action) {
        match action {
            Action::OpenStream {
                conn_id,
                protocol,
                target,
            } => {
                if let Err(error) = self.open(conn_id, &protocol, target) {
                    self.state
                        .open_failed(conn_id, &protocol, &error.to_string());
                }
            }
            Action::SendStream {
                conn_id,
                stream_id,
                data,
            } => {
                let counted = data.len();
                match self.transport.send_stream(conn_id, stream_id, data) {
                    Ok(()) => {}
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
                if let Err(e) = self.transport.close_stream_write(conn_id, stream_id) {
                    self.state.record_runtime_error(transport_error(
                        Some(conn_id),
                        Some(stream_id),
                        format!(
                            "close_stream_write on connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    ));
                }
            }
            Action::ResetStream { conn_id, stream_id } => {
                if let Err(e) = self.transport.reset_stream(conn_id, stream_id) {
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

/// Folds a transport deadline together with the swarm's next protocol timer.
///
/// The state's next timer is reported as milliseconds *remaining*, while
/// [`Deadline`] is an absolute point on the host's timeline, so it has to be
/// anchored to `now` rather than used directly. Getting that wrong makes
/// timers read as long expired once uptime exceeds the timeout, which
/// busy-spins a blocking driver and can hang a host that sleeps for
/// `millis_until`.
///
/// Split out so the unit conversion is testable without arming a real timer.
fn fold_deadlines(
    now: Now,
    transport: Option<Deadline>,
    core_remaining_ms: Option<u64>,
) -> Option<Deadline> {
    let core = core_remaining_ms.map(|remaining| now.deadline_after(remaining));
    Deadline::earliest_opt(transport, core)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;

    use minip2p_core::SansIoProtocol;
    use minip2p_identify::IDENTIFY_PROTOCOL_ID;
    use minip2p_identity::Ed25519Keypair;
    use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
    use minip2p_ping::PING_PROTOCOL_ID;
    use minip2p_platform::EntropyError;
    use minip2p_transport::{ConnectionEndpoint, TransportEvent};

    /// Counter-based entropy: no OS, no `getrandom`, fully deterministic.
    struct SeqEntropy(u8);

    impl EntropySource for SeqEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), minip2p_platform::EntropyError> {
            for byte in output.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// Entropy source with nothing to give -- an embedded target with no RNG,
    /// or a hardware RNG that failed its health check.
    struct BrokenEntropy;

    impl EntropySource for BrokenEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            // Partially written and then failed: per the `EntropySource`
            // contract the buffer holds no entropy, so this is exactly the
            // payload a driver that ignored the error would put on the wire.
            output.fill(0);
            Err(EntropyError::unavailable("no RNG in this test"))
        }
    }

    /// Transport that replays a scripted batch and records opened streams.
    #[derive(Default)]
    struct ScriptedTransport {
        initial: Vec<TransportEvent>,
        next_stream_id: u64,
        next_conn_id: u64,
        opened: usize,
        deadline: Option<Deadline>,
        /// When set, every locally opened stream gets a multistream-select
        /// listener that answers the dialer, so identify and ping streams
        /// actually reach the negotiated state and carry payloads.
        negotiate: bool,
        /// Listeners for streams still negotiating, keyed by stream id.
        negotiators: BTreeMap<StreamId, MultistreamSelect>,
        /// Protocol frames written after negotiation completed. This is the
        /// wire as the remote peer would see it.
        sent: Vec<(StreamId, Vec<u8>)>,
        close_count: usize,
        /// Second `close` returns `ConnectionNotFound` (TCP after map removal).
        fail_second_close: bool,
        /// Every `close` fails with a non-`ConnectionNotFound` error.
        refuse_close: bool,
    }

    impl ScriptedTransport {
        /// Frames the size of a ping payload that reached the wire.
        fn ping_frames(&self) -> Vec<&[u8]> {
            self.sent
                .iter()
                .map(|(_, data)| data.as_slice())
                .filter(|data| data.len() == PING_PAYLOAD_LEN)
                .collect()
        }
    }

    impl Transport for ScriptedTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            self.next_conn_id += 1;
            Ok(ConnectionId::new(self.next_conn_id))
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            Err(TransportError::Unsupported {
                operation: "listen",
            })
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            self.next_stream_id += 1;
            self.opened += 1;
            let stream_id = StreamId::new(self.next_stream_id);
            if self.negotiate {
                let mut listener = MultistreamSelect::listener(vec![
                    IDENTIFY_PROTOCOL_ID.to_string(),
                    PING_PROTOCOL_ID.to_string(),
                ]);
                listener
                    .handle_input(MultistreamInput::Start)
                    .map_err(|error| TransportError::PollError {
                        reason: alloc::format!("listener start failed: {error}"),
                    })?;
                self.negotiators.insert(stream_id, listener);
            }
            Ok(stream_id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Bytes,
        ) -> Result<(), TransportError> {
            let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
                // Negotiation is done (or was never scripted): this is
                // protocol payload, which is what tests assert on.
                self.sent.push((stream_id, data.to_vec()));
                return Ok(());
            };

            negotiator
                .handle_input(MultistreamInput::Data(data.to_vec()))
                .map_err(|error| TransportError::PollError {
                    reason: alloc::format!("listener negotiation input failed: {error}"),
                })?;
            let mut negotiated = false;
            let mut outbound = Vec::new();
            while let Some(output) = negotiator.poll_output() {
                match output {
                    MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                    MultistreamOutput::Negotiated { .. } => negotiated = true,
                    other => {
                        return Err(TransportError::PollError {
                            reason: alloc::format!("unexpected multistream output: {other:?}"),
                        });
                    }
                }
            }
            if negotiated {
                self.negotiators.remove(&stream_id);
            }
            // The dialer only learns the protocol was accepted on its next
            // poll, so hand the answer back as inbound stream data.
            for data in outbound {
                self.initial.push(TransportEvent::StreamData {
                    id,
                    stream_id,
                    data: Bytes::from(data),
                });
            }
            Ok(())
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.close_count += 1;
            if self.refuse_close {
                return Err(TransportError::InvalidConfig {
                    reason: String::from("close refused"),
                });
            }
            if self.fail_second_close && self.close_count > 1 {
                return Err(TransportError::ConnectionNotFound { id });
            }
            Ok(())
        }

        fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(core::mem::take(&mut self.initial))
        }

        fn next_deadline(&self) -> Option<Deadline> {
            self.deadline
        }
    }

    fn swarm(initial: Vec<TransportEvent>) -> SwarmCore<ScriptedTransport, SeqEntropy> {
        swarm_with(
            ScriptedTransport {
                initial,
                ..ScriptedTransport::default()
            },
            SeqEntropy(1),
        )
    }

    /// Same swarm, with the transport and entropy source chosen by the test.
    fn swarm_with<E: EntropySource>(
        transport: ScriptedTransport,
        entropy: E,
    ) -> SwarmCore<ScriptedTransport, E> {
        let keypair = Ed25519Keypair::generate();
        let identify = IdentifyConfig {
            protocol_version: "test/1".into(),
            agent_version: "test/1".into(),
            protocols: Vec::new(),
            public_key: keypair.public_key().encode_protobuf(),
        };
        SwarmCore::new(
            transport,
            identify,
            PingConfig::default(),
            keypair.peer_id(),
            entropy,
        )
    }

    /// A transport already holding a connection to `peer`, whose
    /// multistream-select listener answers so protocol streams negotiate.
    fn negotiating_transport(peer: &PeerId) -> ScriptedTransport {
        ScriptedTransport {
            initial: vec![TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: ConnectionEndpoint::with_peer_id(
                    "/ip4/198.51.100.7/udp/4001/quic-v1"
                        .parse()
                        .expect("endpoint"),
                    peer.clone(),
                ),
            }],
            negotiate: true,
            ..ScriptedTransport::default()
        }
    }

    /// Drives the swarm far enough for a queued ping to finish negotiating
    /// its stream and reach the transport.
    fn settle<E: EntropySource>(swarm: &mut SwarmCore<ScriptedTransport, E>, from_ms: u64) {
        for step in 0..8 {
            swarm.poll(Now::from_millis(from_ms + step)).expect("poll");
        }
    }

    /// The whole point of the extraction: this drives a connection open and
    /// close with no clock, no OS entropy, and no `std` wrapper -- the same
    /// path an embedded host takes.
    #[test]
    fn core_drives_without_a_clock_or_os_entropy() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut swarm = swarm(vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.7/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                peer.clone(),
            ),
        }]);

        let events = swarm.poll(Now::from_millis(5_000)).expect("poll");
        assert!(
            events.iter().any(|event| matches!(
                event,
                SwarmEvent::ConnectionEstablished { peer_id, .. } if *peer_id == peer
            )),
            "expected the connection to surface: {events:?}"
        );
        // Identify started, so an action really was dispatched to the
        // transport during that poll.
        assert!(swarm.transport().opened > 0);
        assert!(swarm.connected_peers().contains(&peer));
        assert!(swarm.state.is_idle(), "core must settle after the open");

        // ...and the close half of the lifecycle, on the same timeline.
        swarm.transport_mut().initial = vec![TransportEvent::Closed {
            id: ConnectionId::new(1),
        }];
        let events = swarm.poll(Now::from_millis(6_000)).expect("poll");
        assert!(
            events.iter().any(|event| matches!(
                event,
                SwarmEvent::ConnectionClosed { peer_id, .. } if *peer_id == peer
            )),
            "expected the close to surface: {events:?}"
        );
        assert!(swarm.connected_peers().is_empty());
    }

    #[test]
    fn actions_from_one_batched_event_run_before_the_next_event() {
        let peer = Ed25519Keypair::generate().peer_id();
        let id = ConnectionId::new(1);
        let mut swarm = swarm(vec![
            TransportEvent::Connected {
                id,
                endpoint: ConnectionEndpoint::with_peer_id(
                    "/ip4/198.51.100.7/udp/4001/quic-v1"
                        .parse()
                        .expect("endpoint"),
                    peer,
                ),
            },
            TransportEvent::Closed { id },
        ]);

        swarm.poll(Now::from_millis(5_000)).expect("poll");
        assert!(
            swarm.transport().opened > 0,
            "the Connected event's protocol opens must run before Closed mutates core state"
        );
    }

    #[test]
    fn core_timers_are_anchored_to_now_not_used_as_absolute() {
        // `SwarmCore::next_timeout` reports remaining milliseconds. Using it
        // as an absolute deadline reads as long expired once uptime exceeds
        // the timeout, so pin the conversion at a realistic uptime where the
        // two interpretations differ wildly.
        let now = Now::from_millis(3_600_000);

        assert_eq!(
            fold_deadlines(now, None, Some(500)),
            Some(Deadline::from_millis(3_600_500)),
            "core timers must be anchored to now"
        );
        assert_eq!(
            fold_deadlines(now, None, Some(500))
                .expect("armed")
                .millis_until(now),
            500,
            "a timer 500ms out must not read as already due"
        );

        // A past-due core timer reports zero remaining, which really is due.
        assert_eq!(fold_deadlines(now, None, Some(0)), Some(now.as_deadline()));
    }

    #[test]
    fn next_deadline_folds_transport_and_core_timers() {
        let now = Now::from_millis(1_000);
        let transport = Deadline::from_millis(1_400);

        // Whichever needs attention first wins.
        assert_eq!(fold_deadlines(now, Some(transport), None), Some(transport));
        assert_eq!(
            fold_deadlines(now, Some(transport), Some(100)),
            Some(Deadline::from_millis(1_100)),
            "the nearer core timer must win"
        );
        assert_eq!(
            fold_deadlines(now, Some(transport), Some(900)),
            Some(transport),
            "the nearer transport timer must win"
        );
        assert_eq!(fold_deadlines(now, None, None), None);

        // And the swarm reports its transport's deadline through the fold.
        let mut swarm = swarm(Vec::new());
        swarm.poll(now).expect("poll");
        assert_eq!(swarm.next_deadline(now), None);
        swarm.transport_mut().deadline = Some(transport);
        assert_eq!(swarm.next_deadline(now), Some(transport));
    }

    #[test]
    fn queued_work_is_reported_as_immediately_due() {
        let now = Now::from_millis(1_000);
        let mut swarm = swarm(Vec::new());
        swarm.poll(now).expect("poll");
        assert_eq!(swarm.next_deadline(now), None);

        // A deferred action has no timer of its own; without this a host
        // would idle until unrelated I/O happened to wake it.
        swarm.state.deferred_closes.push_back(ConnectionId::new(1));
        assert_eq!(swarm.next_deadline(now), Some(Deadline::IMMEDIATE));

        swarm.state.deferred_closes.clear();
        swarm.state.events.push_back(SwarmEvent::ConnectionClosed {
            peer_id: Ed25519Keypair::generate().peer_id(),
            conn_id: ConnectionId::new(1),
        });
        assert_eq!(swarm.next_deadline(now), Some(Deadline::IMMEDIATE));
    }

    #[test]
    fn ping_draws_from_the_injected_entropy_source() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut swarm = swarm(vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.7/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                peer.clone(),
            ),
        }]);
        swarm.poll(Now::from_millis(0)).expect("poll");

        let before = swarm.entropy.0;
        // Reaches the core rather than failing for want of an OS RNG.
        swarm.ping(&peer, 1_000).expect("ping queues");

        // The nonce came from the injected source, not `getrandom`: the
        // counter advanced by exactly one payload.
        assert_eq!(
            swarm.entropy.0,
            before.wrapping_add(PING_PAYLOAD_LEN as u8),
            "ping must consume PING_PAYLOAD_LEN bytes of injected entropy"
        );
    }

    /// A ping nonce that an attacker can predict lets them pre-compute the
    /// reply, so a failed draw must refuse the ping outright -- never fall
    /// back to whatever the buffer happened to contain.
    #[test]
    fn ping_is_refused_when_the_entropy_source_fails() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut swarm = swarm_with(negotiating_transport(&peer), BrokenEntropy);
        swarm.poll(Now::from_millis(0)).expect("poll");
        assert!(
            swarm.connected_peers().contains(&peer),
            "the peer must be connected, so the ping fails for entropy alone"
        );

        let error = swarm
            .ping(&peer, 1_000)
            .expect_err("a ping must not be sent with a payload the RNG never produced");
        assert!(
            matches!(error, DriverError::Entropy),
            "expected DriverError::Entropy, got {error:?}"
        );

        // And nothing weak escaped: driving the swarm on cannot flush a
        // payload the caller was told was never generated.
        settle(&mut swarm, 2_000);
        assert!(
            swarm.transport().ping_frames().is_empty(),
            "no ping payload may reach the wire: {:?}",
            swarm.transport().ping_frames()
        );
    }

    /// The positive direction, observed on the wire rather than through the
    /// helper: the bytes the source produced are the bytes that get sent.
    #[test]
    fn ping_sends_the_payload_the_entropy_source_produced() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut swarm = swarm_with(negotiating_transport(&peer), SeqEntropy(0xA0));
        swarm.poll(Now::from_millis(0)).expect("poll");

        swarm.ping(&peer, 1_000).expect("ping queues");
        settle(&mut swarm, 2_000);

        // SeqEntropy(0xA0) hands out 0xA0, 0xA1, ... one byte at a time.
        let expected: [u8; PING_PAYLOAD_LEN] =
            core::array::from_fn(|i| 0xA0u8.wrapping_add(i as u8));
        assert_eq!(
            swarm.transport().ping_frames(),
            vec![expected.as_slice()],
            "the ping payload on the wire must be exactly the drawn bytes"
        );
    }

    #[test]
    fn a_second_close_of_the_same_connection_is_not_a_runtime_error() {
        let peer = Ed25519Keypair::generate().peer_id();
        let conn = ConnectionId::new(1);
        let address = "/ip4/198.51.100.7/udp/4001/quic-v1"
            .parse()
            .expect("endpoint");
        let mut swarm = swarm_with(
            ScriptedTransport {
                initial: vec![TransportEvent::Connected {
                    id: conn,
                    endpoint: ConnectionEndpoint::with_peer_id(address, peer.clone()),
                }],
                fail_second_close: true,
                ..ScriptedTransport::default()
            },
            SeqEntropy(1),
        );
        swarm.poll(Now::from_millis(0)).expect("connect");
        swarm.disconnect(&peer, 1).expect("first close");
        swarm.disconnect(&peer, 2).expect("second close");
        let events = swarm.poll(Now::from_millis(3)).expect("poll");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, SwarmEvent::Error(_))),
            "already-gone close must not surface as Error: {events:?}"
        );
    }

    #[test]
    fn abort_dial_restores_pending_when_close_fails() {
        let peer = Ed25519Keypair::generate().peer_id();
        let addr = PeerAddr::new(
            "/ip4/198.51.100.8/udp/4001/quic-v1".parse().expect("addr"),
            peer,
        )
        .expect("peer addr");
        let mut swarm = swarm_with(
            ScriptedTransport {
                refuse_close: true,
                ..ScriptedTransport::default()
            },
            SeqEntropy(1),
        );
        let conn_id = swarm.dial(&addr).expect("dial");
        // Record a transport error before the failed abort so restore must
        // keep last_error — not rebuild via note_dial (which clears it).
        swarm.transport_mut().initial.push(TransportEvent::Error {
            id: conn_id,
            message: String::from("refused"),
        });
        let _ = swarm.poll(Now::from_millis(0)).expect("record error");
        assert!(
            swarm.abort_dial(conn_id).is_err(),
            "close refusal must surface"
        );
        // Pending dial was restored: a later close still emits DialFailed,
        // not a silent half-aborted dial that can still establish.
        swarm
            .transport_mut()
            .initial
            .push(TransportEvent::Closed { id: conn_id });
        let events = swarm.poll(Now::from_millis(1)).expect("poll");
        assert!(
            matches!(
                events.as_slice(),
                [SwarmEvent::DialFailed {
                    conn_id: failed,
                    reason,
                    ..
                }] if *failed == conn_id && reason == "refused"
            ),
            "got {events:?}"
        );
    }

    #[test]
    fn veto_establish_closes_dial_without_replacing_existing_peer() {
        let peer = Ed25519Keypair::generate().peer_id();
        let existing_addr = PeerAddr::new(
            "/ip4/198.51.100.9/udp/4001/quic-v1".parse().expect("addr"),
            peer.clone(),
        )
        .expect("peer addr");
        let late_addr = PeerAddr::new(
            "/ip4/198.51.100.10/udp/4001/quic-v1".parse().expect("addr"),
            peer.clone(),
        )
        .expect("peer addr");
        let existing = ConnectionId::new(1);
        let late = ConnectionId::new(2);
        let mut swarm = swarm_with(ScriptedTransport::default(), SeqEntropy(1));
        swarm
            .transport_mut()
            .initial
            .push(TransportEvent::Connected {
                id: existing,
                endpoint: ConnectionEndpoint::with_peer_id(
                    existing_addr.transport().clone(),
                    peer.clone(),
                ),
            });
        let _ = swarm.poll(Now::from_millis(0)).expect("existing");
        assert_eq!(swarm.connection_id(&peer), Some(existing));

        swarm.state.note_dial(late, late_addr.clone());
        swarm.veto_establish(late);
        swarm
            .transport_mut()
            .initial
            .push(TransportEvent::Connected {
                id: late,
                endpoint: ConnectionEndpoint::with_peer_id(
                    late_addr.transport().clone(),
                    peer.clone(),
                ),
            });
        let events = swarm.poll(Now::from_millis(1)).expect("vetoed");
        assert!(
            events.iter().any(|event| {
                matches!(
                    event,
                    SwarmEvent::DialFailed { conn_id, .. } if *conn_id == late
                )
            }),
            "vetoed dial should DialFailed; got {events:?}"
        );
        assert!(
            events.iter().all(|event| {
                !matches!(
                    event,
                    SwarmEvent::ConnectionEstablished { conn_id, .. } if *conn_id == late
                )
            }),
            "vetoed dial must not establish; got {events:?}"
        );
        assert!(
            events.iter().all(|event| {
                !matches!(
                    event,
                    SwarmEvent::ConnectionReplaced { old, .. } if *old == existing
                )
            }),
            "existing connection must not be replaced; got {events:?}"
        );
        assert_eq!(swarm.connection_id(&peer), Some(existing));
        assert!(
            swarm.transport().close_count >= 1,
            "late dial must be closed; close_count={}",
            swarm.transport().close_count
        );
    }
}
