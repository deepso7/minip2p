//! The one application-facing [`Endpoint`], generic over its [`Platform`]
//! (ADR 0029).
//!
//! Every method here runs the same way on every platform: it samples the
//! platform's clock once and calls the shared engine. Platform-specific
//! surface lives next to its platform: binding, the blocking `wait` and
//! `close_within` on the std one (`crate::std`), and caller-owned listening
//! and `next_deadline` on [`Portable`](crate::Portable) (`crate::portable`).

use alloc::{string::String, vec::Vec};

use minip2p_core::platform::Now;
use minip2p_core::{Bytes, Multiaddr, Path, PeerAddr, PeerId};
use minip2p_swarm::{DriverError, IdentifyMessage};
use minip2p_transport::{ConnectionId, StreamKey, Transport};

#[cfg(feature = "_peer-book")]
use crate::KnownPeer;
#[cfg(feature = "autonat")]
use crate::ReachabilityState;
#[cfg(feature = "relay")]
use crate::ReservationInfo;
use crate::engine::Engine;
use crate::platform::Platform;
use crate::platform::sealed::Sealed;
use crate::writes::{SendError, SendOutcome};
use crate::{ConnectId, ConnectTarget, ConnectTargetError, EndpointEvent, ProtocolId, ProtocolRef};

/// The engine an endpoint on platform `P` drives.
pub(crate) type EngineOf<P> =
    Engine<<P as Sealed>::Transport, <P as Sealed>::Entropy, <P as Sealed>::Carrier>;

/// App-facing minip2p endpoint: one ordered [`EndpointEvent`] stream over
/// one private engine, on the platform `P`.
///
/// `P` is `StdPlatform` (the default under `std`), for an endpoint bound
/// with `Endpoint::builder()` over OS sockets with its own clock, Name
/// resolution and a blocking `wait`, or [`Portable`](crate::Portable)
/// (named [`PortableEndpoint`](crate::PortableEndpoint)), the `no_std +
/// alloc` caller-driven endpoint over any [`Transport`] and the host's
/// [`Clock`](minip2p_core::platform::Clock), built with
/// [`PortableEndpointBuilder`](crate::PortableEndpointBuilder). Both run the
/// same engine, emit the same events in the same per-batch order, and
/// share every method on this impl; each call samples the platform's clock
/// once.
///
/// It has one Connection-attempt entry point, [`connect`](Self::connect),
/// and one ordered event stream, read with [`poll`](Self::poll) (and, on
/// std, the blocking `wait`). Every enabled capability (NAT, Gossipsub,
/// Discovery, mDNS, relay-server) delivers its output once, as an
/// [`EndpointEvent`] variant on that stream, in the per-batch order
/// documented there.
///
/// Applications correlate events by the IDs they carry (a [`ConnectId`], a
/// [`ConnectionId`], a [`StreamKey`]) and dispatch unrelated events while
/// they wait for a particular one.
///
/// Dropping an endpoint disconnects its established peers, best effort, so
/// a listener is not left on an idle timeout; `close` reports what that
/// teardown did, and both poll the transport again so its closes reach
/// the wire. Neither helps after `kill -9` or a hard partition.
///
/// # State snapshots
///
/// Getter-style snapshots ([`connected_peers`](Self::connected_peers),
/// [`is_peer_ready`](Self::is_peer_ready), [`peer_info`](Self::peer_info),
/// [`connection_id`](Self::connection_id),
/// [`connection_remote_addr`](Self::connection_remote_addr),
/// [`connection_info`](Self::connection_info), [`path`](Self::path),
/// [`bound_addresses`](Self::bound_addresses)) do not drive the endpoint.
/// Separate getters are not one cross-getter atomic snapshot and may be
/// ahead of the Endpoint event stream (state changes before its
/// corresponding event is queued).
#[cfg(feature = "std")]
pub struct Endpoint<P: Platform = crate::StdPlatform> {
    pub(crate) engine: EngineOf<P>,
    pub(crate) platform: P,
    /// The sample a close took, so the `Drop` after it reuses that time.
    pub(crate) closed_at: Option<Now>,
}

/// App-facing minip2p endpoint: one ordered [`EndpointEvent`] stream over
/// one private engine, on the platform `P`.
///
/// Without `std` the only platform is [`Portable`](crate::Portable), named
/// [`PortableEndpoint`](crate::PortableEndpoint) and built with
/// [`PortableEndpointBuilder`](crate::PortableEndpointBuilder).
///
/// # State snapshots
///
/// Getter-style snapshots ([`connected_peers`](Self::connected_peers),
/// [`is_peer_ready`](Self::is_peer_ready), [`peer_info`](Self::peer_info),
/// [`connection_id`](Self::connection_id),
/// [`connection_remote_addr`](Self::connection_remote_addr),
/// [`connection_info`](Self::connection_info), [`path`](Self::path),
/// [`bound_addresses`](Self::bound_addresses)) do not drive the endpoint.
/// Separate getters are not one cross-getter atomic snapshot and may be
/// ahead of the Endpoint event stream (state changes before its
/// corresponding event is queued).
#[cfg(not(feature = "std"))]
pub struct Endpoint<P: Platform> {
    pub(crate) engine: EngineOf<P>,
    pub(crate) platform: P,
    /// The sample a close took, so the `Drop` after it reuses that time.
    pub(crate) closed_at: Option<Now>,
}

/// Lightweight snapshot of endpoint state, from [`Endpoint::stats`].
///
/// Aggregate counts only. Prefer the individual
/// [State snapshot](Endpoint#state-snapshots) getters for peer and
/// connection detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointStats {
    /// Number of peers with an established transport connection.
    pub connected_peers: usize,
    /// Number of connected peers that completed Identify and are ready for
    /// application protocols.
    pub ready_peers: usize,
    /// Transport-bound local addresses (see [`Endpoint::bound_addresses`]).
    pub bound_addresses: Vec<Multiaddr>,
}

/// A snapshot of one established connection, from
/// [`Endpoint::connection_info`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    /// The peer on the other end.
    pub peer_id: PeerId,
    /// The connection this describes.
    pub conn_id: ConnectionId,
    /// The remote transport address the transport reported for it; a circuit
    /// reports `/p2p/<relay>/p2p-circuit`.
    pub remote_addr: Multiaddr,
    /// How the connection was made.
    pub path: Path,
    /// The protocols the peer advertised through Identify on this
    /// connection: `None` until it is identified (its
    /// [`EndpointEvent::PeerReady`]), which is distinct from `Some` of an
    /// empty list.
    pub ready_protocols: Option<Vec<String>>,
}

/// What closing an endpoint collected: how its teardown ended, what it left
/// unfinished, every event, in order, and every error close's own calls
/// hit, in order.
///
/// A failure the swarm reports as it happens (a transport refusing to close
/// a connection, say) arrives as [`EndpointEvent::Error`] in `events`, as it
/// would from [`Endpoint::poll`]; a clean close has no such event either.
#[derive(Debug)]
#[must_use = "a close report carries the close's events and errors"]
#[non_exhaustive]
pub struct CloseReport {
    /// How the teardown ended.
    pub outcome: CloseOutcome,
    /// Connections still tracked when the teardown ended, pending dials
    /// included, with their peer when known (an inbound handshake may not
    /// have identified one yet). The endpoint drops them without waiting.
    /// Empty means no tracked teardown remains, not that peers acknowledged
    /// it.
    pub unfinished: Vec<(ConnectionId, Option<PeerId>)>,
    /// Events queued before the close and those its teardown produced,
    /// ending with a [`EndpointEvent::StreamWriteAborted`] for every write
    /// [`Endpoint::send_stream`] still held.
    pub events: Vec<EndpointEvent>,
    /// Every transport or swarm failure: each disconnect, and a failed
    /// drive. An mDNS goodbye that could not be sent is an
    /// `EndpointEvent::MdnsFailed` in `events` instead.
    pub errors: Vec<DriverError>,
}

/// How a close's teardown ended. None of these is an error: the endpoint
/// is gone either way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseOutcome {
    /// Every tracked connection finished its teardown in time.
    Drained,
    /// The deadline passed with connections still tracked; they are listed
    /// in [`CloseReport::unfinished`] and are torn down without waiting. A
    /// portable close does not wait, so anything it leaves tracked ends
    /// here, as a std `close_within(Duration::ZERO)` does. A std close also
    /// ends here, with `unfinished` possibly empty, when a gracefully closed
    /// TCP socket was still waiting for its peer to close.
    DeadlineExpired,
    /// Driving the transports failed, which ended the teardown early; the
    /// failure is the last of [`CloseReport::errors`]. A failed disconnect
    /// alone does not end it.
    Failed,
}

impl<P: Platform> Endpoint<P> {
    /// Samples the platform's clock; every engine call takes one sample.
    pub(crate) fn now(&mut self) -> Now {
        self.platform.now()
    }

    /// Returns this endpoint's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        self.engine.core.local_peer_id()
    }

    /// Returns every listen address, as complete peer addresses.
    ///
    /// Starts listening on every address the transport has bound; a no-op
    /// for an address already listening (a std endpoint listens from
    /// `bind`, so this only re-confirms).
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        self.engine.core.listen_on_bound_addrs()
    }

    /// Registers an application protocol for inbound and outbound negotiation,
    /// returning its [`ProtocolId`] handle (the one it already had when it
    /// was registered before).
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`](minip2p_swarm::RESERVED_PROTOCOL_IDS))
    /// are rejected with
    /// [`SwarmError::ReservedProtocol`](minip2p_swarm::SwarmError::ReservedProtocol);
    /// the endpoint's own identify and ping handlers already own them.
    pub fn add_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<ProtocolId, DriverError> {
        let protocol_id = protocol_id.into();
        self.engine.protocols.check_room(&protocol_id)?;
        self.engine.core.add_protocol(protocol_id.as_str())?;
        self.engine.protocols.intern(&protocol_id)
    }

    /// The handle of an application protocol this endpoint registered (with
    /// the builder's `protocol`, [`Self::add_protocol`] or
    /// [`Self::add_manual_ack_protocol`]); `None` for any other string.
    ///
    /// Look a handle up once and compare it with
    /// [`EndpointEvent::StreamReady`]'s `protocol` to dispatch streams
    /// without comparing strings (ADR 0031).
    pub fn protocol_id(&self, protocol_id: &str) -> Option<ProtocolId> {
        self.engine.protocols.id(protocol_id)
    }

    /// The string id behind a handle this endpoint issued; `None` for a
    /// handle it never issued. Handles are endpoint-local indices: one from
    /// another endpoint may name a different protocol here.
    pub fn protocol_name(&self, protocol: ProtocolId) -> Option<&str> {
        self.engine.protocols.name(protocol)
    }

    /// Registers an application protocol whose received data the
    /// application acknowledges itself, with [`Self::stream_consumed`],
    /// instead of as [`Self::poll`] returns it, returning its handle.
    ///
    /// Otherwise like [`Self::add_protocol`]. Use it when bytes outlive the
    /// event that carried them (a reader that queues them for later, a
    /// foreign runtime's stream queue), so the sender is held back until
    /// they are really consumed (ADR 0012). Streams that became ready before
    /// this call keep the acknowledgement they had.
    pub fn add_manual_ack_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<ProtocolId, DriverError> {
        self.engine.add_manual_ack_protocol(protocol_id.into())
    }

    /// Acknowledges `bytes` of a manual-acknowledgement stream's received
    /// data as consumed, replenishing its receive budget so the sender can
    /// continue (ADR 0012).
    ///
    /// A stream delivers at most one receive window of unacknowledged data,
    /// so a reader that never acknowledges stalls its sender. Fails with
    /// [`TransportError::AckExceedsDelivered`](minip2p_transport::TransportError::AckExceedsDelivered)
    /// when `bytes` exceeds the stream's unacknowledged bytes. Acknowledging
    /// a closed stream releases its bytes (and its stream slot, once none
    /// are left), also after its connection closed: an ended connection
    /// keeps its connection slot until all its streams settle, so a reader
    /// that holds bytes across peer churn eventually has the transport
    /// refuse new connections (ADR 0012). A settled or unknown stream or
    /// connection is a no-op. Streams of protocols registered with
    /// [`Self::add_protocol`] are acknowledged as their data is pulled, and
    /// must not be acknowledged here too.
    pub fn stream_consumed(&mut self, stream: StreamKey, bytes: usize) -> Result<(), DriverError> {
        self.engine
            .core
            .ack_stream(stream.conn_id(), stream.stream_id(), bytes)
    }

    /// Admits one Connection attempt and returns its [`ConnectId`].
    ///
    /// `target` is a [`PeerId`], one complete peer address such as
    /// `/ip4/192.0.2.7/udp/4001/quic-v1/p2p/12D3KooW…`, or a non-empty list of
    /// complete peer addresses that all name the same peer. Synchronous errors
    /// are malformed targets only; everything else, including "no usable
    /// route", arrives later as the attempt's one
    /// [`EndpointEvent::ConnectSettled`].
    ///
    /// A [`PeerId`] target uses the discovery book's known addresses (when a
    /// book exists) and the configured relay when one exists and
    /// `force_relay` / the dial source permit. When neither a direct
    /// candidate nor a configured relay exists, the attempt settles
    /// [`ConnectFailure::NoUsableRoute`](crate::ConnectFailure::NoUsableRoute)
    /// through one terminal event.
    ///
    /// Every candidate is dialed immediately, and the relay leg (when there
    /// is one) starts at once. Candidate completion order is not a public
    /// contract. The swarm still keeps a single connection per peer, chosen
    /// the same way on both sides when candidates race (see
    /// [`SIMULTANEOUS_DIAL_WINDOW_MS`](minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS)):
    /// a candidate that finishes after the winner may still replace it
    /// ([`EndpointEvent::ConnectionReplaced`]), so candidates that could still
    /// win stay open until that window ends. The attempt is settled at the
    /// first established connection the swarm keeps (including a simultaneous
    /// inbound), and the app sees any later hand-over as an ordinary
    /// connection event.
    ///
    /// Candidates may name the IP family explicitly (`/ip4`, `/ip6`) or, on
    /// the std platform, a host (`/dns`, `/dns4`, `/dns6`). This call never
    /// blocks on DNS: a name is looked up on a background thread and joins
    /// the race when it answers, dialed once per family it answers with
    /// (`/dns4` and `/dns6` keep to their family). A failed lookup is a
    /// failed candidate whose reason names the host; the attempt fails only
    /// when every candidate, including names still resolving, has failed and
    /// no relay leg remains. There is no separate DNS timeout: the attempt
    /// deadline covers the lookup. Under `force_relay` names are not looked
    /// up at all.
    ///
    /// Connecting to a peer that is already connected reuses that
    /// connection: the attempt settles at once with the current connection,
    /// and the addresses passed are not dialed.
    #[expect(
        clippy::result_large_err,
        reason = "ConnectTargetError retains both peer identities for MixedPeers diagnostics."
    )]
    pub fn connect(
        &mut self,
        target: impl TryInto<ConnectTarget, Error: Into<ConnectTargetError>>,
    ) -> Result<ConnectId, ConnectTargetError> {
        let target = target.try_into().map_err(Into::into)?;
        let now = self.now();
        Ok(self.engine.connect(target, self.platform.names(), now))
    }

    /// Cancels a Connection attempt and its NAT relay leg.
    ///
    /// Idempotent. Settled or unknown ids are a no-op. Never disconnects.
    pub fn cancel_connect(&mut self, id: ConnectId) {
        let now = self.now();
        self.engine.cancel_connect(id, now);
    }

    /// Sends a ping to `peer_id`.
    ///
    /// Once the call returns `Ok`, the attempt ends in one
    /// [`EndpointEvent::PingRttMeasured`] or
    /// [`EndpointEvent::PingFailed`], unless the connection closes first. Its
    /// deadline (`SwarmTimeouts::ping_ms`) covers opening and negotiating the
    /// ping stream as well as the echo.
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), DriverError> {
        let now = self.now();
        self.engine.core.ping(peer_id, now.monotonic_ms)
    }

    /// Closes the active connection to `peer_id`, aborting any dials still
    /// kept open for its simultaneous dial so none of them reconnects it.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), DriverError> {
        let now = self.now();
        self.engine.disconnect(peer_id, now)
    }

    /// Returns the [`Path`] of `peer_id`'s established connection; `None`
    /// only while the peer is not connected.
    ///
    /// See [`Self::connection_info`] and
    /// [State snapshots](Self#state-snapshots).
    pub fn path(&self, peer_id: &PeerId) -> Option<Path> {
        self.engine.path(peer_id)
    }

    /// Returns a snapshot of the established connection `conn_id`: its peer,
    /// remote address, [`Path`], and Identify protocols once ready.
    ///
    /// `None` for a pending, replaced, or closed connection. A connection's
    /// path is [`Path::Relayed`] for a circuit, [`Path::Direct`] for a direct
    /// connection we dialed or accepted, or [`Path::Punched`] once NAT
    /// reports its hole punch produced it (before the event announcing the
    /// punch is queued). On [`EndpointEvent::ConnectionReplaced`] the new
    /// connection has its own path; nothing carries over.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_info(&self, conn_id: ConnectionId) -> Option<ConnectionInfo> {
        self.engine.connection_info(conn_id)
    }

    /// Returns peers with an established connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.engine.core.connected_peers()
    }

    /// Returns whether Identify has completed for `peer_id`, so it is ready
    /// for application protocols.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.engine.core.is_peer_ready(peer_id)
    }

    /// Returns the peer's current connection and its Identify info once that
    /// connection is ready, as one coherent snapshot.
    ///
    /// Readiness belongs to a connection: after
    /// [`EndpointEvent::ConnectionReplaced`] this is `None` until the new
    /// connection's [`EndpointEvent::PeerReady`]. A ready wait checks this
    /// first, then accepts only a `PeerReady` for the current connection.
    pub fn peer_readiness(&self, peer_id: &PeerId) -> Option<(ConnectionId, &IdentifyMessage)> {
        self.engine.core.peer_readiness(peer_id)
    }

    /// Returns the latest Identify information received for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.engine.core.peer_info(peer_id)
    }

    /// Returns the active transport connection selected for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_id(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.engine.core.connection_id(peer_id)
    }

    /// Returns the remote transport address recorded for an exact connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.engine.core.connection_remote_addr(conn_id)
    }

    /// Returns addresses currently bound on the local transport.
    ///
    /// These are what the sockets were given. A std endpoint is already
    /// accepting on each from `bind`; a portable one starts with
    /// [`listen_on`](Self::listen_on) / [`Self::listen_all`], so the set can
    /// be non-empty before listening begins.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn bound_addresses(&self) -> Vec<Multiaddr> {
        self.engine.core.transport().local_addresses()
    }

    /// Returns a lightweight aggregate of durable state without driving the
    /// endpoint.
    ///
    /// Prefer the individual State snapshot getters when you need peer or
    /// connection detail. Aggregate counts here are not atomic with those
    /// getters and may be ahead of the Endpoint event stream.
    pub fn stats(&self) -> EndpointStats {
        let connected = self.engine.core.connected_peers();
        EndpointStats {
            ready_peers: connected
                .iter()
                .filter(|peer_id| self.engine.core.is_peer_ready(peer_id))
                .count(),
            connected_peers: connected.len(),
            bound_addresses: self.bound_addresses(),
        }
    }

    /// Sets externally validated addresses to advertise through Identify.
    ///
    /// Replaces the previous caller-set addresses; pass an empty vector to
    /// stop advertising them. Addresses the endpoint contributes itself (NAT
    /// relay circuits and confirmed public addresses, relay-server announce
    /// addresses) are kept and merged after these.
    pub fn set_external_addresses(&mut self, addresses: Vec<Multiaddr>) {
        self.engine.set_external_addresses(addresses);
    }

    /// Opens an application stream after negotiating `protocol`: a
    /// registered protocol's string id or its [`ProtocolId`] handle.
    ///
    /// The protocol must be registered first, or this fails with
    /// [`SwarmError::ProtocolNotRegistered`](minip2p_swarm::SwarmError::ProtocolNotRegistered)
    /// (as it does for a handle this endpoint never issued; a handle from
    /// another endpoint may name a different protocol here). Allowed once the
    /// peer is connected. Identify (`PeerReady`) is not
    /// required first; after Identify completes, an unsupported protocol can
    /// fail early with
    /// [`SwarmError::RemoteDoesNotSupport`](minip2p_swarm::SwarmError::RemoteDoesNotSupport).
    ///
    /// Returns the stream's [`StreamKey`], which every later stream
    /// operation takes. The open ends in exactly one terminal:
    /// [`EndpointEvent::StreamReady`], or an error event naming the stream
    /// (see [`crate::SwarmErrorKind`]) when negotiation fails, the peer
    /// closes the stream first, or the negotiation deadline
    /// (`SwarmTimeouts::negotiation_ms`, set with the builder's `timeouts`)
    /// passes. That deadline starts when the transport reports
    /// `StreamOpened`, so a QUIC open still waiting for the peer's stream
    /// credit is not timed. A closed or replaced connection ends it with its
    /// own event.
    pub fn open_stream<'a>(
        &mut self,
        peer_id: &PeerId,
        protocol: impl Into<ProtocolRef<'a>>,
    ) -> Result<StreamKey, DriverError> {
        let now = self.now();
        let engine = &mut self.engine;
        let protocol_id = engine.protocols.resolve(protocol.into())?;
        let (conn_id, stream_id) =
            engine
                .core
                .open_stream(peer_id, protocol_id, now.monotonic_ms)?;
        Ok(StreamKey::new(conn_id, stream_id))
    }

    /// Sends a whole payload on a negotiated application stream, queueing
    /// what the stream cannot accept yet.
    ///
    /// The stream is named by the key [`Self::open_stream`] or
    /// [`EndpointEvent::StreamReady`] gave; the peer is its connection's.
    /// `Ok(())` means every byte was accepted or queued, not delivered. The
    /// endpoint resends queued bytes as the stream drains and reports
    /// [`EndpointEvent::StreamWriteAccepted`] once all of them are accepted,
    /// or [`EndpointEvent::StreamWriteAborted`] if the stream or its
    /// connection ends first. Writes behind queued bytes are queued whole, so
    /// bytes leave in call order; check [`Self::is_write_pending`] to tell
    /// whether this one was.
    ///
    /// Queued bytes count against the endpoint's write budget (the builder's
    /// `write_budget`, [`DEFAULT_WRITE_BUDGET`](crate::DEFAULT_WRITE_BUDGET)
    /// by default), admitted per whole payload: one that does not fit what is
    /// left fails with [`SendError::OverBudget`] and one larger than the
    /// whole budget with [`SendError::TooLarge`], and after a deferred
    /// [`Self::close_stream_write`] a write fails with
    /// [`SendError::Closing`]. Each hands the payload back, unsent. With a
    /// budget of `0` use [`Self::try_send_stream`].
    ///
    /// Fails with
    /// [`SwarmError::StreamNotFound`](minip2p_swarm::SwarmError::StreamNotFound)
    /// if the key's connection is no longer the one holding the stream (for
    /// example after `ConnectionReplaced`), so a write never reaches a
    /// same-numbered stream on a newer connection, and with
    /// [`TransportError::ConnectionNotFound`](minip2p_transport::TransportError::ConnectionNotFound)
    /// once nothing names the connection any more.
    /// [`SendError::is_stream_gone`] covers both. The other stream operations
    /// behave the same.
    pub fn send_stream(
        &mut self,
        stream: StreamKey,
        data: impl Into<Bytes>,
    ) -> Result<(), SendError> {
        let now = self.now();
        self.engine.send_stream(stream, data.into(), now)
    }

    /// Sends what the stream accepts now and hands back the rest, without
    /// queueing anything.
    ///
    /// Accepts as much of `data` as the stream can queue (ADR 0012).
    /// [`SendOutcome::Full`] means a prefix may already have been accepted,
    /// and only `unsent` is yours: hold it, wait for
    /// [`EndpointEvent::StreamWritable`] for the stream, and send it again.
    /// Full is an outcome, not an error, so `?` never drops it, and the
    /// outcome is `#[must_use]`. While [`Self::send_stream`] holds bytes for
    /// the stream this accepts nothing, keeping bytes in order, and its
    /// `StreamWritable` follows [`EndpointEvent::StreamWriteAccepted`] once
    /// the queue drained. After a [`Self::close_stream_write`] deferred
    /// behind queued bytes it fails with `SwarmError::WriteClosed`, since no
    /// `StreamWritable` follows a FIN.
    ///
    /// Errors as [`Self::send_stream`]'s driver errors do.
    pub fn try_send_stream(
        &mut self,
        stream: StreamKey,
        data: impl Into<Bytes>,
    ) -> Result<SendOutcome, DriverError> {
        let now = self.now();
        self.engine.try_send_stream(stream, data.into(), now)
    }

    /// Whether [`Self::send_stream`] holds bytes (or a deferred FIN) for the
    /// stream that it has not finished yet.
    pub fn is_write_pending(&self, stream: StreamKey) -> bool {
        self.engine.writes.is_pending(stream)
    }

    /// Whether a [`Self::close_stream_write`] is deferred behind bytes
    /// [`Self::send_stream`] still holds for the stream; further writes are
    /// refused as [`SendError::Closing`].
    pub fn is_write_closing(&self, stream: StreamKey) -> bool {
        self.engine.writes.is_closing(stream)
    }

    /// Whether accepted writes are still on their way out: bytes or a
    /// deferred FIN [`Self::send_stream`] holds, or stream output the
    /// transport has not finished sending.
    ///
    /// `false` means every byte and FIN the endpoint accepted has been
    /// handed to the transport, and every FIN on a direct QUIC or TCP stream
    /// has been sent: over TCP taken by the socket, over QUIC acknowledged
    /// by the peer (which covers every byte before it). Bytes on a stream
    /// left open are best effort: handed to QUIC, which may still hold them
    /// for congestion control. Over a relayed connection the FIN is handed
    /// to the relay, without waiting for its acknowledgement. To deliver
    /// everything, close the write side before flushing. The std `flush`
    /// drives the endpoint until this is `false` or its deadline passes; a
    /// portable endpoint's `flush` drives one batch, so the host repeats it,
    /// polling between attempts, until it returns `true`. Bytes a peer's stop or reset, or a connection failure,
    /// discarded stop counting here; the event that ended the stream or
    /// connection ([`EndpointEvent::StreamWriteAborted`],
    /// [`EndpointEvent::StreamWriteStopped`], [`EndpointEvent::StreamClosed`]
    /// or [`EndpointEvent::ConnectionClosed`]) is all that reports it.
    pub fn has_pending_writes(&self) -> bool {
        !self.engine.writes.is_empty() || self.engine.core.transport().has_pending_writes()
    }

    /// Bytes [`Self::send_stream`] holds across every stream, as charged
    /// against the write budget.
    pub fn queued_write_bytes(&self) -> usize {
        self.engine.writes.held_bytes()
    }

    /// Half-closes the local write side of an application stream.
    ///
    /// The FIN follows every byte the stream accepted and every byte
    /// [`Self::send_stream`] queued: behind queued bytes it is deferred,
    /// sent once they are accepted (just before their
    /// [`EndpointEvent::StreamWriteAccepted`]), and later writes are
    /// refused. A tail you hold yourself after a
    /// [`try_send_stream`](Self::try_send_stream) Full is not among them.
    pub fn close_stream_write(&mut self, stream: StreamKey) -> Result<(), DriverError> {
        let now = self.now();
        self.engine.close_stream_write(stream, now)
    }

    /// Abruptly resets an application stream. Bytes [`Self::send_stream`]
    /// still held for it are dropped, with an
    /// [`EndpointEvent::StreamWriteAborted`].
    pub fn reset_stream(&mut self, stream: StreamKey) -> Result<(), DriverError> {
        let now = self.now();
        self.engine.reset_stream(stream, now)
    }

    /// Resets and forgets an application stream that will no longer be consumed.
    ///
    /// Unlike [`Self::reset_stream`], this also discards matching events
    /// already queued by the endpoint (a failed [`Self::poll`] keeps them),
    /// and the bytes [`Self::send_stream`] held for it, and suppresses later
    /// data, EOF, close and write-queue events for the stream. Abandoning a
    /// live stream again is a no-op. A stream the peer has already closed has
    /// nothing left to reset: it is abandoned (and its undelivered data
    /// acknowledged) only while its [`EndpointEvent::StreamClosed`] is
    /// undelivered, and fails with
    /// [`SwarmError::StreamNotFound`](minip2p_swarm::SwarmError::StreamNotFound)
    /// after that, including on a second call.
    ///
    /// Once the stream's connection has ended, abandoning always succeeds and
    /// needs no queued event: the endpoint and swarm drop what they hold for
    /// it and the transport settles it, giving up the bytes it delivered so
    /// they no longer hold the connection's slot (ADR 0012).
    pub fn abandon_stream(&mut self, stream: StreamKey) -> Result<(), DriverError> {
        let now = self.now();
        self.engine.abandon_stream(stream, now)
    }

    /// Runs one drive batch without blocking and returns every queued event.
    ///
    /// Returned values are [`EndpointEvent`]s from the Endpoint event stream,
    /// including enabled capability output, in the per-batch order documented
    /// on [`EndpointEvent`]. Streams owned by an agent (NAT, relay service,
    /// Gossipsub) are consumed here and never surface as application stream
    /// events. Returning an [`EndpointEvent::StreamData`] acknowledges its
    /// bytes (ADR 0012): a sender's receive budget is replenished as the
    /// application pulls its data, so polling less often slows the sender.
    ///
    /// An error discards nothing: events already queued come out of the next
    /// call (or std `wait`), and a portable `next_deadline` is immediate
    /// until then.
    pub fn poll(&mut self) -> Result<Vec<EndpointEvent>, DriverError> {
        self.platform.harvest(self.engine.core.transport_mut())?;
        let now = self.now();
        self.engine.drive(now, self.platform.names())?;
        Ok(self.engine.take_events())
    }

    /// Pauses or resumes admission of new relay reservations and circuits.
    ///
    /// Existing reservations and circuits remain active, and HOP remains
    /// advertised while admission is paused.
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error retains the rejected address for actionable host diagnostics."
    )]
    pub fn set_relay_server_accepting(
        &mut self,
        accepting: bool,
    ) -> Result<(), crate::RelayServerControlError> {
        let relay_server = self
            .engine
            .relay_server
            .as_mut()
            .ok_or(crate::RelayServerControlError::NotConfigured)?;
        relay_server.agent.set_accepting(accepting);
        Ok(())
    }

    /// The relay reservation currently held, if any.
    #[cfg(feature = "relay")]
    pub fn active_reservation(&self) -> Option<ReservationInfo> {
        self.engine.active_reservation()
    }

    /// Our current reachability verdict from AutoNAT probing
    /// ([`ReachabilityState::Unknown`] until probes gather confidence, or
    /// when NAT is not configured).
    #[cfg(feature = "autonat")]
    pub fn reachability(&self) -> ReachabilityState {
        self.engine.reachability()
    }

    /// Subscribes to a pubsub topic. Returns `Ok(false)` when already
    /// subscribed. The subscription is announced over gossipsub.
    ///
    /// Errors with [`GossipsubError::NotEnabled`](crate::GossipsubError::NotEnabled)
    /// unless the endpoint was built with Gossipsub.
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: &str) -> Result<bool, crate::GossipsubError> {
        let now = self.now();
        self.engine.subscribe(topic, now)
    }

    /// Withdraws a pubsub subscription. Returns `Ok(false)` when not
    /// subscribed. The configured discovery topic is reserved while
    /// discovery is enabled and returns
    /// [`GossipsubError::DiscoveryTopicReserved`](crate::GossipsubError::DiscoveryTopicReserved).
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str) -> Result<bool, crate::GossipsubError> {
        let now = self.now();
        self.engine.unsubscribe(topic, now)
    }

    /// Publishes `data` on `topic`, signed with this endpoint's identity and
    /// forwarded over gossipsub.
    ///
    /// A successful return means the message was accepted and its outbound
    /// streams were initiated — the frames themselves go out as the
    /// endpoint is driven, so keep driving after publishing. Delivery
    /// failures are never synchronous errors; they surface later as
    /// [`crate::GossipsubEvent::OutboundFailure`] (or
    /// [`EndpointEvent::Error`] runtime events). There is no self-delivery.
    /// The configured discovery topic is reserved while discovery is enabled
    /// and returns
    /// [`GossipsubError::DiscoveryTopicReserved`](crate::GossipsubError::DiscoveryTopicReserved).
    #[cfg(feature = "pubsub")]
    pub fn publish(
        &mut self,
        topic: &str,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), crate::GossipsubError> {
        let now = self.now();
        self.engine.publish(topic, data.into(), now)
    }

    /// Returns the bounded peer book shared by mDNS and signed beacons;
    /// empty when neither is configured.
    #[cfg(feature = "_peer-book")]
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.engine.known_peers()
    }

    /// Returns the discovery driver's current monotonic timestamp: the
    /// platform clock's, which `KnownPeer::beacon_last_seen_ms` and
    /// `KnownPeer::mdns_last_seen_ms` are on.
    ///
    /// Callers computing source ages must use this value rather than an
    /// independently created clock. Returns `None` when no discovery source
    /// is active.
    #[cfg(feature = "_peer-book")]
    pub fn discovery_now_ms(&mut self) -> Option<u64> {
        self.engine.discovery.as_ref()?;
        Some(self.now().monotonic_ms)
    }

    /// Sends mDNS goodbyes once and cancels discovery-owned dial attempts.
    ///
    /// mDNS becomes permanently inactive, while the transports and the rest
    /// of the endpoint remain usable. Every interface send and every
    /// cancellation is attempted; the first goodbye that could not be sent
    /// is returned afterwards, and is also queued as a final
    /// [`EndpointEvent::MdnsFailed`]. Idempotent: a second call does nothing.
    ///
    /// This does not close peers; closing the endpoint (or dropping it)
    /// does, after sending these goodbyes itself.
    #[cfg(feature = "mdns")]
    pub fn shutdown_mdns(&mut self) -> Result<(), crate::MdnsError> {
        let now = self.now();
        self.engine.shutdown_mdns(now)
    }

    /// Consumes the endpoint after tearing it down, reporting what that did.
    ///
    /// On std this is `close_within(DEFAULT_CLOSE_TIMEOUT)`: it disconnects
    /// established peers and waits up to 500 ms until none remain.
    ///
    /// On a [`Portable`](crate::Portable) platform it does not wait for
    /// teardown. At one clock sample it sends mDNS goodbyes, disconnects
    /// established peers, drives the endpoint twice more (once to run the
    /// closes, once to send them), and consumes it. The
    /// [`CloseReport`] carries the final Endpoint events, including
    /// capability events still queued (Gossipsub events still inside the
    /// agent too), any a failed [`poll`](Self::poll) left, and those the
    /// swarm queued even when the final drive fails. Dropping the transport
    /// releases listeners and in-progress connections as well as established
    /// ones; the report's `unfinished` lists those abandoned that way, with
    /// [`CloseOutcome::DeadlineExpired`] when the final drive succeeded
    /// ([`CloseOutcome::Failed`] when it did not). Every established peer is attempted
    /// even if an earlier step fails. mDNS goodbyes are best effort: one that
    /// could not be sent is an `EndpointEvent::MdnsFailed` among the events,
    /// not an error.
    pub fn close(self) -> CloseReport {
        P::close(self)
    }

    /// Disconnects every established peer at `now`, returning each failure.
    pub(crate) fn disconnect_established(&mut self, now: Now) -> Vec<DriverError> {
        self.engine
            .core
            .connected_peers()
            .iter()
            .filter_map(|peer| self.engine.core.disconnect(peer, now.monotonic_ms).err())
            .collect()
    }

    /// Connections still tracked, pending dials included, with their peer
    /// when known: what a close leaves unfinished.
    pub(crate) fn tracked_connections(&self) -> Vec<(ConnectionId, Option<PeerId>)> {
        self.engine
            .core
            .tracked_connections()
            .map(|(conn_id, peer)| (conn_id, peer.copied()))
            .collect()
    }
}

impl<P: Platform> Drop for Endpoint<P> {
    fn drop(&mut self) {
        let now = match self.closed_at {
            Some(now) => now,
            None => self.now(),
        };
        if !self.engine.core.connected_peers().is_empty() {
            drop(self.disconnect_established(now));
        }
        for _ in 0..2 {
            drop(self.engine.core.poll(now));
        }
        #[cfg(all(feature = "relay-server", feature = "quic"))]
        if let Some(backbone) = self
            .engine
            .relay_server
            .as_mut()
            .and_then(|relay_server| relay_server.backbone.as_mut())
        {
            backbone.shutdown(now);
            drop(backbone.core.poll(now));
        }
    }
}
