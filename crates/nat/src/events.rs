use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId};
use minip2p_transport::{ConnectionId, StreamId};

use crate::types::{NatError, NatToken, Path, ReachabilityState, UpgradeStop};

/// Local role used when promoting a relay bridge into a circuit connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeRole {
    /// The local endpoint initiated the HOP CONNECT request.
    Initiator,
    /// The local endpoint accepted the STOP CONNECT request.
    Responder,
}

/// Commands the agent asks its driver to execute beyond the swarm.
///
/// Swarm commands (dials, stream opens, writes, resets, pings) are not
/// actions: the agent issues them directly through the
/// [`NatSwarm`](crate::NatSwarm) passed into each call. What remains needs the
/// transport underneath the swarm (raw UDP, circuit adoption and closing).
/// `PromoteBridge` reports its result back through
/// [`NatAgent::promote_result`](crate::NatAgent::promote_result) with its
/// token; the others are fire-and-forget.
#[derive(Clone, Debug)]
// Only 64-bit targets cross clippy's size threshold.
#[cfg_attr(
    target_pointer_width = "64",
    expect(
        clippy::large_enum_variant,
        reason = "actions are drained one at a time, and PromoteBridge, the large one, is rare"
    )
)]
pub enum NatAction {
    /// Send one datagram of `payload_len` random bytes to `target` to open
    /// our NAT mapping (responder-side hole punch). The wiring fills the
    /// random bytes and calls the transport's raw-UDP send; transports
    /// without one may drop the action.
    SendRandomUdp {
        target: Multiaddr,
        payload_len: usize,
    },
    /// Relinquish a negotiated relay bridge to the circuit transport and
    /// report the synchronous adoption result with `token`.
    PromoteBridge {
        token: NatToken,
        inner_conn: minip2p_transport::ConnectionId,
        relay: PeerId,
        stream_id: StreamId,
        remote_peer: PeerId,
        role: BridgeRole,
        pending_data: Vec<u8>,
        /// Bytes NAT wrote on the bridge that the swarm refused as Full and
        /// the agent still held (a STOP STATUS, say). The circuit sends
        /// them before anything of its own.
        unsent_data: Vec<u8>,
        remote_write_closed: bool,
    },
    /// Close a promoted circuit connection, or a NAT dial's handshake that
    /// has not established, through the transport. Closing an already-gone
    /// connection is successful cleanup.
    CloseCircuit {
        conn_id: minip2p_transport::ConnectionId,
    },
}

/// Events the agent surfaces to the application.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NatEvent {
    /// The reachability verdict flipped: a quorum of distinct AutoNAT
    /// servers agreed, so this never flaps on a single server, or the votes
    /// behind the verdict expired and it lapsed to `Unknown`.
    ReachabilityChanged {
        old: ReachabilityState,
        new: ReachabilityState,
        /// AutoNAT-confirmed public addresses associated with the new
        /// verdict. Empty for non-public verdicts.
        confirmed_addrs: Vec<Multiaddr>,
    },
    /// AutoNAT confirmed a different public address set without changing the
    /// already-public reachability verdict.
    PublicAddressesChanged { addrs: Vec<Multiaddr> },
    /// A relay accepted (or renewed) our reservation; we are now dialable
    /// through it.
    RelayReserved {
        relay: PeerId,
        /// Absolute expiry as reported by the relay, if any.
        expires_unix_secs: Option<u64>,
        /// When the agent will renew, on the driver's monotonic clock.
        renew_at_mono_ms: u64,
    },
    /// The reservation lapsed or the relay connection was lost; reacquisition
    /// starts automatically per the configured policy.
    RelayReservationLost { relay: PeerId },
    /// The relay leg started on `relay`: from here on the attempt's relay
    /// diagnostics name it.
    RelayStarted {
        connect_id: ConnectId,
        relay: PeerAddr,
    },
    /// One address of `relay` failed for this attempt; a relay listed under
    /// several addresses reports each. The leg moves on to the next relay
    /// while it has one; otherwise [`NatEvent::ConnectFailed`] follows.
    RelayFailed {
        connect_id: ConnectId,
        relay: PeerAddr,
        error: NatError,
    },
    /// A first usable path to the peer is available.
    PathEstablished {
        connect_id: ConnectId,
        peer: PeerId,
        path: Path,
    },
    /// An inbound relay circuit became a usable path to the peer.
    InboundPathEstablished {
        peer: PeerId,
        path: Path,
        /// The circuit connection carrying the path.
        conn_id: ConnectionId,
    },
    /// A better path replaced the previously announced one. When `from` was
    /// [`Path::Relayed`], its circuit connection is closed automatically.
    PathUpgraded {
        connect_id: ConnectId,
        peer: PeerId,
        from: Path,
        to: Path,
        /// The connection that carried `from`.
        old_conn_id: ConnectionId,
        /// The connection carrying `to`.
        new_conn_id: ConnectionId,
    },
    /// One DCUtR round ended without a direct connection: its punch window
    /// elapsed, or its exchange failed. Informational; the reservation
    /// holder starts the next round.
    HolePunchFailed {
        connect_id: ConnectId,
        /// 1-based DCUtR round.
        attempt: u32,
        reason: String,
    },
    /// The attempt settles on its established Relayed path without a direct
    /// upgrade, for `reason`.
    FellBackToRelay {
        connect_id: ConnectId,
        peer: PeerId,
        reason: UpgradeStop,
    },
    /// The attempt ended with no usable path.
    ConnectFailed {
        connect_id: ConnectId,
        peer: PeerId,
        error: NatError,
    },
    /// An inbound relayed path became direct: an inbound circuit's hole
    /// punch succeeded, or a direct connection replaced the circuit later.
    /// The peer is now directly connected.
    InboundDirectUpgrade {
        peer: PeerId,
        /// The circuit connection that carried the relayed path.
        old_conn_id: ConnectionId,
        /// The direct connection now carrying the peer.
        new_conn_id: ConnectionId,
    },
}

impl NatEvent {
    /// The connection attempt this event reports on, when it is scoped to
    /// one. Reservation and inbound-path events are attempt-independent.
    ///
    /// Exhaustive on purpose: adding an attempt-scoped variant without
    /// returning its `connect_id` here stops the compile.
    pub fn connect_id(&self) -> Option<ConnectId> {
        match self {
            NatEvent::RelayStarted { connect_id, .. }
            | NatEvent::RelayFailed { connect_id, .. }
            | NatEvent::PathEstablished { connect_id, .. }
            | NatEvent::PathUpgraded { connect_id, .. }
            | NatEvent::HolePunchFailed { connect_id, .. }
            | NatEvent::FellBackToRelay { connect_id, .. }
            | NatEvent::ConnectFailed { connect_id, .. } => Some(*connect_id),
            NatEvent::ReachabilityChanged { .. }
            | NatEvent::PublicAddressesChanged { .. }
            | NatEvent::RelayReserved { .. }
            | NatEvent::RelayReservationLost { .. }
            | NatEvent::InboundPathEstablished { .. }
            | NatEvent::InboundDirectUpgrade { .. } => None,
        }
    }
}
