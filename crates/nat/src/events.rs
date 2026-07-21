use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_transport::StreamId;

use crate::types::{ConnectId, NatError, NatToken, Path, ReachabilityState};

/// Local role used when promoting a relay bridge into a circuit connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeRole {
    /// The local endpoint initiated the HOP CONNECT request.
    Initiator,
    /// The local endpoint accepted the STOP CONNECT request.
    Responder,
}

/// Commands the agent asks its driver to execute against the swarm.
///
/// `Dial` and `OpenStream` are synchronous swarm calls; the driver echoes
/// their results back via [`NatAgent::dial_result`](crate::NatAgent::dial_result)
/// and [`NatAgent::stream_open_result`](crate::NatAgent::stream_open_result)
/// with the same token. The remaining actions are fire-and-forget.
#[derive(Clone, Debug)]
pub enum NatAction {
    /// Call `Swarm::dial(&addr)` and report the result with `token`.
    Dial { token: NatToken, addr: PeerAddr },
    /// Call `Swarm::open_stream(&peer, &protocol_id)` and report the result
    /// with `token`.
    OpenStream {
        token: NatToken,
        peer: PeerId,
        protocol_id: String,
    },
    /// Call `Swarm::send_stream(&peer, stream_id, data)`.
    SendStream {
        peer: PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// Call `Swarm::close_stream_write(&peer, stream_id)`.
    CloseStreamWrite { peer: PeerId, stream_id: StreamId },
    /// Call `Swarm::reset_stream(&peer, stream_id)`. Failures may be
    /// ignored — the stream is being abandoned.
    ResetStream { peer: PeerId, stream_id: StreamId },
    /// Call `Swarm::disconnect(&peer)`.
    Disconnect { peer: PeerId },
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
        remote_write_closed: bool,
    },
    /// Close a promoted circuit connection. Closing an already-gone circuit
    /// is successful cleanup.
    CloseCircuit {
        conn_id: minip2p_transport::ConnectionId,
    },
}

/// Events the agent surfaces to the application.
#[derive(Clone, Debug)]
pub enum NatEvent {
    /// The reachability verdict flipped (majority-of-window confidence, so
    /// this never flaps on a single probe).
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
    /// A first usable path to the peer is available.
    PathEstablished {
        connect_id: ConnectId,
        peer: PeerId,
        path: Path,
    },
    /// A better path replaced the previously announced one. When `from` was
    /// [`Path::Relayed`], its circuit connection is closed automatically.
    PathUpgraded {
        connect_id: ConnectId,
        peer: PeerId,
        from: Path,
        to: Path,
    },
    /// One hole-punch window elapsed (or the punch aborted) without a direct
    /// connection. Informational; retries and fallback are automatic.
    HolePunchFailed {
        connect_id: ConnectId,
        /// 1-based punch window index.
        attempt: u32,
        reason: String,
    },
    /// All punch windows are exhausted; the established relayed connection
    /// remains the final path for this attempt.
    FellBackToRelay { connect_id: ConnectId, peer: PeerId },
    /// The attempt ended with no usable path.
    ConnectFailed {
        connect_id: ConnectId,
        peer: PeerId,
        error: NatError,
    },
    /// An inbound circuit's hole punch succeeded; the peer is now directly
    /// connected.
    InboundDirectUpgrade { peer: PeerId },
}
