//! Foreign-facing event model and upstream event conversion.

use minip2p::{
    DiscoveryEvent, DiscoverySource as UpstreamDiscoverySource, Event, NatError, NatEvent, Path,
    PubsubEvent, ReachabilityState,
};
use minip2p_swarm::SwarmErrorKind;

/// Coarse local reachability state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum Reachability {
    /// Not enough evidence is available.
    Unknown,
    /// The endpoint is directly reachable.
    Public,
    /// The endpoint needs traversal or relay assistance.
    Private,
}

/// Kind of usable connection path.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum PathKind {
    /// A known address was dialed directly.
    DirectDialed,
    /// A direct path was established by hole punching.
    DirectPunched,
    /// Traffic is carried through a relay.
    Relayed {
        /// Relay carrying the circuit.
        relay_peer_id: String,
    },
}

/// Source that contributed a discovery observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum DiscoverySource {
    /// Public-key-authenticated signed beacon.
    SignedBeacon,
    /// Unauthenticated local-link mDNS observation.
    Mdns,
}

/// Category of a non-fatal endpoint runtime error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum EndpointErrorKind {
    /// Underlying transport operation failed.
    Transport,
    /// Multistream negotiation failed.
    Multistream,
    /// Identify protocol failed.
    Identify,
    /// Ping protocol failed.
    Ping,
    /// Identify stream setup was rejected.
    IdentifyStreamRejected,
    /// Outbound stream opening failed.
    OpenStreamFailed,
    /// The remote does not support a requested protocol.
    UnsupportedProtocol,
    /// The swarm driver contract failed.
    Driver,
}

/// Category of a failed NAT connection attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NatErrorKind {
    /// No usable direct or relayed path exists.
    NoPathAvailable,
    /// The connection attempt timed out.
    Timeout,
    /// A transport dial failed.
    DialFailed,
    /// A traversal protocol exchange failed.
    Protocol,
    /// A relay refused the circuit.
    RelayRefused,
}

/// Category of a fatal background-driver failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum DriverFailureKind {
    /// The transport driver failed.
    Transport,
    /// The swarm driver failed.
    Swarm,
    /// An internal driver invariant failed.
    Invariant,
    /// The background pump panicked.
    Panic,
}

/// Event delivered by the native endpoint driver.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
#[allow(clippy::large_enum_variant)]
pub enum P2pEvent {
    /// Native event carry overflow discarded source events.
    EventsDropped {
        /// Events discarded since the previous diagnostic.
        dropped: u64,
        /// Events discarded since this driver started.
        total_dropped: u64,
    },
    /// The background driver terminated after a fatal failure.
    DriverFailed {
        /// Machine-readable failure category.
        kind: DriverFailureKind,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// A verified connection was established.
    ConnectionEstablished {
        /// Remote peer.
        peer_id: String,
        /// Endpoint-local transport connection id.
        conn_id: u64,
    },
    /// A connection closed.
    ConnectionClosed {
        /// Remote peer.
        peer_id: String,
        /// Endpoint-local transport connection id.
        conn_id: u64,
    },
    /// A peer completed Identify and is ready for application protocols.
    PeerReady {
        /// Remote peer.
        peer_id: String,
        /// Protocols advertised by the peer.
        protocols: Vec<String>,
    },
    /// A ping round-trip measurement completed.
    PingRttMeasured {
        /// Remote peer.
        peer_id: String,
        /// Round-trip duration in milliseconds.
        rtt_ms: u64,
    },
    /// A ping timed out.
    PingTimeout {
        /// Remote peer.
        peer_id: String,
    },
    /// A non-fatal endpoint error occurred.
    EndpointError {
        /// Machine-readable category.
        kind: EndpointErrorKind,
        /// Remote peer, when known.
        peer_id: Option<String>,
        /// Transport connection, when known.
        conn_id: Option<u64>,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// The local reachability verdict changed.
    ReachabilityChanged {
        /// Previous verdict.
        previous: Reachability,
        /// Current verdict.
        current: Reachability,
        /// AutoNAT-confirmed public addresses.
        confirmed_addrs: Vec<String>,
    },
    /// AutoNAT confirmed a changed public address set.
    PublicAddressesChanged {
        /// Current public addresses.
        addrs: Vec<String>,
    },
    /// A relay reservation was acquired or renewed.
    RelayReserved {
        /// Relay holding the reservation.
        relay_peer_id: String,
        /// Absolute relay-reported expiry, when present.
        expires_unix_secs: Option<u64>,
    },
    /// A relay reservation was lost.
    RelayReservationLost {
        /// Relay that held the reservation.
        relay_peer_id: String,
    },
    /// The first usable path for an attempt became available.
    PathEstablished {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
        /// Established path.
        path: PathKind,
    },
    /// A better path replaced an earlier path.
    PathUpgraded {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
        /// Previous path.
        from: PathKind,
        /// Replacement path.
        to: PathKind,
    },
    /// One hole-punch window failed.
    HolePunchFailed {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// One-based attempt number.
        attempt: u32,
        /// Human-readable failure detail.
        reason: String,
    },
    /// Direct upgrade attempts ended with the relay path retained.
    FellBackToRelay {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
    },
    /// A connection attempt ended without a usable path.
    ConnectFailed {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
        /// Machine-readable failure category.
        kind: NatErrorKind,
        /// Human-readable failure detail.
        detail: String,
    },
    /// An inbound circuit upgraded to a direct connection.
    InboundDirectUpgrade {
        /// Remote peer.
        peer_id: String,
    },
    /// An accepted pubsub message arrived.
    ///
    /// When unsigned messages are enabled, `signed` can be `false`; hosts
    /// must treat both `from_peer_id` and `data` as unauthenticated unless
    /// `signed` is `true`.
    Message {
        /// Publisher identity.
        from_peer_id: String,
        /// Topics carried by the message.
        topics: Vec<String>,
        /// Application payload.
        data: Vec<u8>,
        /// Opaque publisher sequence number.
        seqno: Vec<u8>,
        /// Whether the message carried a verified signature.
        signed: bool,
    },
    /// A peer announced a subscription.
    PeerSubscribed {
        /// Remote peer.
        peer_id: String,
        /// Subscribed topic.
        topic: String,
    },
    /// A peer withdrew a subscription.
    PeerUnsubscribed {
        /// Remote peer.
        peer_id: String,
        /// Unsubscribed topic.
        topic: String,
    },
    /// Pubsub outbound work was discarded.
    PubsubOutboundFailure {
        /// Destination peer.
        peer_id: String,
        /// Human-readable failure detail.
        reason: String,
    },
    /// A peer violated the pubsub protocol.
    PubsubProtocolViolation {
        /// Offending peer.
        peer_id: String,
        /// Human-readable violation detail.
        reason: String,
    },
    /// Discovery introduced a peer.
    PeerDiscovered {
        /// Discovered peer.
        peer_id: String,
        /// Current merged address snapshot.
        addrs: Vec<String>,
        /// Observation source.
        source: DiscoverySource,
    },
    /// Discovery updated a peer.
    PeerUpdated {
        /// Updated peer.
        peer_id: String,
        /// Current merged address snapshot.
        addrs: Vec<String>,
        /// Observation source.
        source: DiscoverySource,
    },
    /// A discovered peer expired or was evicted.
    PeerExpired {
        /// Removed peer.
        peer_id: String,
    },
    /// An automatic discovery dial failed.
    DiscoveryDialFailed {
        /// Peer that could not be reached.
        peer_id: String,
        /// Human-readable failure detail.
        reason: String,
    },
    /// A discovery source supplied an invalid claim.
    DiscoveryProtocolViolation {
        /// Claimed peer, when identifiable.
        peer_id: Option<String>,
        /// Observation source.
        source: DiscoverySource,
        /// Human-readable violation detail.
        reason: String,
        /// Additional violations folded into this event.
        suppressed: u32,
    },
}

/// Listener implemented by the embedding runtime.
#[uniffi::export(with_foreign)]
pub trait P2pEventListener: Send + Sync {
    /// Receives one converted native event.
    fn on_event(&self, event: P2pEvent);
}

pub(crate) fn convert_swarm(event: Event) -> Option<P2pEvent> {
    Some(match event {
        Event::ConnectionEstablished { peer_id, conn_id } => P2pEvent::ConnectionEstablished {
            peer_id: peer_id.to_base58(),
            conn_id: conn_id.as_u64(),
        },
        Event::ConnectionClosed { peer_id, conn_id } => P2pEvent::ConnectionClosed {
            peer_id: peer_id.to_base58(),
            conn_id: conn_id.as_u64(),
        },
        Event::IdentifyReceived { .. }
        | Event::StreamReady { .. }
        | Event::StreamData { .. }
        | Event::StreamRemoteWriteClosed { .. }
        | Event::StreamClosed { .. } => return None,
        Event::PeerReady { peer_id, protocols } => P2pEvent::PeerReady {
            peer_id: peer_id.to_base58(),
            protocols,
        },
        Event::PingRttMeasured { peer_id, rtt_ms } => P2pEvent::PingRttMeasured {
            peer_id: peer_id.to_base58(),
            rtt_ms,
        },
        Event::PingTimeout { peer_id } => P2pEvent::PingTimeout {
            peer_id: peer_id.to_base58(),
        },
        Event::Error(error) => P2pEvent::EndpointError {
            kind: convert_swarm_error_kind(error.kind),
            peer_id: error.peer_id.map(|peer| peer.to_base58()),
            conn_id: error.conn_id.map(|id| id.as_u64()),
            detail: error.detail,
        },
    })
}

pub(crate) fn convert_nat(event: NatEvent) -> P2pEvent {
    match event {
        NatEvent::ReachabilityChanged {
            old,
            new,
            confirmed_addrs,
        } => P2pEvent::ReachabilityChanged {
            previous: convert_reachability(old),
            current: convert_reachability(new),
            confirmed_addrs: display_addrs(confirmed_addrs),
        },
        NatEvent::PublicAddressesChanged { addrs } => P2pEvent::PublicAddressesChanged {
            addrs: display_addrs(addrs),
        },
        NatEvent::RelayReserved {
            relay,
            expires_unix_secs,
            ..
        } => P2pEvent::RelayReserved {
            relay_peer_id: relay.to_base58(),
            expires_unix_secs,
        },
        NatEvent::RelayReservationLost { relay } => P2pEvent::RelayReservationLost {
            relay_peer_id: relay.to_base58(),
        },
        NatEvent::PathEstablished {
            connect_id,
            peer,
            path,
        } => P2pEvent::PathEstablished {
            connect_id: connect_id.as_u64(),
            peer_id: peer.to_base58(),
            path: convert_path(path),
        },
        NatEvent::PathUpgraded {
            connect_id,
            peer,
            from,
            to,
        } => P2pEvent::PathUpgraded {
            connect_id: connect_id.as_u64(),
            peer_id: peer.to_base58(),
            from: convert_path(from),
            to: convert_path(to),
        },
        NatEvent::HolePunchFailed {
            connect_id,
            attempt,
            reason,
        } => P2pEvent::HolePunchFailed {
            connect_id: connect_id.as_u64(),
            attempt,
            reason,
        },
        NatEvent::FellBackToRelay { connect_id, peer } => P2pEvent::FellBackToRelay {
            connect_id: connect_id.as_u64(),
            peer_id: peer.to_base58(),
        },
        NatEvent::ConnectFailed {
            connect_id,
            peer,
            error,
        } => P2pEvent::ConnectFailed {
            connect_id: connect_id.as_u64(),
            peer_id: peer.to_base58(),
            kind: convert_nat_error_kind(&error),
            detail: error.to_string(),
        },
        NatEvent::InboundDirectUpgrade { peer } => P2pEvent::InboundDirectUpgrade {
            peer_id: peer.to_base58(),
        },
    }
}

pub(crate) fn convert_pubsub(event: PubsubEvent) -> P2pEvent {
    match event {
        PubsubEvent::Message {
            from,
            topics,
            data,
            seqno,
            signed,
        } => P2pEvent::Message {
            from_peer_id: from.to_base58(),
            topics,
            data,
            seqno,
            signed,
        },
        PubsubEvent::PeerSubscribed { peer, topic } => P2pEvent::PeerSubscribed {
            peer_id: peer.to_base58(),
            topic,
        },
        PubsubEvent::PeerUnsubscribed { peer, topic } => P2pEvent::PeerUnsubscribed {
            peer_id: peer.to_base58(),
            topic,
        },
        PubsubEvent::OutboundFailure { peer, reason } => P2pEvent::PubsubOutboundFailure {
            peer_id: peer.to_base58(),
            reason,
        },
        PubsubEvent::ProtocolViolation { peer, reason } => P2pEvent::PubsubProtocolViolation {
            peer_id: peer.to_base58(),
            reason,
        },
    }
}

pub(crate) fn convert_discovery(event: DiscoveryEvent) -> P2pEvent {
    match event {
        DiscoveryEvent::PeerDiscovered {
            peer,
            addrs,
            source,
        } => P2pEvent::PeerDiscovered {
            peer_id: peer.to_base58(),
            addrs: display_addrs(addrs),
            source: convert_discovery_source(source),
        },
        DiscoveryEvent::PeerUpdated {
            peer,
            addrs,
            source,
        } => P2pEvent::PeerUpdated {
            peer_id: peer.to_base58(),
            addrs: display_addrs(addrs),
            source: convert_discovery_source(source),
        },
        DiscoveryEvent::PeerExpired { peer } => P2pEvent::PeerExpired {
            peer_id: peer.to_base58(),
        },
        DiscoveryEvent::DialFailed { peer, reason } => P2pEvent::DiscoveryDialFailed {
            peer_id: peer.to_base58(),
            reason,
        },
        DiscoveryEvent::ProtocolViolation {
            peer,
            source,
            reason,
            suppressed,
        } => P2pEvent::DiscoveryProtocolViolation {
            peer_id: peer.map(|peer| peer.to_base58()),
            source: convert_discovery_source(source),
            reason,
            suppressed,
        },
    }
}

pub(crate) fn convert_reachability(state: ReachabilityState) -> Reachability {
    match state {
        ReachabilityState::Unknown => Reachability::Unknown,
        ReachabilityState::Public => Reachability::Public,
        ReachabilityState::Private => Reachability::Private,
    }
}

fn convert_path(path: Path) -> PathKind {
    match path {
        Path::DirectDialed => PathKind::DirectDialed,
        Path::DirectPunched => PathKind::DirectPunched,
        Path::Relayed { relay } => PathKind::Relayed {
            relay_peer_id: relay.to_base58(),
        },
    }
}

fn convert_discovery_source(source: UpstreamDiscoverySource) -> DiscoverySource {
    match source {
        UpstreamDiscoverySource::SignedBeacon => DiscoverySource::SignedBeacon,
        UpstreamDiscoverySource::Mdns => DiscoverySource::Mdns,
    }
}

fn convert_swarm_error_kind(kind: SwarmErrorKind) -> EndpointErrorKind {
    match kind {
        SwarmErrorKind::Transport => EndpointErrorKind::Transport,
        SwarmErrorKind::Multistream => EndpointErrorKind::Multistream,
        SwarmErrorKind::Identify => EndpointErrorKind::Identify,
        SwarmErrorKind::Ping => EndpointErrorKind::Ping,
        SwarmErrorKind::IdentifyStreamRejected => EndpointErrorKind::IdentifyStreamRejected,
        SwarmErrorKind::OpenStreamFailed => EndpointErrorKind::OpenStreamFailed,
        SwarmErrorKind::UnsupportedProtocol => EndpointErrorKind::UnsupportedProtocol,
        SwarmErrorKind::Driver => EndpointErrorKind::Driver,
    }
}

fn convert_nat_error_kind(error: &NatError) -> NatErrorKind {
    match error {
        NatError::NoPathAvailable => NatErrorKind::NoPathAvailable,
        NatError::Timeout => NatErrorKind::Timeout,
        NatError::DialFailed(_) => NatErrorKind::DialFailed,
        NatError::Protocol(_) => NatErrorKind::Protocol,
        NatError::RelayRefused(_) => NatErrorKind::RelayRefused,
    }
}

fn display_addrs(addrs: Vec<minip2p::Multiaddr>) -> Vec<String> {
    addrs
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p::{ConnectionId, Ed25519Keypair, PeerId};
    use std::str::FromStr;

    fn peer(seed: u8) -> PeerId {
        Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id()
    }

    #[test]
    fn swarm_connection_conversion_preserves_ids() {
        let remote = peer(3);

        assert_eq!(
            convert_swarm(Event::ConnectionEstablished {
                peer_id: remote.clone(),
                conn_id: ConnectionId::new(17),
            }),
            Some(P2pEvent::ConnectionEstablished {
                peer_id: remote.to_base58(),
                conn_id: 17,
            })
        );
    }

    #[test]
    fn internal_swarm_events_are_deliberately_not_exported() {
        let remote = peer(4);
        assert!(
            convert_swarm(Event::IdentifyReceived {
                peer_id: remote,
                info: minip2p::IdentifyMessage::default(),
            })
            .is_none()
        );
    }

    #[test]
    fn pubsub_message_conversion_preserves_binary_fields() {
        let remote = peer(5);
        let event = convert_pubsub(PubsubEvent::Message {
            from: remote.clone(),
            topics: vec!["room".into()],
            data: vec![1, 2],
            seqno: vec![3, 4],
            signed: true,
        });

        assert_eq!(
            event,
            P2pEvent::Message {
                from_peer_id: remote.to_base58(),
                topics: vec!["room".into()],
                data: vec![1, 2],
                seqno: vec![3, 4],
                signed: true,
            }
        );
    }

    #[test]
    fn discovery_conversion_preserves_source_and_addresses() {
        let remote = peer(6);
        let address =
            minip2p::Multiaddr::from_str("/ip4/127.0.0.1/udp/7/quic-v1").expect("address");

        assert_eq!(
            convert_discovery(DiscoveryEvent::PeerDiscovered {
                peer: remote.clone(),
                addrs: vec![address.clone()],
                source: UpstreamDiscoverySource::SignedBeacon,
            }),
            P2pEvent::PeerDiscovered {
                peer_id: remote.to_base58(),
                addrs: vec![address.to_string()],
                source: DiscoverySource::SignedBeacon,
            }
        );
    }

    #[test]
    fn nat_error_categories_are_exhaustively_converted() {
        for (error, expected) in [
            (NatError::NoPathAvailable, NatErrorKind::NoPathAvailable),
            (NatError::Timeout, NatErrorKind::Timeout),
            (
                NatError::DialFailed("dial".into()),
                NatErrorKind::DialFailed,
            ),
            (
                NatError::Protocol("protocol".into()),
                NatErrorKind::Protocol,
            ),
            (
                NatError::RelayRefused("relay".into()),
                NatErrorKind::RelayRefused,
            ),
        ] {
            assert_eq!(convert_nat_error_kind(&error), expected);
        }
    }

    #[test]
    fn discovery_terminal_and_failure_events_preserve_fields() {
        let remote = peer(8);
        assert_eq!(
            convert_discovery(DiscoveryEvent::PeerExpired {
                peer: remote.clone()
            }),
            P2pEvent::PeerExpired {
                peer_id: remote.to_base58()
            }
        );
        assert_eq!(
            convert_discovery(DiscoveryEvent::DialFailed {
                peer: remote.clone(),
                reason: "offline".into(),
            }),
            P2pEvent::DiscoveryDialFailed {
                peer_id: remote.to_base58(),
                reason: "offline".into(),
            }
        );
        assert_eq!(
            convert_discovery(DiscoveryEvent::ProtocolViolation {
                peer: Some(remote.clone()),
                source: UpstreamDiscoverySource::Mdns,
                reason: "bad claim".into(),
                suppressed: 3,
            }),
            P2pEvent::DiscoveryProtocolViolation {
                peer_id: Some(remote.to_base58()),
                source: DiscoverySource::Mdns,
                reason: "bad claim".into(),
                suppressed: 3,
            }
        );
    }
}
