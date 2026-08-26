//! Thin napi-rs shell over the binding-agnostic FFI core.

#![warn(missing_docs)]

use std::sync::Arc;

use minip2p_ffi_core::{
    DiscoveryOptions, DiscoverySource, DriverFailureKind, EndpointConfig, EndpointErrorKind,
    EventDoorbell, IdentifyInfo, MdnsOptions, NatErrorKind, P2pEndpoint, P2pEvent, PathKind,
    PubsubRouter, Reachability, TransportOptions,
};
use napi::bindgen_prelude::{BigInt, Uint8Array};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Error, Result, Status};
use napi_derive::napi;

type DoorbellFunction = ThreadsafeFunction<(), (), (), Status, false>;

struct NodeDoorbell(Arc<DoorbellFunction>);

impl EventDoorbell for NodeDoorbell {
    fn on_events_ready(&self) {
        self.0.call((), ThreadsafeFunctionCallMode::NonBlocking);
    }
}

/// QUIC listen configuration accepted from Node.js.
#[napi(object)]
pub struct NodeTransportOptions {
    /// Exact listen addresses, or native defaults when absent.
    pub listen_addrs: Option<Vec<String>>,
}

/// Signed-discovery configuration accepted from Node.js.
#[napi(object)]
pub struct NodeDiscoveryOptions {
    /// Pubsub topic carrying signed beacons.
    pub topic: String,
    /// Beacon interval in milliseconds.
    pub beacon_interval_ms: BigInt,
    /// Peer expiry interval in milliseconds.
    pub peer_ttl_ms: BigInt,
    /// Whether observations may trigger dials.
    pub auto_dial: bool,
}

/// mDNS configuration accepted from Node.js.
#[napi(object)]
pub struct NodeMdnsOptions {
    /// Whether IPv6 multicast is enabled.
    pub enable_ipv6: bool,
    /// Advertised record lifetime in milliseconds.
    pub ttl_ms: BigInt,
    /// Query interval in milliseconds.
    pub query_interval_ms: BigInt,
    /// Maximum encoded packet size.
    pub max_packet_bytes: u32,
    /// Maximum addresses per response.
    pub max_announced_addrs: u32,
    /// Interface refresh interval in milliseconds.
    pub interface_refresh_ms: BigInt,
    /// Socket polling interval in milliseconds.
    pub socket_poll_interval_ms: BigInt,
    /// Whether observations may trigger dials.
    pub auto_dial: bool,
}

/// Endpoint configuration accepted from Node.js.
#[napi(object)]
pub struct NodeEndpointConfig {
    /// Identify agent version.
    pub agent_version: Option<String>,
    /// Relay peer addresses.
    pub relays: Vec<String>,
    /// AutoNAT server peer addresses.
    pub autonat_servers: Vec<String>,
    /// QUIC transport configuration.
    pub quic: Option<NodeTransportOptions>,
    /// TCP transport configuration.
    pub tcp: Option<NodeTransportOptions>,
    /// Whether all outbound paths must remain relayed.
    pub force_relay: bool,
    /// Whether unsigned pubsub messages are accepted.
    pub allow_unsigned: bool,
    /// Pubsub router discriminant.
    pub pubsub_router: u32,
    /// Application protocol identifiers.
    pub protocols: Vec<String>,
    /// Signed discovery configuration.
    pub discovery: Option<NodeDiscoveryOptions>,
    /// mDNS configuration.
    pub mdns: Option<NodeMdnsOptions>,
}

impl TryFrom<NodeEndpointConfig> for EndpointConfig {
    type Error = Error;

    fn try_from(config: NodeEndpointConfig) -> Result<Self> {
        let pubsub_router = match config.pubsub_router {
            0 => PubsubRouter::Gossipsub,
            1 => PubsubRouter::Floodsub,
            value => return Err(Error::from_reason(format!("unknown pubsub router {value}"))),
        };
        Ok(Self {
            agent_version: config.agent_version,
            relays: config.relays,
            autonat_servers: config.autonat_servers,
            quic: config.quic.map(convert_transport),
            tcp: config.tcp.map(convert_transport),
            force_relay: config.force_relay,
            allow_unsigned: config.allow_unsigned,
            pubsub_router,
            protocols: config.protocols,
            discovery: config.discovery.map(convert_discovery).transpose()?,
            mdns: config.mdns.map(convert_mdns).transpose()?,
        })
    }
}

fn convert_discovery(options: NodeDiscoveryOptions) -> Result<DiscoveryOptions> {
    Ok(DiscoveryOptions {
        topic: options.topic,
        beacon_interval_ms: bigint_u64(options.beacon_interval_ms, "beaconIntervalMs")?,
        peer_ttl_ms: bigint_u64(options.peer_ttl_ms, "peerTtlMs")?,
        auto_dial: options.auto_dial,
    })
}

fn convert_mdns(options: NodeMdnsOptions) -> Result<MdnsOptions> {
    Ok(MdnsOptions {
        enable_ipv6: options.enable_ipv6,
        ttl_ms: bigint_u64(options.ttl_ms, "ttlMs")?,
        query_interval_ms: bigint_u64(options.query_interval_ms, "queryIntervalMs")?,
        max_packet_bytes: options.max_packet_bytes,
        max_announced_addrs: options.max_announced_addrs,
        interface_refresh_ms: bigint_u64(options.interface_refresh_ms, "interfaceRefreshMs")?,
        socket_poll_interval_ms: bigint_u64(
            options.socket_poll_interval_ms,
            "socketPollIntervalMs",
        )?,
        auto_dial: options.auto_dial,
    })
}

/// Native stream identity returned to Node.js.
#[napi(object)]
pub struct NodeOpenStream {
    /// Transport connection carrying the stream.
    pub conn_id: BigInt,
    /// Opaque transport stream identifier.
    pub stream_id: BigInt,
}

fn convert_transport(options: NodeTransportOptions) -> TransportOptions {
    TransportOptions {
        listen_addrs: options.listen_addrs,
    }
}

/// A native minip2p endpoint owned by Node.js.
#[napi]
pub struct NodeEndpoint(Arc<P2pEndpoint>);

#[napi]
impl NodeEndpoint {
    /// Binds a native endpoint without starting its driver.
    #[napi(constructor)]
    pub fn new(secret_key: Uint8Array, mut config: NodeEndpointConfig) -> Result<Self> {
        if config.agent_version.is_none() {
            config.agent_version = Some(format!("minip2p-node/{}", env!("CARGO_PKG_VERSION")));
        }
        P2pEndpoint::new(secret_key.to_vec(), config.try_into()?)
            .map(Self)
            .map_err(native_error)
    }

    /// Starts the detached driver with a strong event-loop doorbell.
    #[napi]
    pub fn start(&self, doorbell: Arc<DoorbellFunction>) -> Result<()> {
        self.0
            .start(Arc::new(NodeDoorbell(doorbell)))
            .map_err(native_error)
    }

    /// Requests shutdown without waiting for the driver thread.
    #[napi]
    pub fn close(&self) {
        self.0.stop();
    }

    /// Returns the local peer ID.
    #[napi]
    pub fn peer_id(&self) -> String {
        self.0.peer_id()
    }

    /// Returns bound peer addresses.
    #[napi]
    pub fn listen_addrs(&self) -> Vec<String> {
        self.0.listen_addrs()
    }

    /// Returns whether the driver accepts commands.
    #[napi]
    pub fn is_running(&self) -> bool {
        self.0.is_running()
    }

    /// Pulls a bounded batch of native events.
    #[napi]
    pub fn drain_events(&self, limit: u32) -> Vec<serde_json::Value> {
        self.0
            .drain_events(limit)
            .into_iter()
            .map(event_value)
            .collect()
    }

    /// Returns connected peer IDs.
    #[napi]
    pub fn connected_peers(&self) -> Result<Vec<String>> {
        self.0.connected_peers().map_err(native_error)
    }

    /// Returns whether Identify completed for a peer.
    #[napi]
    pub fn is_peer_ready(&self, peer_id: String) -> Result<bool> {
        self.0.is_peer_ready(peer_id).map_err(native_error)
    }

    /// Returns the latest Identify snapshot.
    #[napi]
    pub fn peer_info(&self, peer_id: String) -> Result<Option<serde_json::Value>> {
        self.0
            .peer_info(peer_id)
            .map(|info| info.map(identify_value))
            .map_err(native_error)
    }

    /// Selects foreground or idle polling.
    #[napi]
    pub fn set_active(&self, active: bool) {
        self.0.set_active(active);
    }

    /// Subscribes to a pubsub topic.
    #[napi]
    pub fn subscribe(&self, topic: String) -> Result<bool> {
        self.0.subscribe(topic).map_err(native_error)
    }

    /// Unsubscribes from a pubsub topic.
    #[napi]
    pub fn unsubscribe(&self, topic: String) -> Result<bool> {
        self.0.unsubscribe(topic).map_err(native_error)
    }

    /// Publishes one pubsub payload.
    #[napi]
    pub fn publish(&self, topic: String, data: Uint8Array) -> Result<()> {
        self.0.publish(topic, data.to_vec()).map_err(native_error)
    }

    /// Starts one ping operation.
    #[napi]
    pub fn ping(&self, peer_id: String) -> Result<()> {
        self.0.ping(peer_id).map_err(native_error)
    }

    /// Registers an application protocol.
    #[napi]
    pub fn add_protocol(&self, protocol_id: String) -> Result<()> {
        self.0.add_protocol(protocol_id).map_err(native_error)
    }

    /// Starts opening an application stream.
    #[napi]
    pub fn open_stream(&self, peer_id: String, protocol_id: String) -> Result<NodeOpenStream> {
        self.0
            .open_stream(peer_id, protocol_id)
            .map(|stream| NodeOpenStream {
                conn_id: stream.conn_id.into(),
                stream_id: stream.stream_id.into(),
            })
            .map_err(native_error)
    }

    /// Sends bytes on an application stream.
    #[napi]
    pub fn send_stream(&self, peer_id: String, stream_id: BigInt, data: Uint8Array) -> Result<()> {
        self.0
            .send_stream(peer_id, bigint_u64(stream_id, "streamId")?, data.to_vec())
            .map_err(native_error)
    }

    /// Half-closes the local stream write side.
    #[napi]
    pub fn close_stream_write(&self, peer_id: String, stream_id: BigInt) -> Result<()> {
        self.0
            .close_stream_write(peer_id, bigint_u64(stream_id, "streamId")?)
            .map_err(native_error)
    }

    /// Resets an application stream.
    #[napi]
    pub fn reset_stream(&self, peer_id: String, stream_id: BigInt) -> Result<()> {
        self.0
            .reset_stream(peer_id, bigint_u64(stream_id, "streamId")?)
            .map_err(native_error)
    }

    /// Resets and relinquishes an application stream.
    #[napi]
    pub fn abandon_stream(&self, peer_id: String, stream_id: BigInt) -> Result<()> {
        self.0
            .abandon_stream(peer_id, bigint_u64(stream_id, "streamId")?)
            .map_err(native_error)
    }

    /// Starts a NAT-orchestrated connection attempt.
    #[napi]
    pub fn connect(&self, peer_id: String) -> Result<BigInt> {
        self.0
            .connect(peer_id)
            .map(BigInt::from)
            .map_err(native_error)
    }

    /// Starts a connection attempt with explicit addresses.
    #[napi]
    pub fn connect_with_addrs(&self, peer_id: String, addresses: Vec<String>) -> Result<BigInt> {
        self.0
            .connect_with_addrs(peer_id, addresses)
            .map(BigInt::from)
            .map_err(native_error)
    }

    /// Starts a direct-address connection attempt.
    #[napi]
    pub fn connect_addr(&self, address: String) -> Result<BigInt> {
        self.0
            .connect_addr(address)
            .map(BigInt::from)
            .map_err(native_error)
    }

    /// Starts direct dials for every applicable address family.
    #[napi]
    pub fn dial(&self, address: String) -> Result<Vec<BigInt>> {
        self.0
            .dial(address)
            .map(|ids| ids.into_iter().map(BigInt::from).collect())
            .map_err(native_error)
    }

    /// Starts one IPv4 dial.
    #[napi]
    pub fn dial_ip4(&self, address: String) -> Result<BigInt> {
        self.0
            .dial_ip4(address)
            .map(BigInt::from)
            .map_err(native_error)
    }

    /// Starts one IPv6 dial.
    #[napi]
    pub fn dial_ip6(&self, address: String) -> Result<BigInt> {
        self.0
            .dial_ip6(address)
            .map(BigInt::from)
            .map_err(native_error)
    }

    /// Cancels a connection attempt.
    #[napi]
    pub fn cancel_connect(&self, id: BigInt) -> Result<()> {
        self.0
            .cancel_connect(bigint_u64(id, "connectId")?)
            .map_err(native_error)
    }

    /// Disconnects one peer.
    #[napi]
    pub fn disconnect(&self, peer_id: String) -> Result<()> {
        self.0.disconnect(peer_id).map_err(native_error)
    }

    /// Returns the current path to a peer.
    #[napi]
    pub fn path(&self, peer_id: String) -> Result<Option<serde_json::Value>> {
        self.0
            .path(peer_id)
            .map(|path| path.map(path_value))
            .map_err(native_error)
    }

    /// Returns the discovery address book.
    #[napi]
    pub fn known_peers(&self) -> Result<Vec<serde_json::Value>> {
        self.0
            .known_peers()
            .map(|peers| {
                peers
                    .into_iter()
                    .map(|peer| {
                        serde_json::json!({
                            "peerId": peer.peer_id,
                            "addrs": peer.addrs,
                            "beaconAddrs": peer.beacon_addrs,
                            "mdnsAddrs": peer.mdns_addrs,
                            "beaconLastSeenAgeMs": peer.beacon_last_seen_age_ms,
                            "mdnsLastSeenAgeMs": peer.mdns_last_seen_age_ms,
                            "connected": peer.connected,
                        })
                    })
                    .collect()
            })
            .map_err(native_error)
    }

    /// Returns the discovery clock.
    #[napi]
    pub fn discovery_now_ms(&self) -> Result<Option<BigInt>> {
        self.0
            .discovery_now_ms()
            .map(|value| value.map(BigInt::from))
            .map_err(native_error)
    }

    /// Returns the current reachability verdict.
    #[napi]
    pub fn reachability(&self) -> Result<u32> {
        self.0
            .reachability()
            .map(reachability_value)
            .map_err(native_error)
    }

    /// Returns the active relay reservation.
    #[napi]
    pub fn active_reservation(&self) -> Result<Option<serde_json::Value>> {
        self.0
            .active_reservation()
            .map(|reservation| {
                reservation.map(|reservation| {
                    serde_json::json!({
                        "relayPeerId": reservation.relay_peer_id,
                        "expiresUnixSecs": reservation.expires_unix_secs,
                    })
                })
            })
            .map_err(native_error)
    }
}

impl Drop for NodeEndpoint {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Generates a 32-byte Ed25519 secret key.
#[napi]
pub fn generate_secret_key() -> Uint8Array {
    minip2p_ffi_core::generate_secret_key().into()
}

/// Derives a peer ID from raw Ed25519 secret key material.
#[napi]
pub fn peer_id_from_secret_key(secret_key: Uint8Array) -> Result<String> {
    minip2p_ffi_core::peer_id_from_secret_key(secret_key.to_vec()).map_err(native_error)
}

/// Builds a circuit address through a direct relay address.
#[napi]
pub fn circuit_address(relay_address: String, peer_id: String) -> Result<String> {
    minip2p_ffi_core::circuit_address(relay_address, peer_id).map_err(native_error)
}

fn native_error(error: minip2p_ffi_core::FfiError) -> Error {
    Error::from_reason(error.to_string())
}

fn event_value(event: P2pEvent) -> serde_json::Value {
    let (tag, inner) = match event {
        P2pEvent::EventsDropped {
            dropped,
            total_dropped,
        } => (
            "EventsDropped",
            serde_json::json!({ "dropped": dropped, "totalDropped": total_dropped }),
        ),
        P2pEvent::DriverFailed { kind, detail } => (
            "DriverFailed",
            serde_json::json!({ "kind": driver_failure_value(kind), "detail": detail }),
        ),
        P2pEvent::ConnectionEstablished { peer_id, conn_id } => (
            "ConnectionEstablished",
            serde_json::json!({ "peerId": peer_id, "connId": conn_id }),
        ),
        P2pEvent::ConnectionClosed { peer_id, conn_id } => (
            "ConnectionClosed",
            serde_json::json!({ "peerId": peer_id, "connId": conn_id }),
        ),
        P2pEvent::PeerReady { peer_id, protocols } => (
            "PeerReady",
            serde_json::json!({ "peerId": peer_id, "protocols": protocols }),
        ),
        P2pEvent::IdentifyReceived { peer_id, info } => (
            "IdentifyReceived",
            serde_json::json!({ "peerId": peer_id, "info": identify_value(info) }),
        ),
        P2pEvent::PingRttMeasured { peer_id, rtt_ms } => (
            "PingRttMeasured",
            serde_json::json!({ "peerId": peer_id, "rttMs": rtt_ms }),
        ),
        P2pEvent::PingTimeout { peer_id } => {
            ("PingTimeout", serde_json::json!({ "peerId": peer_id }))
        }
        P2pEvent::StreamReady {
            peer_id,
            conn_id,
            stream_id,
            protocol_id,
            initiated_locally,
        } => (
            "StreamReady",
            serde_json::json!({
                "peerId": peer_id,
                "connId": conn_id,
                "streamId": stream_id,
                "protocolId": protocol_id,
                "initiatedLocally": initiated_locally,
            }),
        ),
        P2pEvent::StreamData {
            peer_id,
            conn_id,
            stream_id,
            data,
        } => (
            "StreamData",
            serde_json::json!({
                "peerId": peer_id,
                "connId": conn_id,
                "streamId": stream_id,
                "data": data,
            }),
        ),
        P2pEvent::StreamRemoteWriteClosed {
            peer_id,
            conn_id,
            stream_id,
        } => (
            "StreamRemoteWriteClosed",
            serde_json::json!({
                "peerId": peer_id,
                "connId": conn_id,
                "streamId": stream_id,
            }),
        ),
        P2pEvent::StreamClosed {
            peer_id,
            conn_id,
            stream_id,
        } => (
            "StreamClosed",
            serde_json::json!({
                "peerId": peer_id,
                "connId": conn_id,
                "streamId": stream_id,
            }),
        ),
        P2pEvent::EndpointError {
            kind,
            peer_id,
            conn_id,
            stream_id,
            detail,
        } => (
            "EndpointError",
            serde_json::json!({
                "kind": endpoint_error_value(kind),
                "peerId": peer_id,
                "connId": conn_id,
                "streamId": stream_id,
                "detail": detail,
            }),
        ),
        P2pEvent::ReachabilityChanged {
            previous,
            current,
            confirmed_addrs,
        } => (
            "ReachabilityChanged",
            serde_json::json!({
                "previous": reachability_value(previous),
                "current": reachability_value(current),
                "confirmedAddrs": confirmed_addrs,
            }),
        ),
        P2pEvent::PublicAddressesChanged { addrs } => (
            "PublicAddressesChanged",
            serde_json::json!({ "addrs": addrs }),
        ),
        P2pEvent::RelayReserved {
            relay_peer_id,
            expires_unix_secs,
        } => (
            "RelayReserved",
            serde_json::json!({
                "relayPeerId": relay_peer_id,
                "expiresUnixSecs": expires_unix_secs,
            }),
        ),
        P2pEvent::RelayReservationLost { relay_peer_id } => (
            "RelayReservationLost",
            serde_json::json!({ "relayPeerId": relay_peer_id }),
        ),
        P2pEvent::PathEstablished {
            connect_id,
            peer_id,
            path,
        } => (
            "PathEstablished",
            serde_json::json!({
                "connectId": connect_id,
                "peerId": peer_id,
                "path": path_value(path),
            }),
        ),
        P2pEvent::InboundPathEstablished { peer_id, path } => (
            "InboundPathEstablished",
            serde_json::json!({ "peerId": peer_id, "path": path_value(path) }),
        ),
        P2pEvent::PathUpgraded {
            connect_id,
            peer_id,
            from,
            to,
        } => (
            "PathUpgraded",
            serde_json::json!({
                "connectId": connect_id,
                "peerId": peer_id,
                "from": path_value(from),
                "to": path_value(to),
            }),
        ),
        P2pEvent::HolePunchFailed {
            connect_id,
            attempt,
            reason,
        } => (
            "HolePunchFailed",
            serde_json::json!({
                "connectId": connect_id,
                "attempt": attempt,
                "reason": reason,
            }),
        ),
        P2pEvent::FellBackToRelay {
            connect_id,
            peer_id,
        } => (
            "FellBackToRelay",
            serde_json::json!({ "connectId": connect_id, "peerId": peer_id }),
        ),
        P2pEvent::ConnectFailed {
            connect_id,
            peer_id,
            kind,
            detail,
        } => (
            "ConnectFailed",
            serde_json::json!({
                "connectId": connect_id,
                "peerId": peer_id,
                "kind": nat_error_value(kind),
                "detail": detail,
            }),
        ),
        P2pEvent::InboundDirectUpgrade { peer_id } => (
            "InboundDirectUpgrade",
            serde_json::json!({ "peerId": peer_id }),
        ),
        P2pEvent::Message {
            from_peer_id,
            topics,
            data,
            seqno,
            signed,
        } => (
            "Message",
            serde_json::json!({
                "fromPeerId": from_peer_id,
                "topics": topics,
                "data": data,
                "seqno": seqno,
                "signed": signed,
            }),
        ),
        P2pEvent::PeerSubscribed { peer_id, topic } => (
            "PeerSubscribed",
            serde_json::json!({ "peerId": peer_id, "topic": topic }),
        ),
        P2pEvent::PeerUnsubscribed { peer_id, topic } => (
            "PeerUnsubscribed",
            serde_json::json!({ "peerId": peer_id, "topic": topic }),
        ),
        P2pEvent::PubsubOutboundFailure { peer_id, reason } => (
            "PubsubOutboundFailure",
            serde_json::json!({ "peerId": peer_id, "reason": reason }),
        ),
        P2pEvent::PubsubProtocolViolation { peer_id, reason } => (
            "PubsubProtocolViolation",
            serde_json::json!({ "peerId": peer_id, "reason": reason }),
        ),
        P2pEvent::PeerDiscovered {
            peer_id,
            addrs,
            source,
        } => (
            "PeerDiscovered",
            serde_json::json!({
                "peerId": peer_id,
                "addrs": addrs,
                "source": discovery_source_value(source),
            }),
        ),
        P2pEvent::PeerUpdated {
            peer_id,
            addrs,
            source,
        } => (
            "PeerUpdated",
            serde_json::json!({
                "peerId": peer_id,
                "addrs": addrs,
                "source": discovery_source_value(source),
            }),
        ),
        P2pEvent::PeerExpired { peer_id } => {
            ("PeerExpired", serde_json::json!({ "peerId": peer_id }))
        }
        P2pEvent::DiscoveryDialFailed { peer_id, reason } => (
            "DiscoveryDialFailed",
            serde_json::json!({ "peerId": peer_id, "reason": reason }),
        ),
        P2pEvent::DiscoveryProtocolViolation {
            peer_id,
            source,
            reason,
            suppressed,
        } => (
            "DiscoveryProtocolViolation",
            serde_json::json!({
                "peerId": peer_id,
                "source": discovery_source_value(source),
                "reason": reason,
                "suppressed": suppressed,
            }),
        ),
    };
    serde_json::json!({ "tag": tag, "inner": inner })
}

fn identify_value(info: IdentifyInfo) -> serde_json::Value {
    serde_json::json!({
        "publicKey": info.public_key,
        "listenAddrs": info.listen_addrs,
        "protocols": info.protocols,
        "observedAddr": info.observed_addr,
        "protocolVersion": info.protocol_version,
        "agentVersion": info.agent_version,
    })
}

fn path_value(path: PathKind) -> serde_json::Value {
    match path {
        PathKind::DirectDialed => serde_json::json!({ "tag": "DirectDialed" }),
        PathKind::DirectPunched => serde_json::json!({ "tag": "DirectPunched" }),
        PathKind::Relayed { relay_peer_id } => serde_json::json!({
            "tag": "Relayed",
            "inner": { "relayPeerId": relay_peer_id },
        }),
    }
}

const fn reachability_value(value: Reachability) -> u32 {
    match value {
        Reachability::Unknown => 0,
        Reachability::Public => 1,
        Reachability::Private => 2,
    }
}

const fn discovery_source_value(value: DiscoverySource) -> u32 {
    match value {
        DiscoverySource::SignedBeacon => 0,
        DiscoverySource::Mdns => 1,
    }
}

const fn endpoint_error_value(value: EndpointErrorKind) -> u32 {
    match value {
        EndpointErrorKind::Transport => 0,
        EndpointErrorKind::Multistream => 1,
        EndpointErrorKind::Identify => 2,
        EndpointErrorKind::Ping => 3,
        EndpointErrorKind::IdentifyStreamRejected => 4,
        EndpointErrorKind::OpenStreamFailed => 5,
        EndpointErrorKind::UnsupportedProtocol => 6,
        EndpointErrorKind::Driver => 7,
    }
}

const fn nat_error_value(value: NatErrorKind) -> u32 {
    match value {
        NatErrorKind::NoPathAvailable => 0,
        NatErrorKind::Timeout => 1,
        NatErrorKind::DialFailed => 2,
        NatErrorKind::Protocol => 3,
        NatErrorKind::RelayRefused => 4,
    }
}

const fn driver_failure_value(value: DriverFailureKind) -> u32 {
    match value {
        DriverFailureKind::Transport => 0,
        DriverFailureKind::Swarm => 1,
        DriverFailureKind::Invariant => 2,
        DriverFailureKind::Panic => 3,
    }
}

fn bigint_u64(value: BigInt, name: &str) -> Result<u64> {
    let (_, value, lossless) = value.get_u64();
    if lossless {
        Ok(value)
    } else {
        Err(Error::from_reason(format!(
            "{name} must be an unsigned 64-bit integer"
        )))
    }
}
