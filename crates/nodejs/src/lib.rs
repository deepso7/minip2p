//! Thin napi-rs shell over the binding-agnostic FFI core.

#![warn(missing_docs)]

use std::sync::Arc;

use minip2p_ffi_core::{
    ConnectTarget, DiscoveryOptions, EndpointConfig, EventDoorbell, FfiError, MdnsOptions,
    P2pEndpoint,
};
use napi::bindgen_prelude::{BigInt, Either, JsObjectValue, JsValue, Uint8Array};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, Error, Result, Status, Unknown};
use napi_derive::napi;

// napi-rs's default MaxQueueSize of 0 is intentionally unbounded. The FFI core
// coalesces doorbells, so this wakeup must never block the network driver.
type DoorbellFunction = ThreadsafeFunction<(), (), (), Status, false>;

struct NodeDoorbell(Arc<DoorbellFunction>);

impl EventDoorbell for NodeDoorbell {
    fn on_events_ready(&self) {
        self.0.call((), ThreadsafeFunctionCallMode::NonBlocking);
    }
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
    /// Listen multiaddresses, or the QUIC dual-stack defaults when absent.
    pub listen: Option<Vec<String>>,
    /// Whether all outbound paths must remain relayed.
    pub force_relay: bool,
    /// Whether unsigned pubsub messages are accepted.
    pub allow_unsigned: bool,
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
        Ok(Self {
            agent_version: config.agent_version,
            relays: config.relays,
            autonat_servers: config.autonat_servers,
            listen: config.listen,
            force_relay: config.force_relay,
            allow_unsigned: config.allow_unsigned,
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

/// A native minip2p endpoint owned by Node.js.
#[napi]
pub struct NodeEndpoint(Arc<P2pEndpoint>);

#[napi]
impl NodeEndpoint {
    /// Binds a native endpoint without starting its driver.
    #[napi(constructor)]
    pub fn new(env: Env, secret_key: Uint8Array, mut config: NodeEndpointConfig) -> Result<Self> {
        if config.agent_version.is_none() {
            config.agent_version = Some(format!("minip2p-node/{}", env!("CARGO_PKG_VERSION")));
        }
        P2pEndpoint::new(secret_key.to_vec(), config.try_into()?)
            .map(Self)
            .map_err(|error| native_error(&env, error))
    }

    /// Starts the detached driver with a strong event-loop doorbell.
    #[napi(ts_args_type = "doorbell: () => void")]
    pub fn start(&self, env: Env, doorbell: Arc<DoorbellFunction>) -> Result<()> {
        self.0
            .start(Arc::new(NodeDoorbell(doorbell)))
            .map_err(|error| native_error(&env, error))
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
    #[napi(ts_return_type = "Array<NativeEvent>")]
    pub fn drain_events(&self, env: Env, limit: u32) -> Result<Vec<Unknown<'static>>> {
        self.0
            .drain_events(limit)
            .iter()
            .map(|event| env.to_js_value(event))
            .collect()
    }

    /// Returns connected peer IDs.
    #[napi]
    pub fn connected_peers(&self, env: Env) -> Result<Vec<String>> {
        self.0
            .connected_peers()
            .map_err(|error| native_error(&env, error))
    }

    /// Returns whether Identify completed for a peer.
    #[napi]
    pub fn is_peer_ready(&self, env: Env, peer_id: String) -> Result<bool> {
        self.0
            .is_peer_ready(peer_id)
            .map_err(|error| native_error(&env, error))
    }

    /// Returns the latest Identify snapshot.
    #[napi(ts_return_type = "NativeIdentifyInfo | null")]
    pub fn peer_info(&self, env: Env, peer_id: String) -> Result<Unknown<'static>> {
        js_value(&env, self.0.peer_info(peer_id))
    }

    /// Accepted for compatibility; has no effect, since the driver sleeps until the endpoint's next deadline.
    #[napi]
    pub fn set_active(&self, active: bool) {
        self.0.set_active(active);
    }

    /// Subscribes to a pubsub topic.
    #[napi]
    pub fn subscribe(&self, env: Env, topic: String) -> Result<bool> {
        self.0
            .subscribe(topic)
            .map_err(|error| native_error(&env, error))
    }

    /// Unsubscribes from a pubsub topic.
    #[napi]
    pub fn unsubscribe(&self, env: Env, topic: String) -> Result<bool> {
        self.0
            .unsubscribe(topic)
            .map_err(|error| native_error(&env, error))
    }

    /// Publishes one pubsub payload.
    #[napi]
    pub fn publish(&self, env: Env, topic: String, data: Uint8Array) -> Result<()> {
        self.0
            .publish(topic, data.to_vec())
            .map_err(|error| native_error(&env, error))
    }

    /// Starts one ping operation.
    #[napi]
    pub fn ping(&self, env: Env, peer_id: String) -> Result<()> {
        self.0
            .ping(peer_id)
            .map_err(|error| native_error(&env, error))
    }

    /// Registers an application protocol.
    #[napi]
    pub fn add_protocol(&self, env: Env, protocol_id: String) -> Result<()> {
        self.0
            .add_protocol(protocol_id)
            .map_err(|error| native_error(&env, error))
    }

    /// Starts opening an application stream.
    #[napi(ts_return_type = "NativeOpenStream")]
    pub fn open_stream(
        &self,
        env: Env,
        peer_id: String,
        protocol_id: String,
    ) -> Result<Unknown<'static>> {
        js_value(&env, self.0.open_stream(peer_id, protocol_id))
    }

    /// Sends bytes on an application stream, named by its connection and
    /// stream ids. Returns `true` once every byte is accepted, or `false`
    /// when the rest is held: `StreamWriteAccepted` follows once it is
    /// accepted, unless the write side ends first (`StreamWriteStopped`,
    /// `StreamClosed`, a reset, or the connection closing or being replaced),
    /// which drops the tail.
    #[napi]
    pub fn send_stream(
        &self,
        env: Env,
        peer_id: String,
        conn_id: BigInt,
        stream_id: BigInt,
        data: Uint8Array,
    ) -> Result<bool> {
        self.0
            .send_stream(
                peer_id,
                bigint_u64(conn_id, "connId")?,
                bigint_u64(stream_id, "streamId")?,
                data.to_vec(),
            )
            .map_err(|error| native_error(&env, error))
    }

    /// Half-closes the local stream write side.
    #[napi]
    pub fn close_stream_write(
        &self,
        env: Env,
        peer_id: String,
        conn_id: BigInt,
        stream_id: BigInt,
    ) -> Result<()> {
        self.0
            .close_stream_write(
                peer_id,
                bigint_u64(conn_id, "connId")?,
                bigint_u64(stream_id, "streamId")?,
            )
            .map_err(|error| native_error(&env, error))
    }

    /// Resets an application stream.
    #[napi]
    pub fn reset_stream(
        &self,
        env: Env,
        peer_id: String,
        conn_id: BigInt,
        stream_id: BigInt,
    ) -> Result<()> {
        self.0
            .reset_stream(
                peer_id,
                bigint_u64(conn_id, "connId")?,
                bigint_u64(stream_id, "streamId")?,
            )
            .map_err(|error| native_error(&env, error))
    }

    /// Resets and relinquishes an application stream.
    #[napi]
    pub fn abandon_stream(
        &self,
        env: Env,
        peer_id: String,
        conn_id: BigInt,
        stream_id: BigInt,
    ) -> Result<()> {
        self.0
            .abandon_stream(
                peer_id,
                bigint_u64(conn_id, "connId")?,
                bigint_u64(stream_id, "streamId")?,
            )
            .map_err(|error| native_error(&env, error))
    }

    /// Acknowledges `bytes` of a stream's received data as consumed,
    /// letting its sender continue. Every registered protocol needs this.
    #[napi]
    pub fn stream_consumed(
        &self,
        env: Env,
        conn_id: BigInt,
        stream_id: BigInt,
        bytes: u32,
    ) -> Result<()> {
        self.0
            .stream_consumed(
                bigint_u64(conn_id, "connId")?,
                bigint_u64(stream_id, "streamId")?,
                u64::from(bytes),
            )
            .map_err(|error| native_error(&env, error))
    }

    /// Starts one Connection attempt: a peer ID string, or an array of
    /// complete peer addresses naming one peer. Returns the Connect ID.
    #[napi]
    pub fn connect(&self, env: Env, target: Either<String, Vec<String>>) -> Result<BigInt> {
        let target = match target {
            Either::A(peer_id) => ConnectTarget::Peer { peer_id },
            Either::B(addresses) => ConnectTarget::Addresses { addresses },
        };
        self.0
            .connect(target)
            .map(BigInt::from)
            .map_err(|error| native_error(&env, error))
    }

    /// Cancels a connection attempt.
    #[napi]
    pub fn cancel_connect(&self, env: Env, id: BigInt) -> Result<()> {
        self.0
            .cancel_connect(bigint_u64(id, "connectId")?)
            .map_err(|error| native_error(&env, error))
    }

    /// Disconnects one peer.
    #[napi]
    pub fn disconnect(&self, env: Env, peer_id: String) -> Result<()> {
        self.0
            .disconnect(peer_id)
            .map_err(|error| native_error(&env, error))
    }

    /// Returns the current path to a peer.
    #[napi(ts_return_type = "NativePathKind | null")]
    pub fn path(&self, env: Env, peer_id: String) -> Result<Unknown<'static>> {
        js_value(&env, self.0.path(peer_id))
    }

    /// Returns the transport connection selected for a peer.
    #[napi(ts_return_type = "NativeConnectionInfo | null")]
    pub fn connection_info(&self, env: Env, peer_id: String) -> Result<Unknown<'static>> {
        js_value(&env, self.0.connection_info(peer_id))
    }

    /// Returns the discovery address book.
    #[napi(ts_return_type = "Array<NativeKnownPeerInfo>")]
    pub fn known_peers(&self, env: Env) -> Result<Unknown<'static>> {
        js_value(&env, self.0.known_peers())
    }

    /// Returns the discovery clock.
    #[napi]
    pub fn discovery_now_ms(&self, env: Env) -> Result<Option<BigInt>> {
        self.0
            .discovery_now_ms()
            .map(|value| value.map(BigInt::from))
            .map_err(|error| native_error(&env, error))
    }

    /// Returns the current reachability verdict.
    #[napi(ts_return_type = "Reachability")]
    pub fn reachability(&self, env: Env) -> Result<Unknown<'static>> {
        js_value(&env, self.0.reachability())
    }

    /// Returns the active relay reservation.
    #[napi(ts_return_type = "NativeRelayReservationInfo | null")]
    pub fn active_reservation(&self, env: Env) -> Result<Unknown<'static>> {
        js_value(&env, self.0.active_reservation())
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
pub fn peer_id_from_secret_key(env: Env, secret_key: Uint8Array) -> Result<String> {
    minip2p_ffi_core::peer_id_from_secret_key(secret_key.to_vec())
        .map_err(|error| native_error(&env, error))
}

/// Builds a circuit address through a direct relay address.
#[napi]
pub fn circuit_address(env: Env, relay_address: String, peer_id: String) -> Result<String> {
    minip2p_ffi_core::circuit_address(relay_address, peer_id)
        .map_err(|error| native_error(&env, error))
}

/// Converts an `FfiError` into a JS `Error` that keeps the formatted message
/// and adds a stable `code` (the variant name) plus the variant's `detail`,
/// when it has one. The TypeScript adapter maps `code` to typed SDK errors.
fn native_error(env: &Env, error: FfiError) -> Error {
    let (code, detail) = match &error {
        FfiError::AlreadyStarted => ("AlreadyStarted", None),
        FfiError::Stopped => ("Stopped", None),
        FfiError::InvalidConfig { detail } => ("InvalidConfig", Some(detail)),
        FfiError::InvalidKey { detail } => ("InvalidKey", Some(detail)),
        FfiError::InvalidPeerId { detail } => ("InvalidPeerId", Some(detail)),
        FfiError::InvalidAddress { detail } => ("InvalidAddress", Some(detail)),
        FfiError::InvalidTopic { detail } => ("InvalidTopic", Some(detail)),
        FfiError::NotPermitted { detail } => ("NotPermitted", Some(detail)),
        FfiError::Backpressure => ("Backpressure", None),
        FfiError::MessageTooLarge => ("MessageTooLarge", None),
        FfiError::Transport { detail } => ("Transport", Some(detail)),
        FfiError::InvalidState { detail } => ("InvalidState", Some(detail)),
        FfiError::Internal { detail } => ("Internal", Some(detail)),
    };
    let tagged = || -> Result<Error> {
        let mut js_error = env.create_error(Error::from_reason(error.to_string()))?;
        js_error.set_named_property("code", code)?;
        if let Some(detail) = detail {
            js_error.set_named_property("detail", detail.as_str())?;
        }
        Ok(Error::from(js_error.to_unknown()))
    };
    // Building the JS value only fails if the engine is unusable; the message
    // alone is still the most useful thing to throw then.
    tagged().unwrap_or_else(|_| Error::from_reason(error.to_string()))
}

/// Converts a core result into its JS value through the serde shape that
/// `minip2p-ffi-core` defines behind its `serde` feature; `None` becomes `null`.
fn js_value<T: serde::Serialize>(
    env: &Env,
    value: core::result::Result<T, FfiError>,
) -> Result<Unknown<'static>> {
    value
        .map_err(|error| native_error(env, error))
        .and_then(|value| env.to_js_value(&value))
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
