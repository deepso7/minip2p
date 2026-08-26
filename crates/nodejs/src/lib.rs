//! Thin napi-rs shell over the binding-agnostic FFI core.

#![warn(missing_docs)]

use std::sync::Arc;

use minip2p_ffi_core::{
    EndpointConfig, EventDoorbell, P2pEndpoint, PubsubRouter, TransportOptions,
};
use napi::bindgen_prelude::Uint8Array;
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
            discovery: None,
            mdns: None,
        })
    }
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
