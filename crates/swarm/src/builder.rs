//! Builder with sensible defaults for constructing a [`Swarm`].
//!
//! The builder removes per-field boilerplate (Identify metadata, ping
//! configuration) so the common case takes a keypair and returns a ready-to-use
//! swarm.

use minip2p_core::PeerId;
use minip2p_identify::{IDENTIFY_PROTOCOL_ID, IdentifyConfig};
use minip2p_identity::Ed25519Keypair;
use minip2p_ping::{PING_PROTOCOL_ID, PingConfig};
use minip2p_transport::Transport;

use crate::Swarm;

/// Default protocol-version string advertised to peers on Identify.
const DEFAULT_PROTOCOL_VERSION: &str = "minip2p/0.1.0";
/// Default agent-version string advertised to peers on Identify.
const DEFAULT_AGENT_VERSION: &str = "minip2p/0.1.0";

/// Fluent builder for [`Swarm`].
///
/// Defaults:
/// - `protocolVersion = "minip2p/0.1.0"`
/// - `agentVersion = "minip2p/0.1.0"`
/// - Supported protocols: `/ipfs/id/1.0.0` and `/ipfs/ping/1.0.0`
/// - Ping timeout: 10 seconds (the ping default)
///
/// Use the setter methods to override. Call [`SwarmBuilder::build`] to
/// construct the swarm over a caller-provided transport.
///
/// Note: Identify's `listen_addrs` is **not** set via the builder --
/// the swarm snapshots it from the transport's `local_addresses()` on
/// every `poll()` tick, so the advertised set always reflects what
/// the peer is actually bound to.
pub struct SwarmBuilder {
    protocol_version: String,
    agent_version: String,
    protocols: Vec<String>,
    public_key: Vec<u8>,
    /// Derived once from the keypair and cached so [`Swarm::local_peer_id`]
    /// is infallible.
    local_peer_id: PeerId,
    ping_config: PingConfig,
}

impl SwarmBuilder {
    /// Starts a builder from an Ed25519 host keypair.
    ///
    /// The keypair's public key is used to populate the Identify protobuf
    /// `publicKey` field so remote peers can derive this node's `PeerId`
    /// without a separate handshake.
    pub fn new(keypair: &Ed25519Keypair) -> Self {
        Self {
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_string(),
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            protocols: vec![
                IDENTIFY_PROTOCOL_ID.to_string(),
                PING_PROTOCOL_ID.to_string(),
            ],
            public_key: keypair.public_key().encode_protobuf(),
            local_peer_id: keypair.peer_id(),
            ping_config: PingConfig::default(),
        }
    }

    /// Overrides the `protocolVersion` string advertised on Identify.
    pub fn protocol_version(mut self, value: impl Into<String>) -> Self {
        self.protocol_version = value.into();
        self
    }

    /// Overrides the `agentVersion` string advertised on Identify.
    ///
    /// Typical format: `"my-app/1.2.3"`.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.agent_version = value.into();
        self
    }

    /// Advertises an additional protocol id on Identify.
    ///
    /// Built-in protocols (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0`) are always
    /// included; this method adds further protocols. If you also want the
    /// swarm to accept inbound streams for this protocol, call
    /// [`Swarm::add_user_protocol`] after building.
    pub fn advertise_protocol(mut self, protocol_id: impl Into<String>) -> Self {
        let id = protocol_id.into();
        if !self.protocols.iter().any(|p| p == &id) {
            self.protocols.push(id);
        }
        self
    }

    /// Overrides the ping configuration (timeout, etc.).
    pub fn ping_config(mut self, config: PingConfig) -> Self {
        self.ping_config = config;
        self
    }

    /// Consumes the builder and returns a ready-to-use [`Swarm`] over the
    /// given transport.
    pub fn build<T: Transport>(self, transport: T) -> Swarm<T> {
        let identify = IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        };
        Swarm::new(transport, identify, self.ping_config, self.local_peer_id)
    }

    /// Returns the underlying [`IdentifyConfig`] assembled from the builder.
    ///
    /// Primarily useful for callers that want to construct the transport
    /// separately but keep the same Identify defaults.
    pub fn into_identify_config(self) -> IdentifyConfig {
        IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        }
    }
}
