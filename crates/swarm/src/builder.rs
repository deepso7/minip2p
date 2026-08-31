//! Builder with sensible defaults for constructing a [`SwarmRuntime`].
//!
//! The builder removes per-field boilerplate (Identify metadata, ping
//! configuration) so the common case takes a keypair and returns a ready-to-use
//! swarm.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use minip2p_core::PeerId;
use minip2p_identify::{IDENTIFY_PROTOCOL_ID, IdentifyConfig};
use minip2p_identity::Ed25519Keypair;
use minip2p_ping::{PING_PROTOCOL_ID, PingConfig};
use minip2p_transport::Transport;

use minip2p_platform::EntropySource;

#[cfg(feature = "std")]
use crate::Swarm;
use crate::{SwarmError, SwarmRuntime};

/// Default protocol-version string advertised to peers on Identify.
const DEFAULT_PROTOCOL_VERSION: &str = "minip2p/0.1.0";
/// Default agent-version string advertised to peers on Identify.
const DEFAULT_AGENT_VERSION: &str = "minip2p/0.1.0";

/// Fluent builder for the portable [`SwarmRuntime`] and the std blocking
/// `Swarm` wrapper.
///
/// Defaults:
/// - `protocolVersion = "minip2p/0.1.0"`
/// - `agentVersion = "minip2p/0.1.0"`
/// - Supported protocols: `/ipfs/id/1.0.0` and `/ipfs/ping/1.0.0`
/// - Ping timeout: 10 seconds (the ping default)
///
/// Use the setter methods to override. Call
/// [`SwarmBuilder::build_runtime`] with a caller-provided transport and
/// entropy source. Under `std`, `SwarmBuilder::build` constructs the
/// blocking convenience wrapper instead.
///
/// Note: Identify's `listen_addrs` is **not** set via the builder --
/// the swarm snapshots it from the transport's `local_addresses()` on
/// every `poll()` tick, so the advertised set always reflects what
/// the peer is actually bound to.
pub struct SwarmBuilder {
    protocol_version: String,
    agent_version: String,
    protocols: Vec<String>,
    user_protocols: Vec<String>,
    public_key: Vec<u8>,
    /// Derived once from the keypair and cached so the runtime's
    /// `local_peer_id` accessor is infallible.
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
            user_protocols: Vec::new(),
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

    /// Registers an application protocol for both Identify advertisement and
    /// inbound/outbound multistream-select negotiation.
    ///
    /// Built-in protocols (`/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0`) are always
    /// included and reserved for the swarm's own handlers; registering one
    /// here makes [`SwarmBuilder::build_runtime`] (or the std-only
    /// `SwarmBuilder::build`) fail with [`SwarmError::ReservedProtocol`].
    /// Equivalent to calling [`SwarmRuntime::add_protocol`] after building.
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        let id = protocol_id.into();
        if !self.protocols.iter().any(|protocol| protocol == &id) {
            self.protocols.push(id.clone());
        }
        if !self.user_protocols.iter().any(|protocol| protocol == &id) {
            self.user_protocols.push(id);
        }
        self
    }

    /// Overrides the ping configuration (timeout, etc.).
    pub fn ping_config(mut self, config: PingConfig) -> Self {
        self.ping_config = config;
        self
    }

    /// Consumes the builder and returns a portable caller-driven runtime.
    ///
    /// The caller supplies entropy explicitly, keeping construction usable in
    /// `no_std + alloc` environments without assuming an operating-system RNG.
    pub fn build_runtime<T, E>(
        self,
        transport: T,
        entropy: E,
    ) -> Result<SwarmRuntime<T, E>, SwarmError>
    where
        T: Transport,
        E: EntropySource,
    {
        let user_protocols = self.user_protocols;
        let identify = IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        };
        let mut runtime = SwarmRuntime::new(
            transport,
            identify,
            self.ping_config,
            self.local_peer_id,
            entropy,
        );
        register_user_protocols(&mut runtime, user_protocols)?;
        Ok(runtime)
    }

    /// Consumes the builder and returns a ready-to-use std [`Swarm`] over the
    /// given transport.
    ///
    /// Fails with [`SwarmError::ReservedProtocol`] if a built-in protocol id
    /// was registered via [`SwarmBuilder::protocol`].
    #[cfg(feature = "std")]
    pub fn build<T: Transport>(self, transport: T) -> Result<Swarm<T>, SwarmError> {
        let user_protocols = self.user_protocols;
        let identify = IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        };
        let mut swarm = Swarm::new(transport, identify, self.ping_config, self.local_peer_id);
        for protocol in user_protocols {
            swarm.core_mut().add_protocol(protocol)?;
        }
        Ok(swarm)
    }

    /// Returns the underlying [`IdentifyConfig`] assembled from the builder.
    #[cfg(test)]
    pub fn into_identify_config(self) -> IdentifyConfig {
        IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        }
    }
}

/// Registers the builder's user protocols on the freshly built swarm; the
/// core is the single validation point for reserved built-in ids.
fn register_user_protocols<T: Transport, E: EntropySource>(
    swarm: &mut SwarmRuntime<T, E>,
    user_protocols: Vec<String>,
) -> Result<(), SwarmError> {
    for protocol in user_protocols {
        swarm.core_mut().add_protocol(protocol)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DriverError, RESERVED_PROTOCOL_IDS};
    use minip2p_core::{Multiaddr, PeerAddr};
    use minip2p_platform::{EntropyError, Now};
    use minip2p_transport::{ConnectionId, StreamId, TransportError, TransportEvent};

    struct NoopTransport;

    struct ZeroEntropy;

    impl EntropySource for ZeroEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            output.fill(0);
            Ok(())
        }
    }

    impl Transport for NoopTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            Err(TransportError::Unsupported { operation: "dial" })
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            Err(TransportError::Unsupported {
                operation: "listen",
            })
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            Err(TransportError::Unsupported {
                operation: "open_stream",
            })
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "send_stream",
            })
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "close_stream_write",
            })
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "reset_stream",
            })
        }

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            Err(TransportError::Unsupported { operation: "close" })
        }

        fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(Vec::new())
        }
    }

    const PROTOCOL: &str = "/myapp/1.0.0";

    #[test]
    fn build_runtime_registers_protocol_for_stream_routing() {
        let keypair = Ed25519Keypair::generate();
        let peer_id = keypair.peer_id();
        let mut runtime = SwarmBuilder::new(&keypair)
            .protocol(PROTOCOL)
            .build_runtime(NoopTransport, ZeroEntropy)
            .expect("portable runtime configuration is valid");

        assert_eq!(runtime.local_peer_id(), &peer_id);
        let remote = Ed25519Keypair::generate().peer_id();
        assert!(matches!(
            runtime.open_stream(&remote, PROTOCOL, 0),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            runtime.open_stream(&remote, "/other/1.0.0", 0),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));
    }

    #[test]
    fn protocol_registers_for_identify_advertisement() {
        let keypair = Ed25519Keypair::generate();
        let identify = SwarmBuilder::new(&keypair)
            .protocol(PROTOCOL)
            .into_identify_config();
        assert!(identify.protocols.iter().any(|p| p == PROTOCOL));
        // Built-ins stay advertised alongside the user protocol.
        assert!(identify.protocols.iter().any(|p| p == IDENTIFY_PROTOCOL_ID));
        assert!(identify.protocols.iter().any(|p| p == PING_PROTOCOL_ID));
    }

    #[test]
    #[cfg(feature = "std")]
    fn std_build_registers_protocol_for_stream_routing() {
        let keypair = Ed25519Keypair::generate();
        let mut swarm = SwarmBuilder::new(&keypair)
            .protocol(PROTOCOL)
            .build(NoopTransport)
            .expect("user protocol id is not reserved");

        // A registered protocol fails with NotConnected (no such peer), not
        // ProtocolNotRegistered -- proving registration reached the core.
        let peer_id = Ed25519Keypair::generate().peer_id();
        assert!(matches!(
            swarm.open_stream(&peer_id, PROTOCOL),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            swarm.open_stream(&peer_id, "/other/1.0.0"),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));
    }

    #[test]
    fn build_runtime_rejects_reserved_protocol_ids() {
        for reserved in RESERVED_PROTOCOL_IDS {
            let keypair = Ed25519Keypair::generate();
            let error = SwarmBuilder::new(&keypair)
                .protocol(reserved)
                .build_runtime(NoopTransport, ZeroEntropy)
                .err()
                .expect("reserved ids must fail the build");
            assert_eq!(
                error,
                SwarmError::ReservedProtocol {
                    protocol_id: reserved.into()
                }
            );
        }
    }

    #[test]
    fn runtime_add_protocol_rejects_reserved_protocol_ids_after_build() {
        let keypair = Ed25519Keypair::generate();
        let mut swarm = SwarmBuilder::new(&keypair)
            .build_runtime(NoopTransport, ZeroEntropy)
            .expect("no user protocols registered");
        let error = swarm
            .add_protocol(IDENTIFY_PROTOCOL_ID)
            .expect_err("reserved ids must be rejected");
        assert!(matches!(
            error,
            DriverError::Swarm(SwarmError::ReservedProtocol { .. })
        ));
    }
}
