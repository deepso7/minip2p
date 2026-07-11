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
use std::sync::Arc;

use crate::{Clock, Swarm, SwarmError};

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
    user_protocols: Vec<String>,
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
    /// here makes [`SwarmBuilder::build`] fail with
    /// [`SwarmError::ReservedProtocol`]. Equivalent to calling
    /// [`Swarm::add_protocol`] after building.
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

    /// Consumes the builder and returns a ready-to-use [`Swarm`] over the
    /// given transport.
    ///
    /// Fails with [`SwarmError::ReservedProtocol`] if a built-in protocol id
    /// was registered via [`SwarmBuilder::protocol`].
    pub fn build<T: Transport>(self, transport: T) -> Result<Swarm<T>, SwarmError> {
        let user_protocols = self.user_protocols;
        let identify = IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        };
        let mut swarm = Swarm::new(transport, identify, self.ping_config, self.local_peer_id);
        register_user_protocols(&mut swarm, user_protocols)?;
        Ok(swarm)
    }

    /// Consumes the builder and returns a swarm using an injected clock.
    ///
    /// Intended for deterministic tests of timeout behavior. Normal callers
    /// should use [`SwarmBuilder::build`]. Fails with
    /// [`SwarmError::ReservedProtocol`] if a built-in protocol id was
    /// registered via [`SwarmBuilder::protocol`].
    pub fn build_with_clock<T: Transport>(
        self,
        transport: T,
        clock: Arc<dyn Clock>,
    ) -> Result<Swarm<T>, SwarmError> {
        let user_protocols = self.user_protocols;
        let identify = IdentifyConfig {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            protocols: self.protocols,
            public_key: self.public_key,
        };
        let mut swarm = Swarm::with_clock(
            transport,
            identify,
            self.ping_config,
            self.local_peer_id,
            clock,
        );
        register_user_protocols(&mut swarm, user_protocols)?;
        Ok(swarm)
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

/// Registers the builder's user protocols on the freshly built swarm; the
/// core is the single validation point for reserved built-in ids.
fn register_user_protocols<T: Transport>(
    swarm: &mut Swarm<T>,
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
    use minip2p_transport::{ConnectionId, StreamId, TransportError, TransportEvent};

    struct NoopTransport;

    impl Transport for NoopTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            unreachable!()
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(Vec::new())
        }
    }

    const PROTOCOL: &str = "/myapp/1.0.0";

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
    fn protocol_registers_for_user_stream_routing() {
        let keypair = Ed25519Keypair::generate();
        let mut swarm = SwarmBuilder::new(&keypair)
            .protocol(PROTOCOL)
            .build(NoopTransport)
            .expect("user protocol id is not reserved");

        // A registered protocol fails with NotConnected (no such peer), not
        // ProtocolNotRegistered -- proving registration reached the core.
        let peer_id = Ed25519Keypair::generate().peer_id();
        assert!(matches!(
            swarm.open_user_stream(&peer_id, PROTOCOL),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            swarm.open_user_stream(&peer_id, "/other/1.0.0"),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));
    }

    #[test]
    fn build_rejects_reserved_protocol_ids() {
        for reserved in RESERVED_PROTOCOL_IDS {
            let keypair = Ed25519Keypair::generate();
            let error = SwarmBuilder::new(&keypair)
                .protocol(reserved)
                .build(NoopTransport)
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
    fn add_protocol_rejects_reserved_protocol_ids_after_build() {
        let keypair = Ed25519Keypair::generate();
        let mut swarm = SwarmBuilder::new(&keypair)
            .build(NoopTransport)
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
