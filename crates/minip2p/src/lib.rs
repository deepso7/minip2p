//! App-facing facade for minip2p.
//!
//! This crate is the ergonomic std entrypoint. It composes the lower-level
//! crates without hiding them: protocol crates and `SwarmCore` remain the
//! Sans-I/O / `no_std + alloc` surface, while [`Endpoint`] gives applications a
//! small batteries-included API for identity, QUIC, listen/dial, ping, and
//! event polling.

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
pub use minip2p_identify::IdentifyMessage;
pub use minip2p_identity::Ed25519Keypair;
pub use minip2p_quic::QuicLimits;
use minip2p_quic::{QuicEndpoint, QuicNodeConfig};
pub use minip2p_swarm::{
    Deadline, DriverError as Error, RESERVED_PROTOCOL_IDS, SwarmError, SwarmEvent as Event,
};
use minip2p_swarm::{Swarm, SwarmBuilder};
pub use minip2p_transport::{ConnectionId, StreamId, TransportError};

const DEFAULT_AGENT_VERSION: &str = "minip2p/0.1.0";

/// App-facing minip2p endpoint over the default QUIC transport.
///
/// `Endpoint` owns identity, transport, and the std swarm driver. Advanced
/// users can still borrow the underlying [`Swarm`] with [`Endpoint::swarm`]
/// and [`Endpoint::swarm_mut`].
pub struct Endpoint {
    swarm: Swarm<QuicEndpoint>,
}

impl Endpoint {
    /// Starts building an endpoint.
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Returns this node's peer id.
    pub fn peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Starts listening on the transport's first already-bound address.
    pub fn listen(&mut self) -> Result<PeerAddr, Error> {
        self.swarm.listen_on_bound_addr()
    }

    /// Starts listening on all transport-bound addresses.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, Error> {
        self.swarm.listen_on_bound_addrs()
    }

    /// Dials a remote peer on every applicable local address family.
    ///
    /// For dual-stack endpoints, `/dns` targets are resolved and both IPv4 and
    /// IPv6 dials are started when both families are available. Use
    /// [`Endpoint::dial_ip4`] or [`Endpoint::dial_ip6`] to force one family.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<Vec<ConnectionId>, Error> {
        Ok(self.swarm.transport_mut().dial_all(addr)?)
    }

    /// Dials a remote peer using IPv4.
    pub fn dial_ip4(&mut self, addr: &PeerAddr) -> Result<ConnectionId, Error> {
        Ok(self.swarm.transport_mut().dial_ip4(addr)?)
    }

    /// Dials a remote peer using IPv6.
    pub fn dial_ip6(&mut self, addr: &PeerAddr) -> Result<ConnectionId, Error> {
        Ok(self.swarm.transport_mut().dial_ip6(addr)?)
    }

    /// Sends a ping to `peer_id`.
    ///
    /// The RTT is emitted later as [`Event::PingRttMeasured`].
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), Error> {
        self.swarm.ping(peer_id)
    }

    /// Closes the active connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), Error> {
        self.swarm.disconnect(peer_id)
    }

    /// Returns peers with an established connection.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers()
    }

    /// Returns whether Identify has completed for `peer_id`.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_peer_ready(peer_id)
    }

    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.swarm.peer_info(peer_id)
    }

    /// Registers an application protocol for inbound and outbound negotiation.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]; the endpoint's own identify and
    /// ping handlers already own them.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), Error> {
        self.swarm.add_protocol(protocol_id)
    }

    /// Opens an application stream after negotiating `protocol_id`.
    pub fn open_stream(&mut self, peer_id: &PeerId, protocol_id: &str) -> Result<StreamId, Error> {
        self.swarm.open_stream(peer_id, protocol_id)
    }

    /// Sends bytes on a negotiated application stream.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), Error> {
        self.swarm.send_stream(peer_id, stream_id, data.into())
    }

    /// Half-closes the local write side of an application stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        self.swarm.close_stream_write(peer_id, stream_id)
    }

    /// Resets an application stream.
    pub fn reset_stream(&mut self, peer_id: &PeerId, stream_id: StreamId) -> Result<(), Error> {
        self.swarm.reset_stream(peer_id, stream_id)
    }

    /// Polls the endpoint once and returns all currently available events.
    pub fn poll(&mut self) -> Result<Vec<Event>, Error> {
        self.swarm.poll()
    }

    /// Returns the next event, waiting internally until `deadline`.
    ///
    /// `deadline` accepts an [`std::time::Instant`], a relative
    /// [`std::time::Duration`], or [`Deadline::NEVER`] to wait indefinitely.
    pub fn next_event(&mut self, deadline: impl Into<Deadline>) -> Result<Option<Event>, Error> {
        self.swarm.poll_next(deadline)
    }

    /// Waits until a peer is ready or `deadline` expires.
    pub fn wait_peer_ready(
        &mut self,
        peer_id: &PeerId,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<Event>, Error> {
        self.swarm.run_until(
            deadline,
            |event| matches!(event, Event::PeerReady { peer_id: ready, .. } if ready == peer_id),
        )
    }

    /// Waits until a ping RTT for `peer_id` is measured or `deadline` expires.
    pub fn wait_ping_rtt(
        &mut self,
        peer_id: &PeerId,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<u64>, Error> {
        let event = self.swarm.run_until(deadline, |event| {
            matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
        })?;
        Ok(match event {
            Some(Event::PingRttMeasured { rtt_ms, .. }) => Some(rtt_ms),
            _ => None,
        })
    }

    /// Borrows the underlying swarm.
    pub fn swarm(&self) -> &Swarm<QuicEndpoint> {
        &self.swarm
    }

    /// Mutably borrows the underlying swarm.
    pub fn swarm_mut(&mut self) -> &mut Swarm<QuicEndpoint> {
        &mut self.swarm
    }

    /// Decomposes this endpoint into the underlying swarm.
    pub fn into_swarm(self) -> Swarm<QuicEndpoint> {
        self.swarm
    }
}

/// Builder for [`Endpoint`].
pub struct EndpointBuilder {
    keypair: Option<Ed25519Keypair>,
    agent_version: String,
    quic_limits: QuicLimits,
    protocols: Vec<String>,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            keypair: None,
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            quic_limits: QuicLimits::default(),
            protocols: Vec::new(),
        }
    }
}

impl EndpointBuilder {
    /// Uses an explicit host keypair.
    pub fn identity(mut self, keypair: Ed25519Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Overrides the Identify `agentVersion` string.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.agent_version = value.into();
        self
    }

    /// Overrides QUIC connection, stream, queue, and timeout limits.
    pub fn quic_limits(mut self, limits: QuicLimits) -> Self {
        self.quic_limits = limits;
        self
    }

    /// Registers an application protocol before the endpoint starts.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are reserved; registering
    /// one makes the `bind_quic*` build step fail with
    /// [`SwarmError::ReservedProtocol`].
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        let id = protocol_id.into();
        if !self.protocols.iter().any(|protocol| protocol == &id) {
            self.protocols.push(id);
        }
        self
    }

    /// Builds an endpoint with a QUIC transport bound to `bind_addr`.
    pub fn bind_quic(self, bind_addr: impl AsRef<str>) -> Result<Endpoint, Error> {
        let (keypair, agent_version, limits, protocols) = self.into_parts()?;
        let config = QuicNodeConfig::new(keypair.clone()).with_limits(limits);
        let transport = QuicEndpoint::bind(config, bind_addr.as_ref())?;
        build_endpoint(keypair, agent_version, protocols, transport)
    }

    /// Builds an endpoint with a QUIC transport bound to a QUIC multiaddr.
    pub fn bind_quic_multiaddr(self, addr: &Multiaddr) -> Result<Endpoint, Error> {
        let (keypair, agent_version, limits, protocols) = self.into_parts()?;
        let config = QuicNodeConfig::new(keypair.clone()).with_limits(limits);
        let transport = QuicEndpoint::bind_multiaddr(config, addr)?;
        build_endpoint(keypair, agent_version, protocols, transport)
    }

    /// Builds an endpoint with separate IPv4 and IPv6 wildcard QUIC sockets.
    pub fn bind_quic_dual_stack(self) -> Result<Endpoint, Error> {
        let (keypair, agent_version, limits, protocols) = self.into_parts()?;
        let config = QuicNodeConfig::new(keypair.clone()).with_limits(limits);
        let transport = QuicEndpoint::dual_stack(config)?;
        build_endpoint(keypair, agent_version, protocols, transport)
    }

    /// Validates the static configuration and decomposes the builder.
    ///
    /// Reserved protocol ids are rejected here -- before any socket is
    /// bound -- so a configuration error can neither allocate resources
    /// nor be masked by a bind failure.
    fn into_parts(self) -> Result<(Ed25519Keypair, String, QuicLimits, Vec<String>), Error> {
        if let Some(protocol) = self
            .protocols
            .iter()
            .find(|protocol| RESERVED_PROTOCOL_IDS.contains(&protocol.as_str()))
        {
            return Err(SwarmError::ReservedProtocol {
                protocol_id: protocol.clone(),
            }
            .into());
        }
        Ok((
            self.keypair.unwrap_or_else(Ed25519Keypair::generate),
            self.agent_version,
            self.quic_limits,
            self.protocols,
        ))
    }
}

fn build_endpoint(
    keypair: Ed25519Keypair,
    agent_version: String,
    protocols: Vec<String>,
    transport: QuicEndpoint,
) -> Result<Endpoint, Error> {
    let mut builder = SwarmBuilder::new(&keypair).agent_version(agent_version);
    for protocol in protocols {
        builder = builder.protocol(protocol);
    }
    let swarm = builder.build(transport)?;
    Ok(Endpoint { swarm })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTOCOL: &str = "/myapp/1.0.0";

    #[test]
    fn builder_protocol_registers_for_stream_routing() {
        let mut endpoint = Endpoint::builder()
            .protocol(PROTOCOL)
            .bind_quic("127.0.0.1:0")
            .expect("bind loopback endpoint");

        // A registered protocol fails with NotConnected for an unknown
        // peer, not ProtocolNotRegistered -- proving the builder wired the
        // protocol into user-stream routing.
        let peer_id = Ed25519Keypair::generate().peer_id();
        assert!(matches!(
            endpoint.open_stream(&peer_id, PROTOCOL),
            Err(Error::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            endpoint.open_stream(&peer_id, "/other/1.0.0"),
            Err(Error::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));
    }

    #[test]
    fn builder_rejects_reserved_protocol_ids() {
        for reserved in RESERVED_PROTOCOL_IDS {
            let error = Endpoint::builder()
                .protocol(reserved)
                .bind_quic("127.0.0.1:0")
                .err()
                .expect("reserved ids must fail the build");
            assert!(matches!(
                error,
                Error::Swarm(SwarmError::ReservedProtocol { .. })
            ));
        }
    }

    #[test]
    fn builder_rejects_reserved_protocol_ids_before_binding() {
        // An unbindable address must not mask the configuration error:
        // validation happens before any socket is allocated.
        let error = Endpoint::builder()
            .protocol(RESERVED_PROTOCOL_IDS[0])
            .bind_quic("not-a-bindable-address")
            .err()
            .expect("reserved ids must fail the build");
        assert!(matches!(
            error,
            Error::Swarm(SwarmError::ReservedProtocol { .. })
        ));
    }

    #[test]
    fn add_protocol_rejects_reserved_protocol_ids() {
        let mut endpoint = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind loopback endpoint");
        let error = endpoint
            .add_protocol(RESERVED_PROTOCOL_IDS[0])
            .expect_err("reserved ids must be rejected");
        assert!(matches!(
            error,
            Error::Swarm(SwarmError::ReservedProtocol { .. })
        ));
        endpoint
            .add_protocol(PROTOCOL)
            .expect("application ids must be accepted");
    }
}
