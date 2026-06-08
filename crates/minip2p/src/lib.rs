//! App-facing facade for minip2p.
//!
//! This crate is the ergonomic std entrypoint. It composes the lower-level
//! crates without hiding them: protocol crates and `SwarmCore` remain the
//! Sans-I/O / `no_std + alloc` surface, while [`Endpoint`] gives applications a
//! small batteries-included API for identity, QUIC, listen/dial, ping, and
//! event polling.

use std::time::Instant;

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
pub use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicEndpoint, QuicNodeConfig};
pub use minip2p_swarm::SwarmEvent as Event;
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
    pub fn listen(&mut self) -> Result<PeerAddr, TransportError> {
        self.swarm.listen_on_bound_addr()
    }

    /// Starts listening on all transport-bound addresses.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, TransportError> {
        self.swarm.listen_on_bound_addrs()
    }

    /// Dials a remote peer.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        self.swarm.dial(addr)
    }

    /// Sends a ping to `peer_id`.
    ///
    /// The RTT is emitted later as [`Event::PingRttMeasured`].
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), TransportError> {
        self.swarm.ping(peer_id)
    }

    /// Polls the endpoint once and returns all currently available events.
    pub fn poll(&mut self) -> Result<Vec<Event>, TransportError> {
        self.swarm.poll()
    }

    /// Returns the next event, waiting internally until `deadline`.
    pub fn next_event(&mut self, deadline: Instant) -> Result<Option<Event>, TransportError> {
        self.swarm.poll_next(deadline)
    }

    /// Waits until a peer is ready or `deadline` expires.
    pub fn wait_peer_ready(
        &mut self,
        peer_id: &PeerId,
        deadline: Instant,
    ) -> Result<Option<Event>, TransportError> {
        self.swarm.run_until(
            deadline,
            |event| matches!(event, Event::PeerReady { peer_id: ready, .. } if ready == peer_id),
        )
    }

    /// Waits until a ping RTT for `peer_id` is measured or `deadline` expires.
    pub fn wait_ping_rtt(
        &mut self,
        peer_id: &PeerId,
        deadline: Instant,
    ) -> Result<Option<u64>, TransportError> {
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
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            keypair: None,
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
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

    /// Builds an endpoint with a QUIC transport bound to `bind_addr`.
    pub fn bind_quic(self, bind_addr: impl AsRef<str>) -> Result<Endpoint, TransportError> {
        let (keypair, agent_version) = self.into_parts();
        let transport =
            QuicEndpoint::bind(QuicNodeConfig::new(keypair.clone()), bind_addr.as_ref())?;
        Ok(build_endpoint(keypair, agent_version, transport))
    }

    /// Builds an endpoint with a QUIC transport bound to a QUIC multiaddr.
    pub fn bind_quic_multiaddr(self, addr: &Multiaddr) -> Result<Endpoint, TransportError> {
        let (keypair, agent_version) = self.into_parts();
        let transport = QuicEndpoint::bind_multiaddr(QuicNodeConfig::new(keypair.clone()), addr)?;
        Ok(build_endpoint(keypair, agent_version, transport))
    }

    /// Builds an endpoint with separate IPv4 and IPv6 wildcard QUIC sockets.
    pub fn bind_quic_dual_stack(self) -> Result<Endpoint, TransportError> {
        let (keypair, agent_version) = self.into_parts();
        let transport = QuicEndpoint::dual_stack(QuicNodeConfig::new(keypair.clone()))?;
        Ok(build_endpoint(keypair, agent_version, transport))
    }

    fn into_parts(self) -> (Ed25519Keypair, String) {
        (
            self.keypair.unwrap_or_else(Ed25519Keypair::generate),
            self.agent_version,
        )
    }
}

fn build_endpoint(
    keypair: Ed25519Keypair,
    agent_version: String,
    transport: QuicEndpoint,
) -> Endpoint {
    let swarm = SwarmBuilder::new(&keypair)
        .agent_version(agent_version)
        .build(transport);
    Endpoint { swarm }
}
