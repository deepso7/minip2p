use minip2p_core::{Multiaddr, PeerAddr, PeerId};

/// One side of a connection, combining a transport address with an optional peer identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionEndpoint {
    transport: Multiaddr,
    peer_id: Option<PeerId>,
}

impl ConnectionEndpoint {
    /// Creates an endpoint with no peer identity.
    pub fn new(transport: Multiaddr) -> Self {
        Self {
            transport,
            peer_id: None,
        }
    }

    /// Creates an endpoint with a known peer identity.
    pub fn with_peer_id(transport: Multiaddr, peer_id: PeerId) -> Self {
        Self {
            transport,
            peer_id: Some(peer_id),
        }
    }

    /// Creates an endpoint from a [`PeerAddr`].
    pub fn from_peer_addr(addr: &PeerAddr) -> Self {
        Self::with_peer_id(addr.transport().clone(), addr.peer_id().clone())
    }

    /// Returns the transport address.
    pub fn transport(&self) -> &Multiaddr {
        &self.transport
    }

    /// Returns the peer identity, if known.
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }

    /// Sets the peer identity.
    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        self.peer_id = Some(peer_id);
    }

    /// Removes the peer identity.
    pub fn clear_peer_id(&mut self) {
        self.peer_id = None;
    }

    /// Converts to a [`PeerAddr`], returning `None` if no peer id is set.
    pub fn to_peer_addr(&self) -> Option<PeerAddr> {
        let peer_id = self.peer_id.as_ref()?.clone();
        PeerAddr::new(self.transport.clone(), peer_id).ok()
    }

    /// Consumes this value and returns the transport address and optional peer id.
    pub fn into_parts(self) -> (Multiaddr, Option<PeerId>) {
        (self.transport, self.peer_id)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn creates_endpoint_without_peer_id() {
        let transport = Multiaddr::from_str("/ip4/127.0.0.1/udp/7777/quic-v1").expect("must parse");

        let endpoint = ConnectionEndpoint::new(transport.clone());
        assert_eq!(endpoint.transport(), &transport);
        assert!(endpoint.peer_id().is_none());
        assert!(endpoint.to_peer_addr().is_none());
    }

    #[test]
    fn converts_between_peer_addr_and_endpoint() {
        let peer_addr = PeerAddr::from_str(
            "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
        )
        .expect("must parse");

        let endpoint = ConnectionEndpoint::from_peer_addr(&peer_addr);
        assert_eq!(endpoint.to_peer_addr().expect("must rebuild"), peer_addr);
    }
}
