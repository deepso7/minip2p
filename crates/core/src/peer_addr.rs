use core::{fmt, str::FromStr};

use minip2p_identity::PeerId;

use crate::{Multiaddr, PeerAddrError, Protocol};

/// A validated peer address: a transport [`Multiaddr`] paired with a [`PeerId`].
///
/// The transport portion must not contain `/p2p` and the peer id is always terminal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerAddr {
    transport: Multiaddr,
    peer_id: PeerId,
}

impl PeerAddr {
    /// Creates a peer address from a transport multiaddr and peer id.
    pub fn new(transport: Multiaddr, peer_id: PeerId) -> Result<Self, PeerAddrError> {
        if transport
            .protocols()
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2p(_)))
        {
            return Err(PeerAddrError::TransportContainsPeerId);
        }

        if transport.is_empty() {
            return Err(PeerAddrError::EmptyTransport);
        }

        Ok(Self { transport, peer_id })
    }

    /// Extracts a peer address from a multiaddr with a terminal `/p2p/<peer-id>`.
    pub fn from_multiaddr(multiaddr: &Multiaddr) -> Result<Self, PeerAddrError> {
        let protocols = multiaddr.protocols();
        // Find the last /p2p component; it must be the final protocol (terminal).
        let last = protocols
            .iter()
            .rposition(|protocol| matches!(protocol, Protocol::P2p(_)))
            .ok_or(PeerAddrError::MissingPeerId)?;

        if last != protocols.len() - 1 {
            return Err(PeerAddrError::NonTerminalPeerId);
        }

        // Find the first /p2p component; if it differs from `last`, there are
        // multiple /p2p segments, which is not allowed.
        let first = protocols
            .iter()
            .position(|protocol| matches!(protocol, Protocol::P2p(_)))
            .ok_or(PeerAddrError::MissingPeerId)?;

        if first != last {
            return Err(PeerAddrError::NonTerminalPeerId);
        }

        let peer_id = match &protocols[last] {
            Protocol::P2p(peer_id) => peer_id.clone(),
            _ => return Err(PeerAddrError::MissingPeerId),
        };

        let transport_slice = &protocols[..last];
        if transport_slice.is_empty() {
            return Err(PeerAddrError::EmptyTransport);
        }

        let transport = Multiaddr::from_protocols(transport_slice.to_vec());
        Ok(Self { transport, peer_id })
    }

    /// Returns the transport portion (without `/p2p`).
    pub fn transport(&self) -> &Multiaddr {
        &self.transport
    }

    /// Returns the peer id.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Consumes this value and returns the transport and peer id.
    pub fn into_parts(self) -> (Multiaddr, PeerId) {
        (self.transport, self.peer_id)
    }

    /// Rebuilds the full multiaddr with the terminal `/p2p/<peer-id>`.
    pub fn to_multiaddr(&self) -> Multiaddr {
        let mut protocols = self.transport.protocols().to_vec();
        protocols.push(Protocol::P2p(self.peer_id.clone()));
        Multiaddr::from_protocols(protocols)
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_multiaddr())
    }
}

impl FromStr for PeerAddr {
    type Err = PeerAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let multiaddr = Multiaddr::from_str(s)?;
        Self::from_multiaddr(&multiaddr)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    const PEER_ID: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

    #[test]
    fn parses_peer_addr_from_multiaddr() {
        let input = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{PEER_ID}");
        let parsed = PeerAddr::from_str(&input).expect("must parse");

        assert_eq!(parsed.to_string(), input);
        assert_eq!(parsed.peer_id().to_string(), PEER_ID);
        assert_eq!(
            parsed.transport().to_string(),
            "/ip4/127.0.0.1/udp/4001/quic-v1"
        );
    }

    #[test]
    fn rejects_missing_peer_id() {
        let input = "/ip4/127.0.0.1/udp/4001/quic-v1";
        let err = PeerAddr::from_str(input).expect_err("must fail");
        assert!(matches!(err, PeerAddrError::MissingPeerId));
    }

    #[test]
    fn rejects_non_terminal_peer_id() {
        let input = format!("/ip4/127.0.0.1/p2p/{PEER_ID}/udp/4001/quic-v1");
        let err = PeerAddr::from_str(&input).expect_err("must fail");
        assert!(matches!(err, PeerAddrError::NonTerminalPeerId));
    }

    #[test]
    fn builds_from_transport_and_peer_id() {
        let transport =
            Multiaddr::from_str("/dns4/example.com/udp/7777/quic-v1").expect("must parse");
        let peer_id = PeerId::from_str(PEER_ID).expect("peer id must parse");
        let peer_addr = PeerAddr::new(transport, peer_id).expect("must build");

        assert_eq!(
            peer_addr.to_string(),
            format!("/dns4/example.com/udp/7777/quic-v1/p2p/{PEER_ID}")
        );
    }

    #[test]
    fn allows_transport_without_quic_marker() {
        let transport = Multiaddr::from_str("/ip4/127.0.0.1/udp/4001").expect("must parse");
        let peer_id = PeerId::from_str(PEER_ID).expect("peer id must parse");
        let peer_addr = PeerAddr::new(transport, peer_id).expect("must build");

        assert_eq!(
            peer_addr.to_string(),
            format!("/ip4/127.0.0.1/udp/4001/p2p/{PEER_ID}")
        );
    }
}
