use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;

/// Configuration for a QUIC transport node.
///
/// QUIC always uses mutual libp2p TLS in minip2p, so a node identity is
/// mandatory. A TLS certificate is auto-generated from the keypair, and the
/// remote peer's identity is verified automatically after each QUIC handshake.
#[derive(Clone, Debug)]
pub struct QuicNodeConfig {
    /// Ed25519 host keypair for libp2p TLS identity.
    pub(crate) keypair: Ed25519Keypair,
}

impl QuicNodeConfig {
    /// Creates a configuration from an Ed25519 host keypair.
    ///
    /// A libp2p-spec TLS certificate is auto-generated from the keypair. Both
    /// dialing and listening are enabled. Peer identity is verified
    /// automatically after each QUIC handshake.
    pub fn new(keypair: Ed25519Keypair) -> Self {
        Self { keypair }
    }

    /// Convenience: generates a fresh keypair for a dev/test dialer.
    pub fn dev_dialer() -> Self {
        Self::new(Ed25519Keypair::generate())
    }

    /// Convenience: generates a fresh keypair for a dev/test listener.
    pub fn dev_listener() -> Self {
        Self::new(Ed25519Keypair::generate())
    }

    /// Returns this node's `PeerId`, derived from the configured keypair.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    /// Returns the Ed25519 host keypair.
    pub(crate) fn keypair(&self) -> &Ed25519Keypair {
        &self.keypair
    }
}
