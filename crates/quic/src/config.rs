use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;

/// Configuration for a QUIC transport node.
///
/// Use [`with_keypair`](Self::with_keypair) to create a node with a libp2p
/// identity. A TLS certificate is auto-generated from the keypair, and the
/// remote peer's identity is verified automatically after each QUIC handshake.
#[derive(Clone, Debug)]
pub struct QuicNodeConfig {
    /// Ed25519 host keypair for libp2p TLS identity.
    pub(crate) keypair: Option<Ed25519Keypair>,
}

impl Default for QuicNodeConfig {
    fn default() -> Self {
        Self { keypair: None }
    }
}

impl QuicNodeConfig {
    /// Creates an empty configuration (no identity, cannot listen).
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration from an Ed25519 host keypair.
    ///
    /// A libp2p-spec TLS certificate is auto-generated from the keypair. Both
    /// dialing and listening are enabled. Peer identity is verified
    /// automatically after each QUIC handshake.
    pub fn with_keypair(keypair: Ed25519Keypair) -> Self {
        Self {
            keypair: Some(keypair),
        }
    }

    /// Convenience: generates a fresh keypair for a dev/test dialer.
    pub fn dev_dialer() -> Self {
        Self::with_keypair(Ed25519Keypair::generate())
    }

    /// Convenience: generates a fresh keypair for a dev/test listener.
    pub fn dev_listener() -> Self {
        Self::with_keypair(Ed25519Keypair::generate())
    }

    /// Returns this node's `PeerId`, derived from the configured keypair.
    ///
    /// Returns `None` if no keypair is configured.
    pub fn peer_id(&self) -> Option<PeerId> {
        self.keypair.as_ref().map(|kp| kp.peer_id())
    }

    /// Returns `true` if TLS is configured (required for listening).
    pub fn can_listen(&self) -> bool {
        self.keypair.is_some()
    }

    /// Returns the Ed25519 host keypair, if configured.
    pub(crate) fn keypair(&self) -> Option<&Ed25519Keypair> {
        self.keypair.as_ref()
    }
}
