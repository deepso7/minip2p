use core::fmt;

/// A value both ends of one established connection compute identically.
///
/// Adapters derive it from handshake state the two ends share -- QUIC from
/// the connection's two connection IDs, Noise-secured byte streams from the
/// Noise handshake hash -- and attach it to the [`ConnectionEndpoint`] of
/// `Connected` and `PeerIdentityVerified`. It is not secret and identifies
/// nothing on its own; its use is to let both peers make the same choice
/// between two connections without talking to each other, which is how the
/// swarm settles two same-direction connections that race to one peer.
///
/// [`ConnectionEndpoint`]: crate::ConnectionEndpoint
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionToken([u8; 32]);

impl ConnectionToken {
    /// Wraps 32 bytes both ends of the connection share.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the token's bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ConnectionToken {
    /// Prints the first eight bytes in hex, which is plenty to tell tokens apart in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionToken(")?;
        for byte in self.0.iter().take(8) {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}
