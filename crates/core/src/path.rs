use crate::PeerId;

/// How a peer's established connection was made.
///
/// Every established connection has exactly one Path, fixed for its
/// lifetime except for one upgrade: NAT traversal may mark a direct
/// connection its DCUtR hole punch produced as [`Path::Punched`]. A
/// Connection replacement does not carry the old connection's Path over.
///
/// Ranking: [`Path::Direct`] ≈ [`Path::Punched`] > [`Path::Relayed`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Path {
    /// A direct connection we dialed or accepted.
    Direct,
    /// A direct connection made by a DCUtR hole punch.
    Punched,
    /// A Noise- and Yamux-protected circuit connection through a relay.
    Relayed {
        /// The relay carrying the circuit.
        relay: PeerId,
    },
}
