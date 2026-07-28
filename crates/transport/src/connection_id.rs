use core::fmt;

use crate::TransportError;

/// Bits of a [`ConnectionId`] holding the [`ConnectionNamespace`].
const NAMESPACE_SHIFT: u32 = 56;

/// Which transport a [`ConnectionId`] was allocated by.
///
/// A host may run several transports at once — TCP and QUIC side by side, each
/// possibly split per address family, plus relay circuits layered on top — and
/// every one of them hands connection ids to the same swarm. Namespaces keep
/// those id spaces disjoint by construction, so a router can tell which
/// transport an id belongs to by looking at it, and no transport needs to remap
/// another's ids.
///
/// The constants below are a workspace-wide registry: allocating a new one here
/// is what guarantees disjointness. Hosts embedding a custom transport can use
/// [`new`](Self::new) with an unregistered tag, taking care not to collide with
/// a registered one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionNamespace(u8);

impl ConnectionNamespace {
    /// Transports that do not participate in multi-transport routing.
    ///
    /// Ids in this namespace are the bare sequence number, which keeps test
    /// doubles and single-transport hosts readable.
    pub const UNSPECIFIED: Self = Self(0);
    /// QUIC over IPv4.
    pub const QUIC_IPV4: Self = Self(1);
    /// QUIC over IPv6.
    pub const QUIC_IPV6: Self = Self(2);
    /// TCP over IPv4.
    pub const TCP_IPV4: Self = Self(3);
    /// TCP over IPv6.
    pub const TCP_IPV6: Self = Self(4);
    /// Relay circuits.
    ///
    /// Deliberately `0x80`, so every circuit id has the top bit of its `u64`
    /// set and circuit ids stay trivially distinguishable from the base
    /// transport ids they are layered over.
    pub const CIRCUIT: Self = Self(0x80);

    /// Creates a namespace from a raw tag.
    pub const fn new(tag: u8) -> Self {
        Self(tag)
    }

    /// Returns the raw tag.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Returns whether this is the relay-circuit namespace.
    pub const fn is_circuit(self) -> bool {
        self.0 == Self::CIRCUIT.0
    }

    /// Returns the registered name of this namespace, if it has one.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            0 => Some("unspecified"),
            1 => Some("quic/ip4"),
            2 => Some("quic/ip6"),
            3 => Some("tcp/ip4"),
            4 => Some("tcp/ip6"),
            0x80 => Some("circuit"),
            _ => None,
        }
    }
}

impl fmt::Display for ConnectionNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "ns({})", self.0),
        }
    }
}

/// Opaque identifier for a transport connection.
///
/// The underlying `u64` is split into an 8-bit [`ConnectionNamespace`] and a
/// 56-bit sequence number, so ids minted by different transports can never
/// collide. Allocate them with [`ConnectionIdAllocator`] rather than building
/// them by hand.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Largest sequence number an id can carry.
    ///
    /// 2^56 - 1: at a sustained million connections per second, exhausting a
    /// single namespace takes over two thousand years.
    pub const MAX_SEQUENCE: u64 = (1 << NAMESPACE_SHIFT) - 1;

    /// Creates a connection id from a raw `u64`.
    ///
    /// The value is interpreted as a packed namespace and sequence. Prefer
    /// [`namespaced`](Self::namespaced) or [`ConnectionIdAllocator`]; this is
    /// for round-tripping ids that have already been allocated.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Creates an id in `namespace`, or `None` if `sequence` exceeds
    /// [`MAX_SEQUENCE`](Self::MAX_SEQUENCE).
    pub const fn namespaced(namespace: ConnectionNamespace, sequence: u64) -> Option<Self> {
        if sequence > Self::MAX_SEQUENCE {
            return None;
        }
        Some(Self(
            ((namespace.get() as u64) << NAMESPACE_SHIFT) | sequence,
        ))
    }

    /// Returns the underlying `u64` value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the namespace that allocated this id.
    pub const fn namespace(self) -> ConnectionNamespace {
        ConnectionNamespace::new((self.0 >> NAMESPACE_SHIFT) as u8)
    }

    /// Returns this id's sequence number within its namespace.
    pub const fn sequence(self) -> u64 {
        self.0 & Self::MAX_SEQUENCE
    }

    /// Returns whether this id belongs to a relay circuit rather than a base
    /// transport.
    pub const fn is_circuit(self) -> bool {
        self.namespace().is_circuit()
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let namespace = self.namespace();
        if namespace == ConnectionNamespace::UNSPECIFIED {
            write!(f, "{}", self.sequence())
        } else {
            write!(f, "{namespace}#{}", self.sequence())
        }
    }
}

impl From<u64> for ConnectionId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<ConnectionId> for u64 {
    fn from(value: ConnectionId) -> Self {
        value.0
    }
}

/// Hands out fresh [`ConnectionId`]s within one [`ConnectionNamespace`].
///
/// Sequence numbers are strictly increasing and never reused, so an id can
/// never name a different connection than it did before. Allocation fails once
/// the namespace is exhausted instead of wrapping onto live ids.
///
/// # Example
///
/// ```
/// use minip2p_transport::{ConnectionIdAllocator, ConnectionNamespace};
///
/// let mut ids = ConnectionIdAllocator::new(ConnectionNamespace::TCP_IPV4);
/// let first = ids.allocate().expect("fresh namespace");
/// let second = ids.allocate().expect("fresh namespace");
///
/// assert_ne!(first, second);
/// assert_eq!(first.namespace(), ConnectionNamespace::TCP_IPV4);
/// assert_eq!(first.to_string(), "tcp/ip4#1");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionIdAllocator {
    namespace: ConnectionNamespace,
    next: u64,
}

impl ConnectionIdAllocator {
    /// Creates an allocator for `namespace`.
    ///
    /// Sequence numbers start at 1, leaving 0 free as an obviously-invalid
    /// value in logs and debugger output.
    pub const fn new(namespace: ConnectionNamespace) -> Self {
        Self::starting_at(namespace, 1)
    }

    /// Creates an allocator whose first id carries `sequence`.
    ///
    /// Use this to reserve low sequence numbers, or to drive an allocator to
    /// exhaustion in tests by starting past
    /// [`ConnectionId::MAX_SEQUENCE`](ConnectionId::MAX_SEQUENCE).
    pub const fn starting_at(namespace: ConnectionNamespace, sequence: u64) -> Self {
        Self {
            namespace,
            next: sequence,
        }
    }

    /// Returns the namespace this allocator mints ids in.
    pub const fn namespace(&self) -> ConnectionNamespace {
        self.namespace
    }

    /// Returns the id [`allocate`](Self::allocate) will hand out next, or
    /// `None` if the namespace is exhausted.
    pub const fn peek(&self) -> Option<ConnectionId> {
        ConnectionId::namespaced(self.namespace, self.next)
    }

    /// Allocates the next id in this namespace.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ResourceExhausted`] once every sequence number
    /// in the namespace has been handed out.
    pub fn allocate(&mut self) -> Result<ConnectionId, TransportError> {
        let id = self.peek().ok_or(TransportError::ResourceExhausted {
            resource: "connection ids",
        })?;
        self.next += 1;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec::Vec;

    #[test]
    fn namespace_and_sequence_round_trip() {
        let id = ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV6, 42).expect("in range");
        assert_eq!(id.namespace(), ConnectionNamespace::QUIC_IPV6);
        assert_eq!(id.sequence(), 42);
        assert_eq!(ConnectionId::new(id.as_u64()), id);
    }

    #[test]
    fn unspecified_ids_are_their_bare_sequence() {
        let id = ConnectionId::namespaced(ConnectionNamespace::UNSPECIFIED, 7).expect("in range");
        assert_eq!(id.as_u64(), 7);
        assert_eq!(ConnectionId::new(7).sequence(), 7);
    }

    #[test]
    fn sequence_beyond_the_namespace_is_rejected() {
        assert!(
            ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, ConnectionId::MAX_SEQUENCE)
                .is_some()
        );
        assert!(
            ConnectionId::namespaced(
                ConnectionNamespace::TCP_IPV4,
                ConnectionId::MAX_SEQUENCE + 1
            )
            .is_none()
        );
        assert!(ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, u64::MAX).is_none());
    }

    #[test]
    fn distinct_namespaces_never_collide_on_the_same_sequence() {
        let namespaces = [
            ConnectionNamespace::UNSPECIFIED,
            ConnectionNamespace::QUIC_IPV4,
            ConnectionNamespace::QUIC_IPV6,
            ConnectionNamespace::TCP_IPV4,
            ConnectionNamespace::TCP_IPV6,
            ConnectionNamespace::CIRCUIT,
        ];

        for sequence in [1, 2, 1_000, ConnectionId::MAX_SEQUENCE] {
            let ids: Vec<u64> = namespaces
                .iter()
                .map(|namespace| {
                    ConnectionId::namespaced(*namespace, sequence)
                        .expect("in range")
                        .as_u64()
                })
                .collect();

            let mut unique = ids.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), ids.len(), "collision at sequence {sequence}");
        }
    }

    #[test]
    fn circuit_ids_have_the_top_bit_set() {
        let circuit = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 1).expect("in range");
        assert!(circuit.is_circuit());
        assert_ne!(circuit.as_u64() & (1 << 63), 0);

        let base = ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 1).expect("in range");
        assert!(!base.is_circuit());
        assert_eq!(base.as_u64() & (1 << 63), 0);
    }

    #[test]
    fn every_base_transport_namespace_leaves_the_top_bit_clear() {
        for namespace in [
            ConnectionNamespace::UNSPECIFIED,
            ConnectionNamespace::QUIC_IPV4,
            ConnectionNamespace::QUIC_IPV6,
            ConnectionNamespace::TCP_IPV4,
            ConnectionNamespace::TCP_IPV6,
        ] {
            let id =
                ConnectionId::namespaced(namespace, ConnectionId::MAX_SEQUENCE).expect("in range");
            assert!(!id.is_circuit(), "{namespace} must not look like a circuit");
        }
    }

    #[test]
    fn display_names_the_namespace() {
        let quic = ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 3).expect("in range");
        assert_eq!(format!("{quic}"), "quic/ip4#3");

        let circuit = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 3).expect("in range");
        assert_eq!(format!("{circuit}"), "circuit#3");

        // Unregistered tags stay printable.
        let custom = ConnectionId::namespaced(ConnectionNamespace::new(9), 3).expect("in range");
        assert_eq!(format!("{custom}"), "ns(9)#3");

        let bare = ConnectionId::new(3);
        assert_eq!(format!("{bare}"), "3");
    }

    #[test]
    fn allocator_hands_out_increasing_ids_in_its_namespace() {
        let mut allocator = ConnectionIdAllocator::new(ConnectionNamespace::TCP_IPV6);
        assert_eq!(allocator.namespace(), ConnectionNamespace::TCP_IPV6);

        let first = allocator.allocate().expect("fresh");
        let second = allocator.allocate().expect("fresh");
        assert_eq!(first.sequence(), 1, "0 is left free as an invalid marker");
        assert_eq!(second.sequence(), 2);
        assert_eq!(first.namespace(), ConnectionNamespace::TCP_IPV6);
        assert_eq!(second.namespace(), ConnectionNamespace::TCP_IPV6);
    }

    #[test]
    fn peek_matches_the_next_allocation() {
        let mut allocator = ConnectionIdAllocator::new(ConnectionNamespace::QUIC_IPV4);
        let peeked = allocator.peek().expect("fresh");
        assert_eq!(allocator.allocate().expect("fresh"), peeked);
        assert_ne!(allocator.peek().expect("fresh"), peeked);
    }

    #[test]
    fn allocator_fails_instead_of_reusing_a_live_id() {
        let mut allocator = ConnectionIdAllocator::new(ConnectionNamespace::QUIC_IPV4);
        // Jump to the last usable sequence rather than allocating 2^56 ids.
        allocator.next = ConnectionId::MAX_SEQUENCE;

        let last = allocator.allocate().expect("last id");
        assert_eq!(last.sequence(), ConnectionId::MAX_SEQUENCE);

        // Exhaustion is permanent: no wrap back onto ids already in use.
        for _ in 0..3 {
            assert_eq!(allocator.peek(), None);
            assert_eq!(
                allocator.allocate(),
                Err(TransportError::ResourceExhausted {
                    resource: "connection ids"
                })
            );
        }
    }
}
