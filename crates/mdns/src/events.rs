//! mDNS interface snapshots, actions, and observations.

use alloc::{string::String, vec::Vec};
use core::net::{IpAddr, SocketAddr};

use minip2p_core::{Multiaddr, PeerId};

/// Stable driver-assigned identity for one interface and address family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceId(u32);

impl InterfaceId {
    /// Constructs an opaque interface handle from a driver-stable numeric id.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}

/// IP address family represented by an [`InterfaceId`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// One interface address and its checked prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IpNet {
    ip: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    /// Constructs a network address, rejecting prefixes over 32 for IPv4 or 128 for IPv6.
    pub const fn new(ip: IpAddr, prefix_len: u8) -> Option<Self> {
        let valid = match ip {
            IpAddr::V4(_) => prefix_len <= 32,
            IpAddr::V6(_) => prefix_len <= 128,
        };
        if valid {
            Some(Self { ip, prefix_len })
        } else {
            None
        }
    }

    /// Returns the interface IP address.
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Returns the checked network prefix length.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// Current addresses for one OS interface and one IP family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceSnapshot {
    /// Stable interface/family handle.
    pub id: InterfaceId,
    /// OS interface index.
    pub index: u32,
    /// Address family represented by this snapshot.
    pub family: IpFamily,
    /// Addresses currently assigned to the interface in this family.
    pub addrs: Vec<IpNet>,
}

/// Destination selected for an emitted mDNS datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsTarget {
    /// The family-specific mDNS group on the selected interface.
    Multicast,
    /// A QU or legacy-unicast response sent directly to its requester.
    Unicast {
        /// Datagram destination.
        to: SocketAddr,
    },
}

/// Datagram work emitted by [`MdnsAgent`](crate::MdnsAgent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MdnsAction {
    /// Send one already-encoded DNS datagram.
    Send {
        /// Interface/family socket to use.
        interface: InterfaceId,
        /// Multicast or unicast destination.
        target: MdnsTarget,
        /// Encoded DNS/UDP payload.
        payload: Vec<u8>,
    },
}

/// Validated observations and wire-policy diagnostics emitted by mDNS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MdnsEvent {
    /// A peer claimed normalized addresses with individual lifetimes.
    PeerObserved {
        /// Claimed peer identity.
        peer: PeerId,
        /// Normalized address and TTL in milliseconds; zero is a goodbye.
        addrs: Vec<(Multiaddr, u64)>,
    },
    /// A recognizable libp2p mDNS claim broke wire or identity invariants.
    ProtocolViolation {
        /// Claimed peer, if one could be decoded.
        peer: Option<PeerId>,
        /// Human-readable rejection cause.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipnet_rejects_invalid_prefixes() {
        assert!(IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).is_some());
        assert!(IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33).is_none());
        assert!(IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).is_some());
        assert!(IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).is_none());
    }
}
