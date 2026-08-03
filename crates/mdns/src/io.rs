//! The seam between mDNS and whatever carries its datagrams.

use alloc::string::String;
use core::net::{IpAddr, SocketAddr};

use crate::{InterfaceId, InterfaceSnapshot, IpNet, MdnsAction};

/// The largest datagram mDNS will accept.
///
/// A claim bigger than this is not a claim this implementation will act on, so
/// reading further into it would be work done for nothing.
pub const MAX_DATAGRAM_BYTES: usize = 9_000;

/// What went wrong in an mDNS driver or its I/O.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MdnsError {
    /// The current target cannot provide the required multicast socket options.
    #[error("mDNS sockets are unsupported on this target")]
    Unsupported,
    /// No usable address exists for an enumerated interface/family pair.
    #[error("mDNS interface {interface:?} has no usable address")]
    NoInterfaceAddress {
        /// Interface that could not be bound.
        interface: InterfaceId,
    },
    /// A send action referenced an interface that has disappeared.
    ///
    /// Not a fault: interfaces come and go, and a packet encoded for one that
    /// left is simply dropped.
    #[error("mDNS interface {interface:?} is no longer active")]
    UnknownInterface {
        /// Missing interface handle.
        interface: InterfaceId,
    },
    /// The stable interface-id counter was exhausted.
    #[error("mDNS interface id space is exhausted")]
    InterfaceIdsExhausted,
    /// The underlying I/O failed.
    #[error("{operation} failed: {reason}")]
    Io {
        /// Which operation failed, for the message.
        operation: &'static str,
        /// What the platform reported.
        reason: String,
    },
}

impl MdnsError {
    /// Builds an [`MdnsError::Io`] from anything the platform can describe.
    pub fn io(operation: &'static str, reason: impl core::fmt::Display) -> Self {
        use alloc::string::ToString;

        Self::Io {
            operation,
            reason: reason.to_string(),
        }
    }
}

/// One datagram a [`MdnsIo`] handed over, and where it came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdnsDatagram {
    /// The interface it arrived on.
    pub interface: InterfaceId,
    /// The sender, for unicast replies and for the on-link check.
    pub from: SocketAddr,
    /// How many leading bytes of the caller's buffer it filled.
    ///
    /// Never more: a stack that truncates on the way in reports what it wrote,
    /// which is all most of them can say. Truncation is still visible, because
    /// the buffer the driver passes is one byte longer than
    /// [`MAX_DATAGRAM_BYTES`] -- so a datagram that reaches the end of it was
    /// too big to act on either way.
    pub len: usize,
}

/// Multicast datagrams for [`MdnsDriver`](crate::MdnsDriver), from whatever
/// carries them.
///
/// mDNS needs three things a network stack has to answer for: which interfaces
/// exist and what addresses they hold, datagrams that arrived on the mDNS
/// group, and a way to send one back out of a chosen interface. Everything
/// else -- scheduling, validation, fairness, the on-link check -- is the
/// driver's, and is the same code on a hosted socket and an embedded stack.
///
/// # Interfaces
///
/// [`InterfaceId`] is this implementation's own handle, and the driver only
/// ever hands back one it was given. Ids must be stable while an interface
/// stays up and must never be reused for a different one: the agent tracks
/// per-interface state against them, and a reused id would attach one
/// interface's history to another.
///
/// # Receiving
///
/// [`receive`](Self::receive) never blocks. Returning `None` means nothing is
/// waiting right now, and the driver stops asking until its next tick, so an
/// implementation that has several sockets should rotate between them rather
/// than drain one first -- a busy interface would otherwise starve a quiet one
/// of a caller's budget.
///
/// Fill the buffer and report how much was written -- never more, whatever the
/// datagram's true size was. A datagram too big to fit is not an error and
/// needs no special report: the driver's buffer is one byte longer than
/// [`MAX_DATAGRAM_BYTES`], so filling it is itself the signal, and the driver
/// drops what it finds there. Do not silently cap a read at some smaller
/// length of your own, though -- that would hand over a truncated claim
/// wearing a plausible length.
///
/// # Sending
///
/// [`send`](Self::send) resolves an action's [`MdnsTarget`](crate::MdnsTarget)
/// to a destination, which is the one piece of addressing an implementation
/// owns: the mDNS group differs by family, and IPv6 needs the interface's
/// scope. An action naming an interface that has gone away is
/// [`MdnsError::UnknownInterface`], which the driver treats as a drop rather
/// than a failure. Any other error stops mDNS: a stack that cannot send cannot
/// participate, and retrying into it would only produce the same error with
/// the peer's view of us going stale either way.
pub trait MdnsIo {
    /// The interfaces mDNS is currently running on.
    fn interfaces(&self) -> &[InterfaceSnapshot];

    /// Re-enumerates interfaces, returning whether anything changed.
    ///
    /// Ids and their sockets survive for interfaces that are still there with
    /// the same addresses; the driver re-arms the agent when this says the
    /// snapshot moved.
    fn refresh(&mut self) -> Result<bool, MdnsError>;

    /// Takes one waiting datagram into `buffer`, or `None` if none is waiting.
    fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<MdnsDatagram>, MdnsError>;

    /// Sends one encoded datagram out of the interface the action names.
    fn send(&mut self, action: &MdnsAction) -> Result<(), MdnsError>;

    /// Moves whatever is waiting, in either direction.
    ///
    /// An operating system does this on its own, so the default does nothing.
    /// A stack running in this process does not: nothing arrives or leaves
    /// except when it is driven, and it needs to be told the time to do it.
    /// The driver calls this before reading and again after writing, so
    /// neither direction waits a whole tick.
    fn poll(&mut self, now_ms: u64) -> Result<(), MdnsError> {
        let _ = now_ms;
        Ok(())
    }

    /// How long the host may idle before this needs [`poll`](Self::poll)
    /// again, in milliseconds from `now_ms`.
    ///
    /// A stack of its own has timers -- retransmits, group memberships to
    /// renew -- that no amount of mDNS quiet makes unnecessary. `None`, the
    /// default, means the carrier needs nothing on a timer, which is the
    /// truth for a socket the operating system services.
    fn next_deadline(&self, now_ms: u64) -> Option<u64> {
        let _ = now_ms;
        None
    }
}

/// Whether `source` is on one of the networks this interface holds.
///
/// mDNS is a link-local protocol, so a datagram from off-link is not a peer on
/// this link -- it is something that reached the group from elsewhere, and
/// acting on it would let a remote host inject addresses into a local peer
/// book. Checked here rather than in an implementation, so every one of them
/// gets it.
pub(crate) fn source_is_on_link(snapshot: &InterfaceSnapshot, source: IpAddr) -> bool {
    snapshot
        .addrs
        .iter()
        .any(|network| same_subnet(*network, source))
}

fn same_subnet(network: IpNet, source: IpAddr) -> bool {
    let prefix_len = network.prefix_len();
    match (network.ip(), source) {
        (IpAddr::V4(network_ip), IpAddr::V4(source_ip)) => {
            let mask = prefix_mask_u32(prefix_len);
            u32::from(source_ip) & mask == u32::from(network_ip) & mask
        }
        (IpAddr::V6(network_ip), IpAddr::V6(source_ip)) => {
            let mask = prefix_mask_u128(prefix_len);
            u128::from(source_ip) & mask == u128::from(network_ip) & mask
        }
        _ => false,
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpFamily;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn net(ip: IpAddr, prefix: u8) -> IpNet {
        IpNet::new(ip, prefix).expect("a valid prefix")
    }

    fn snapshot(family: IpFamily, addrs: Vec<IpNet>) -> InterfaceSnapshot {
        InterfaceSnapshot {
            id: InterfaceId::new(1),
            index: 1,
            family,
            addrs,
        }
    }

    #[test]
    fn on_link_check_uses_checked_prefix() {
        let snapshot = snapshot(
            IpFamily::V4,
            vec![net(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 24)],
        );
        assert!(source_is_on_link(
            &snapshot,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))
        ));
        assert!(
            !source_is_on_link(&snapshot, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))),
            "a host outside the prefix is not on this link"
        );
    }

    #[test]
    fn a_source_from_another_family_is_never_on_link() {
        let snapshot = snapshot(
            IpFamily::V4,
            vec![net(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 24)],
        );
        // Comparing a v6 source against a v4 network by its bits would make
        // every one of them look local.
        assert!(!source_is_on_link(
            &snapshot,
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        ));
    }

    #[test]
    fn a_zero_prefix_is_the_whole_family() {
        let snapshot = snapshot(IpFamily::V6, vec![net(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)]);
        assert!(source_is_on_link(
            &snapshot,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        ));
    }
}
