use alloc::vec::Vec;

use crate::{Multiaddr, Protocol};

/// Where a direct-connect candidate came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectCandidateSource {
    /// User-supplied explicit public address.
    Manual,
    /// Address observed by a public peer through Identify.
    IdentifyObserved,
    /// Local non-wildcard listen address.
    Listen,
}

impl DirectCandidateSource {
    /// Stable text for logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::IdentifyObserved => "identify-observed",
            Self::Listen => "listen",
        }
    }
}

/// Why a direct-connect candidate was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectCandidateRejectReason {
    /// The address starts with `0.0.0.0` or `::` and is not remotely dialable.
    WildcardBindAddress,
    /// The address is not exactly host + udp + quic-v1.
    NotQuicV1Transport,
    /// The address was already accepted from a higher-priority source.
    Duplicate,
}

impl DirectCandidateRejectReason {
    /// Stable text for logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WildcardBindAddress => "wildcard-bind-address",
            Self::NotQuicV1Transport => "not-quic-v1-transport",
            Self::Duplicate => "duplicate",
        }
    }
}

/// A candidate skipped by [`select_direct_candidates`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCandidateRejection {
    pub source: DirectCandidateSource,
    pub addr: Multiaddr,
    pub reason: DirectCandidateRejectReason,
}

/// A candidate accepted by [`select_direct_candidates`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCandidate {
    pub source: DirectCandidateSource,
    pub addr: Multiaddr,
}

/// Ordered direct-connect candidates plus skipped candidates for diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirectCandidateSelection {
    pub accepted: Vec<DirectCandidate>,
    pub rejected: Vec<DirectCandidateRejection>,
}

impl DirectCandidateSelection {
    /// Returns true when no dialable candidates were accepted.
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Consumes the selection and returns accepted candidate addresses in order.
    pub fn into_addrs(self) -> Vec<Multiaddr> {
        self.accepted
            .into_iter()
            .map(|candidate| candidate.addr)
            .collect()
    }
}

/// Selects dialable direct-connect candidates in deterministic priority order.
///
/// Priority is:
/// 1. manual external addresses,
/// 2. Identify observed address,
/// 3. local non-wildcard listen address.
///
/// The selector is pure Sans-I/O policy: no DNS resolution, socket access,
/// logging, timing, or transport side effects. It intentionally accepts only
/// strict QUIC-v1 transport addresses (`/<host>/udp/<port>/quic-v1`).
pub fn select_direct_candidates(
    manual: &[Multiaddr],
    identify_observed: Option<Multiaddr>,
    listen: Option<Multiaddr>,
) -> DirectCandidateSelection {
    let capacity = manual.len() + identify_observed.is_some() as usize + listen.is_some() as usize;
    let mut selection = DirectCandidateSelection {
        accepted: Vec::with_capacity(capacity),
        rejected: Vec::new(),
    };

    for addr in manual {
        push_candidate(&mut selection, DirectCandidateSource::Manual, addr.clone());
    }
    if let Some(addr) = identify_observed {
        push_candidate(
            &mut selection,
            DirectCandidateSource::IdentifyObserved,
            addr,
        );
    }
    if let Some(addr) = listen {
        push_candidate(&mut selection, DirectCandidateSource::Listen, addr);
    }

    selection
}

fn push_candidate(
    selection: &mut DirectCandidateSelection,
    source: DirectCandidateSource,
    addr: Multiaddr,
) {
    if is_wildcard_addr(&addr) {
        reject(
            selection,
            source,
            addr,
            DirectCandidateRejectReason::WildcardBindAddress,
        );
        return;
    }
    if !addr.is_quic_transport() {
        reject(
            selection,
            source,
            addr,
            DirectCandidateRejectReason::NotQuicV1Transport,
        );
        return;
    }
    if selection
        .accepted
        .iter()
        .any(|candidate| candidate.addr == addr)
    {
        reject(
            selection,
            source,
            addr,
            DirectCandidateRejectReason::Duplicate,
        );
        return;
    }

    selection.accepted.push(DirectCandidate { source, addr });
}

fn reject(
    selection: &mut DirectCandidateSelection,
    source: DirectCandidateSource,
    addr: Multiaddr,
    reason: DirectCandidateRejectReason,
) {
    selection.rejected.push(DirectCandidateRejection {
        source,
        addr,
        reason,
    });
}

/// Returns true when the multiaddr starts with a wildcard IP host.
fn is_wildcard_addr(addr: &Multiaddr) -> bool {
    match addr.protocols().first() {
        Some(Protocol::Ip4(bytes)) => *bytes == [0, 0, 0, 0],
        Some(Protocol::Ip6(bytes)) => *bytes == [0; 16],
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    fn addr(value: &str) -> Multiaddr {
        Multiaddr::from_str(value).unwrap()
    }

    #[test]
    fn selects_candidates_in_priority_order() {
        let manual = addr("/ip4/203.0.113.7/udp/4001/quic-v1");
        let observed = addr("/ip4/198.51.100.9/udp/5001/quic-v1");
        let listen = addr("/ip4/127.0.0.1/udp/6001/quic-v1");

        let selected = select_direct_candidates(
            core::slice::from_ref(&manual),
            Some(observed.clone()),
            Some(listen.clone()),
        );

        assert_eq!(selected.accepted.len(), 3);
        assert_eq!(selected.accepted[0].source, DirectCandidateSource::Manual);
        assert_eq!(selected.accepted[0].addr, manual);
        assert_eq!(
            selected.accepted[1].source,
            DirectCandidateSource::IdentifyObserved
        );
        assert_eq!(selected.accepted[1].addr, observed);
        assert_eq!(selected.accepted[2].source, DirectCandidateSource::Listen);
        assert_eq!(selected.accepted[2].addr, listen);
        assert!(selected.rejected.is_empty());
    }

    #[test]
    fn rejects_wildcard_listen_addresses() {
        for listen in [
            addr("/ip4/0.0.0.0/udp/4001/quic-v1"),
            addr("/ip6/::/udp/4001/quic-v1"),
        ] {
            let selected = select_direct_candidates(&[], None, Some(listen.clone()));

            assert!(selected.is_empty());
            assert_eq!(
                selected.rejected,
                vec![DirectCandidateRejection {
                    source: DirectCandidateSource::Listen,
                    addr: listen,
                    reason: DirectCandidateRejectReason::WildcardBindAddress,
                }]
            );
        }
    }

    #[test]
    fn rejects_non_quic_v1_transport_shapes() {
        let bad = addr("/ip4/203.0.113.7/udp/4001");

        let selected = select_direct_candidates(core::slice::from_ref(&bad), None, None);

        assert!(selected.is_empty());
        assert_eq!(
            selected.rejected[0].reason,
            DirectCandidateRejectReason::NotQuicV1Transport
        );
    }

    #[test]
    fn removes_duplicates_deterministically() {
        let manual = addr("/ip4/203.0.113.7/udp/4001/quic-v1");

        let selected = select_direct_candidates(
            core::slice::from_ref(&manual),
            Some(manual.clone()),
            Some(manual.clone()),
        );

        assert_eq!(selected.clone().into_addrs(), vec![manual.clone()]);
        assert_eq!(selected.rejected.len(), 2);
        assert_eq!(
            selected.rejected[0].source,
            DirectCandidateSource::IdentifyObserved
        );
        assert_eq!(
            selected.rejected[0].reason,
            DirectCandidateRejectReason::Duplicate
        );
        assert_eq!(selected.rejected[1].source, DirectCandidateSource::Listen);
        assert_eq!(
            selected.rejected[1].reason,
            DirectCandidateRejectReason::Duplicate
        );
    }
}
