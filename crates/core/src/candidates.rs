use alloc::vec::Vec;

use crate::Multiaddr;

/// Selects dialable direct-connect addresses in deterministic priority order.
///
/// Priority is:
/// 1. manual external addresses,
/// 2. Identify observed address,
/// 3. local non-wildcard listen address.
///
/// The selector is pure Sans-I/O policy: no DNS resolution, socket access,
/// logging, timing, or transport side effects. It intentionally accepts only
/// strict QUIC-v1 transport addresses (`/<host>/udp/<port>/quic-v1`);
/// wildcard-host addresses and duplicates are dropped.
pub fn select_direct_addrs(
    manual: &[Multiaddr],
    identify_observed: Option<Multiaddr>,
    listen: Option<Multiaddr>,
) -> Vec<Multiaddr> {
    let capacity = manual.len() + identify_observed.is_some() as usize + listen.is_some() as usize;
    let mut accepted = Vec::with_capacity(capacity);

    for addr in manual {
        push_candidate(&mut accepted, addr.clone());
    }
    if let Some(addr) = identify_observed {
        push_candidate(&mut accepted, addr);
    }
    if let Some(addr) = listen {
        push_candidate(&mut accepted, addr);
    }

    accepted
}

fn push_candidate(accepted: &mut Vec<Multiaddr>, addr: Multiaddr) {
    if addr.is_wildcard_host() {
        return;
    }
    if !addr.is_quic_transport() {
        return;
    }
    if accepted.contains(&addr) {
        return;
    }

    accepted.push(addr);
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

        let selected = select_direct_addrs(
            core::slice::from_ref(&manual),
            Some(observed.clone()),
            Some(listen.clone()),
        );

        assert_eq!(selected, vec![manual, observed, listen]);
    }

    #[test]
    fn rejects_wildcard_listen_addresses() {
        for listen in [
            addr("/ip4/0.0.0.0/udp/4001/quic-v1"),
            addr("/ip6/::/udp/4001/quic-v1"),
        ] {
            let selected = select_direct_addrs(&[], None, Some(listen));

            assert!(selected.is_empty());
        }
    }

    #[test]
    fn rejects_non_quic_v1_transport_shapes() {
        let bad = addr("/ip4/203.0.113.7/udp/4001");

        let selected = select_direct_addrs(core::slice::from_ref(&bad), None, None);

        assert!(selected.is_empty());
    }

    #[test]
    fn removes_duplicates_deterministically() {
        let manual = addr("/ip4/203.0.113.7/udp/4001/quic-v1");

        let selected = select_direct_addrs(
            core::slice::from_ref(&manual),
            Some(manual.clone()),
            Some(manual.clone()),
        );

        assert_eq!(selected, vec![manual]);
    }
}
