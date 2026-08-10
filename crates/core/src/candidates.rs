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
/// logging, timing, or transport side effects. It accepts any address a
/// transport can dial -- `/<host>/tcp/<port>` or
/// `/<host>/udp/<port>/quic-v1` -- and nothing else: a bare host, a circuit
/// address, or anything with a trailing `/p2p` is not something to dial
/// directly. Wildcard-host addresses and duplicates are dropped.
///
/// Which transports a host can actually dial is the host's business, not this
/// function's: an address for one it did not bind simply fails to dial, the
/// same way an unreachable address of a bound transport does. Callers that
/// need a narrower set filter further -- hole punching keeps only QUIC,
/// because that is the only transport that can be punched.
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
    if addr.transport_kind().is_none() {
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
    fn rejects_shapes_nothing_can_dial() {
        for bad in [
            // Half a QUIC address.
            "/ip4/203.0.113.7/udp/4001",
            // A host with no transport on it.
            "/ip4/203.0.113.7",
            // A whole, valid circuit address: reached by dialing the relay and
            // asking it to connect, which is not the same as dialing this.
            "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWA8EXV3KjBxEU9NMLC4ksHy4Zi8Kj9Y9Wq6ZFVvhFTa9J/p2p-circuit",
            // A dialable address wearing someone's peer id, which belongs to a
            // `PeerAddr` rather than to a transport candidate.
            "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWA8EXV3KjBxEU9NMLC4ksHy4Zi8Kj9Y9Wq6ZFVvhFTa9J",
        ] {
            let bad = addr(bad);
            let selected = select_direct_addrs(core::slice::from_ref(&bad), None, None);
            assert!(selected.is_empty(), "{bad}");
        }
    }

    #[test]
    fn accepts_every_transport_a_host_might_have_bound() {
        // A device with no operating system has no QUIC, so a TCP address is
        // the only direct candidate it can offer. Dropping it here would be
        // dropping it everywhere: this selector feeds the whole NAT agent, so
        // such a host would advertise nothing to dial and never be dialed back.
        let tcp = addr("/ip4/203.0.113.7/tcp/4001");
        let quic = addr("/ip4/203.0.113.7/udp/4001/quic-v1");

        let selected = select_direct_addrs(
            core::slice::from_ref(&tcp),
            Some(quic.clone()),
            Some(addr("/dns4/host.example.com/tcp/4001")),
        );

        assert_eq!(
            selected,
            vec![tcp, quic, addr("/dns4/host.example.com/tcp/4001")],
            "one host can offer both, and the order is still the priority order"
        );
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
