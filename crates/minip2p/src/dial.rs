//! Turning one dial target into the concrete addresses to try.
//!
//! A host can be reachable over more than one transport and more than one
//! address family, and a `/dns` name can answer with both. Deciding which of
//! those to dial is the endpoint's job rather than any one transport's: the
//! transports below it each serve one address shape, and none of them can see
//! the others' sockets.
//!
//! Resolution happens here, so what reaches a transport is always a concrete
//! `/ip4` or `/ip6` address it can act on without asking the network anything.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_transport::TransportError;

/// Which IP family an address belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    V4,
    V6,
}

impl Family {
    fn of(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => Self::V4,
            SocketAddr::V6(_) => Self::V6,
        }
    }
}

/// The concrete addresses `addr` names, at most one per family.
///
/// A `/ip4` or `/ip6` target is already concrete and expands to itself. A
/// `/dns*` target is resolved and reduced to the first answer per family, which
/// is what makes one `dial` reach a dual-stack peer over both: two addresses
/// from the same family would be the same peer twice.
///
/// Everything after the host is carried through untouched, so the shape that
/// went in -- `/tcp`, `/udp/quic-v1`, whatever follows -- is the shape that
/// comes out, and routing it stays the set's decision.
pub(crate) fn targets(addr: &PeerAddr) -> Result<Vec<(Family, PeerAddr)>, TransportError> {
    let protocols = addr.transport().protocols();
    let Some(host) = protocols.first() else {
        return Err(invalid("dial target has no host component"));
    };
    let rest = &protocols[1..];

    let (name, filter) = match host {
        Protocol::Ip4(_) | Protocol::Ip6(_) => {
            let family = match host {
                Protocol::Ip4(_) => Family::V4,
                _ => Family::V6,
            };
            return Ok(vec![(family, addr.clone())]);
        }
        Protocol::Dns(name) => (name, None),
        Protocol::Dns4(name) => (name, Some(Family::V4)),
        Protocol::Dns6(name) => (name, Some(Family::V6)),
        _ => return Err(invalid("dial target has no host component")),
    };

    // The port belongs to whichever transport the address names, so it is read
    // from the address rather than assumed: `/tcp/4001` and `/udp/4001` are
    // the same query to the resolver.
    let port = rest
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Tcp(port) | Protocol::Udp(port) => Some(*port),
            _ => None,
        })
        .ok_or_else(|| invalid("a dns dial target needs a /tcp or /udp port to resolve"))?;

    // `(name, port)` rather than a reassembled `"name:port"`: the string form
    // has to be parsed back apart, and a name carrying a colon would be split
    // in the wrong place. This is the same resolution the TCP provider does.
    let resolved = (name.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| invalid(format!("dns resolution failed for {name}: {error}")))?;

    let targets = rebuild(addr, rest, resolved, filter)?;
    if targets.is_empty() {
        return Err(invalid(format!(
            "dns resolution returned no usable address for {name}"
        )));
    }
    Ok(targets)
}

/// Turns what a resolver answered into dial targets: the first address of each
/// wanted family, wearing the shape of the address that was asked about.
///
/// Split out from resolution so the choosing can be tested without a network:
/// a resolver that answers with four addresses of one family is one dial, not
/// four, and no test can make DNS produce that on demand.
fn rebuild(
    addr: &PeerAddr,
    rest: &[Protocol],
    resolved: impl IntoIterator<Item = SocketAddr>,
    filter: Option<Family>,
) -> Result<Vec<(Family, PeerAddr)>, TransportError> {
    let mut targets: Vec<(Family, PeerAddr)> = Vec::new();
    for socket_addr in resolved {
        let family = Family::of(socket_addr);
        if filter.is_some_and(|wanted| wanted != family) {
            continue;
        }
        if targets.iter().any(|(seen, _)| *seen == family) {
            continue;
        }
        let mut expanded = vec![host_protocol(socket_addr.ip())];
        expanded.extend_from_slice(rest);
        let transport = Multiaddr::from_protocols(expanded);
        let target = PeerAddr::new(transport, addr.peer_id().clone())
            .map_err(|error| invalid(format!("resolved address was not a peer addr: {error}")))?;
        targets.push((family, target));
    }
    Ok(targets)
}

fn host_protocol(ip: IpAddr) -> Protocol {
    match ip {
        IpAddr::V4(v4) => Protocol::Ip4(v4.octets()),
        IpAddr::V6(v6) => Protocol::Ip6(v6.octets()),
    }
}

fn invalid(reason: impl Into<String>) -> TransportError {
    TransportError::InvalidAddress {
        context: "dial target",
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_identity::Ed25519Keypair;

    fn peer_addr(text: &str) -> PeerAddr {
        let transport: Multiaddr = text.parse().expect("test address parses");
        PeerAddr::new(transport, Ed25519Keypair::generate().peer_id()).expect("peer addr")
    }

    #[test]
    fn a_concrete_address_is_its_own_only_target() {
        let addr = peer_addr("/ip4/198.51.100.7/udp/4001/quic-v1");
        assert_eq!(targets(&addr).expect("targets"), vec![(Family::V4, addr)]);

        let addr = peer_addr("/ip6/2001:db8::1/tcp/4001");
        assert_eq!(targets(&addr).expect("targets"), vec![(Family::V6, addr)]);
    }

    #[test]
    fn a_name_expands_to_one_target_per_family_keeping_the_shape() {
        // localhost is the one name a test may rely on, and it is exactly the
        // interesting case: it answers with both families.
        let addr = peer_addr("/dns/localhost/tcp/4001");
        let expanded = targets(&addr).expect("targets");

        assert!(
            !expanded.is_empty(),
            "localhost has to resolve to something"
        );
        for (family, target) in &expanded {
            let protocols = target.transport().protocols();
            assert!(
                matches!(
                    (family, &protocols[0]),
                    (Family::V4, Protocol::Ip4(_)) | (Family::V6, Protocol::Ip6(_))
                ),
                "the host is concrete and matches its family: {protocols:?}"
            );
            assert_eq!(
                &protocols[1..],
                &[Protocol::Tcp(4001)],
                "everything after the host is the caller's, not the resolver's"
            );
            assert_eq!(target.peer_id(), addr.peer_id());
        }
    }

    #[test]
    fn a_dns_component_is_resolved_as_a_name_and_not_as_an_address() {
        // The whole `/dns` component is the query. Reassembling it into
        // `"name:port"` and handing that to the resolver hands over something
        // that is parsed as an address first, so a bracketed IP literal in a
        // `/dns` component would resolve -- an address wearing a name's
        // clothes, taking the path meant for names. The TCP provider resolves
        // the same way, and this is the endpoint agreeing with it.
        let addr = peer_addr("/dns/[::1]/tcp/4001");
        assert!(
            matches!(targets(&addr), Err(TransportError::InvalidAddress { .. })),
            "an IP literal is not a name to look up"
        );
    }

    #[test]
    fn a_family_is_dialed_once_however_many_addresses_it_answered_with() {
        let addr = peer_addr("/dns/example.invalid/udp/4001/quic-v1");
        let answers = vec![
            "198.51.100.7:4001".parse().expect("v4"),
            "198.51.100.8:4001".parse().expect("v4"),
            "[2001:db8::1]:4001".parse().expect("v6"),
            "[2001:db8::2]:4001".parse().expect("v6"),
        ];

        // Two dials over the same socket to the same peer is a wasted
        // connection, not a second path -- the point of trying more than one
        // is trying more than one *way*.
        let targets = rebuild(
            &addr,
            &[Protocol::Udp(4001), Protocol::QuicV1],
            answers,
            None,
        )
        .expect("rebuild");
        assert_eq!(
            targets
                .iter()
                .map(|(family, target)| (*family, target.transport().to_string()))
                .collect::<Vec<_>>(),
            vec![
                (Family::V4, "/ip4/198.51.100.7/udp/4001/quic-v1".to_string()),
                (Family::V6, "/ip6/2001:db8::1/udp/4001/quic-v1".to_string()),
            ],
            "the first answer of each family, in the order they arrived"
        );
    }

    #[test]
    fn a_family_specific_name_stays_in_its_family() {
        let addr = peer_addr("/dns4/localhost/udp/4001/quic-v1");
        for (family, target) in targets(&addr).expect("targets") {
            assert_eq!(family, Family::V4, "/dns4 must not produce an ipv6 dial");
            assert!(matches!(
                target.transport().protocols()[0],
                Protocol::Ip4(_)
            ));
        }
    }

    #[test]
    fn a_name_without_a_port_cannot_be_resolved() {
        // Nothing to ask the resolver for. Guessing a port would dial a
        // service the caller never named.
        let addr = peer_addr("/dns/localhost");
        let error = targets(&addr).expect_err("no port");
        assert!(
            matches!(&error, TransportError::InvalidAddress { reason, .. } if reason.contains("port")),
            "got {error:?}"
        );
    }
}
