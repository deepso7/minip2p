//! Candidate expansion and Name-resolution answers: the seam between the
//! engine and whatever resolves `/dns*` names for it.
//!
//! The engine expands every candidate it dials through an [`Expander`]: the
//! std Endpoint's resolver (`std::dial::Resolver`), which looks names up off
//! the driver, or [`Concrete`] on portable, whose addresses are already
//! concrete. Answers come back per hostname from [`Expander::take_answers`],
//! and each consumer -- a Connection attempt's candidate or a parked NAT
//! dial -- rebuilds its own dial targets with [`answer_for`], so one lookup
//! serves every address shape that named the host.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::IpAddr;

use minip2p_core::{Multiaddr, PeerAddr, Protocol};

/// What admission's `expand` step made of one candidate address.
pub(crate) enum Expansion {
    /// Concrete addresses to dial now.
    Ready(Vec<PeerAddr>),
    /// Name resolution started; the answer arrives later through
    /// [`Expander::take_answers`].
    #[cfg_attr(
        not(any(feature = "std", test)),
        expect(dead_code, reason = "only the std Endpoint resolves names")
    )]
    Resolving,
    /// The candidate cannot be used; the reason becomes its
    /// `CandidateFailure`.
    #[cfg_attr(
        not(any(feature = "std", test)),
        expect(dead_code, reason = "portable expansion never refuses")
    )]
    Refused(String),
}

/// What a lookup produced: the host's IP addresses, or the resolver's error.
pub(crate) type Answer = Result<Vec<IpAddr>, String>;

/// Lookup answers keyed by hostname.
pub(crate) type NameAnswers = BTreeMap<String, Answer>;

/// What Name resolution made of one `/dns*` candidate: the concrete
/// addresses to dial, or why there are none.
pub(crate) type NameAnswer = Result<Vec<PeerAddr>, String>;

/// How an engine turns candidate addresses into dial targets. The engine
/// calls [`Self::take_answers`] once per drive batch and routes what it
/// returns to every Connection attempt and parked NAT dial waiting on it.
pub(crate) trait Expander {
    /// Expands one candidate: concrete addresses, a lookup under way, or a
    /// refusal with its reason.
    fn expand(&mut self, addr: &PeerAddr) -> Expansion;
    /// Every answer that arrived since the last call, keyed by hostname.
    fn take_answers(&mut self) -> NameAnswers;
}

/// Candidate expansion for portable endpoints: addresses are already
/// concrete, so expansion is the identity and there are never answers.
pub(crate) struct Concrete;

impl Expander for Concrete {
    fn expand(&mut self, addr: &PeerAddr) -> Expansion {
        Expansion::Ready(vec![addr.clone()])
    }

    fn take_answers(&mut self) -> NameAnswers {
        NameAnswers::new()
    }
}

/// Which IP family an address belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

/// The name a `/dns*` candidate asks about, and the family it wants.
pub(crate) struct Name<'a> {
    pub(crate) host: &'a str,
    filter: Option<Family>,
}

/// The name `addr` needs resolved: `Ok(None)` for an `/ip4` or `/ip6`
/// address, which is already concrete, and `Err` for one that cannot be
/// dialed or resolved at all.
pub(crate) fn name_of(addr: &PeerAddr) -> Result<Option<Name<'_>>, String> {
    let protocols = addr.transport().protocols();
    let Some((host, rest)) = protocols.split_first() else {
        return Err(invalid("dial target has no host component"));
    };
    let (host, filter) = match host {
        Protocol::Ip4(_) | Protocol::Ip6(_) => return Ok(None),
        Protocol::Dns(name) => (name.as_str(), None),
        Protocol::Dns4(name) => (name.as_str(), Some(Family::V4)),
        Protocol::Dns6(name) => (name.as_str(), Some(Family::V6)),
        _ => return Err(invalid("dial target has no host component")),
    };
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if literal.parse::<IpAddr>().is_ok() {
        return Err(invalid(
            "a /dns component must contain a DNS name, not an IP address",
        ));
    }
    // Nothing to dial without a port, and guessing one would dial a service
    // the caller never named.
    if !rest
        .iter()
        .any(|protocol| matches!(protocol, Protocol::Tcp(_) | Protocol::Udp(_)))
    {
        return Err(invalid("a dns dial target needs a /tcp or /udp port"));
    }
    Ok(Some(Name { host, filter }))
}

/// The dial targets a resolver answer gives `addr`, or why there are none.
///
/// `None` while `answers` holds nothing for `addr`'s name, so the candidate
/// keeps waiting. The engine calls this for every still-resolving candidate
/// and parked NAT dial when a batch has answers, which is why one lookup
/// serves every address that named the host: `/dns4` and `/dns6` filter the
/// shared answer, and each keeps its own port and transport.
pub(crate) fn answer_for(addr: &PeerAddr, answers: &NameAnswers) -> Option<NameAnswer> {
    let Ok(Some(Name { host, filter })) = name_of(addr) else {
        return None;
    };
    Some(match answers.get(host)? {
        Err(error) => Err(format!("dns resolution failed for {host}: {error}")),
        Ok(ips) => rebuild(addr, ips.iter().copied(), filter).and_then(|targets| {
            if targets.is_empty() {
                Err(format!(
                    "dns resolution returned no usable address for {host}"
                ))
            } else {
                Ok(targets)
            }
        }),
    })
}

/// Turns what a resolver answered into dial targets: the first address of
/// each wanted family, wearing the shape of the address that was asked about.
///
/// At most one per family is what makes one `connect` reach a dual-stack peer
/// over both: two addresses from the same family would be the same peer
/// twice. Everything after the host -- `/udp/4001/quic-v1`, `/tcp/4001` -- is
/// carried through untouched, so routing it stays the transport set's call.
fn rebuild(
    addr: &PeerAddr,
    resolved: impl IntoIterator<Item = IpAddr>,
    filter: Option<Family>,
) -> Result<Vec<PeerAddr>, String> {
    let rest = addr.transport().protocols().get(1..).unwrap_or_default();
    let mut seen = Vec::new();
    let mut targets = Vec::new();
    for ip in resolved {
        let family = Family::of(ip);
        if filter.is_some_and(|wanted| wanted != family) || seen.contains(&family) {
            continue;
        }
        seen.push(family);
        let mut expanded = vec![match ip {
            IpAddr::V4(v4) => Protocol::Ip4(v4.octets()),
            IpAddr::V6(v6) => Protocol::Ip6(v6.octets()),
        }];
        expanded.extend_from_slice(rest);
        let target = PeerAddr::new(Multiaddr::from_protocols(expanded), addr.peer_id().clone())
            .map_err(|error| invalid(format!("resolved address was not a peer addr: {error}")))?;
        targets.push(target);
    }
    Ok(targets)
}

fn invalid(reason: impl Into<String>) -> String {
    format!("invalid address for dial target: {}", reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use minip2p_identity::Ed25519Keypair;

    fn peer_addr(text: &str) -> PeerAddr {
        let transport: Multiaddr = text.parse().expect("test address parses");
        PeerAddr::new(
            transport,
            Ed25519Keypair::from_secret_key_bytes([7; 32]).peer_id(),
        )
        .expect("peer addr")
    }

    fn answers(host: &str, answer: Answer) -> NameAnswers {
        NameAnswers::from([(host.to_string(), answer)])
    }

    fn transports(targets: Vec<PeerAddr>) -> Vec<String> {
        targets
            .iter()
            .map(|target| target.transport().to_string())
            .collect()
    }

    #[test]
    fn a_family_is_dialed_once_however_many_addresses_it_answered_with() {
        let addr = peer_addr("/dns/example.invalid/udp/4001/quic-v1");
        let ips = vec![
            "198.51.100.7".parse().expect("v4"),
            "198.51.100.8".parse().expect("v4"),
            "2001:db8::1".parse().expect("v6"),
            "2001:db8::2".parse().expect("v6"),
        ];

        // Two dials over the same socket to the same peer is a wasted
        // connection, not a second path -- the point of trying more than one
        // is trying more than one *way*.
        let targets = answer_for(&addr, &answers("example.invalid", Ok(ips)))
            .expect("answered")
            .expect("targets");
        assert_eq!(
            transports(targets),
            vec![
                "/ip4/198.51.100.7/udp/4001/quic-v1".to_string(),
                "/ip6/2001:db8::1/udp/4001/quic-v1".to_string(),
            ],
            "the first answer of each family, in the order they arrived, \
             keeping everything after the host"
        );
    }

    #[test]
    fn a_family_specific_name_filters_the_shared_answer() {
        let ips: Vec<IpAddr> = vec![
            "2001:db8::1".parse().expect("v6"),
            "198.51.100.7".parse().expect("v4"),
        ];
        let shared = answers("example.invalid", Ok(ips));

        let v4 = answer_for(&peer_addr("/dns4/example.invalid/tcp/4001"), &shared)
            .expect("answered")
            .expect("targets");
        assert_eq!(transports(v4), vec!["/ip4/198.51.100.7/tcp/4001"]);

        let v6 = answer_for(&peer_addr("/dns6/example.invalid/tcp/4001"), &shared)
            .expect("answered")
            .expect("targets");
        assert_eq!(transports(v6), vec!["/ip6/2001:db8::1/tcp/4001"]);

        let only_v6 = answers(
            "example.invalid",
            Ok(vec!["2001:db8::1".parse().expect("v6")]),
        );
        let refused = answer_for(&peer_addr("/dns4/example.invalid/tcp/4001"), &only_v6)
            .expect("answered")
            .expect_err("no v4 answer");
        assert!(refused.contains("example.invalid"), "{refused}");
    }

    #[test]
    fn a_failed_lookup_names_the_host() {
        let addr = peer_addr("/dns/example.invalid/tcp/4001");
        let reason = answer_for(&addr, &answers("example.invalid", Err("NXDOMAIN".into())))
            .expect("answered")
            .expect_err("failed");
        assert!(
            reason.contains("example.invalid") && reason.contains("NXDOMAIN"),
            "{reason}"
        );
        assert!(
            answer_for(&addr, &answers("other.invalid", Err("NXDOMAIN".into()))).is_none(),
            "another name's answer leaves the candidate waiting"
        );
    }
}
