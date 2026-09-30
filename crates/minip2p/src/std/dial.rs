//! Name resolution for the std Endpoint: turns a `/dns*` candidate into the
//! concrete addresses to dial, without blocking the driver.
//!
//! A host can be reachable over more than one transport and more than one
//! address family, and a `/dns` name can answer with both. Deciding which of
//! those to dial is the endpoint's job rather than any one transport's: the
//! transports below it each serve one address shape, accept only `/ip4` and
//! `/ip6`, and never resolve names.
//!
//! A lookup blocks for as long as the system resolver takes, so it never runs
//! on the driver thread. [`Resolver::expand`] starts one detached thread per
//! distinct in-flight name and reports the candidate as resolving. The thread
//! wakes the driver through the transport [`WaitHandle`]; the next tick drains
//! [`Resolver::take_answers`] and hands them to the Connection-attempt engine,
//! which dials what [`answer_for`] rebuilt or records the failure.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_transport::WaitHandle;

use crate::portable::connect::{Expansion, NameAnswer};

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
struct Name<'a> {
    host: &'a str,
    filter: Option<Family>,
}

/// The name `addr` needs resolved: `Ok(None)` for an `/ip4` or `/ip6`
/// address, which is already concrete, and `Err` for one that cannot be
/// dialed or resolved at all.
fn name_of(addr: &PeerAddr) -> Result<Option<Name<'_>>, String> {
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
/// when a tick has answers, which is why one lookup serves every attempt that
/// named the host: `/dns4` and `/dns6` filter the shared answer.
pub(crate) fn answer_for(
    addr: &PeerAddr,
    answers: &BTreeMap<String, Answer>,
) -> Option<NameAnswer> {
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

/// What a lookup produced: the host's IP addresses, or the resolver's error.
pub(crate) type Answer = Result<Vec<IpAddr>, String>;

/// A blocking name lookup. Swappable only inside the crate, so tests can
/// inject one that stalls or fails; there is no public resolver API.
pub(crate) type Lookup = Arc<dyn Fn(&str) -> Answer + Send + Sync>;

/// The system resolver. The port is irrelevant to which addresses a name
/// has, so it asks with 0 and the candidate's own port is kept by [`rebuild`].
fn system_lookup(host: &str) -> Answer {
    (host, 0)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
        .map_err(|error| error.to_string())
}

/// Runs lookups off the driver and collects their answers for it.
///
/// There is no cache and no DNS-specific timeout: every answer is applied
/// once and forgotten, and the Connection attempt's deadline bounds the wait.
/// A lookup cannot be cancelled, so an answer for an attempt that has already
/// settled is simply dropped.
pub(crate) struct Resolver {
    lookup: Lookup,
    wake: WaitHandle,
    /// Names with a lookup thread running or an answer not yet taken.
    in_flight: BTreeSet<String>,
    answers_tx: Sender<(String, Answer)>,
    answers_rx: Receiver<(String, Answer)>,
}

impl Resolver {
    /// A resolver on the system lookup that wakes the driver with `wake`.
    pub(crate) fn new(wake: WaitHandle) -> Self {
        Self::with_lookup(wake, Arc::new(system_lookup))
    }

    /// A resolver on `lookup`: the test seam.
    pub(crate) fn with_lookup(wake: WaitHandle, lookup: Lookup) -> Self {
        let (answers_tx, answers_rx) = channel();
        Self {
            lookup,
            wake,
            in_flight: BTreeSet::new(),
            answers_tx,
            answers_rx,
        }
    }

    /// Admission's expand step: a concrete address is dialed as is, a name
    /// starts (or joins) its lookup and resolves later, and anything else is
    /// refused with the reason.
    pub(crate) fn expand(&mut self, addr: &PeerAddr) -> Expansion {
        match name_of(addr) {
            Err(reason) => Expansion::Refused(reason),
            Ok(None) => Expansion::Ready(vec![addr.clone()]),
            Ok(Some(Name { host, .. })) => match self.start(host) {
                Ok(()) => Expansion::Resolving,
                Err(reason) => Expansion::Refused(reason),
            },
        }
    }

    /// Starts a lookup of `host` unless one is already in flight.
    fn start(&mut self, host: &str) -> Result<(), String> {
        if self.in_flight.contains(host) {
            return Ok(());
        }
        let lookup = Arc::clone(&self.lookup);
        let answers = self.answers_tx.clone();
        let wake = self.wake.clone();
        let name = host.to_owned();
        std::thread::Builder::new()
            .name("minip2p-dns".into())
            .spawn(move || {
                let answer = lookup(&name);
                // A closed channel means the endpoint is gone and nobody
                // is waiting for this answer.
                if answers.send((name, answer)).is_ok() {
                    wake.interrupt();
                }
            })
            .map_err(|error| format!("could not start a dns lookup for {host}: {error}"))?;
        self.in_flight.insert(host.to_owned());
        Ok(())
    }

    /// Every answer that arrived since the last call, keyed by name. Each
    /// name leaves the in-flight set, so a later attempt looks it up afresh.
    pub(crate) fn take_answers(&mut self) -> BTreeMap<String, Answer> {
        let mut answers = BTreeMap::new();
        while let Ok((name, answer)) = self.answers_rx.try_recv() {
            self.in_flight.remove(&name);
            answers.insert(name, answer);
        }
        answers
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

    fn answers(host: &str, answer: Answer) -> BTreeMap<String, Answer> {
        BTreeMap::from([(host.to_string(), answer)])
    }

    fn transports(targets: Vec<PeerAddr>) -> Vec<String> {
        targets
            .iter()
            .map(|target| target.transport().to_string())
            .collect()
    }

    #[test]
    fn a_concrete_address_needs_no_resolution() {
        let mut resolver = Resolver::with_lookup(
            WaitHandle::noop(),
            Arc::new(|_| panic!("a concrete address must not be looked up")),
        );
        for text in [
            "/ip4/198.51.100.7/udp/4001/quic-v1",
            "/ip6/2001:db8::1/tcp/4001",
        ] {
            let addr = peer_addr(text);
            assert!(matches!(
                resolver.expand(&addr),
                Expansion::Ready(targets) if targets == vec![addr.clone()]
            ));
        }
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

    #[test]
    fn a_dns_component_is_resolved_as_a_name_and_not_as_an_address() {
        // An IP literal in a `/dns` component is an address wearing a
        // name's clothes; it is refused rather than taking the path meant for
        // names.
        let mut resolver = Resolver::with_lookup(
            WaitHandle::noop(),
            Arc::new(|_| panic!("an IP literal must not be looked up")),
        );
        for text in ["/dns/[::1]/tcp/4001", "/dns/127.0.0.1/tcp/4001"] {
            assert!(
                matches!(resolver.expand(&peer_addr(text)), Expansion::Refused(_)),
                "{text} is not a name to look up"
            );
        }
    }

    #[test]
    fn a_name_without_a_port_cannot_be_resolved() {
        let mut resolver = Resolver::with_lookup(
            WaitHandle::noop(),
            Arc::new(|_| panic!("a portless name must not be looked up")),
        );
        let refused = resolver.expand(&peer_addr("/dns/localhost"));
        assert!(
            matches!(&refused, Expansion::Refused(reason) if reason.contains("port")),
            "a portless name is refused"
        );
    }
}
