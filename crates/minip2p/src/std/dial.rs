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
//! on the driver thread. [`Resolver`]'s [`Expander::expand`] starts one
//! detached thread per distinct in-flight name and reports the candidate as
//! resolving. The thread wakes the driver through the swarm's wake-only
//! [`WakeHandle`], so the wait sees a host wakeup rather than an interrupt;
//! the next drive batch takes the answers ([`Expander::take_answers`]) and
//! the engine routes them to the Connection attempts and parked NAT dials
//! waiting on each name (see [`crate::names`]). This module keeps only the
//! OS side: the lookup threads, the wake, and the in-flight cap.

use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

use minip2p_core::PeerAddr;
use minip2p_swarm::WakeHandle;

use crate::names::{Answer, Expander, Expansion, Name, NameAnswers, name_of};

/// Lookup threads that may be blocked in the resolver at once, one per
/// distinct name.
const MAX_IN_FLIGHT_LOOKUPS: usize = 32;

/// A blocking name lookup. Swappable only inside the crate, so tests can
/// inject one that stalls or fails; there is no public resolver API.
pub(crate) type Lookup = Arc<dyn Fn(&str) -> Answer + Send + Sync>;

/// The system resolver. The port is irrelevant to which addresses a name
/// has, so it asks with 0 and each candidate keeps its own port when the
/// engine rebuilds it ([`crate::names::answer_for`]).
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
    /// Wakes the driver once an answer is queued.
    wake: Arc<dyn Fn() + Send + Sync>,
    /// Names with a lookup thread running or an answer not yet taken.
    in_flight: BTreeSet<String>,
    /// Lookup threads still blocked in the resolver; what the cap counts.
    /// An answered name leaves this at once, before its answer is taken.
    running: Arc<AtomicUsize>,
    answers_tx: Sender<(String, Answer)>,
    answers_rx: Receiver<(String, Answer)>,
}

impl Resolver {
    /// A resolver on the system lookup that wakes the driver with `wake`.
    pub(crate) fn new(wake: WakeHandle) -> Self {
        Self::with_lookup(move || wake.wake(), Arc::new(system_lookup))
    }

    /// A resolver on `lookup`: the test seam.
    pub(crate) fn with_lookup(wake: impl Fn() + Send + Sync + 'static, lookup: Lookup) -> Self {
        let (answers_tx, answers_rx) = channel();
        Self {
            lookup,
            wake: Arc::new(wake),
            in_flight: BTreeSet::new(),
            running: Arc::default(),
            answers_tx,
            answers_rx,
        }
    }

    /// Starts a lookup of `host` unless one is already in flight.
    fn start(&mut self, host: &str) -> Result<(), String> {
        if self.in_flight.contains(host) {
            return Ok(());
        }
        // A stalled resolver holds its thread until the OS gives up, so the
        // number of lookup threads is capped rather than trusted to whatever
        // candidates discovery or the application supplies.
        if self.running.load(Ordering::SeqCst) >= MAX_IN_FLIGHT_LOOKUPS {
            return Err(format!(
                "not looking up {host}: {MAX_IN_FLIGHT_LOOKUPS} dns lookups are already in flight"
            ));
        }
        let lookup = Arc::clone(&self.lookup);
        let answers = self.answers_tx.clone();
        let wake = Arc::clone(&self.wake);
        let running = Arc::clone(&self.running);
        let name = host.to_owned();
        running.fetch_add(1, Ordering::SeqCst);
        std::thread::Builder::new()
            .name("minip2p-dns".into())
            .spawn(move || {
                let answer = lookup(&name);
                running.fetch_sub(1, Ordering::SeqCst);
                // A closed channel means the endpoint is gone and nobody
                // is waiting for this answer.
                if answers.send((name, answer)).is_ok() {
                    wake();
                }
            })
            .map_err(|error| {
                self.running.fetch_sub(1, Ordering::SeqCst);
                format!("could not start a dns lookup for {host}: {error}")
            })?;
        self.in_flight.insert(host.to_owned());
        Ok(())
    }
}

/// Admission's expand step and the batch's answers: a concrete address is
/// dialed as is, a name starts (or joins) its lookup and resolves later, and
/// anything else is refused with the reason.
impl Expander for Resolver {
    fn expand(&mut self, addr: &PeerAddr) -> Expansion {
        match name_of(addr) {
            Err(reason) => Expansion::Refused(reason),
            Ok(None) => Expansion::Ready(vec![addr.clone()]),
            Ok(Some(Name { host, .. })) => match self.start(host) {
                Ok(()) => Expansion::Resolving,
                Err(reason) => Expansion::Refused(reason),
            },
        }
    }

    /// Each answered name leaves the in-flight set, so a later candidate
    /// looks it up afresh.
    fn take_answers(&mut self) -> NameAnswers {
        let mut answers = NameAnswers::new();
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
    use minip2p_core::Multiaddr;
    use minip2p_identity::Ed25519Keypair;

    fn peer_addr(text: &str) -> PeerAddr {
        let transport: Multiaddr = text.parse().expect("test address parses");
        PeerAddr::new(transport, Ed25519Keypair::generate().peer_id()).expect("peer addr")
    }

    #[test]
    fn a_concrete_address_needs_no_resolution() {
        let mut resolver = Resolver::with_lookup(
            || {},
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
    fn a_dns_component_is_resolved_as_a_name_and_not_as_an_address() {
        // An IP literal in a `/dns` component is an address wearing a
        // name's clothes; it is refused rather than taking the path meant for
        // names.
        let mut resolver = Resolver::with_lookup(
            || {},
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
            || {},
            Arc::new(|_| panic!("a portless name must not be looked up")),
        );
        let refused = resolver.expand(&peer_addr("/dns/localhost"));
        assert!(
            matches!(&refused, Expansion::Refused(reason) if reason.contains("port")),
            "a portless name is refused"
        );
    }

    #[test]
    fn lookups_in_flight_are_capped() {
        let (release_tx, release_rx) = channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let mut resolver = Resolver::with_lookup(
            || {},
            Arc::new(move |_: &str| {
                // Held until the test ends, like a dead resolver.
                match release_rx.lock().expect("lock").recv() {
                    Ok(()) | Err(_) => {}
                }
                Err("released".into())
            }),
        );
        for index in 0..MAX_IN_FLIGHT_LOOKUPS {
            let addr = peer_addr(&format!("/dns/host{index}.invalid/tcp/4001"));
            assert!(matches!(resolver.expand(&addr), Expansion::Resolving));
        }
        let refused = resolver.expand(&peer_addr("/dns/one-more.invalid/tcp/4001"));
        assert!(
            matches!(&refused, Expansion::Refused(reason) if reason.contains("one-more.invalid")),
            "a name past the cap is refused with an actionable reason"
        );
        assert!(
            matches!(
                resolver.expand(&peer_addr("/dns4/host0.invalid/tcp/4002")),
                Expansion::Resolving
            ),
            "a name already in flight still joins its lookup"
        );

        // Finished lookups free their slots before their answers are taken.
        drop(release_tx);
        while resolver.running.load(Ordering::SeqCst) > 0 {
            std::thread::yield_now();
        }
        assert!(matches!(
            resolver.expand(&peer_addr("/dns/one-more.invalid/tcp/4001")),
            Expansion::Resolving
        ));
    }
}
