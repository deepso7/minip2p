//! The path ledger: the one place that decides how a connection reached its
//! peer (Direct, Punched, or Relayed) and the only owner of why NAT dialed a
//! connection.
//!
//! Attempts and inbound circuits never write paths. When a connection
//! establishes, the agent asks the ledger once, passing what the machines
//! claim about it, and every machine acts on that one answer. The answer
//! follows a fixed order (see [`PathLedger::attribute`]), so it never
//! depends on which machine sees the connection first.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use minip2p_core::{ConnectId, PeerAddr, PeerId};
use minip2p_transport::ConnectionId;

use crate::swarm::NatSwarm;
use crate::types::{NatToken, Path};

/// Why NAT dialed a connection. The swarm does not know, so the ledger
/// keeps it per dial until the connection establishes or the dial fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DialPurpose {
    /// Dial of a relay address (to start a relay leg on it). The address is
    /// kept so a failure arriving after the leg moved on to another relay,
    /// or to another address of the same relay, is not taken for the
    /// current one.
    Relay(ConnectId, PeerAddr),
    /// Simultaneous-open dial of a DCUtR observed address.
    Punch(ConnectId),
    /// Dial of an AutoNAT server for a reachability probe. The server is
    /// kept so a late failure is only applied to a probe still waiting on
    /// it.
    Probe(PeerId),
    /// Dial of the relay for a reservation, keyed like [`Self::Probe`].
    Reserve(PeerId),
}

impl DialPurpose {
    pub(crate) fn connect_id(&self) -> Option<ConnectId> {
        match self {
            Self::Relay(id, _) | Self::Punch(id) => Some(*id),
            Self::Probe(_) | Self::Reserve(_) => None,
        }
    }
}

/// The NAT machine a path belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owner {
    /// A connect attempt.
    Attempt(ConnectId),
    /// An inbound circuit (a relay bridged the peer to us).
    Inbound,
}

/// What a machine claims about a connection as it establishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Claim {
    /// The circuit `owner` promoted through `relay`.
    Circuit { relay: PeerId, owner: Owner },
    /// A direct connection the attempt takes as its own: the engine dials
    /// an attempt's direct candidates, so no dial purpose records them.
    Direct(ConnectId),
}

/// How an established connection reached its peer, and the machine that
/// owns that path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Attribution {
    pub(crate) path: Path,
    /// `None` for a direct connection no machine made or claimed.
    pub(crate) owner: Option<Owner>,
}

/// A replacement that left a relay for a direct connection: reported once,
/// against the owner of the relayed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Upgrade {
    pub(crate) owner: Owner,
    pub(crate) from: Path,
    pub(crate) to: Path,
}

/// See the module docs.
#[derive(Default)]
pub(crate) struct PathLedger {
    /// Started dials still awaiting establishment or a dial failure:
    /// connection → (dial token, purpose).
    dialed: BTreeMap<ConnectionId, (NatToken, DialPurpose)>,
    /// Peers whose next direct connections are punches, until a deadline
    /// (monotonic ms). A reservation holder dials nothing, so the deadline
    /// is its only evidence that a connection is the dialer's punch.
    windows: BTreeMap<PeerId, u64>,
    /// The attribution of each established connection.
    paths: BTreeMap<ConnectionId, Attribution>,
}

impl PathLedger {
    /// Records why NAT dialed `conn_id`.
    pub(crate) fn dial_started(
        &mut self,
        conn_id: ConnectionId,
        token: NatToken,
        purpose: DialPurpose,
    ) {
        self.dialed.insert(conn_id, (token, purpose));
    }

    /// Ends the dial that made `conn_id` (it established or failed),
    /// returning its token and purpose.
    pub(crate) fn finish_dial(&mut self, conn_id: ConnectionId) -> Option<(NatToken, DialPurpose)> {
        self.dialed.remove(&conn_id)
    }

    /// Drops the dials attempt `id` (connecting to `target`) still has in
    /// flight. Returns the tokens it retired and the connections to close:
    /// those whose handshake has not established. A dial whose connection
    /// the swarm already reports established stays, its event still
    /// buffered: another attempt may have started work on it, and a punch
    /// keeps its purpose so the connection is still attributed Punched.
    pub(crate) fn abort_attempt_dials(
        &mut self,
        id: ConnectId,
        target: &PeerId,
        swarm: &dyn NatSwarm,
    ) -> (Vec<NatToken>, Vec<ConnectionId>) {
        let mut retired = Vec::new();
        let mut close = Vec::new();
        self.dialed.retain(|conn_id, (token, purpose)| {
            if purpose.connect_id() != Some(id) {
                return true;
            }
            retired.push(*token);
            let peer = match purpose {
                DialPurpose::Relay(_, addr) => addr.peer_id(),
                _ => target,
            };
            if swarm.connection(peer) != Some(*conn_id) {
                close.push(*conn_id);
                false
            } else {
                matches!(purpose, DialPurpose::Punch(_))
            }
        });
        (retired, close)
    }

    /// Opens (or extends) a window in which direct connections from `peer`
    /// are its punches, until `until` (monotonic ms, exclusive).
    pub(crate) fn expect_punches(&mut self, peer: PeerId, until: u64) {
        let end = self.windows.entry(peer).or_insert(until);
        *end = (*end).max(until);
    }

    /// Closes `peer`'s punch window early: the reservation holder gave up
    /// on the hole punch.
    pub(crate) fn end_punches(&mut self, peer: &PeerId) {
        self.windows.remove(peer);
    }

    /// Decides, once, how the just-established `conn_id` from `peer` reached
    /// it, and records that. `claim` is what the machines say about it.
    /// In order:
    ///
    /// 1. a circuit is Relayed when a machine claims it, and otherwise
    ///    unattributed (`None`);
    /// 2. a punch dial is Punched, even when an attempt to the same peer
    ///    claims it as its own direct connection;
    /// 3. an attempt's own direct connection is Direct, even inside an open
    ///    punch window;
    /// 4. a connection inside an open punch window for `peer` is Punched;
    /// 5. anything else is Direct.
    pub(crate) fn attribute(
        &mut self,
        conn_id: ConnectionId,
        peer: &PeerId,
        is_circuit: bool,
        claim: Option<Claim>,
        now_ms: u64,
    ) -> Option<Attribution> {
        let punch = |owner| Attribution {
            path: Path::Punched,
            owner: Some(owner),
        };
        let attribution = match (is_circuit, claim) {
            (true, Some(Claim::Circuit { relay, owner })) => Attribution {
                path: Path::Relayed { relay },
                owner: Some(owner),
            },
            (true, _) => return None,
            (false, claim) => match (self.dialed.get(&conn_id), claim) {
                (Some((_, DialPurpose::Punch(id))), _) => punch(Owner::Attempt(*id)),
                (_, Some(Claim::Direct(id))) => Attribution {
                    path: Path::Direct,
                    owner: Some(Owner::Attempt(id)),
                },
                _ if self.window_open(peer, now_ms) => punch(Owner::Inbound),
                _ => Attribution {
                    path: Path::Direct,
                    owner: None,
                },
            },
        };
        self.paths.insert(conn_id, attribution.clone());
        Some(attribution)
    }

    /// The upgrade, if any, that `new` replacing a connection attributed
    /// `old` represents: leaving a relayed path for a direct one.
    pub(crate) fn replaced(&self, old: &Attribution, new: ConnectionId) -> Option<Upgrade> {
        let new = self.paths.get(&new)?;
        match (&old.path, &new.path, old.owner) {
            (Path::Relayed { .. }, Path::Direct | Path::Punched, Some(owner)) => Some(Upgrade {
                owner,
                from: old.path.clone(),
                to: new.path.clone(),
            }),
            _ => None,
        }
    }

    /// Forgets `conn_id` (closed or replaced) and its dial, returning its
    /// attribution.
    pub(crate) fn forget(&mut self, conn_id: ConnectionId) -> Option<Attribution> {
        self.dialed.remove(&conn_id);
        self.paths.remove(&conn_id)
    }

    /// Whether `conn_id` is attributed to a hole punch.
    pub(crate) fn is_punched(&self, conn_id: ConnectionId) -> bool {
        self.paths
            .get(&conn_id)
            .is_some_and(|attribution| attribution.path == Path::Punched)
    }

    /// Closes the punch windows that ended by `now_ms`.
    pub(crate) fn on_tick(&mut self, now_ms: u64) {
        self.windows.retain(|_, until| *until > now_ms);
    }

    /// When the next punch window ends.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.windows.values().copied().min()
    }

    /// No punch window is open. Dial and path records are not work: they
    /// end with their dial or connection.
    pub(crate) fn is_quiet(&self) -> bool {
        self.windows.is_empty()
    }

    fn window_open(&self, peer: &PeerId, now_ms: u64) -> bool {
        self.windows.get(peer).is_some_and(|until| now_ms < *until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use minip2p_transport::ConnectionNamespace;

    fn peer(tag: u8) -> PeerId {
        PeerId::from_public_key_protobuf(&[tag; 8])
    }

    fn conn(n: u64) -> ConnectionId {
        ConnectionId::new(n)
    }

    fn circuit(n: u64) -> ConnectionId {
        ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, n).expect("circuit id")
    }

    fn attempt(n: u64) -> ConnectId {
        ConnectId::from_u64(n)
    }

    fn path(
        ledger: &mut PathLedger,
        conn_id: ConnectionId,
        claim: Option<Claim>,
        now: u64,
    ) -> Path {
        ledger
            .attribute(conn_id, &peer(1), conn_id.is_circuit(), claim, now)
            .expect("attributed")
            .path
    }

    fn punch_dial(ledger: &mut PathLedger, conn_id: ConnectionId, id: ConnectId) {
        ledger.dial_started(conn_id, NatToken(conn_id.as_u64()), DialPurpose::Punch(id));
    }

    #[test]
    fn a_punch_dial_is_punched_even_when_another_attempt_claims_it() {
        let mut ledger = PathLedger::default();
        punch_dial(&mut ledger, conn(1), attempt(1));
        let attribution = ledger
            .attribute(conn(1), &peer(1), false, Some(Claim::Direct(attempt(2))), 0)
            .expect("attributed");
        assert_eq!(
            attribution,
            Attribution {
                path: Path::Punched,
                owner: Some(Owner::Attempt(attempt(1))),
            }
        );
        assert!(ledger.is_punched(conn(1)));
    }

    #[test]
    fn a_claimed_circuit_is_relayed_and_an_unclaimed_one_is_not_attributed() {
        let mut ledger = PathLedger::default();
        let relay = peer(9);
        let claim = Claim::Circuit {
            relay: relay.clone(),
            owner: Owner::Inbound,
        };
        assert_eq!(
            path(&mut ledger, circuit(1), Some(claim), 0),
            Path::Relayed { relay }
        );
        assert_eq!(ledger.attribute(circuit(2), &peer(1), true, None, 0), None);
        assert!(!ledger.is_punched(circuit(2)));
    }

    #[test]
    fn a_punch_window_attributes_until_its_deadline() {
        let mut ledger = PathLedger::default();
        ledger.expect_punches(peer(1), 100);
        assert!(!ledger.is_quiet());
        assert_eq!(ledger.next_deadline(), Some(100));

        assert_eq!(path(&mut ledger, conn(1), None, 99), Path::Punched);
        // An attempt's own direct connection stays Direct inside the window.
        let claim = Some(Claim::Direct(attempt(1)));
        assert_eq!(path(&mut ledger, conn(2), claim, 99), Path::Direct);
        // Another peer's connection is not in the window.
        let other = ledger.attribute(conn(3), &peer(2), false, None, 99);
        assert_eq!(other.map(|a| a.path), Some(Path::Direct));
        // The deadline is exclusive, with or without a tick.
        assert_eq!(path(&mut ledger, conn(4), None, 100), Path::Direct);
        ledger.on_tick(100);
        assert!(ledger.is_quiet());
        assert_eq!(path(&mut ledger, conn(5), None, 50), Path::Direct);

        // A holder that gives up closes the window early.
        ledger.expect_punches(peer(1), 200);
        ledger.end_punches(&peer(1));
        assert!(ledger.is_quiet());
        assert_eq!(path(&mut ledger, conn(6), None, 150), Path::Direct);
    }

    #[test]
    fn replacements_report_only_leaving_a_relay() {
        let mut ledger = PathLedger::default();
        let id = attempt(1);
        let relayed = ledger
            .attribute(
                circuit(1),
                &peer(1),
                true,
                Some(Claim::Circuit {
                    relay: peer(9),
                    owner: Owner::Attempt(id),
                }),
                0,
            )
            .expect("attributed");

        // Relayed to punch.
        punch_dial(&mut ledger, conn(1), id);
        let punched = ledger
            .attribute(conn(1), &peer(1), false, None, 0)
            .expect("attributed");
        assert_eq!(
            ledger.replaced(&relayed, conn(1)),
            Some(Upgrade {
                owner: Owner::Attempt(id),
                from: relayed.path.clone(),
                to: Path::Punched,
            })
        );

        // Punch to punch.
        punch_dial(&mut ledger, conn(2), id);
        path(&mut ledger, conn(2), None, 0);
        assert_eq!(ledger.replaced(&punched, conn(2)), None);

        // Relayed to direct.
        path(&mut ledger, conn(3), None, 0);
        assert_eq!(
            ledger.replaced(&relayed, conn(3)).map(|up| up.to),
            Some(Path::Direct)
        );

        // Relayed to relayed.
        let claim = Claim::Circuit {
            relay: peer(8),
            owner: Owner::Attempt(id),
        };
        path(&mut ledger, circuit(2), Some(claim), 0);
        assert_eq!(ledger.replaced(&relayed, circuit(2)), None);
    }

    #[test]
    fn forgetting_a_connection_drops_its_dial_and_path() {
        let mut ledger = PathLedger::default();
        punch_dial(&mut ledger, conn(1), attempt(1));
        path(&mut ledger, conn(1), None, 0);
        assert!(ledger.forget(conn(1)).is_some());
        assert!(!ledger.is_punched(conn(1)));
        assert_eq!(ledger.finish_dial(conn(1)), None);
    }
}
