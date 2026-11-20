//! Connection-attempt types and the sans-I/O engine that owns them, shared
//! by both Endpoint types.
//!
//! One [`ConnectId`] covers every candidate Transport dial, relay fallback,
//! and direct-path upgrade in an attempt. The engine races complete
//! [`PeerAddr`]s through [`SwarmCore::dial`] and emits exactly one
//! [`EndpointEvent::ConnectSettled`] per admitted attempt.
//!
//! It also owns the attempt's relay leg end to end (ADR-0008): admission
//! attaches it while the attempt is still pending, cancellation cancels it,
//! NAT output is routed through the engine, and every terminal settles it.
//! The leg provider (the NAT driver, when NAT is compiled in and
//! configured) is lent to each call as [`Legs`], so no caller forks on NAT;
//! the provider itself knows nothing of this engine.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(not(feature = "autonat"))]
use core::marker::PhantomData;

use minip2p_core::platform::{Deadline, EntropySource, Now};
use minip2p_core::{Multiaddr, Path, PeerAddr, PeerId, Protocol};
use minip2p_swarm::{SwarmCore, SwarmEvent};
use minip2p_transport::{ConnectionId, Transport};

use crate::EndpointEvent;
use crate::names::{Expander, Expansion, NameAnswers, answer_for};
#[cfg(feature = "autonat")]
use crate::nat::NatDriver;

/// Default Connection-attempt deadline: 30 seconds.
pub(crate) const DEFAULT_CONNECT_DEADLINE_MS: u64 = 30_000;

pub use minip2p_core::ConnectId;

/// Peer plus zero or more complete addresses for it.
///
/// Zero addresses is a Peer-ID target: the endpoint resolves known addresses
/// and relay policy at `connect` time. Collections of addresses must name one
/// peer. Candidate order is not a public contract: every candidate is dialed
/// at start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTarget {
    peer: PeerId,
    addrs: Vec<PeerAddr>,
}

impl ConnectTarget {
    /// Peer named by the target.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    /// Candidate addresses. Empty for a Peer-ID target.
    pub fn candidates(&self) -> &[PeerAddr] {
        &self.addrs
    }
}

impl From<PeerId> for ConnectTarget {
    fn from(peer: PeerId) -> Self {
        Self {
            peer,
            addrs: Vec::new(),
        }
    }
}

impl From<&PeerId> for ConnectTarget {
    fn from(peer: &PeerId) -> Self {
        Self::from(*peer)
    }
}

impl From<PeerAddr> for ConnectTarget {
    fn from(addr: PeerAddr) -> Self {
        Self {
            peer: *addr.peer_id(),
            addrs: alloc::vec![addr],
        }
    }
}

impl From<&PeerAddr> for ConnectTarget {
    fn from(addr: &PeerAddr) -> Self {
        Self::from(addr.clone())
    }
}

impl TryFrom<Vec<PeerAddr>> for ConnectTarget {
    type Error = ConnectTargetError;

    fn try_from(addrs: Vec<PeerAddr>) -> Result<Self, Self::Error> {
        let mut iter = addrs.iter();
        let Some(first) = iter.next() else {
            return Err(ConnectTargetError::Empty);
        };
        let expected = *first.peer_id();
        for addr in iter {
            if addr.peer_id() != &expected {
                return Err(ConnectTargetError::MixedPeers {
                    expected,
                    found: *addr.peer_id(),
                });
            }
        }
        Ok(Self {
            peer: expected,
            addrs,
        })
    }
}

impl<'a> TryFrom<&'a [PeerAddr]> for ConnectTarget {
    type Error = ConnectTargetError;

    fn try_from(addrs: &'a [PeerAddr]) -> Result<Self, Self::Error> {
        Self::try_from(addrs.to_vec())
    }
}

/// Why a [`ConnectTarget`] was refused synchronously.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectTargetError {
    /// The collection was empty.
    #[error("a Connection target needs at least one complete peer address")]
    Empty,
    /// Addresses named more than one peer.
    #[error("addresses name different peers: {expected} and {found}")]
    MixedPeers {
        /// Peer named by the first address.
        expected: PeerId,
        /// Peer named by a later address.
        found: PeerId,
    },
}

impl From<core::convert::Infallible> for ConnectTargetError {
    fn from(never: core::convert::Infallible) -> Self {
        match never {}
    }
}

/// Terminal outcome; exactly one per admitted attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectOutcome {
    /// A transport connection to the target peer is established.
    Connected {
        conn_id: ConnectionId,
        /// The connection's [`Path`] when the attempt settled. It stays
        /// true after the connection is replaced or closed, when
        /// `connection_info(conn_id)` no longer answers.
        path: Path,
    },
    /// The attempt ended without a connection.
    Failed(ConnectFailure),
    /// `PortableEndpoint::cancel_connect` / `Endpoint::cancel_connect` (std)
    /// ran while the attempt was still unsettled.
    Cancelled,
}

/// Why a Connection attempt failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectFailure {
    /// No route ever started: every candidate was refused before a
    /// Transport dial, and no relay was tried.
    #[error("no usable route: {}{}", no_usable_route_detail(.candidates, .relays), relay_suffix(.relays))]
    NoUsableRoute {
        /// Per-candidate refusals (no transport, DNS produced nothing, …).
        candidates: Vec<CandidateFailure>,
        /// Relay-leg diagnostics when a relay leg was in play but none of
        /// its relays started.
        relays: Vec<RelayFailure>,
    },
    /// Routes started (direct dials, relays, or both) and every one failed.
    /// A relay-only attempt whose relays all failed lands here too.
    #[error("every route failed: {}{}", candidate_summary(.candidates), relay_suffix(.relays))]
    AllRoutesFailed {
        /// Per-candidate dial failures.
        candidates: Vec<CandidateFailure>,
        /// One failure per relay address tried, in order.
        relays: Vec<RelayFailure>,
    },
    /// The attempt deadline elapsed with dials still pending.
    #[error("connect deadline elapsed after {elapsed_ms} ms{}", relay_suffix(.relays))]
    Timeout {
        /// Milliseconds from admit to the tick that expired the attempt.
        elapsed_ms: u64,
        /// Failures observed before the deadline, plus pending candidates.
        candidates: Vec<CandidateFailure>,
        /// One failure per relay address tried, then the relay still pending.
        relays: Vec<RelayFailure>,
    },
}

/// Why the relay leg of a Connection attempt failed, or why it had not
/// settled when the attempt did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayFailure {
    /// The relay (peer and address) being tried, when one had started.
    pub relay: Option<PeerAddr>,
    /// Transport, protocol, or policy reason.
    pub reason: String,
}

impl core::fmt::Display for RelayFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.relay {
            Some(relay) => write!(f, "relay {relay}: {}", self.reason),
            None => write!(f, "relay: {}", self.reason),
        }
    }
}

/// Whether this attempt may wait on a NAT relay leg.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayPolicy {
    /// Direct candidates only.
    None,
    /// Race direct candidates against the relay; Relayed is provisional.
    #[cfg_attr(
        all(not(test), not(feature = "autonat")),
        expect(
            dead_code,
            reason = "only NAT-enabled compositions construct a racing relay policy"
        )
    )]
    Race,
    /// Race direct candidates against a relay leg that never upgrades
    /// (DCUtR off): Relayed is provisional only while a direct candidate is
    /// still in the race.
    #[cfg_attr(
        all(not(test), not(feature = "autonat")),
        expect(
            dead_code,
            reason = "only NAT-enabled compositions construct a racing relay policy"
        )
    )]
    RaceWithoutUpgrade,
    /// Skip direct racing; a circuit is a terminal Connected path.
    #[cfg_attr(
        all(not(test), not(feature = "autonat")),
        expect(
            dead_code,
            reason = "only NAT-enabled compositions construct a forced relay policy"
        )
    )]
    Forced,
}

impl RelayPolicy {
    /// Whether an established circuit ends the attempt as Connected, given
    /// whether a direct candidate is still in the race.
    fn circuit_settles(self, racing_direct: bool) -> bool {
        match self {
            Self::None | Self::Forced => true,
            Self::RaceWithoutUpgrade => !racing_direct,
            Self::Race => false,
        }
    }
}

/// One candidate's failure diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateFailure {
    /// Address that could not be used.
    pub addr: PeerAddr,
    /// Transport or resolution error text.
    pub reason: String,
}

fn no_usable_route_detail(candidates: &[CandidateFailure], relays: &[RelayFailure]) -> String {
    if candidates.is_empty() {
        if relays.is_empty() {
            String::from("no known addresses and no relay configured")
        } else {
            String::from("no known addresses")
        }
    } else {
        candidate_summary(candidates)
    }
}

fn relay_suffix(relays: &[RelayFailure]) -> String {
    relays
        .iter()
        .map(|failure| format!("; {failure}"))
        .collect()
}

fn candidate_summary(candidates: &[CandidateFailure]) -> String {
    candidates
        .iter()
        .map(|failure| format!("{} ({})", failure.addr, failure.reason))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One attempt's candidates, sorted by admission.
#[derive(Default)]
pub(crate) struct Candidates {
    /// Concrete addresses to dial now.
    pub(crate) ready: Vec<PeerAddr>,
    /// `/dns*` candidates whose Name resolution is under way.
    pub(crate) resolving: Vec<PeerAddr>,
    /// Candidates already refused, with why.
    pub(crate) refused: Vec<CandidateFailure>,
}

impl Candidates {
    /// Concrete addresses only.
    #[cfg(test)]
    pub(crate) fn ready(ready: Vec<PeerAddr>) -> Self {
        Self {
            ready,
            ..Self::default()
        }
    }
}

/// Sans-I/O engine that owns Connection attempts for both Endpoint compositions.
pub(crate) struct ConnectEngine {
    next_id: u64,
    /// Relative attempt budget in milliseconds (not an absolute clock reading).
    deadline_ms: u64,
    attempts: BTreeMap<ConnectId, Attempt>,
    /// Conn ids whose `DialFailed` may already be queued after settle/cancel.
    /// Consumed on observe so a same-batch loser failure does not reach the app.
    suppressed: BTreeSet<ConnectionId>,
    /// Our dials still open after a direct connection settled their
    /// attempts, per peer (see [`Self::peer_connected`]). Whatever has not
    /// ended on its own is aborted when the window ends.
    retained: BTreeMap<PeerId, RetainedDials>,
    /// Connections settled on before their own `ConnectionEstablished` or
    /// `ConnectionReplaced` was observed (see [`Self::peer_connected`]).
    /// Their terminals wait for that event: NAT records a punch on it.
    unannounced: BTreeSet<ConnectionId>,
    events: VecDeque<Terminal>,
    /// Queued Connected terminals still without a path, so
    /// [`Self::resolve_paths`] skips the scan when none is left.
    unresolved: usize,
}

/// A queued attempt terminal. A Connected one names only its connection,
/// and a circuit's relay, until [`ConnectEngine::resolve_paths`] adds the
/// path.
enum Terminal {
    Connected {
        connect_id: ConnectId,
        peer_id: PeerId,
        conn_id: ConnectionId,
        /// The relay of a circuit, read while the swarm still recorded it.
        circuit_relay: Option<PeerId>,
    },
    Settled(EndpointEvent),
}

/// Dials kept open while a connection race to one peer settles.
struct RetainedDials {
    dials: BTreeSet<ConnectionId>,
    /// Absolute mono-ms at which the tie-break no longer applies.
    expires_ms: u64,
}

struct Attempt {
    peer: PeerId,
    started_ms: u64,
    /// Absolute mono-ms when this attempt expires (`started_ms +` engine budget).
    expires_ms: u64,
    direct: BTreeMap<ConnectionId, PeerAddr>,
    /// `/dns*` candidates whose Name resolution has not answered yet. Each
    /// joins `direct` or `failed` when [`ConnectEngine::resolved`] sees it.
    resolving: Vec<PeerAddr>,
    /// True once at least one route started: a Transport dial, or a relay
    /// the NAT leg began trying.
    dialed_any: bool,
    failed: Vec<CandidateFailure>,
    relay: RelayLeg,
    /// One failure per relay address the leg gave up on, in order.
    relay_failures: Vec<RelayFailure>,
}

impl Attempt {
    /// Whether a direct candidate is still in the race: dialing, or waiting on
    /// Name resolution to become a dial.
    fn racing_direct(&self) -> bool {
        !self.direct.is_empty() || !self.resolving.is_empty()
    }

    /// Every relay failure so far, plus the relay still being tried with
    /// `pending_reason` when the leg is still live.
    fn relay_diagnostics(&self, pending_reason: Option<&str>) -> Vec<RelayFailure> {
        let mut relays = self.relay_failures.clone();
        if let (
            RelayLeg::Pending { relay, .. } | RelayLeg::Provisional { relay, .. },
            Some(reason),
        ) = (&self.relay, pending_reason)
        {
            relays.push(RelayFailure {
                relay: relay.clone(),
                reason: String::from(reason),
            });
        }
        relays
    }
}

enum RelayLeg {
    None,
    /// `relay` is the relay currently being tried, once the leg started one.
    Pending {
        policy: RelayPolicy,
        relay: Option<PeerAddr>,
    },
    /// `conn_id` is an established circuit through `circuit_relay`.
    Provisional {
        conn_id: ConnectionId,
        circuit_relay: PeerId,
        policy: RelayPolicy,
        relay: Option<PeerAddr>,
    },
    #[cfg_attr(
        not(feature = "autonat"),
        expect(dead_code, reason = "only observe_nat constructs a failed relay leg",)
    )]
    Failed,
}

impl RelayLeg {
    fn from_policy(policy: RelayPolicy) -> Self {
        match policy {
            RelayPolicy::None => Self::None,
            policy => Self::Pending {
                policy,
                relay: None,
            },
        }
    }

    #[cfg_attr(
        not(feature = "autonat"),
        expect(dead_code, reason = "only observe_nat records the relay")
    )]
    fn set_relay(&mut self, started: PeerAddr) {
        if let Self::Pending { relay, .. } | Self::Provisional { relay, .. } = self {
            *relay = Some(started);
        }
    }

    #[cfg_attr(
        not(feature = "autonat"),
        expect(dead_code, reason = "only observe_nat reads the relay")
    )]
    fn relay(&self) -> Option<&PeerAddr> {
        match self {
            Self::Pending { relay, .. } | Self::Provisional { relay, .. } => relay.as_ref(),
            Self::None | Self::Failed => None,
        }
    }
}

impl ConnectEngine {
    pub(crate) fn new(deadline_ms: u64) -> Self {
        Self {
            next_id: 1,
            deadline_ms,
            attempts: BTreeMap::new(),
            suppressed: BTreeSet::new(),
            retained: BTreeMap::new(),
            unannounced: BTreeSet::new(),
            events: VecDeque::new(),
            unresolved: 0,
        }
    }

    /// Admits one attempt. Terminal events are queued, not returned.
    #[cfg(test)]
    pub(crate) fn connect<T: Transport, E: EntropySource>(
        &mut self,
        target: ConnectTarget,
        runtime: &mut SwarmCore<T, E>,
        now_ms: u64,
    ) -> ConnectId {
        self.connect_candidates(
            *target.peer_id(),
            Candidates::ready(target.candidates().to_vec()),
            RelayPolicy::None,
            runtime,
            now_ms,
        )
    }

    /// Like [`Self::connect`], with candidates as admission sorted them and
    /// a relay-leg policy.
    pub(crate) fn connect_candidates<T: Transport, E: EntropySource>(
        &mut self,
        peer: PeerId,
        candidates: Candidates,
        relay: RelayPolicy,
        runtime: &mut SwarmCore<T, E>,
        now_ms: u64,
    ) -> ConnectId {
        let Candidates {
            ready: candidates,
            resolving,
            refused: extra_failed,
        } = candidates;
        let id = self.alloc();
        if let Some(conn_id) = runtime.connection_id(&peer)
            && let Ok(circuit_relay) = settle_record(runtime, conn_id)
        {
            self.push_connected(id, peer, conn_id, circuit_relay);
            return id;
        }

        let mut direct = BTreeMap::new();
        let mut failed = extra_failed;
        for addr in candidates {
            match runtime.dial(&addr) {
                Ok(conn_id) => {
                    direct.insert(conn_id, addr);
                }
                Err(error) => failed.push(CandidateFailure {
                    addr,
                    reason: error.to_string(),
                }),
            }
        }
        let dialed_any = !direct.is_empty();
        let relay = RelayLeg::from_policy(relay);

        if direct.is_empty() && resolving.is_empty() && matches!(relay, RelayLeg::None) {
            self.push_settled(
                id,
                peer,
                ConnectOutcome::Failed(ConnectFailure::NoUsableRoute {
                    candidates: failed,
                    relays: Vec::new(),
                }),
            );
            return id;
        }

        self.attempts.insert(
            id,
            Attempt {
                peer,
                started_ms: now_ms,
                expires_ms: now_ms.saturating_add(self.deadline_ms),
                direct,
                resolving,
                dialed_any,
                failed,
                relay,
                relay_failures: Vec::new(),
            },
        );
        id
    }

    /// Feeds Name resolution answers to every attempt waiting on one.
    ///
    /// Each still-resolving candidate rebuilds its own dial targets from the
    /// answer for its name ([`answer_for`]): no answer keeps it waiting, a
    /// usable one dials the concrete addresses, and a failed one records a
    /// failed candidate. An attempt left with no direct candidate and no
    /// relay leg settles as failed. Answers for attempts that already
    /// settled have nowhere to go and are dropped.
    pub(crate) fn resolved<T: Transport, E: EntropySource>(
        &mut self,
        answers: &NameAnswers,
        runtime: &mut SwarmCore<T, E>,
    ) {
        if answers.is_empty() {
            return;
        }
        let ids: Vec<ConnectId> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| !attempt.resolving.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let Some(mut attempt) = self.attempts.remove(&id) else {
                continue;
            };
            let mut answered = false;
            for addr in core::mem::take(&mut attempt.resolving) {
                match answer_for(&addr, answers) {
                    None => attempt.resolving.push(addr),
                    Some(Ok(addrs)) => {
                        answered = true;
                        for addr in addrs {
                            match runtime.dial(&addr) {
                                Ok(conn_id) => {
                                    attempt.dialed_any = true;
                                    attempt.direct.insert(conn_id, addr);
                                }
                                Err(error) => attempt.failed.push(CandidateFailure {
                                    addr,
                                    reason: error.to_string(),
                                }),
                            }
                        }
                    }
                    Some(Err(reason)) => {
                        answered = true;
                        attempt.failed.push(CandidateFailure { addr, reason });
                    }
                }
            }
            if answered && !attempt.racing_direct() {
                self.settle_if_exhausted(id, attempt);
            } else {
                self.attempts.insert(id, attempt);
            }
        }
    }

    pub(crate) fn is_pending(&self, id: ConnectId) -> bool {
        self.attempts.contains_key(&id)
    }

    /// Whether admission left the attempt racing a direct candidate: a dial,
    /// or a name still resolving into one. [`Self::admit`] reads this
    /// snapshot when it attaches the relay leg, which staggers itself behind
    /// direct dials; it does not track later direct-dial failures.
    #[cfg(feature = "autonat")]
    fn dialed_direct(&self, id: ConnectId) -> bool {
        self.attempts.get(&id).is_some_and(Attempt::racing_direct)
    }

    /// When the pending attempt expires, in monotonic ms. [`Self::admit`]
    /// hands it to the relay leg so relays split time the attempt has.
    #[cfg(feature = "autonat")]
    fn expires_ms(&self, id: ConnectId) -> Option<u64> {
        self.attempts.get(&id).map(|attempt| attempt.expires_ms)
    }

    /// Cancels the attempt in this engine alone (see [`Self::cancel`] for
    /// its relay leg). Idempotent. Settled or unknown ids are a no-op. Never
    /// disconnects.
    fn abort_attempt<T: Transport, E: EntropySource>(
        &mut self,
        id: ConnectId,
        runtime: &mut SwarmCore<T, E>,
    ) {
        let Some(attempt) = self.attempts.remove(&id) else {
            return;
        };
        self.abort_pending(runtime, attempt.direct.keys().copied());
        self.push_settled(id, attempt.peer, ConnectOutcome::Cancelled);
    }

    /// Sees every swarm event before the app. Returns true when the event is
    /// consumed (owned/suppressed [`SwarmEvent::DialFailed`]).
    ///
    /// [`SwarmEvent::ConnectionEstablished`] for the attempt's peer settles
    /// Connected and aborts the other candidates; the event itself still
    /// passes through. The matching [`EndpointEvent::ConnectSettled`] is
    /// queued immediately after, so drains see Established then Settled.
    pub(crate) fn observe<T: Transport, E: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        runtime: &mut SwarmCore<T, E>,
        now_ms: u64,
    ) -> bool {
        match event {
            SwarmEvent::DialFailed {
                conn_id,
                addr,
                reason,
            } => {
                self.forget_retained(*conn_id);
                if self.suppressed.remove(conn_id) {
                    return true;
                }
                let Some(id) = self.owner(*conn_id) else {
                    return false;
                };
                let Some(mut attempt) = self.attempts.remove(&id) else {
                    return false;
                };
                attempt.direct.remove(conn_id);
                attempt.failed.push(CandidateFailure {
                    addr: addr.clone(),
                    reason: reason.clone(),
                });
                if !attempt.racing_direct() {
                    self.settle_if_exhausted(id, attempt);
                } else {
                    self.attempts.insert(id, attempt);
                }
                true
            }
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                self.unannounced.remove(conn_id);
                self.peer_connected(peer_id, *conn_id, runtime, now_ms);
                false
            }
            SwarmEvent::ConnectionReplaced {
                peer_id, old, new, ..
            } => {
                self.unannounced.remove(new);
                // `old` has ended as surely as a closed one, even when `new`
                // is already gone too and so takes no attempt's place.
                self.provisional_ended(*old);
                // `new` satisfies every pending attempt for the peer exactly
                // as a first establishment would, whichever side made it.
                self.peer_connected(peer_id, *new, runtime, now_ms);
                false
            }
            SwarmEvent::ConnectionClosed { conn_id, .. } => {
                self.provisional_ended(*conn_id);
                false
            }
            _ => false,
        }
    }

    /// Returns every attempt provisional on `conn_id`, which the swarm let
    /// go, to waiting on its relay leg.
    fn provisional_ended(&mut self, conn_id: ConnectionId) {
        for attempt in self.attempts.values_mut() {
            if let RelayLeg::Provisional {
                conn_id: provisional,
                policy,
                ref relay,
                ..
            } = attempt.relay
                && provisional == conn_id
            {
                attempt.relay = RelayLeg::Pending {
                    policy,
                    relay: relay.clone(),
                };
            }
        }
    }

    /// `conn_id` is now the peer's connection. Every in-flight attempt for
    /// the peer succeeds together: the swarm keeps one connection per peer,
    /// so a later attempt's dial (or an inbound) is success for the earlier
    /// ones too. A circuit is only provisional while a direct leg can still
    /// win; it becomes the attempt's provisional path, replacing an older
    /// provisional circuit.
    ///
    /// Settling on a direct connection keeps the attempt's other direct dials
    /// open rather than aborting them: the peer may already have accepted
    /// one, and the swarm settles such races the same way on both sides
    /// (within its simultaneous-dial window) only if both sides see both
    /// connections. Against our own dial they race by connection token;
    /// against the peer's dial, when we are the lower peer, ours can only
    /// replace it. Their failures stay inside the engine, and they stay
    /// bounded: whatever has not ended on its own is aborted once the window
    /// ends. The higher peer settled by the peer's dial, and any circuit,
    /// aborts them at once: those dials lose on both sides anyway.
    fn peer_connected<T: Transport, E: EntropySource>(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        runtime: &mut SwarmCore<T, E>,
        now_ms: u64,
    ) {
        // Abort Ok(false) tombstones may never see DialFailed once the
        // candidate has established — drop the stale id here.
        self.suppressed.remove(&conn_id);
        // The swarm registers a whole transport batch before the engine sees
        // any of it, so a later connection in the same batch (another of our
        // candidates winning the same-direction race) may already hold the
        // slot. Settle on that now rather than on a connection the swarm has
        // already let go: waiting for its queued `ConnectionReplaced` would let
        // a `DialFailed` queued in between exhaust the attempt. Retired without
        // failing, `conn_id` leaves the race, so nothing aborts it. (When the
        // slot is already empty again, every connection of the batch is gone
        // and settling on `conn_id` is as good as any; its close is queued.
        // Not for a circuit: the swarm forgot the address naming its relay,
        // so it has no path to settle on, and it leaves the race.) The slot
        // holder's own event is still queued, so its path waits for it.
        if let Some(current) = runtime.connection_id(peer_id)
            && current != conn_id
        {
            self.forget_retained(conn_id);
            for attempt in self.attempts.values_mut() {
                attempt.direct.remove(&conn_id);
            }
            self.unannounced.insert(current);
            self.peer_connected(peer_id, current, runtime, now_ms);
            return;
        }
        let Ok(circuit_relay) = settle_record(runtime, conn_id) else {
            return;
        };
        // A kept dial that took the slot leaves the race; the rest stay in
        // it, as one may still win at the peer. A direct connection taking
        // the slot restarts the swarm's window, so theirs restarts with it.
        // Whether it is our dial comes from the swarm, which records it for
        // the slot holder: the attempt that made it, or its retained entry,
        // may be gone by the time the engine sees it establish. Engine
        // bookkeeping covers a slot already empty again.
        let ours = runtime.is_outbound(conn_id).unwrap_or_else(|| {
            self.owner(conn_id).is_some()
                || self
                    .retained
                    .get(peer_id)
                    .is_some_and(|retained| retained.dials.contains(&conn_id))
        });
        self.forget_retained(conn_id);
        let circuit = conn_id.is_circuit();
        let keep_dials = !circuit && (ours || runtime.local_peer_id() < peer_id);
        if keep_dials {
            if let Some(retained) = self.retained.get_mut(peer_id) {
                retained.expires_ms = retained
                    .expires_ms
                    .max(now_ms.saturating_add(runtime.simultaneous_dial_window_ms()));
            }
        } else if !circuit {
            // The peer's dial won as the lower peer: every dial of ours now
            // loses on both sides, including those kept from earlier.
            self.abort_retained(peer_id, runtime);
        }
        let ids: Vec<ConnectId> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| &attempt.peer == peer_id)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let Some(mut attempt) = self.attempts.remove(&id) else {
                continue;
            };
            let settle = match attempt.relay {
                _ if !circuit => true,
                RelayLeg::None | RelayLeg::Failed => true,
                RelayLeg::Pending { policy, .. } | RelayLeg::Provisional { policy, .. } => {
                    policy.circuit_settles(attempt.racing_direct())
                }
            };
            if settle {
                let pending = attempt
                    .direct
                    .keys()
                    .copied()
                    .filter(|pending| *pending != conn_id);
                if keep_dials {
                    let pending: Vec<ConnectionId> = pending.collect();
                    self.suppressed.extend(pending.iter().copied());
                    // A later settle opens a new window for every kept dial.
                    let expires_ms = now_ms.saturating_add(runtime.simultaneous_dial_window_ms());
                    if let Some(retained) = self.retained.get_mut(peer_id) {
                        retained.expires_ms = retained.expires_ms.max(expires_ms);
                        retained.dials.extend(pending);
                    } else if !pending.is_empty() {
                        self.retained.insert(
                            *peer_id,
                            RetainedDials {
                                dials: pending.into_iter().collect(),
                                expires_ms,
                            },
                        );
                    }
                } else {
                    self.abort_pending(runtime, pending);
                }
                self.push_connected(id, attempt.peer, conn_id, circuit_relay);
                continue;
            }
            // Only a circuit reaches here, so its relay is known.
            if let Some(circuit_relay) = circuit_relay
                && let RelayLeg::Pending { policy, relay }
                | RelayLeg::Provisional { policy, relay, .. } = attempt.relay
            {
                attempt.relay = RelayLeg::Provisional {
                    conn_id,
                    circuit_relay,
                    policy,
                    relay,
                };
            }
            self.attempts.insert(id, attempt);
        }
    }

    /// Aborts the dials kept open for a race to `peer`, so an
    /// explicit disconnect is not undone by one of them landing later.
    pub(crate) fn abort_retained<T: Transport, E: EntropySource>(
        &mut self,
        peer: &PeerId,
        runtime: &mut SwarmCore<T, E>,
    ) {
        if let Some(retained) = self.retained.remove(peer) {
            self.abort_pending(runtime, retained.dials);
        }
    }

    /// Settles attempts whose deadline passed and ends lapsed kept-dial
    /// windows; see [`Self::expire`].
    fn tick<T: Transport, E: EntropySource>(&mut self, runtime: &mut SwarmCore<T, E>, now_ms: u64) {
        let lapsed: Vec<PeerId> = self
            .retained
            .iter()
            .filter(|(_, retained)| now_ms >= retained.expires_ms)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in lapsed {
            if let Some(retained) = self.retained.remove(&peer) {
                self.abort_pending(runtime, retained.dials);
            }
        }
        let expired: Vec<ConnectId> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| now_ms >= attempt.expires_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            let Some(mut attempt) = self.attempts.remove(&id) else {
                continue;
            };
            if let RelayLeg::Provisional {
                conn_id,
                circuit_relay,
                ..
            } = attempt.relay
            {
                self.abort_pending(runtime, attempt.direct.keys().copied());
                self.push_connected(id, attempt.peer, conn_id, Some(circuit_relay));
                continue;
            }
            let relays = attempt.relay_diagnostics(Some("relay leg still pending"));
            for (conn_id, addr) in attempt.direct.iter() {
                attempt.failed.push(CandidateFailure {
                    addr: addr.clone(),
                    reason: String::from("connect deadline elapsed"),
                });
                self.abort_one(runtime, *conn_id);
            }
            for addr in attempt.resolving.drain(..) {
                attempt.failed.push(CandidateFailure {
                    addr,
                    reason: String::from("connect deadline elapsed while resolving the name"),
                });
            }
            self.push_settled(
                id,
                attempt.peer,
                ConnectOutcome::Failed(ConnectFailure::Timeout {
                    elapsed_ms: now_ms.saturating_sub(attempt.started_ms),
                    candidates: attempt.failed,
                    relays,
                }),
            );
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Deadline> {
        if !self.events.is_empty() {
            return Some(Deadline::IMMEDIATE);
        }
        self.attempts
            .values()
            .map(|attempt| attempt.expires_ms)
            .chain(self.retained.values().map(|retained| retained.expires_ms))
            .min()
            .map(Deadline::from_millis)
    }

    /// Names the path of every queued Connected terminal whose connection's
    /// own lifecycle event has been observed: Relayed through a circuit's
    /// recorded relay, else Punched when `punched` says NAT recorded a punch
    /// on it, else Direct. [`Self::route`] and [`Self::expire`] run this as
    /// soon as the step that settled them (or, for one settled ahead of that
    /// event, the event's ingest) ends: NAT has recorded a punch, and no
    /// later event of the batch has ended the connection yet.
    fn resolve_paths(&mut self, mut punched: impl FnMut(ConnectionId) -> bool) {
        if self.unresolved == 0 {
            return;
        }
        for terminal in &mut self.events {
            if let Terminal::Connected {
                connect_id,
                peer_id,
                conn_id,
                circuit_relay,
            } = terminal
                && !self.unannounced.contains(conn_id)
            {
                let path = match circuit_relay.take() {
                    Some(relay) => Path::Relayed { relay },
                    None if punched(*conn_id) => Path::Punched,
                    None => Path::Direct,
                };
                self.unresolved -= 1;
                *terminal = Terminal::Settled(EndpointEvent::ConnectSettled {
                    connect_id: *connect_id,
                    peer_id: *peer_id,
                    outcome: ConnectOutcome::Connected {
                        conn_id: *conn_id,
                        path,
                    },
                });
            }
        }
    }

    /// Pops the next terminal once [`Self::resolve_paths`] has named its path.
    fn pop_event(&mut self) -> Option<EndpointEvent> {
        match self.events.pop_front()? {
            Terminal::Settled(event) => Some(event),
            unresolved => {
                debug_assert!(
                    false,
                    "a Connected terminal is popped before its path is resolved"
                );
                self.events.push_front(unresolved);
                None
            }
        }
    }

    fn alloc(&mut self) -> ConnectId {
        let id = ConnectId::from_u64(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Drops a retained dial that ended on its own.
    fn forget_retained(&mut self, conn_id: ConnectionId) {
        self.retained.retain(|_, retained| {
            retained.dials.remove(&conn_id);
            !retained.dials.is_empty()
        });
    }

    fn owner(&self, conn_id: ConnectionId) -> Option<ConnectId> {
        self.attempts
            .iter()
            .find(|(_, attempt)| attempt.direct.contains_key(&conn_id))
            .map(|(id, _)| *id)
    }

    fn settle_if_exhausted(&mut self, id: ConnectId, attempt: Attempt) {
        match attempt.relay {
            RelayLeg::Provisional {
                conn_id,
                ref circuit_relay,
                policy,
                ..
            } if policy.circuit_settles(attempt.racing_direct()) => {
                let circuit_relay = *circuit_relay;
                self.push_connected(id, attempt.peer, conn_id, Some(circuit_relay));
            }
            RelayLeg::Pending { .. } | RelayLeg::Provisional { .. } => {
                self.attempts.insert(id, attempt);
            }
            RelayLeg::Failed if attempt.racing_direct() => {
                self.attempts.insert(id, attempt);
            }
            RelayLeg::None | RelayLeg::Failed => {
                let relays = attempt.relay_diagnostics(None);
                let failure = if attempt.dialed_any {
                    ConnectFailure::AllRoutesFailed {
                        candidates: attempt.failed,
                        relays,
                    }
                } else {
                    ConnectFailure::NoUsableRoute {
                        candidates: attempt.failed,
                        relays,
                    }
                };
                self.push_settled(id, attempt.peer, ConnectOutcome::Failed(failure));
            }
        }
    }

    /// Applies one routed NAT event to the attempt it names.
    #[cfg(feature = "autonat")]
    fn observe_nat<T: Transport, E: EntropySource>(
        &mut self,
        event: &minip2p_nat::NatEvent,
        runtime: &mut SwarmCore<T, E>,
        _now_ms: u64,
    ) {
        use minip2p_nat::NatEvent;
        match event {
            NatEvent::RelayStarted { connect_id, relay } => {
                if let Some(attempt) = self.attempts.get_mut(connect_id) {
                    attempt.dialed_any = true;
                    attempt.relay.set_relay(relay.clone());
                }
            }
            NatEvent::RelayFailed {
                connect_id,
                relay,
                error,
            } => {
                if let Some(attempt) = self.attempts.get_mut(connect_id) {
                    // Track the relay even when it was refused before it
                    // started, so `ConnectFailed` for it is not recorded twice.
                    attempt.relay.set_relay(relay.clone());
                    attempt.relay_failures.push(RelayFailure {
                        relay: Some(relay.clone()),
                        reason: error.to_string(),
                    });
                }
            }
            NatEvent::ConnectFailed {
                connect_id, error, ..
            } => {
                let Some(mut attempt) = self.attempts.remove(connect_id) else {
                    return;
                };
                // The last relay's own failure is already recorded; any
                // other leg-ending error is added once.
                let failure = RelayFailure {
                    relay: attempt.relay.relay().cloned(),
                    reason: error.to_string(),
                };
                if attempt.relay_failures.last() != Some(&failure) {
                    attempt.relay_failures.push(failure);
                }
                attempt.relay = RelayLeg::Failed;
                self.settle_if_exhausted(*connect_id, attempt);
            }
            NatEvent::FellBackToRelay { connect_id, .. } => {
                let Some(attempt) = self.attempts.remove(connect_id) else {
                    return;
                };
                if let RelayLeg::Provisional {
                    conn_id,
                    circuit_relay,
                    ..
                } = attempt.relay
                {
                    self.abort_pending(runtime, attempt.direct.keys().copied());
                    self.push_connected(*connect_id, attempt.peer, conn_id, Some(circuit_relay));
                } else {
                    self.attempts.insert(*connect_id, attempt);
                }
            }
            NatEvent::PathEstablished { .. }
            | NatEvent::PathUpgraded { .. }
            | NatEvent::HolePunchFailed { .. } => {}
            _ => {}
        }
    }

    /// Queues a Connected terminal; its path is resolved later (see
    /// [`Self::resolve_paths`]).
    fn push_connected(
        &mut self,
        connect_id: ConnectId,
        peer_id: PeerId,
        conn_id: ConnectionId,
        circuit_relay: Option<PeerId>,
    ) {
        self.unresolved += 1;
        self.events.push_back(Terminal::Connected {
            connect_id,
            peer_id,
            conn_id,
            circuit_relay,
        });
    }

    fn push_settled(&mut self, connect_id: ConnectId, peer_id: PeerId, outcome: ConnectOutcome) {
        self.events
            .push_back(Terminal::Settled(EndpointEvent::ConnectSettled {
                connect_id,
                peer_id,
                outcome,
            }));
    }

    fn abort_pending<T: Transport, E: EntropySource>(
        &mut self,
        runtime: &mut SwarmCore<T, E>,
        ids: impl IntoIterator<Item = ConnectionId>,
    ) {
        for conn_id in ids {
            self.abort_one(runtime, conn_id);
        }
    }

    /// Aborts a candidate dial. When the dial was already gone (`Ok(false)`)
    /// or `close` failed (`Err`, pending restored), a `DialFailed` may still
    /// be queued — tombstone the id so `observe` consumes it. On `Err`, also
    /// veto establishment so a restored dial cannot replace an existing peer
    /// connection.
    fn abort_one<T: Transport, E: EntropySource>(
        &mut self,
        runtime: &mut SwarmCore<T, E>,
        conn_id: ConnectionId,
    ) {
        match runtime.abort_dial(conn_id) {
            // Aborted before it could fail, so no `DialFailed` will come to
            // consume a tombstone (a kept dial already has one).
            Ok(true) => {
                self.suppressed.remove(&conn_id);
            }
            Ok(false) => {
                self.suppressed.insert(conn_id);
            }
            Err(_) => {
                self.suppressed.insert(conn_id);
                runtime.veto_establish(conn_id);
            }
        }
    }
}

/// What settling on `conn_id` must record now: nothing for a direct
/// connection, whose path waits on NAT; a circuit's relay, which only the
/// swarm's record of its address names. `Err` when there is no such record
/// to read: the swarm already let the circuit go.
fn settle_record<T: Transport, E: EntropySource>(
    runtime: &SwarmCore<T, E>,
    conn_id: ConnectionId,
) -> Result<Option<PeerId>, ()> {
    if !conn_id.is_circuit() {
        return Ok(None);
    }
    circuit_relay(runtime, conn_id).map(Some).ok_or(())
}

/// The relay an established circuit runs through, named by its remote
/// address (`/p2p/<relay>/p2p-circuit`); `None` once the swarm let it go.
/// An address naming no relay is a circuit transport bug: debug builds
/// assert, release builds report no relay, so the circuit is not settled
/// on rather than named a wrong path.
pub(crate) fn circuit_relay<T: Transport, E: EntropySource>(
    runtime: &SwarmCore<T, E>,
    conn_id: ConnectionId,
) -> Option<PeerId> {
    let addr = runtime.connection_remote_addr(conn_id)?;
    let relay = match addr.protocols() {
        [.., Protocol::P2p(relay), Protocol::P2pCircuit] => Some(*relay),
        _ => None,
    };
    debug_assert!(
        relay.is_some(),
        "circuit {conn_id:?} has no /p2p/<relay>/p2p-circuit remote address: {addr}"
    );
    relay
}

/// What one Connection attempt should dial: the peer, its candidate
/// addresses, whether a relay leg may race them, and every address known
/// for the peer.
pub(crate) struct ConnectAdmission {
    pub(crate) peer: PeerId,
    pub(crate) candidates: Vec<PeerAddr>,
    pub(crate) allow_relay: bool,
    /// Every address known for the peer from any source, circuit addresses
    /// included. Circuit addresses tell the relay leg where the peer holds a
    /// reservation; they are not among the direct `candidates`, so the
    /// caller hands them over here.
    pub(crate) targets: Vec<Multiaddr>,
}

/// Where an engine keeps its relay-leg provider: the NAT driver once NAT is
/// configured, and nothing in a build without NAT. Lend it to one
/// Connection-attempt call with [`Legs::of`].
#[cfg(feature = "autonat")]
pub(crate) type LegProvider<T> = Option<NatDriver<T>>;
/// Where an engine keeps its relay-leg provider: nothing, without NAT.
#[cfg(not(feature = "autonat"))]
pub(crate) type LegProvider<T> = PhantomData<fn(T)>;

/// The relay-leg provider lent to one Connection-attempt call. The engine
/// reaches the NAT driver only through its leg primitives (register, cancel,
/// settle, and its raw event queue), so callers never fork on whether NAT is
/// compiled in.
pub(crate) struct Legs<'a, T> {
    #[cfg(feature = "autonat")]
    nat: Option<&'a mut NatDriver<T>>,
    #[cfg(not(feature = "autonat"))]
    provider: PhantomData<&'a mut LegProvider<T>>,
}

impl<'a, T: Transport> Legs<'a, T> {
    /// Lends `provider` for one call.
    pub(crate) fn of(provider: &'a mut LegProvider<T>) -> Self {
        #[cfg(feature = "autonat")]
        {
            Self {
                nat: provider.as_mut(),
            }
        }
        #[cfg(not(feature = "autonat"))]
        {
            let _ = provider;
            Self {
                provider: PhantomData,
            }
        }
    }

    /// Lends the same provider again, for a caller that makes several calls.
    #[cfg_attr(
        not(feature = "_peer-book"),
        expect(dead_code, reason = "only the discovery sweep makes several calls")
    )]
    pub(crate) fn reborrow(&mut self) -> Legs<'_, T> {
        Legs {
            #[cfg(feature = "autonat")]
            nat: self.nat.as_deref_mut(),
            #[cfg(not(feature = "autonat"))]
            provider: PhantomData,
        }
    }

    /// How an admitted attempt may use a relay: not at all without a
    /// configured relay (or when `allow_relay` is off), else as NAT is
    /// configured.
    fn relay_policy(&self, allow_relay: bool) -> RelayPolicy {
        #[cfg(feature = "autonat")]
        if let Some(nat) = self.nat.as_deref()
            && allow_relay
            && nat.has_relay()
        {
            return if nat.force_relay() {
                RelayPolicy::Forced
            } else if nat.dcutr() {
                RelayPolicy::Race
            } else {
                RelayPolicy::RaceWithoutUpgrade
            };
        }
        let _ = allow_relay;
        RelayPolicy::None
    }

    fn is_punched(&self, conn_id: ConnectionId) -> bool {
        #[cfg(feature = "autonat")]
        {
            self.nat
                .as_deref()
                .is_some_and(|nat| nat.is_punched(conn_id))
        }
        #[cfg(not(feature = "autonat"))]
        {
            let _ = conn_id;
            false
        }
    }
}

/// Whether NAT's hole punch produced `conn_id` (always `false` without
/// NAT), for naming a live connection's path.
pub(crate) fn is_punched<T: Transport>(provider: &LegProvider<T>, conn_id: ConnectionId) -> bool {
    #[cfg(feature = "autonat")]
    {
        provider.as_ref().is_some_and(|nat| nat.is_punched(conn_id))
    }
    #[cfg(not(feature = "autonat"))]
    {
        let _ = (provider, conn_id);
        false
    }
}

/// `ConnectFailed` and `FellBackToRelay` are attempt terminals the engine
/// already reports as `ConnectSettled`, so they are not repeated to the
/// application.
#[cfg(feature = "autonat")]
fn reaches_application(event: &minip2p_nat::NatEvent) -> bool {
    use minip2p_nat::NatEvent;
    !matches!(
        event,
        NatEvent::ConnectFailed { .. } | NatEvent::FellBackToRelay { .. }
    )
}

/// Events that speak for a still-pending attempt's outcome. Once the engine
/// settled the attempt, they are stale and dropped.
#[cfg(feature = "autonat")]
fn is_attempt_outcome(event: &minip2p_nat::NatEvent) -> bool {
    use minip2p_nat::NatEvent;
    matches!(
        event,
        NatEvent::ConnectFailed { .. }
            | NatEvent::FellBackToRelay { .. }
            | NatEvent::HolePunchFailed { .. }
    )
}

/// The Connection-attempt lifecycle both Endpoint types drive, relay leg
/// included: [`Self::admit`], then [`Self::route`] after every step that can
/// make the leg provider speak, [`Self::cancel`], and [`Self::pop_terminal`]
/// for each terminal. Each takes the provider as [`Legs`].
impl ConnectEngine {
    /// Admits one Connection attempt: selects the relay policy from the leg
    /// provider, expands each candidate through `names` (Name resolution on
    /// std, identity on portable), starts direct dials, and attaches the
    /// relay leg while the attempt is still pending. Under `force_relay`
    /// direct candidates are discarded unexpanded, so no name is looked up
    /// for them. An attempt that settles at once (the peer is already
    /// connected, or nothing can be dialed) attaches no leg; its terminal is
    /// queued.
    pub(crate) fn admit<T: Transport, E: EntropySource>(
        &mut self,
        mut legs: Legs<'_, T>,
        core: &mut SwarmCore<T, E>,
        admission: ConnectAdmission,
        names: &mut dyn Expander,
        now: Now,
    ) -> ConnectId {
        let ConnectAdmission {
            peer,
            candidates,
            allow_relay,
            targets,
        } = admission;
        let relay = legs.relay_policy(allow_relay);
        let candidates = if matches!(relay, RelayPolicy::Forced) {
            Vec::new()
        } else {
            candidates
        };
        let mut sorted = Candidates::default();
        for addr in candidates {
            match names.expand(&addr) {
                Expansion::Ready(addrs) => sorted.ready.extend(addrs),
                Expansion::Resolving => sorted.resolving.push(addr),
                Expansion::Refused(reason) => {
                    sorted.refused.push(CandidateFailure { addr, reason });
                }
            }
        }
        let id = self.connect_candidates(peer, sorted, relay, core, now.monotonic_ms);
        #[cfg(feature = "autonat")]
        if let Some(nat) = legs.nat.as_deref_mut()
            && self.is_pending(id)
        {
            nat.connect(
                id,
                peer,
                minip2p_nat::ConnectLegs {
                    direct_racing: self.dialed_direct(id),
                    allow_relay,
                    target_addrs: targets,
                    deadline_ms: self.expires_ms(id),
                },
                core,
                now,
            );
        }
        #[cfg(not(feature = "autonat"))]
        let _ = (&mut legs, peer, targets);
        id
    }

    /// Cancels a pending attempt: its direct dials, then its relay leg,
    /// whose cleanup runs before this returns. Settled or unknown ids are a
    /// no-op, so a relayed circuit an attempt already settled on stays open
    /// even while its terminal is still queued. Never disconnects.
    pub(crate) fn cancel<T: Transport, E: EntropySource>(
        &mut self,
        mut legs: Legs<'_, T>,
        core: &mut SwarmCore<T, E>,
        id: ConnectId,
        now: Now,
    ) {
        if !self.is_pending(id) {
            return;
        }
        self.abort_attempt(id, core);
        #[cfg(feature = "autonat")]
        if let Some(nat) = legs.nat.as_deref_mut() {
            nat.cancel(id, core, now);
        }
        #[cfg(not(feature = "autonat"))]
        let _ = (&mut legs, now);
    }

    /// Routes every event the leg provider produced since the last call,
    /// each exactly once: an attempt outcome for an attempt already settled
    /// is dropped as stale; the rest updates the attempt it names, then is
    /// staged for the Endpoint event stream unless `owned` claims its
    /// attempt (discovery's automatic dials) or it is an attempt terminal
    /// this engine reports as `ConnectSettled` instead. Then names the paths
    /// of what settled meanwhile.
    ///
    /// Call it after every swarm event and every step that can make the
    /// provider speak, so attempts see NAT output in step with its cause.
    pub(crate) fn route<T: Transport, E: EntropySource>(
        &mut self,
        mut legs: Legs<'_, T>,
        core: &mut SwarmCore<T, E>,
        owned: impl Fn(ConnectId) -> bool,
        now: Now,
    ) {
        #[cfg(feature = "autonat")]
        if let Some(nat) = legs.nat.as_deref_mut() {
            while let Some(event) = nat.take_unrouted() {
                // An outcome produced in the turn the attempt settled,
                // before the agent learned of it.
                if is_attempt_outcome(&event)
                    && event.connect_id().is_some_and(|id| !self.is_pending(id))
                {
                    continue;
                }
                self.observe_nat(&event, core, now.monotonic_ms);
                if !event.connect_id().is_some_and(&owned) && reaches_application(&event) {
                    nat.stage(event);
                }
            }
        }
        #[cfg(not(feature = "autonat"))]
        let _ = (&mut legs, core, owned, now);
        self.resolve_paths(|conn_id| legs.is_punched(conn_id));
    }

    /// Settles attempts whose deadline passed, then names their paths.
    pub(crate) fn expire<T: Transport, E: EntropySource>(
        &mut self,
        legs: Legs<'_, T>,
        core: &mut SwarmCore<T, E>,
        now: Now,
    ) {
        self.tick(core, now.monotonic_ms);
        self.resolve_paths(|conn_id| legs.is_punched(conn_id));
    }

    /// Pops the next terminal and settles its relay leg: the provider drops
    /// what it holds for the attempt and emits nothing more for it, keeping
    /// a Connected terminal's connection open. The leg's cleanup can produce
    /// more provider output, so [`Self::route`] runs before every pop.
    pub(crate) fn pop_terminal<T: Transport, E: EntropySource>(
        &mut self,
        mut legs: Legs<'_, T>,
        core: &mut SwarmCore<T, E>,
        now: Now,
    ) -> Option<EndpointEvent> {
        let event = self.pop_event()?;
        #[cfg(feature = "autonat")]
        if let Some(nat) = legs.nat.as_deref_mut()
            && let EndpointEvent::ConnectSettled {
                connect_id,
                outcome,
                ..
            } = &event
        {
            let kept = match outcome {
                ConnectOutcome::Connected { conn_id, .. } => Some(*conn_id),
                ConnectOutcome::Failed(_) | ConnectOutcome::Cancelled => None,
            };
            nat.settled(*connect_id, kept, core, now);
        }
        #[cfg(not(feature = "autonat"))]
        let _ = (&mut legs, core, now);
        Some(event)
    }
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
