//! Direct Connection-attempt types and the sans-I/O engine that owns them.
//!
//! One [`ConnectId`] covers every candidate Transport dial in an attempt.
//! The engine races complete [`PeerAddr`]s through [`SwarmRuntime::dial`] and
//! emits exactly one [`EndpointEvent::ConnectSettled`] per admitted attempt.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::{PeerAddr, PeerId};
use minip2p_platform::{Deadline, EntropySource};
use minip2p_swarm::{SwarmEvent, SwarmRuntime};
use minip2p_transport::{ConnectionId, Transport};

use super::event_stream::EndpointEvent;

/// Default Connection-attempt deadline: 30 seconds.
pub(crate) const DEFAULT_CONNECT_DEADLINE_MS: u64 = 30_000;

pub use minip2p_core::ConnectId;

/// Non-empty, same-peer address list behind [`ConnectTarget::Addrs`].
///
/// Crate-private so callers cannot bypass [`TryFrom`] and build an empty or
/// mixed-peer [`ConnectTarget`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConnectAddrs(Vec<PeerAddr>);

/// What `PortableEndpoint::connect` / `Endpoint::connect` (std feature) accepts.
///
/// #176 adds `Peer(PeerId)`. Collections must be non-empty and name one peer.
/// Candidate order is not a public contract: every candidate is dialed at
/// start.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    private_interfaces,
    reason = "ConnectAddrs is a sealed TryFrom payload so callers cannot build an invalid Addrs."
)]
pub enum ConnectTarget {
    /// One complete peer address.
    Addr(PeerAddr),
    /// Non-empty set of complete addresses for one peer.
    ///
    /// Construct through [`TryFrom<Vec<PeerAddr>>`] / [`TryFrom<&[PeerAddr]>`];
    /// the inner list type is crate-private so invalid values cannot be built
    /// from outside this crate.
    Addrs(ConnectAddrs),
}

impl ConnectTarget {
    /// Peer named by every candidate.
    pub fn peer_id(&self) -> &PeerId {
        match self {
            Self::Addr(addr) => addr.peer_id(),
            Self::Addrs(ConnectAddrs(addrs)) => addrs
                .first()
                .map(PeerAddr::peer_id)
                .expect("ConnectTarget::Addrs is non-empty"),
        }
    }

    /// Candidate addresses. `Addr` is a slice of one.
    pub fn candidates(&self) -> &[PeerAddr] {
        match self {
            Self::Addr(addr) => core::slice::from_ref(addr),
            Self::Addrs(ConnectAddrs(addrs)) => addrs,
        }
    }

    /// Re-runs [`TryFrom`] checks. Identity `TryInto<ConnectTarget>` would
    /// otherwise admit a hand-built `Addrs` that skipped validation.
    #[expect(
        clippy::result_large_err,
        reason = "ConnectTargetError retains both peer identities for MixedPeers diagnostics."
    )]
    pub(crate) fn validated(self) -> Result<Self, ConnectTargetError> {
        match self {
            Self::Addr(_) => Ok(self),
            Self::Addrs(ConnectAddrs(addrs)) => Self::try_from(addrs),
        }
    }
}

impl From<PeerAddr> for ConnectTarget {
    fn from(addr: PeerAddr) -> Self {
        Self::Addr(addr)
    }
}

impl TryFrom<Vec<PeerAddr>> for ConnectTarget {
    type Error = ConnectTargetError;

    fn try_from(mut addrs: Vec<PeerAddr>) -> Result<Self, Self::Error> {
        let mut iter = addrs.iter();
        let Some(first) = iter.next() else {
            return Err(ConnectTargetError::Empty);
        };
        let expected = first.peer_id().clone();
        for addr in iter {
            if addr.peer_id() != &expected {
                return Err(ConnectTargetError::MixedPeers {
                    expected,
                    found: addr.peer_id().clone(),
                });
            }
        }
        if addrs.len() == 1 {
            Ok(Self::Addr(addrs.remove(0)))
        } else {
            Ok(Self::Addrs(ConnectAddrs(addrs)))
        }
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
pub enum ConnectOutcome {
    /// A transport connection to the target peer is established.
    Connected { conn_id: ConnectionId },
    /// The attempt ended without a connection.
    Failed(ConnectFailure),
    /// `PortableEndpoint::cancel_connect` / `Endpoint::cancel_connect` (std)
    /// ran while the attempt was still unsettled.
    Cancelled,
}

/// Why a Connection attempt failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectFailure {
    /// Every candidate was refused before a Transport dial started.
    #[error("no usable route: {}", candidate_summary(.candidates))]
    NoUsableRoute {
        /// Per-candidate refusals (no transport, DNS produced nothing, …).
        candidates: Vec<CandidateFailure>,
    },
    /// Dials started; every one of them failed.
    #[error("every candidate dial failed: {}", candidate_summary(.candidates))]
    AllCandidatesFailed {
        /// Per-candidate dial failures.
        candidates: Vec<CandidateFailure>,
    },
    /// The attempt deadline elapsed with dials still pending.
    #[error("connect deadline elapsed after {elapsed_ms} ms")]
    Timeout {
        /// Milliseconds from admit to the tick that expired the attempt.
        elapsed_ms: u64,
        /// Failures observed before the deadline, plus pending candidates.
        candidates: Vec<CandidateFailure>,
    },
}

/// One candidate's failure diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateFailure {
    /// Address that could not be used.
    pub addr: PeerAddr,
    /// Transport or resolution error text.
    pub reason: String,
}

fn candidate_summary(candidates: &[CandidateFailure]) -> String {
    candidates
        .iter()
        .map(|failure| format!("{} ({})", failure.addr, failure.reason))
        .collect::<Vec<_>>()
        .join("; ")
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
    events: VecDeque<EndpointEvent>,
}

struct Attempt {
    peer: PeerId,
    started_ms: u64,
    /// Absolute mono-ms when this attempt expires (`started_ms +` engine budget).
    expires_ms: u64,
    pending: BTreeMap<ConnectionId, PeerAddr>,
    failed: Vec<CandidateFailure>,
}

impl ConnectEngine {
    pub(crate) fn new(deadline_ms: u64) -> Self {
        Self {
            next_id: 1,
            deadline_ms,
            attempts: BTreeMap::new(),
            suppressed: BTreeSet::new(),
            events: VecDeque::new(),
        }
    }

    /// Admits one attempt. Terminal events are queued, not returned.
    pub(crate) fn connect<T: Transport, E: EntropySource>(
        &mut self,
        target: ConnectTarget,
        runtime: &mut SwarmRuntime<T, E>,
        now_ms: u64,
    ) -> ConnectId {
        self.connect_candidates(
            target.peer_id().clone(),
            target.candidates().to_vec(),
            Vec::new(),
            runtime,
            now_ms,
        )
    }

    /// Like [`Self::connect`], with extra per-candidate failures (DNS, …)
    /// already observed by the std adapter.
    pub(crate) fn connect_candidates<T: Transport, E: EntropySource>(
        &mut self,
        peer: PeerId,
        candidates: Vec<PeerAddr>,
        extra_failed: Vec<CandidateFailure>,
        runtime: &mut SwarmRuntime<T, E>,
        now_ms: u64,
    ) -> ConnectId {
        let id = self.alloc();
        if let Some(conn_id) = runtime.connection_id(&peer) {
            self.push_settled(id, peer, ConnectOutcome::Connected { conn_id });
            return id;
        }

        let mut pending = BTreeMap::new();
        let mut failed = extra_failed;
        for addr in candidates {
            match runtime.dial(&addr) {
                Ok(conn_id) => {
                    pending.insert(conn_id, addr);
                }
                Err(error) => failed.push(CandidateFailure {
                    addr,
                    reason: error.to_string(),
                }),
            }
        }

        if pending.is_empty() {
            self.push_settled(
                id,
                peer,
                ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates: failed }),
            );
            return id;
        }

        self.attempts.insert(
            id,
            Attempt {
                peer,
                started_ms: now_ms,
                expires_ms: now_ms.saturating_add(self.deadline_ms),
                pending,
                failed,
            },
        );
        id
    }

    /// Idempotent. Settled or unknown ids are a no-op. Never disconnects.
    pub(crate) fn cancel<T: Transport, E: EntropySource>(
        &mut self,
        id: ConnectId,
        runtime: &mut SwarmRuntime<T, E>,
    ) {
        let Some(attempt) = self.attempts.remove(&id) else {
            return;
        };
        self.abort_pending(runtime, attempt.pending.keys().copied());
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
        runtime: &mut SwarmRuntime<T, E>,
        _now_ms: u64,
    ) -> bool {
        match event {
            SwarmEvent::DialFailed {
                conn_id,
                addr,
                reason,
            } => {
                if self.suppressed.remove(conn_id) {
                    return true;
                }
                let Some(id) = self.owner(*conn_id) else {
                    return false;
                };
                let Some(mut attempt) = self.attempts.remove(&id) else {
                    return false;
                };
                attempt.pending.remove(conn_id);
                attempt.failed.push(CandidateFailure {
                    addr: addr.clone(),
                    reason: reason.clone(),
                });
                if attempt.pending.is_empty() {
                    self.push_settled(
                        id,
                        attempt.peer,
                        ConnectOutcome::Failed(ConnectFailure::AllCandidatesFailed {
                            candidates: attempt.failed,
                        }),
                    );
                } else {
                    self.attempts.insert(id, attempt);
                }
                true
            }
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                // Abort Ok(false) tombstones may never see DialFailed once the
                // candidate has established — drop the stale id here.
                self.suppressed.remove(conn_id);
                // Every in-flight attempt for this peer succeeds together: the
                // swarm keeps one connection per peer, so a later attempt's
                // dial (or an inbound) is success for the earlier ones too.
                let ids: Vec<ConnectId> = self
                    .attempts
                    .iter()
                    .filter(|(_, attempt)| &attempt.peer == peer_id)
                    .map(|(id, _)| *id)
                    .collect();
                for id in ids {
                    let Some(attempt) = self.attempts.remove(&id) else {
                        continue;
                    };
                    self.abort_pending(
                        runtime,
                        attempt
                            .pending
                            .keys()
                            .copied()
                            .filter(|pending| pending != conn_id),
                    );
                    self.push_settled(
                        id,
                        attempt.peer,
                        ConnectOutcome::Connected { conn_id: *conn_id },
                    );
                }
                false
            }
            _ => false,
        }
    }

    pub(crate) fn tick<T: Transport, E: EntropySource>(
        &mut self,
        runtime: &mut SwarmRuntime<T, E>,
        now_ms: u64,
    ) {
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
            for (conn_id, addr) in attempt.pending.iter() {
                attempt.failed.push(CandidateFailure {
                    addr: addr.clone(),
                    reason: String::from("connect deadline elapsed"),
                });
                self.abort_one(runtime, *conn_id);
            }
            self.push_settled(
                id,
                attempt.peer,
                ConnectOutcome::Failed(ConnectFailure::Timeout {
                    elapsed_ms: now_ms.saturating_sub(attempt.started_ms),
                    candidates: attempt.failed,
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
            .map(|attempt| Deadline::from_millis(attempt.expires_ms))
            .min()
    }

    pub(crate) fn pop_event(&mut self) -> Option<EndpointEvent> {
        self.events.pop_front()
    }

    fn alloc(&mut self) -> ConnectId {
        let id = ConnectId::from_u64(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    fn owner(&self, conn_id: ConnectionId) -> Option<ConnectId> {
        self.attempts
            .iter()
            .find(|(_, attempt)| attempt.pending.contains_key(&conn_id))
            .map(|(id, _)| *id)
    }

    fn push_settled(&mut self, connect_id: ConnectId, peer_id: PeerId, outcome: ConnectOutcome) {
        self.events.push_back(EndpointEvent::ConnectSettled {
            connect_id,
            peer_id,
            outcome,
        });
    }

    fn abort_pending<T: Transport, E: EntropySource>(
        &mut self,
        runtime: &mut SwarmRuntime<T, E>,
        ids: impl IntoIterator<Item = ConnectionId>,
    ) {
        for conn_id in ids {
            self.abort_one(runtime, conn_id);
        }
    }

    /// Aborts a candidate dial. When the dial was already gone (`Ok(false)`)
    /// or `close` failed (`Err`, pending restored), a `DialFailed` may still
    /// be queued — tombstone the id so `observe` consumes it. On `Err`, also
    /// veto establishment so a restored dial cannot supersede an existing peer
    /// connection.
    fn abort_one<T: Transport, E: EntropySource>(
        &mut self,
        runtime: &mut SwarmRuntime<T, E>,
        conn_id: ConnectionId,
    ) {
        match runtime.abort_dial(conn_id) {
            Ok(true) => {}
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

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr};

    use minip2p_identity::Ed25519Keypair;
    use minip2p_platform::{EntropyError, EntropySource, Now};
    use minip2p_swarm::{SwarmBuilder, SwarmRuntime};
    use minip2p_transport::{
        ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
    };

    use super::*;

    fn peer(label: &[u8]) -> PeerId {
        PeerId::from_public_key_protobuf(label)
    }

    fn addr(peer: &PeerId, port: u16) -> PeerAddr {
        PeerAddr::quic_v1(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port, peer.clone())
    }

    #[test]
    fn empty_target_is_empty_error() {
        let err = ConnectTarget::try_from(Vec::<PeerAddr>::new()).expect_err("empty");
        assert_eq!(err, ConnectTargetError::Empty);
        assert_eq!(
            ConnectTarget::try_from(&[] as &[PeerAddr]).expect_err("empty slice"),
            ConnectTargetError::Empty
        );
    }

    #[test]
    fn mixed_peers_names_both() {
        let alice = peer(b"alice");
        let bob = peer(b"bob");
        let err = ConnectTarget::try_from(vec![addr(&alice, 1), addr(&bob, 2)]).expect_err("mixed");
        assert_eq!(
            err,
            ConnectTargetError::MixedPeers {
                expected: alice,
                found: bob,
            }
        );
    }

    #[test]
    fn single_peer_addr_from_is_infallible() {
        let target = ConnectTarget::from(addr(&peer(b"solo"), 9));
        assert_eq!(target.candidates().len(), 1);
        assert_eq!(target.peer_id(), &peer(b"solo"));
    }

    #[test]
    fn hand_built_empty_addrs_fails_validation() {
        let err = ConnectTarget::Addrs(ConnectAddrs(Vec::new()))
            .validated()
            .expect_err("empty");
        assert_eq!(err, ConnectTargetError::Empty);
    }

    #[test]
    fn candidates_preserve_input() {
        let p = peer(b"same");
        let first = addr(&p, 1);
        let second = addr(&p, 2);
        let target =
            ConnectTarget::try_from(vec![first.clone(), second.clone()]).expect("same peer");
        assert_eq!(target.candidates(), &[first, second]);
    }

    struct SeqEntropy(u8);

    impl EntropySource for SeqEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            for byte in output.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTransport {
        next_id: u64,
        dials: Vec<PeerAddr>,
        closes: Vec<ConnectionId>,
        refuse: bool,
        /// When set, `close` fails with a non-`ConnectionNotFound` error.
        refuse_close: bool,
        events: VecDeque<TransportEvent>,
        next_stream: u64,
    }

    impl FakeTransport {
        fn push_connected(&mut self, id: ConnectionId, peer: PeerId, remote: PeerAddr) {
            self.events.push_back(TransportEvent::Connected {
                id,
                endpoint: ConnectionEndpoint::with_peer_id(remote.transport().clone(), peer),
            });
        }

        fn push_closed(&mut self, id: ConnectionId) {
            self.events.push_back(TransportEvent::Closed { id });
        }
    }

    impl Transport for FakeTransport {
        fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
            if self.refuse {
                return Err(TransportError::InvalidAddress {
                    context: "dial target",
                    reason: format!("this set has no Tcp transport for {addr}"),
                });
            }
            self.next_id += 1;
            let id = ConnectionId::new(self.next_id);
            self.dials.push(addr.clone());
            Ok(id)
        }

        fn listen(
            &mut self,
            _: &minip2p_core::Multiaddr,
        ) -> Result<minip2p_core::Multiaddr, TransportError> {
            Err(TransportError::Unsupported {
                operation: "listen",
            })
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            self.next_stream += 1;
            Ok(StreamId::new(self.next_stream))
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            if self.refuse_close {
                return Err(TransportError::InvalidConfig {
                    reason: String::from("close refused"),
                });
            }
            self.closes.push(id);
            Ok(())
        }

        fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(self.events.drain(..).collect())
        }

        fn local_addresses(&self) -> Vec<minip2p_core::Multiaddr> {
            Vec::new()
        }

        fn next_deadline(&self) -> Option<Deadline> {
            None
        }
    }

    fn runtime(transport: FakeTransport) -> SwarmRuntime<FakeTransport, SeqEntropy> {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        SwarmBuilder::new(&identity)
            .agent_version("minip2p-test/0.1.0")
            .build_runtime(transport, SeqEntropy(1))
            .expect("runtime")
    }

    fn drain(
        engine: &mut ConnectEngine,
        runtime: &mut SwarmRuntime<FakeTransport, SeqEntropy>,
        now_ms: u64,
    ) -> Vec<EndpointEvent> {
        engine.tick(runtime, now_ms);
        let mut out = Vec::new();
        while let Some(event) = engine.pop_event() {
            out.push(event);
        }
        for event in runtime.poll(Now::from_millis(now_ms)).expect("poll") {
            let consumed = engine.observe(&event, runtime, now_ms);
            if !consumed {
                out.push(EndpointEvent::from(event));
            }
            while let Some(engine_event) = engine.pop_event() {
                out.push(engine_event);
            }
        }
        out
    }

    fn settled_for(events: &[EndpointEvent], id: ConnectId) -> Option<&ConnectOutcome> {
        events.iter().find_map(|event| match event {
            EndpointEvent::ConnectSettled {
                connect_id,
                outcome,
                ..
            } if *connect_id == id => Some(outcome),
            _ => None,
        })
    }

    #[test]
    fn one_candidate_connected_then_settled() {
        let peer = peer(b"one");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(target.clone().into(), &mut runtime, 0);
        let conn_id = ConnectionId::new(1);
        runtime
            .transport_mut()
            .push_connected(conn_id, peer.clone(), target);
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(
            matches!(
                events.as_slice(),
                [
                    EndpointEvent::ConnectionEstablished {
                        peer_id,
                        conn_id: established,
                    },
                    EndpointEvent::ConnectSettled {
                        connect_id,
                        outcome: ConnectOutcome::Connected { conn_id: settled },
                        ..
                    },
                    ..
                ] if peer_id == &peer
                    && *established == conn_id
                    && *connect_id == id
                    && *settled == conn_id
            ),
            "{events:?}"
        );
        assert!(settled_for(&drain(&mut engine, &mut runtime, 1), id).is_none());
        assert_eq!(runtime.transport().dials.len(), 1);
    }

    #[test]
    fn two_candidates_first_fails_second_connects_without_leaking_dial_failed() {
        let peer = peer(b"race");
        let first = addr(&peer, 1);
        let second = addr(&peer, 2);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(
            ConnectTarget::try_from(vec![first.clone(), second.clone()]).expect("same peer"),
            &mut runtime,
            0,
        );
        runtime.transport_mut().push_closed(ConnectionId::new(1));
        runtime
            .transport_mut()
            .push_connected(ConnectionId::new(2), peer.clone(), second);
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EndpointEvent::DialFailed { .. })),
            "{events:?}"
        );
        assert!(matches!(
            settled_for(&events, id),
            Some(ConnectOutcome::Connected { conn_id }) if *conn_id == ConnectionId::new(2)
        ));
    }

    #[test]
    fn all_dial_failed_is_all_candidates_failed() {
        let peer = peer(b"all-fail");
        let first = addr(&peer, 1);
        let second = addr(&peer, 2);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(
            ConnectTarget::try_from(vec![first.clone(), second.clone()]).expect("same peer"),
            &mut runtime,
            0,
        );
        runtime.transport_mut().push_closed(ConnectionId::new(1));
        runtime.transport_mut().push_closed(ConnectionId::new(2));
        let events = drain(&mut engine, &mut runtime, 0);
        match settled_for(&events, id) {
            Some(ConnectOutcome::Failed(ConnectFailure::AllCandidatesFailed { candidates })) => {
                let addrs: Vec<_> = candidates.iter().map(|c| c.addr.clone()).collect();
                assert!(
                    addrs.contains(&first) && addrs.contains(&second),
                    "{candidates:?}"
                );
            }
            other => panic!("expected AllCandidatesFailed, got {other:?} from {events:?}"),
        }
        assert!(settled_for(&drain(&mut engine, &mut runtime, 1), id).is_none());
    }

    #[test]
    fn synchronous_refusals_return_id_and_queue_no_usable_route() {
        let peer = peer(b"no-route");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport {
            refuse: true,
            ..FakeTransport::default()
        });
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(target.clone().into(), &mut runtime, 0);
        assert_eq!(runtime.transport().dials.len(), 0);
        match engine.pop_event() {
            Some(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates }),
                ..
            }) => {
                assert_eq!(connect_id, id);
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].addr, target);
                assert!(
                    candidates[0].reason.contains("no Tcp transport"),
                    "{}",
                    candidates[0].reason
                );
            }
            other => panic!("expected NoUsableRoute, got {other:?}"),
        }
        assert!(engine.pop_event().is_none());
    }

    #[test]
    fn tick_past_deadline_times_out_and_aborts() {
        let peer = peer(b"slow");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(1_000);
        let id = engine.connect(target.into(), &mut runtime, 0);
        let events = drain(&mut engine, &mut runtime, 1_000);
        match settled_for(&events, id) {
            Some(ConnectOutcome::Failed(ConnectFailure::Timeout { elapsed_ms, .. })) => {
                assert_eq!(*elapsed_ms, 1_000);
            }
            other => panic!("expected Timeout, got {other:?} from {events:?}"),
        }
        assert_eq!(runtime.transport().closes, vec![ConnectionId::new(1)]);
        assert!(settled_for(&drain(&mut engine, &mut runtime, 1_001), id).is_none());
    }

    #[test]
    fn winner_aborts_losers() {
        let peer = peer(b"winner");
        let first = addr(&peer, 1);
        let second = addr(&peer, 2);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let _id = engine.connect(
            ConnectTarget::try_from(vec![first, second.clone()]).expect("same peer"),
            &mut runtime,
            0,
        );
        runtime
            .transport_mut()
            .push_connected(ConnectionId::new(1), peer, second);
        let _ = drain(&mut engine, &mut runtime, 0);
        assert_eq!(runtime.transport().closes, vec![ConnectionId::new(2)]);
    }

    #[test]
    fn cancel_unsettled_aborts_and_is_idempotent() {
        let peer = peer(b"cancel");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(target.into(), &mut runtime, 0);
        engine.cancel(id, &mut runtime);
        match engine.pop_event() {
            Some(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Cancelled,
                ..
            }) if connect_id == id => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
        assert_eq!(runtime.transport().closes, vec![ConnectionId::new(1)]);
        engine.cancel(id, &mut runtime);
        assert!(engine.pop_event().is_none());
        engine.cancel(ConnectId::from_u64(99), &mut runtime);
        assert!(engine.pop_event().is_none());
        assert_eq!(runtime.transport().closes.len(), 1);
    }

    #[test]
    fn already_connected_peer_settles_without_dials() {
        let peer = peer(b"existing");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport::default());
        let conn_id = runtime.dial(&target).expect("seed dial");
        runtime
            .transport_mut()
            .push_connected(conn_id, peer.clone(), target.clone());
        let _ = runtime.poll(Now::from_millis(0)).expect("establish");
        assert_eq!(runtime.connection_id(&peer), Some(conn_id));

        let mut engine = ConnectEngine::new(30_000);
        let dials_before = runtime.transport().dials.len();
        let id = engine.connect(target.into(), &mut runtime, 10);
        assert_eq!(runtime.transport().dials.len(), dials_before);
        match engine.pop_event() {
            Some(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Connected { conn_id: settled },
                ..
            }) => {
                assert_eq!(connect_id, id);
                assert_eq!(settled, conn_id);
            }
            other => panic!("expected Connected, got {other:?}"),
        }
        engine.cancel(id, &mut runtime);
        assert!(engine.pop_event().is_none());
        assert_eq!(runtime.connected_peers(), vec![peer]);
    }

    #[test]
    fn inbound_established_settles_the_attempt() {
        let peer = peer(b"inbound");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(target.clone().into(), &mut runtime, 0);
        let inbound = ConnectionId::new(99);
        runtime
            .transport_mut()
            .push_connected(inbound, peer.clone(), target);
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(matches!(
            settled_for(&events, id),
            Some(ConnectOutcome::Connected { conn_id }) if *conn_id == inbound
        ));
        assert_eq!(runtime.transport().closes, vec![ConnectionId::new(1)]);
    }

    #[test]
    fn winner_before_loser_dial_failed_in_same_batch_does_not_leak() {
        let peer = peer(b"batch-order");
        let first = addr(&peer, 1);
        let second = addr(&peer, 2);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(
            ConnectTarget::try_from(vec![first, second.clone()]).expect("same peer"),
            &mut runtime,
            0,
        );
        // Winner establishes first; loser's close is already in the same poll
        // batch. abort_dial cannot retract the queued DialFailed.
        runtime
            .transport_mut()
            .push_connected(ConnectionId::new(1), peer.clone(), second);
        runtime.transport_mut().push_closed(ConnectionId::new(2));
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EndpointEvent::DialFailed { .. })),
            "loser DialFailed must stay inside the engine; got {events:?}"
        );
        assert!(matches!(
            settled_for(&events, id),
            Some(ConnectOutcome::Connected { conn_id }) if *conn_id == ConnectionId::new(1)
        ));
    }

    #[test]
    fn same_peer_attempts_all_settle_when_one_candidate_establishes() {
        let peer = peer(b"shared");
        let first_addr = addr(&peer, 1);
        let second_addr = addr(&peer, 2);
        let mut runtime = runtime(FakeTransport::default());
        let mut engine = ConnectEngine::new(30_000);
        let first = engine.connect(first_addr.into(), &mut runtime, 0);
        let second = engine.connect(second_addr.clone().into(), &mut runtime, 0);
        runtime
            .transport_mut()
            .push_connected(ConnectionId::new(2), peer.clone(), second_addr);
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(matches!(
            settled_for(&events, first),
            Some(ConnectOutcome::Connected { conn_id }) if *conn_id == ConnectionId::new(2)
        ));
        assert!(matches!(
            settled_for(&events, second),
            Some(ConnectOutcome::Connected { conn_id }) if *conn_id == ConnectionId::new(2)
        ));
        let later = drain(&mut engine, &mut runtime, 1);
        assert!(settled_for(&later, first).is_none());
        assert!(settled_for(&later, second).is_none());
        assert_eq!(runtime.transport().closes, vec![ConnectionId::new(1)]);
    }

    #[test]
    fn failed_abort_then_establish_is_closed_not_forwarded() {
        let peer = peer(b"abort-fail");
        let target = addr(&peer, 4001);
        let mut runtime = runtime(FakeTransport {
            refuse_close: true,
            ..FakeTransport::default()
        });
        let mut engine = ConnectEngine::new(30_000);
        let id = engine.connect(target.clone().into(), &mut runtime, 0);
        let conn_id = ConnectionId::new(1);
        engine.cancel(id, &mut runtime);
        match engine.pop_event() {
            Some(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Cancelled,
                ..
            }) if connect_id == id => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
        // Abort close failed: dial restored + vetoed. Allow close for refuse.
        runtime.transport_mut().refuse_close = false;
        runtime
            .transport_mut()
            .push_connected(conn_id, peer.clone(), target);
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EndpointEvent::ConnectionEstablished { .. })),
            "restored dial must not reach the app after Cancelled; got {events:?}"
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, EndpointEvent::DialFailed { .. })),
            "vetoed DialFailed stays inside the engine; got {events:?}"
        );
        assert!(settled_for(&events, id).is_none());
        assert_eq!(runtime.transport().closes, vec![conn_id]);
        assert!(runtime.connection_id(&peer).is_none());
    }

    #[test]
    fn failed_abort_establish_does_not_supersede_existing_connection() {
        let peer = peer(b"keep-alive");
        let existing_addr = addr(&peer, 4000);
        let target = addr(&peer, 4001);
        let late = ConnectionId::new(1);
        let existing = ConnectionId::new(2);
        let mut runtime = runtime(FakeTransport {
            refuse_close: true,
            ..FakeTransport::default()
        });
        let mut engine = ConnectEngine::new(30_000);
        // Dial first while the peer is still offline, then cancel with a
        // failed abort so the candidate is restored + vetoed.
        let id = engine.connect(target.clone().into(), &mut runtime, 0);
        assert_eq!(runtime.transport().dials, vec![target.clone()]);
        engine.cancel(id, &mut runtime);
        match engine.pop_event() {
            Some(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Cancelled,
                ..
            }) if connect_id == id => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }

        // A valid connection lands for the same peer (e.g. inbound) while the
        // restored dial is still live.
        runtime.transport_mut().refuse_close = false;
        runtime
            .transport_mut()
            .push_connected(existing, peer.clone(), existing_addr);
        let mid = drain(&mut engine, &mut runtime, 0);
        assert!(
            mid.iter().any(|event| {
                matches!(
                    event,
                    EndpointEvent::ConnectionEstablished {
                        peer_id,
                        conn_id,
                    } if peer_id == &peer && *conn_id == existing
                )
            }),
            "{mid:?}"
        );
        assert_eq!(runtime.connection_id(&peer), Some(existing));

        // Late establish of the vetoed dial must close by conn_id only.
        runtime
            .transport_mut()
            .push_connected(late, peer.clone(), target);
        let events = drain(&mut engine, &mut runtime, 0);
        assert!(
            events.iter().all(|event| !matches!(
                event,
                EndpointEvent::ConnectionEstablished { conn_id, .. } if *conn_id == late
            )),
            "late vetoed establish must not reach the app; got {events:?}"
        );
        assert!(
            events.iter().all(|event| !matches!(
                event,
                EndpointEvent::ConnectionClosed {
                    conn_id,
                    cause: minip2p_swarm::ConnectionCloseCause::Superseded,
                    ..
                } if *conn_id == existing
            )),
            "existing connection must not be superseded; got {events:?}"
        );
        assert_eq!(
            runtime.connection_id(&peer),
            Some(existing),
            "existing peer mapping must survive the vetoed late dial"
        );
        assert!(
            runtime.transport().closes.contains(&late),
            "late dial must be closed by id; closes={:?}",
            runtime.transport().closes
        );
        assert!(
            !runtime.transport().closes.contains(&existing),
            "existing connection must stay open; closes={:?}",
            runtime.transport().closes
        );
    }
}
