use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr, TransportKind};
use minip2p_platform::{Deadline, Now};
use thiserror::Error;

use crate::{
    ConnectionId, ConnectionNamespace, StreamId, Transport, TransportError, TransportEvent,
};

/// How a member is held.
///
/// Under `std` a member must also be a
/// [`BlockingTransport`](crate::BlockingTransport), so the set as a whole can
/// park a driver rather than spin. That costs a member nothing it was not
/// already paying: every method of that trait has a default, so
/// `impl BlockingTransport for MyTransport {}` is the whole of it.
#[cfg(feature = "std")]
type BoxedTransport = Box<dyn crate::BlockingTransport>;
#[cfg(not(feature = "std"))]
type BoxedTransport = Box<dyn Transport>;

/// Why a transport could not join a [`TransportSet`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportSetError {
    /// Another member already dials this address shape.
    #[error("this set already has a transport for {kind:?} addresses")]
    DuplicateKind {
        /// The address shape both members claim.
        kind: TransportKind,
    },
    /// Another member already allocates ids in this namespace.
    #[error("{namespace} is already claimed by another member of this set")]
    DuplicateNamespace {
        /// The namespace both members claim.
        namespace: ConnectionNamespace,
    },
    /// The member named no namespace, so nothing it returns could be routed
    /// back to it.
    #[error("a member must claim at least one connection namespace")]
    NoNamespace,
}

struct Member {
    /// The address shape this member dials and listens on.
    kind: TransportKind,
    /// The namespaces it allocates connection ids in, which is what routes an
    /// id back to it.
    namespaces: Vec<ConnectionNamespace>,
    transport: BoxedTransport,
}

/// Several transports behind one [`Transport`].
///
/// This is what lets a host speak TCP and QUIC at once without the swarm above
/// it knowing there is more than one of anything. It owns no I/O of its own: it
/// is a router, and every decision it makes is a lookup.
///
/// # Routing
///
/// Two questions, two answers already in the types:
///
/// - **Which member dials this address?** [`Multiaddr::transport_kind`] says
///   whether an address is `/tcp` or `/udp/quic-v1`, and each member claims one
///   shape.
/// - **Which member owns this connection?** [`ConnectionId`] carries the
///   [`ConnectionNamespace`] its allocator stamped, and each member claims the
///   namespaces it allocates in. That is what namespaces were for.
///
/// Both are checked when a member joins, so neither question can have two
/// answers at the time it is asked.
///
/// # Address families
///
/// A member claims an address *shape*, not an address family, so one TCP
/// transport serves `/ip4` and `/ip6` alike. That suits how the transports are
/// actually built -- `StdTcpProvider` binds listeners of either family, and a
/// smoltcp interface holds addresses of both -- and it means a dual-stack host
/// runs one member per protocol rather than one per family. A member that does
/// split by family internally, as the dual-stack QUIC transport does, claims
/// both of its namespaces and keeps that split to itself.
///
/// A host composes one with [`insert`](Self::insert), naming each member's
/// address shape and the namespaces its allocator stamps -- for a TCP
/// transport, [`TransportKind::Tcp`] and whichever of
/// [`ConnectionNamespace::TCP_IPV4`] or [`ConnectionNamespace::TCP_IPV6`] it
/// was configured with.
#[derive(Default)]
pub struct TransportSet {
    members: Vec<Member>,
    /// Events collected from members that a failing member kept this poll from
    /// returning. Drained by the next one.
    pending: VecDeque<TransportEvent>,
}

impl TransportSet {
    /// Creates an empty set.
    ///
    /// A set with no members refuses every dial and listen, which is what an
    /// empty set should do rather than something more helpful.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a transport, claiming an address shape and the namespaces it
    /// allocates ids in.
    ///
    /// Rejects a claim another member already holds: two members answering one
    /// question would make routing a guess, and a guess here delivers a
    /// connection's events to the wrong transport.
    pub fn insert(
        &mut self,
        kind: TransportKind,
        namespaces: impl IntoIterator<Item = ConnectionNamespace>,
        transport: BoxedTransport,
    ) -> Result<(), TransportSetError> {
        let namespaces: Vec<ConnectionNamespace> = namespaces.into_iter().collect();
        if namespaces.is_empty() {
            return Err(TransportSetError::NoNamespace);
        }
        if self.members.iter().any(|member| member.kind == kind) {
            return Err(TransportSetError::DuplicateKind { kind });
        }
        for namespace in &namespaces {
            if self
                .members
                .iter()
                .any(|member| member.namespaces.contains(namespace))
            {
                return Err(TransportSetError::DuplicateNamespace {
                    namespace: *namespace,
                });
            }
        }
        self.members.push(Member {
            kind,
            namespaces,
            transport,
        });
        Ok(())
    }

    /// Whether the set can dial anything at all.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The address shapes this set can dial and listen on.
    pub fn kinds(&self) -> Vec<TransportKind> {
        self.members.iter().map(|member| member.kind).collect()
    }

    fn for_id(&mut self, id: ConnectionId) -> Result<&mut BoxedTransport, TransportError> {
        let namespace = id.namespace();
        self.members
            .iter_mut()
            .find(|member| member.namespaces.contains(&namespace))
            .map(|member| &mut member.transport)
            // An id from a namespace nobody claims names no connection here,
            // which is the same thing as a connection that does not exist.
            .ok_or(TransportError::ConnectionNotFound { id })
    }

    fn for_addr(
        &mut self,
        addr: &Multiaddr,
        context: &'static str,
    ) -> Result<&mut BoxedTransport, TransportError> {
        let kind = addr
            .transport_kind()
            .ok_or_else(|| TransportError::InvalidAddress {
                context,
                reason: format!("{addr} is not a transport address"),
            })?;
        self.members
            .iter_mut()
            .find(|member| member.kind == kind)
            .map(|member| &mut member.transport)
            .ok_or_else(|| TransportError::InvalidAddress {
                context,
                reason: format!("this set has no {kind:?} transport for {addr}"),
            })
    }
}

impl Transport for TransportSet {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let target = addr.transport().clone();
        self.for_addr(&target, "dial target")?.dial(addr)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.for_addr(addr, "listen address")?.listen(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.for_id(id)?.open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.for_id(id)?.send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.for_id(id)?.close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.for_id(id)?.reset_stream(id, stream_id)
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.for_id(id)?.close(id)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        // Every member is polled, even after one fails: a member that has
        // events ready is not answerable for another one's fault, and the
        // failing member has already told the host what went wrong through the
        // error. What has been collected so far is kept for the next poll
        // rather than dropped, so no connection loses events to a sibling.
        let mut failure = None;
        for index in 0..self.members.len() {
            match self.members[index].transport.poll(now) {
                Ok(events) => self.pending.extend(events),
                Err(error) => failure = failure.or(Some(error)),
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(self.pending.drain(..).collect()),
        }
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() {
            // Events a failed poll held back are due regardless of the clock.
            return Some(Deadline::IMMEDIATE);
        }
        self.members
            .iter()
            .filter_map(|member| member.transport.next_deadline())
            .min()
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.members
            .iter()
            .flat_map(|member| member.transport.local_addresses())
            .collect()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.members
            .iter()
            .flat_map(|member| member.transport.active_inbound_connection_sources())
            .collect()
    }
}

#[cfg(feature = "std")]
mod blocking_set {
    use super::TransportSet;
    use crate::{BlockingTransport, WaitHandle, WaitOutcome};
    use alloc::vec::Vec;
    use core::time::Duration;

    /// How long one member may hold the wait before the next gets a turn.
    ///
    /// Short enough that a member with input waiting is not sat on for long,
    /// long enough that a set of quiet members is not a spin loop.
    const SLICE: Duration = Duration::from_millis(10);

    impl BlockingTransport for TransportSet {
        fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
            // Events a failed poll held back are input the caller has not seen.
            if !self.pending.is_empty() {
                return WaitOutcome::Ready;
            }

            // Probe every member without blocking before blocking on any of
            // them: a budget spent waiting on a quiet member would report
            // `TimedOut` while another already had something to hand over.
            let mut anyone_can_wait = false;
            for member in &mut self.members {
                match member.transport.wait_for_input(Duration::ZERO) {
                    WaitOutcome::Ready => return WaitOutcome::Ready,
                    WaitOutcome::Interrupted => return WaitOutcome::Interrupted,
                    WaitOutcome::TimedOut => anyone_can_wait = true,
                    WaitOutcome::Unsupported => {}
                }
            }
            if !anyone_can_wait {
                // No member can park on readiness, so neither can the set. The
                // caller has to sleep on its own clock instead of reading a
                // prompt return as "nothing happened yet".
                return WaitOutcome::Unsupported;
            }
            if timeout.is_zero() {
                return WaitOutcome::TimedOut;
            }

            // A caller's timeout can exceed what `Instant` arithmetic
            // represents; an unrepresentable deadline means "no deadline".
            let deadline = std::time::Instant::now().checked_add(timeout);
            loop {
                for index in 0..self.members.len() {
                    let remaining = match deadline {
                        Some(deadline) => {
                            let left =
                                deadline.saturating_duration_since(std::time::Instant::now());
                            if left.is_zero() {
                                return WaitOutcome::TimedOut;
                            }
                            left
                        }
                        None => SLICE,
                    };
                    // Every member has to get a turn within this call, so what
                    // is left is divided among the members still to come
                    // rather than spent on the first. A budget too small to
                    // divide degrades to a non-blocking probe, which is still
                    // a turn.
                    let share = u32::try_from(self.members.len() - index)
                        .map_or(remaining, |left| remaining / left);
                    let slice = SLICE.min(remaining).min(share);
                    match self.members[index].transport.wait_for_input(slice) {
                        WaitOutcome::Ready => return WaitOutcome::Ready,
                        WaitOutcome::Interrupted => return WaitOutcome::Interrupted,
                        WaitOutcome::TimedOut | WaitOutcome::Unsupported => {}
                    }
                }
            }
        }

        fn wait_handle(&self) -> WaitHandle {
            // The set blocks inside whichever member holds the current slice,
            // and a caller cannot know which. Nudging all of them is what makes
            // one handle interrupt the set rather than whichever member
            // happened to be next.
            let handles: Vec<WaitHandle> = self
                .members
                .iter()
                .map(|member| member.transport.wait_handle())
                .filter(|handle| !handle.is_noop())
                .collect();
            if handles.is_empty() {
                return WaitHandle::noop();
            }
            WaitHandle::new(move || {
                for handle in &handles {
                    handle.interrupt();
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use core::cell::RefCell;

    /// What a member was asked to do, so routing can be asserted on the member
    /// that actually received the call rather than on a return value that
    /// several members could have produced.
    #[derive(Default)]
    struct Log {
        calls: Vec<String>,
        events: Vec<TransportEvent>,
        deadline: Option<Deadline>,
        addresses: Vec<Multiaddr>,
        fails_poll: bool,
    }

    #[derive(Clone)]
    struct Fake {
        name: &'static str,
        namespace: ConnectionNamespace,
        log: Rc<RefCell<Log>>,
    }

    impl Fake {
        fn new(name: &'static str, namespace: ConnectionNamespace) -> Self {
            Self {
                name,
                namespace,
                log: Rc::new(RefCell::new(Log::default())),
            }
        }

        fn record(&self, call: &str) {
            self.log.borrow_mut().calls.push(call.to_string());
        }

        fn calls(&self) -> Vec<String> {
            self.log.borrow().calls.clone()
        }

        fn boxed(&self) -> BoxedTransport {
            Box::new(self.clone())
        }
    }

    impl Transport for Fake {
        fn dial(&mut self, _addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
            self.record("dial");
            Ok(ConnectionId::namespaced(self.namespace, 1).expect("in range"))
        }

        fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
            self.record("listen");
            Ok(addr.clone())
        }

        fn open_stream(&mut self, _id: ConnectionId) -> Result<StreamId, TransportError> {
            self.record("open_stream");
            Ok(StreamId::new(1))
        }

        fn send_stream(
            &mut self,
            _id: ConnectionId,
            _stream_id: StreamId,
            _data: Vec<u8>,
        ) -> Result<(), TransportError> {
            self.record("send_stream");
            Ok(())
        }

        fn close_stream_write(
            &mut self,
            _id: ConnectionId,
            _stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.record("close_stream_write");
            Ok(())
        }

        fn reset_stream(
            &mut self,
            _id: ConnectionId,
            _stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.record("reset_stream");
            Ok(())
        }

        fn close(&mut self, _id: ConnectionId) -> Result<(), TransportError> {
            self.record("close");
            Ok(())
        }

        fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            self.record("poll");
            if self.log.borrow().fails_poll {
                return Err(TransportError::PollError {
                    reason: self.name.to_string(),
                });
            }
            Ok(core::mem::take(&mut self.log.borrow_mut().events))
        }

        fn next_deadline(&self) -> Option<Deadline> {
            self.log.borrow().deadline
        }

        fn local_addresses(&self) -> Vec<Multiaddr> {
            self.log.borrow().addresses.clone()
        }

        fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
            self.log.borrow().addresses.clone()
        }
    }

    #[cfg(feature = "std")]
    impl crate::BlockingTransport for Fake {}

    fn addr(text: &str) -> Multiaddr {
        text.parse().expect("test address parses")
    }

    fn tcp_addr() -> Multiaddr {
        addr("/ip4/127.0.0.1/tcp/4001")
    }

    fn quic_addr() -> Multiaddr {
        addr("/ip4/127.0.0.1/udp/4001/quic-v1")
    }

    /// A set with one TCP member and one QUIC member, and both fakes.
    fn duo() -> (TransportSet, Fake, Fake) {
        let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
        let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4);
        let mut set = TransportSet::new();
        set.insert(
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            tcp.boxed(),
        )
        .expect("tcp joins");
        set.insert(
            TransportKind::Quic,
            [ConnectionNamespace::QUIC_IPV4],
            quic.boxed(),
        )
        .expect("quic joins");
        (set, tcp, quic)
    }

    fn peer() -> minip2p_core::PeerId {
        // Identity-key ed25519 multihash: 0x00 code, 32-byte digest. Built by
        // hand so the routing tests need no signing crate to dial with.
        let mut multihash = vec![0x00, 32];
        multihash.extend_from_slice(&[7u8; 32]);
        minip2p_core::PeerId::from_bytes(&multihash).expect("a well-formed peer id")
    }

    #[test]
    fn an_address_is_dialed_by_the_member_that_serves_its_shape() {
        let (mut set, tcp, quic) = duo();

        set.dial(&PeerAddr::new(tcp_addr(), peer()).expect("target"))
            .expect("tcp dial");
        assert_eq!(tcp.calls(), vec!["dial"], "the /tcp address is TCP's");
        assert!(quic.calls().is_empty(), "and nobody else's");

        set.dial(&PeerAddr::new(quic_addr(), peer()).expect("target"))
            .expect("quic dial");
        assert_eq!(quic.calls(), vec!["dial"]);
        assert_eq!(tcp.calls(), vec!["dial"], "TCP saw nothing new");
    }

    #[test]
    fn a_listen_goes_to_the_member_that_serves_its_shape() {
        let (mut set, tcp, quic) = duo();
        let bound = set.listen(&quic_addr()).expect("quic listen");

        assert_eq!(bound, quic_addr());
        assert_eq!(quic.calls(), vec!["listen"]);
        assert!(tcp.calls().is_empty());
    }

    #[test]
    fn everything_about_a_connection_returns_to_the_member_that_issued_its_id() {
        let (mut set, tcp, quic) = duo();
        // Nothing in this test names an address. The namespace the id carries
        // is the only thing saying where it belongs -- which is what makes the
        // set a lookup rather than a search.
        let id = ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 7).expect("in range");
        let stream = StreamId::new(3);

        set.open_stream(id).expect("open");
        set.send_stream(id, stream, vec![1]).expect("send");
        set.close_stream_write(id, stream).expect("close write");
        set.reset_stream(id, stream).expect("reset");
        set.close(id).expect("close");

        assert_eq!(
            quic.calls(),
            vec![
                "open_stream",
                "send_stream",
                "close_stream_write",
                "reset_stream",
                "close"
            ]
        );
        assert!(
            tcp.calls().is_empty(),
            "a connection's calls must not reach a sibling transport"
        );
    }

    #[test]
    fn an_id_from_a_namespace_nobody_claims_names_no_connection() {
        let (mut set, ..) = duo();
        let id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV6, 1).expect("in range");

        let error = set.open_stream(id).expect_err("no member owns this");
        assert!(
            matches!(error, TransportError::ConnectionNotFound { id: missing } if missing == id),
            "got {error:?}"
        );
    }

    #[test]
    fn an_address_shape_with_no_member_is_refused_by_name() {
        let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
        let mut set = TransportSet::new();
        set.insert(
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            tcp.boxed(),
        )
        .expect("tcp joins");

        let error = set.listen(&quic_addr()).expect_err("no quic here");
        assert!(
            matches!(&error, TransportError::InvalidAddress { reason, .. } if reason.contains("Quic")),
            "the error should name what is missing, got {error:?}"
        );
    }

    #[test]
    fn an_address_that_names_no_transport_is_refused() {
        let (mut set, ..) = duo();
        // A relay address is somebody else's to dial; guessing a member for it
        // would hand it to a transport that cannot reach it.
        let error = set
            .listen(&addr("/ip4/127.0.0.1/tcp/4001/p2p-circuit"))
            .expect_err("not a transport address");
        assert!(
            matches!(error, TransportError::InvalidAddress { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn one_address_shape_cannot_have_two_members() {
        let (mut set, ..) = duo();
        let other = Fake::new("tcp2", ConnectionNamespace::TCP_IPV6);

        let error = set
            .insert(
                TransportKind::Tcp,
                [ConnectionNamespace::TCP_IPV6],
                other.boxed(),
            )
            .expect_err("TCP is taken");
        assert_eq!(
            error,
            TransportSetError::DuplicateKind {
                kind: TransportKind::Tcp
            }
        );
    }

    #[test]
    fn one_namespace_cannot_have_two_members() {
        let mut set = TransportSet::new();
        let first = Fake::new("a", ConnectionNamespace::TCP_IPV4);
        let second = Fake::new("b", ConnectionNamespace::TCP_IPV4);
        set.insert(
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            first.boxed(),
        )
        .expect("first joins");

        // Different shape, same namespace: ids would be ambiguous, and an
        // ambiguous id delivers a connection's work to the wrong transport.
        let error = set
            .insert(
                TransportKind::Quic,
                [ConnectionNamespace::TCP_IPV4],
                second.boxed(),
            )
            .expect_err("the namespace is taken");
        assert_eq!(
            error,
            TransportSetError::DuplicateNamespace {
                namespace: ConnectionNamespace::TCP_IPV4
            }
        );
    }

    #[test]
    fn a_member_that_claims_no_namespace_is_refused() {
        let mut set = TransportSet::new();
        let fake = Fake::new("a", ConnectionNamespace::TCP_IPV4);
        // Nothing it returned could ever be routed back to it.
        assert_eq!(
            set.insert(TransportKind::Tcp, [], fake.boxed())
                .expect_err("no namespace"),
            TransportSetError::NoNamespace
        );
    }

    #[test]
    fn a_poll_gathers_what_every_member_produced() {
        let (mut set, tcp, quic) = duo();
        let tcp_id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("in range");
        let quic_id =
            ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 1).expect("in range");
        tcp.log.borrow_mut().events = vec![TransportEvent::Closed { id: tcp_id }];
        quic.log.borrow_mut().events = vec![TransportEvent::Closed { id: quic_id }];

        let events = set.poll(Now::from_millis(0)).expect("poll");
        assert_eq!(events.len(), 2, "both members are polled: {events:?}");
    }

    #[test]
    fn a_failing_member_does_not_cost_a_healthy_one_its_events() {
        let (mut set, tcp, quic) = duo();
        let tcp_id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("in range");
        tcp.log.borrow_mut().events = vec![TransportEvent::Closed { id: tcp_id }];
        quic.log.borrow_mut().fails_poll = true;

        let error = set
            .poll(Now::from_millis(0))
            .expect_err("the failing member is reported");
        assert!(matches!(error, TransportError::PollError { .. }));

        // TCP's connection did nothing wrong. Dropping its events because a
        // sibling transport failed would lose a close nobody could recover.
        quic.log.borrow_mut().fails_poll = false;
        let events = set.poll(Now::from_millis(0)).expect("the next poll");
        assert_eq!(
            events,
            vec![TransportEvent::Closed { id: tcp_id }],
            "events held back by a failed poll have to survive it"
        );
    }

    #[test]
    fn held_back_events_are_due_immediately() {
        let (mut set, tcp, quic) = duo();
        let tcp_id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("in range");
        tcp.log.borrow_mut().events = vec![TransportEvent::Closed { id: tcp_id }];
        quic.log.borrow_mut().fails_poll = true;
        let _ = set.poll(Now::from_millis(0));

        // A host that slept here would sit on an event it has never seen.
        assert_eq!(set.next_deadline(), Some(Deadline::IMMEDIATE));
    }

    #[test]
    fn the_earliest_member_deadline_is_the_sets_deadline() {
        let (set, tcp, quic) = duo();
        assert_eq!(set.next_deadline(), None, "an idle set waits on nothing");

        // Asserted with the earliest deadline in each position in turn: the
        // set owes the host the soonest of them, not whichever member it
        // happens to reach first.
        for (first, second) in [(300, 900), (900, 300)] {
            tcp.log.borrow_mut().deadline = Some(Deadline::from_millis(first));
            quic.log.borrow_mut().deadline = Some(Deadline::from_millis(second));
            assert_eq!(
                set.next_deadline(),
                Some(Deadline::from_millis(300)),
                "the earliest deadline was in the member reporting {first}ms"
            );
        }

        tcp.log.borrow_mut().deadline = None;
        assert_eq!(
            set.next_deadline(),
            Some(Deadline::from_millis(300)),
            "a member with nothing due must not hide one that has"
        );
    }

    #[test]
    fn addresses_are_reported_from_every_member() {
        let (set, tcp, quic) = duo();
        tcp.log.borrow_mut().addresses = vec![tcp_addr()];
        quic.log.borrow_mut().addresses = vec![quic_addr()];

        // A host announces where it can be reached; leaving out a transport
        // would make half of those ways invisible to peers.
        assert_eq!(set.local_addresses(), vec![tcp_addr(), quic_addr()]);
        assert_eq!(
            set.active_inbound_connection_sources(),
            vec![tcp_addr(), quic_addr()]
        );
    }
}
