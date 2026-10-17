use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec::Vec;
use core::fmt;

use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Bytes, Multiaddr, PeerAddr, TransportKind};
use thiserror::Error;

use crate::{
    ConnectionId, ConnectionNamespace, StreamId, Transport, TransportError, TransportEvent,
};

/// How a member is held.
///
/// Under `std` a member must also be a
/// [`BlockingTransport`](crate::BlockingTransport) -- a transport that is a
/// [`PollSource`](crate::PollSource) -- so the set can register every member
/// with the host's one shared poll and route readiness back to it.
///
/// `Send` comes with it, for the same reason blocking does: a hosted driver
/// lives on a thread, and an endpoint that could not be moved onto one would
/// be useless there. A `no_std` host has no thread to move anything to, so it
/// asks for neither.
#[cfg(feature = "std")]
type BoxedTransport = Box<dyn crate::BlockingTransport + Send>;
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
    /// The set is already attached to a host's shared poll, and the member
    /// could not be attached to it: its sockets failed to register, or the
    /// set's token space has no subspace left for it.
    #[error("could not attach the member to the shared poll ({kind}): {detail}")]
    AttachFailed {
        /// What kind of failure the registration reported.
        kind: minip2p_core::platform::IoErrorKind,
        /// The registration's own description, for diagnostics.
        detail: alloc::string::String,
    },
}

/// A transport a [`TransportSet`] refused, handed back with the reason.
///
/// A transport owns things a host still needs -- a bound socket, a listener,
/// live connections -- so a rejected join returns it rather than dropping it
/// where the caller cannot reach it. The host can claim differently and try
/// again, or shut it down deliberately.
pub struct RejectedTransport {
    error: TransportSetError,
    transport: BoxedTransport,
}

impl RejectedTransport {
    /// Why the set refused this transport.
    pub fn error(&self) -> &TransportSetError {
        &self.error
    }

    /// Takes the refused transport back.
    pub fn into_transport(self) -> BoxedTransport {
        self.transport
    }

    /// Splits into the reason and the transport it refused.
    pub fn into_parts(self) -> (TransportSetError, BoxedTransport) {
        (self.error, self.transport)
    }
}

impl fmt::Debug for RejectedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A boxed transport is not `Debug`, and the reason is the whole of
        // what a failed `expect` needs to say.
        f.debug_struct("RejectedTransport")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RejectedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl core::error::Error for RejectedTransport {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

struct Member {
    /// The address shape this member dials and listens on.
    kind: TransportKind,
    /// The namespaces it allocates connection ids in, which is what routes an
    /// id back to it.
    namespaces: Vec<ConnectionNamespace>,
    transport: BoxedTransport,
}

/// Bits of a set's token space that name a member: up to 256 members, each
/// with its own subspace.
#[cfg(feature = "std")]
const MEMBER_PREFIX_BITS: u32 = 8;

/// Several transports behind one [`Transport`].
///
/// This is what lets a host speak QUIC and TCP at once without the swarm above
/// it knowing there is more than one of anything. It owns no I/O of its own: it
/// is a router, and every decision it makes is a lookup.
///
/// # Routing
///
/// Two questions, two answers already in the types:
///
/// - **Which member dials this address?** [`Multiaddr::transport_kind`] says
///   whether an address is `/udp/quic-v1` or `/tcp`, and each member claims one
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
/// # One member's fault
///
/// A member that fails a [`poll`](Transport::poll) does not cost its siblings
/// what they produced in the same round: those events are handed over by the
/// next poll, before any member is driven again. So a transport that stays
/// broken reports its fault every time without burying a healthy member's
/// events behind it, and the queue that makes that possible holds one round
/// rather than growing.
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
    /// Additional member failures from a round whose first failure has
    /// already been returned to the caller.
    failures: VecDeque<TransportError>,
    /// The shared poll this set was attached to, for members that join
    /// afterwards.
    #[cfg(feature = "std")]
    attachment: Option<polling::Attachment>,
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
    /// connection's events to the wrong transport. A refused transport comes
    /// back with the reason, inside [`RejectedTransport`], rather than being
    /// dropped somewhere the caller cannot reach it.
    ///
    /// The namespaces named here must be every namespace this transport
    /// allocates ids in. An id from one it did not claim could not be routed
    /// back, so a dial that produces one is refused rather than handed out.
    pub fn insert(
        &mut self,
        kind: TransportKind,
        namespaces: impl IntoIterator<Item = ConnectionNamespace>,
        transport: BoxedTransport,
    ) -> Result<(), RejectedTransport> {
        let namespaces: Vec<ConnectionNamespace> = namespaces.into_iter().collect();
        if let Some(error) = self.conflict(kind, &namespaces) {
            return Err(RejectedTransport { error, transport });
        }
        #[cfg(feature = "std")]
        let mut transport = transport;
        #[cfg(feature = "std")]
        if let Some(attachment) = &self.attachment
            && let Err(error) = attachment.attach_member(self.members.len(), &mut transport)
        {
            return Err(RejectedTransport {
                error: TransportSetError::AttachFailed {
                    kind: error.kind().into(),
                    detail: error.to_string(),
                },
                transport,
            });
        }
        self.members.push(Member {
            kind,
            namespaces,
            transport,
        });
        Ok(())
    }

    /// Why this claim cannot be granted, if it cannot.
    fn conflict(
        &self,
        kind: TransportKind,
        namespaces: &[ConnectionNamespace],
    ) -> Option<TransportSetError> {
        if namespaces.is_empty() {
            return Some(TransportSetError::NoNamespace);
        }
        if self.members.iter().any(|member| member.kind == kind) {
            return Some(TransportSetError::DuplicateKind { kind });
        }
        namespaces
            .iter()
            .find(|namespace| {
                self.members
                    .iter()
                    .any(|member| member.namespaces.contains(namespace))
            })
            .map(|namespace| TransportSetError::DuplicateNamespace {
                namespace: *namespace,
            })
    }

    /// Whether the set can dial anything at all.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The address shapes this set can dial and listen on.
    pub fn kinds(&self) -> Vec<TransportKind> {
        self.members.iter().map(|member| member.kind).collect()
    }

    fn index_for_id(&self, id: ConnectionId) -> Result<usize, TransportError> {
        let namespace = id.namespace();
        self.members
            .iter()
            .position(|member| member.namespaces.contains(&namespace))
            // An id from a namespace nobody claims names no connection here,
            // which is the same thing as a connection that does not exist.
            .ok_or(TransportError::ConnectionNotFound { id })
    }

    fn for_id(&mut self, id: ConnectionId) -> Result<&mut BoxedTransport, TransportError> {
        let index = self.index_for_id(id)?;
        self.members
            .get_mut(index)
            .map(|member| &mut member.transport)
            .ok_or(TransportError::ConnectionNotFound { id })
    }

    fn index_for_addr(
        &self,
        addr: &Multiaddr,
        context: &'static str,
    ) -> Result<usize, TransportError> {
        let kind = addr
            .transport_kind()
            .ok_or_else(|| TransportError::InvalidAddress {
                context,
                reason: format!("{addr} is not a transport address"),
            })?;
        self.members
            .iter()
            .position(|member| member.kind == kind)
            .ok_or_else(|| TransportError::InvalidAddress {
                context,
                reason: format!("this set has no {kind:?} transport for {addr}"),
            })
    }

    fn for_addr(
        &mut self,
        addr: &Multiaddr,
        context: &'static str,
    ) -> Result<&mut Member, TransportError> {
        let index = self.index_for_addr(addr, context)?;
        self.members
            .get_mut(index)
            .ok_or_else(|| TransportError::InvalidAddress {
                context,
                reason: format!("the route for {addr} is no longer available"),
            })
    }
}

impl Transport for TransportSet {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let target = addr.transport().clone();
        let member = self.for_addr(&target, "dial target")?;
        let id = member.transport.dial(addr)?;
        // A member that stamps an id in a namespace it did not claim hands
        // back an id this set cannot route: every later call on it would look
        // for an owner and find none, and the connection would be unreachable
        // while still costing the member everything a connection costs. Fail
        // the dial where the mis-claim is visible, and close what it opened.
        if !member.namespaces.contains(&id.namespace()) {
            // The routing failure is what the caller can correct. `id` does
            // not belong to the set, so a failed best-effort cleanup cannot
            // be retried or reported through the set's public API.
            drop(member.transport.close(id));
            return Err(TransportError::DialFailed {
                id,
                reason: format!(
                    "the {:?} member allocated {id} in {}, a namespace it did not claim",
                    member.kind,
                    id.namespace()
                ),
            });
        }
        Ok(id)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.for_addr(addr, "listen address")?
            .transport
            .listen(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.for_id(id)?.open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
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

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        // A connection no member owns is unknown, and acknowledging an
        // unknown connection is a no-op.
        match self.for_id(id) {
            Ok(member) => member.ack_stream(id, stream_id, bytes),
            Err(_) => Ok(()),
        }
    }

    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        if let Ok(member) = self.for_id(id) {
            member.set_control_stream(id, stream_id, control);
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.for_id(id)?.close(id)
    }

    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        // Routed by shape like a dial: a hole punch has to leave the socket the
        // connection it is opening will arrive on, so the member that would
        // dial this address is the only one it can come from.
        self.for_addr(target, "datagram target")?
            .transport
            .send_datagram(target, payload)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        // Events a failing poll held back are delivered before any member is
        // polled again. That bounds what this queue holds to a single round
        // and, more importantly, means a member that fails every time cannot
        // keep a healthy sibling's events queued behind it forever: the host
        // alternates between hearing the fault and draining what still works.
        if !self.pending.is_empty() {
            return Ok(self.pending.drain(..).collect());
        }
        if let Some(error) = self.failures.pop_front() {
            return Err(error);
        }

        // Every member is polled, even after one fails: a member that has
        // events ready is not answerable for another one's fault, and the
        // failing member has already told the host what went wrong through the
        // error. What has been collected so far is kept for the next poll
        // rather than dropped, so no connection loses events to a sibling.
        for member in &mut self.members {
            match member.transport.poll(now) {
                Ok(events) => self.pending.extend(events),
                Err(error) => self.failures.push_back(error),
            }
        }
        match self.failures.pop_front() {
            Some(error) => Err(error),
            None => Ok(self.pending.drain(..).collect()),
        }
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if !self.pending.is_empty() || !self.failures.is_empty() {
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

    /// The members' counters added up, plus the member count: members are
    /// only ever added and each counter only advances, so the sum moves
    /// whenever any member's addresses may have. `None` as soon as one
    /// member cannot tell.
    fn local_addresses_revision(&self) -> Option<u64> {
        self.members.iter().try_fold(
            u64::try_from(self.members.len()).unwrap_or(u64::MAX),
            |sum, member| Some(sum.wrapping_add(member.transport.local_addresses_revision()?)),
        )
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.members
            .iter()
            .flat_map(|member| member.transport.active_inbound_connection_sources())
            .collect()
    }
}

#[cfg(feature = "std")]
mod polling {
    use alloc::sync::Arc;
    use std::io;

    use mio::event::Event;
    use mio::{Registry, Waker};

    use super::{BoxedTransport, MEMBER_PREFIX_BITS, TransportSet};
    use crate::{PollSource, TokenSpace};

    /// What [`PollSource::attach`] handed the set, kept for members that join
    /// later.
    pub(super) struct Attachment {
        registry: Registry,
        tokens: TokenSpace,
        waker: Arc<Waker>,
    }

    impl Attachment {
        /// Attaches member `index` in its own subspace.
        pub(super) fn attach_member(
            &self,
            index: usize,
            member: &mut BoxedTransport,
        ) -> io::Result<()> {
            let tokens = self
                .tokens
                .subspace(MEMBER_PREFIX_BITS, index)
                .map_err(io::Error::other)?;
            member.attach(self.registry.try_clone()?, tokens, Arc::clone(&self.waker))
        }
    }

    /// Routes readiness to members by token prefix.
    ///
    /// Each member gets the subspace its index names, under an 8-bit prefix
    /// of the set's own space, so an event's token says which member it is
    /// for without a lookup table. Members inserted after the set is
    /// attached are attached as they join.
    ///
    /// # Errors
    ///
    /// A member that fails to attach rolls back its own registrations, but
    /// members attached before it stay registered, and the set records no
    /// attachment. Drop a set whose attach failed rather than attach it
    /// again: a retry would find those members already registered.
    impl PollSource for TransportSet {
        fn attach(
            &mut self,
            registry: Registry,
            tokens: TokenSpace,
            waker: Arc<Waker>,
        ) -> io::Result<()> {
            let attachment = Attachment {
                registry,
                tokens,
                waker,
            };
            for (index, member) in self.members.iter_mut().enumerate() {
                attachment.attach_member(index, &mut member.transport)?;
            }
            self.attachment = Some(attachment);
            Ok(())
        }

        fn dispatch(&mut self, event: &Event) {
            let Some(attachment) = &self.attachment else {
                return;
            };
            let member = attachment
                .tokens
                .subspace_of(MEMBER_PREFIX_BITS, event.token())
                .and_then(|index| self.members.get_mut(index));
            // A token no member holds is stale: harmless, and dropped.
            if let Some(member) = member {
                member.transport.dispatch(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionCloseReason;
    use alloc::string::{String, ToString};
    use alloc::vec;

    /// A fake's shared state, held the way its host would have to hold it: a
    /// `std` member is `Send`, so nothing behind it may be a bare `Rc`.
    #[cfg(feature = "std")]
    type Shared = alloc::sync::Arc<std::sync::Mutex<Log>>;
    #[cfg(not(feature = "std"))]
    type Shared = alloc::rc::Rc<core::cell::RefCell<Log>>;

    /// What a member was asked to do, so routing can be asserted on the member
    /// that actually received the call rather than on a return value that
    /// several members could have produced.
    #[derive(Default)]
    struct Log {
        calls: Vec<String>,
        events: Vec<TransportEvent>,
        deadline: Option<Deadline>,
        addresses: Vec<Multiaddr>,
        /// Reported separately from `addresses`: a set that answered both
        /// questions from one member method would look right against a fake
        /// that did the same.
        inbound: Vec<Multiaddr>,
        fails_poll: bool,
        /// The space this member was attached in, if it was.
        #[cfg(feature = "std")]
        attached: Option<crate::TokenSpace>,
        /// A socket the member registers when attached, so readiness can be
        /// routed to it for real.
        #[cfg(feature = "std")]
        socket: Option<mio::net::UdpSocket>,
        /// Tokens dispatched to this member.
        #[cfg(feature = "std")]
        dispatched: Vec<mio::Token>,
    }

    #[derive(Clone)]
    struct Fake {
        name: &'static str,
        /// The namespace `dial` stamps its ids with, which a test can put out
        /// of step with what the member claimed.
        namespace: ConnectionNamespace,
        shared: Shared,
    }

    impl Fake {
        fn new(name: &'static str, namespace: ConnectionNamespace) -> Self {
            Self {
                name,
                namespace,
                shared: Shared::new(Log::default().into()),
            }
        }

        /// The shared log, however this build has to reach it.
        #[cfg(feature = "std")]
        fn log(&self) -> std::sync::MutexGuard<'_, Log> {
            self.shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        #[cfg(not(feature = "std"))]
        fn log(&self) -> core::cell::RefMut<'_, Log> {
            self.shared.borrow_mut()
        }

        fn record(&self, call: &str) {
            self.log().calls.push(call.to_string());
        }

        fn calls(&self) -> Vec<String> {
            self.log().calls.clone()
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
            _data: Bytes,
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

        fn ack_stream(
            &mut self,
            _id: ConnectionId,
            _stream_id: StreamId,
            _bytes: usize,
        ) -> Result<(), TransportError> {
            self.record("ack_stream");
            Ok(())
        }

        fn close(&mut self, _id: ConnectionId) -> Result<(), TransportError> {
            self.record("close");
            Ok(())
        }

        fn send_datagram(
            &mut self,
            _target: &Multiaddr,
            _payload: &[u8],
        ) -> Result<(), TransportError> {
            self.record("send_datagram");
            Ok(())
        }

        fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            self.record("poll");
            if self.log().fails_poll {
                return Err(TransportError::PollError {
                    reason: self.name.to_string(),
                });
            }
            Ok(core::mem::take(&mut self.log().events))
        }

        fn next_deadline(&self) -> Option<Deadline> {
            self.log().deadline
        }

        fn local_addresses(&self) -> Vec<Multiaddr> {
            self.log().addresses.clone()
        }

        fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
            self.log().inbound.clone()
        }
    }

    /// Registers a loopback UDP socket at the first token of its space.
    #[cfg(feature = "std")]
    impl crate::PollSource for Fake {
        fn attach(
            &mut self,
            registry: mio::Registry,
            tokens: crate::TokenSpace,
            _waker: alloc::sync::Arc<mio::Waker>,
        ) -> std::io::Result<()> {
            let mut socket =
                mio::net::UdpSocket::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let token = tokens
                .token(0)
                .ok_or_else(|| std::io::Error::other("no token"))?;
            registry.register(&mut socket, token, mio::Interest::READABLE)?;
            let mut log = self.log();
            log.attached = Some(tokens);
            log.socket = Some(socket);
            Ok(())
        }

        fn dispatch(&mut self, event: &mio::event::Event) {
            self.log().dispatched.push(event.token());
        }
    }

    fn addr(text: &str) -> Multiaddr {
        text.parse().expect("test address parses")
    }

    fn tcp_addr() -> Multiaddr {
        addr("/ip4/127.0.0.1/tcp/4001")
    }

    fn quic_addr() -> Multiaddr {
        addr("/ip4/127.0.0.1/udp/4001/quic-v1")
    }

    /// A set with one QUIC member and one TCP member, and both fakes.
    fn duo() -> (TransportSet, Fake, Fake) {
        let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
        let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4);
        (set_of(&[&tcp, &quic]), tcp, quic)
    }

    /// A set of the given fakes, TCP first, each claiming the namespace it
    /// dials in.
    fn set_of(members: &[&Fake]) -> TransportSet {
        let mut set = TransportSet::new();
        for member in members {
            let kind = match member.namespace {
                ConnectionNamespace::QUIC_IPV4 | ConnectionNamespace::QUIC_IPV6 => {
                    TransportKind::Quic
                }
                _ => TransportKind::Tcp,
            };
            set.insert(kind, [member.namespace], member.boxed())
                .expect("a fresh claim");
        }
        set
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
        set.send_stream(id, stream, Bytes::from_static(&[1]))
            .expect("send");
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
    fn a_member_that_claims_two_namespaces_owns_ids_from_both() {
        // What a transport that splits by family internally looks like from
        // out here: the dual-stack QUIC transport allocates in two namespaces
        // and keeps the split to itself, so both have to route to it.
        let dual = Fake::new("quic", ConnectionNamespace::QUIC_IPV4);
        let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
        let mut set = TransportSet::new();
        set.insert(
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            tcp.boxed(),
        )
        .expect("tcp joins");
        set.insert(
            TransportKind::Quic,
            [
                ConnectionNamespace::QUIC_IPV4,
                ConnectionNamespace::QUIC_IPV6,
            ],
            dual.boxed(),
        )
        .expect("quic joins");

        for namespace in [
            ConnectionNamespace::QUIC_IPV4,
            ConnectionNamespace::QUIC_IPV6,
        ] {
            let id = ConnectionId::namespaced(namespace, 9).expect("in range");
            set.close(id)
                .unwrap_or_else(|error| panic!("{namespace}: {error}"));
        }
        assert_eq!(
            dual.calls(),
            vec!["close", "close"],
            "a member owns every namespace it claimed, not just the first"
        );
        assert!(tcp.calls().is_empty());
    }

    #[test]
    fn a_datagram_leaves_from_the_member_that_would_dial_its_target() {
        let (mut set, tcp, quic) = duo();

        // A hole punch has to leave the socket the connection it is opening
        // will arrive on. Sending it from a sibling transport would open a
        // binding for packets that never come.
        set.send_datagram(&quic_addr(), b"punch").expect("sent");
        assert_eq!(quic.calls(), vec!["send_datagram"]);
        assert!(tcp.calls().is_empty());

        let error = set
            .send_datagram(&addr("/ip4/127.0.0.1/tcp/4001/p2p-circuit"), b"punch")
            .expect_err("not a transport address");
        assert!(
            matches!(error, TransportError::InvalidAddress { .. }),
            "got {error:?}"
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
    fn a_dial_landing_outside_the_members_claim_is_refused_and_closed() {
        // The member allocates in TCP_IPV6 but joined claiming only TCP_IPV4,
        // so its ids route nowhere. Handing one back would give the host a
        // connection every later call reports as not found.
        let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV6);
        let mut set = TransportSet::new();
        set.insert(
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            tcp.boxed(),
        )
        .expect("tcp joins");

        let error = set
            .dial(&PeerAddr::new(tcp_addr(), peer()).expect("target"))
            .expect_err("the id is unroutable");
        assert!(
            matches!(&error, TransportError::DialFailed { reason, .. } if reason.contains("did not claim")),
            "the error should name the mis-claim, got {error:?}"
        );
        assert_eq!(
            tcp.calls(),
            vec!["dial", "close"],
            "a connection nobody can reach must not be left open"
        );
    }

    #[test]
    fn an_address_shape_with_no_member_is_refused_by_name() {
        let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
        let mut set = set_of(&[&tcp]);

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

        let rejected = set
            .insert(
                TransportKind::Tcp,
                [ConnectionNamespace::TCP_IPV6],
                other.boxed(),
            )
            .expect_err("TCP is taken");
        assert_eq!(
            rejected.error(),
            &TransportSetError::DuplicateKind {
                kind: TransportKind::Tcp
            }
        );
    }

    #[test]
    fn one_namespace_cannot_have_two_members() {
        let first = Fake::new("a", ConnectionNamespace::TCP_IPV4);
        let second = Fake::new("b", ConnectionNamespace::TCP_IPV4);
        let mut set = set_of(&[&first]);

        // Different shape, same namespace: ids would be ambiguous, and an
        // ambiguous id delivers a connection's work to the wrong transport.
        let rejected = set
            .insert(
                TransportKind::Quic,
                [ConnectionNamespace::TCP_IPV4],
                second.boxed(),
            )
            .expect_err("the namespace is taken");
        assert_eq!(
            rejected.error(),
            &TransportSetError::DuplicateNamespace {
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
                .expect_err("no namespace")
                .error(),
            &TransportSetError::NoNamespace
        );
    }

    #[test]
    fn a_refused_transport_is_handed_back() {
        let (mut set, ..) = duo();
        let other = Fake::new("tcp2", ConnectionNamespace::TCP_IPV6);

        // A transport owns a bound socket by the time it is offered. Dropping
        // it inside a rejected insert would close a listener the host still
        // believes it has, with nothing left to close it deliberately.
        let mut returned = set
            .insert(
                TransportKind::Tcp,
                [ConnectionNamespace::TCP_IPV6],
                other.boxed(),
            )
            .expect_err("TCP is taken")
            .into_transport();
        returned
            .close(ConnectionId::namespaced(ConnectionNamespace::TCP_IPV6, 1).expect("id"))
            .expect("the refused transport is still usable");
        assert_eq!(other.calls(), vec!["close"]);
    }

    #[test]
    fn a_poll_gathers_what_every_member_produced() {
        let (mut set, tcp, quic) = duo();
        let tcp_id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("in range");
        let quic_id =
            ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 1).expect("in range");
        tcp.log().events = vec![TransportEvent::Closed {
            id: tcp_id,
            reason: ConnectionCloseReason::Local,
        }];
        quic.log().events = vec![TransportEvent::Closed {
            id: quic_id,
            reason: ConnectionCloseReason::Local,
        }];

        // Both connections, each exactly once: a count alone would pass on a
        // set that reported one member's event twice and lost the other's.
        let events = set.poll(Now::from_millis(0)).expect("poll");
        assert_eq!(
            events,
            vec![
                TransportEvent::Closed {
                    id: tcp_id,
                    reason: ConnectionCloseReason::Local
                },
                TransportEvent::Closed {
                    id: quic_id,
                    reason: ConnectionCloseReason::Local
                },
            ],
            "both members are polled"
        );
    }

    #[test]
    fn a_failing_member_does_not_cost_a_healthy_one_its_events() {
        let (mut set, tcp, quic) = duo();
        let quic_id =
            ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 1).expect("in range");
        // The failure comes first, so a set that gave up on the first error
        // would never reach the member with something to report.
        tcp.log().fails_poll = true;
        quic.log().events = vec![TransportEvent::Closed {
            id: quic_id,
            reason: ConnectionCloseReason::Local,
        }];

        let error = set
            .poll(Now::from_millis(0))
            .expect_err("the failing member is reported");
        assert!(matches!(error, TransportError::PollError { .. }));
        assert!(
            quic.calls().contains(&"poll".to_string()),
            "a member after the failing one still gets polled"
        );

        // QUIC's connection did nothing wrong. Dropping its events because a
        // sibling transport failed would lose a close nobody could recover.
        tcp.log().fails_poll = false;
        let events = set.poll(Now::from_millis(0)).expect("the next poll");
        assert_eq!(
            events,
            vec![TransportEvent::Closed {
                id: quic_id,
                reason: ConnectionCloseReason::Local
            }],
            "events held back by a failed poll have to survive it"
        );
    }

    #[test]
    fn every_member_failure_is_reported() {
        let (mut set, tcp, quic) = duo();
        tcp.log().fails_poll = true;
        quic.log().fails_poll = true;

        let first = set.poll(Now::from_millis(0)).expect_err("first failure");
        let second = set
            .poll(Now::from_millis(0))
            .expect_err("second member's failure must be retained");

        let reasons = [first, second].map(|error| match error {
            TransportError::PollError { reason } => reason,
            other => panic!("unexpected error: {other:?}"),
        });
        assert_eq!(reasons[0], "tcp");
        assert_eq!(reasons[1], "quic");
        assert_eq!(tcp.calls(), vec!["poll"]);
        assert_eq!(quic.calls(), vec!["poll"]);
    }

    #[test]
    fn a_member_that_never_recovers_does_not_bury_its_siblings_events() {
        let (mut set, tcp, quic) = duo();
        let quic_id =
            ConnectionId::namespaced(ConnectionNamespace::QUIC_IPV4, 1).expect("in range");
        tcp.log().fails_poll = true;

        // A transport can stay broken. Holding a healthy member's events until
        // every member succeeds would mean a host never seeing them again, and
        // a queue that only grows.
        let mut delivered = 0;
        for _ in 0..6 {
            quic.log().events = vec![TransportEvent::Closed {
                id: quic_id,
                reason: ConnectionCloseReason::Local,
            }];
            if let Ok(events) = set.poll(Now::from_millis(0)) {
                delivered += events.len();
            }
        }
        assert!(
            delivered >= 2,
            "the healthy member's events kept coming: {delivered} delivered over six polls"
        );
    }

    #[test]
    fn held_back_events_are_due_immediately() {
        let (mut set, tcp, quic) = duo();
        let tcp_id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("in range");
        tcp.log().events = vec![TransportEvent::Closed {
            id: tcp_id,
            reason: ConnectionCloseReason::Local,
        }];
        quic.log().fails_poll = true;
        drop(set.poll(Now::from_millis(0)));

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
            tcp.log().deadline = Some(Deadline::from_millis(first));
            quic.log().deadline = Some(Deadline::from_millis(second));
            assert_eq!(
                set.next_deadline(),
                Some(Deadline::from_millis(300)),
                "the earliest deadline was in the member reporting {first}ms"
            );
        }

        tcp.log().deadline = None;
        assert_eq!(
            set.next_deadline(),
            Some(Deadline::from_millis(300)),
            "a member with nothing due must not hide one that has"
        );
    }

    #[test]
    fn addresses_are_reported_from_every_member() {
        let (set, tcp, quic) = duo();
        tcp.log().addresses = vec![tcp_addr()];
        quic.log().addresses = vec![quic_addr()];
        // Where peers reached us is a different question from where we are
        // bound, and each member answers both. Asking one for the other would
        // advertise an address nothing is listening on.
        let tcp_source = addr("/ip4/198.51.100.7/tcp/4001");
        let quic_source = addr("/ip4/198.51.100.9/udp/4001/quic-v1");
        tcp.log().inbound = vec![tcp_source.clone()];
        quic.log().inbound = vec![quic_source.clone()];

        // A host announces where it can be reached; leaving out a transport
        // would make half of those ways invisible to peers.
        assert_eq!(set.local_addresses(), vec![tcp_addr(), quic_addr()]);
        assert_eq!(
            set.active_inbound_connection_sources(),
            vec![tcp_source, quic_source]
        );
    }

    #[cfg(feature = "std")]
    mod polling {
        use super::*;
        use crate::{SharedPoll, TokenSpace, TokenSpaceError};
        use core::time::Duration;

        impl Fake {
            /// Sends one datagram to this member's registered socket.
            fn poke(&self) {
                let to = self
                    .log()
                    .socket
                    .as_ref()
                    .expect("attached")
                    .local_addr()
                    .expect("addr");
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .expect("bind")
                    .send_to(b"x", to)
                    .expect("send");
            }

            fn dispatched(&self) -> usize {
                self.log().dispatched.len()
            }
        }

        /// Waits until `member` has been dispatched to, failing after a long
        /// budget; returns how long it took.
        fn wait_for(poll: &mut SharedPoll, set: &mut TransportSet, member: &Fake) -> Duration {
            let started = std::time::Instant::now();
            while member.dispatched() == 0 {
                assert!(started.elapsed() < Duration::from_secs(5), "never routed");
                poll.harvest(set, Duration::from_secs(5)).expect("harvest");
            }
            started.elapsed()
        }

        #[test]
        fn input_on_either_member_ends_one_wait_and_reaches_only_that_member() {
            let (mut set, tcp, quic) = duo();
            let mut poll = SharedPoll::new().expect("poll");
            poll.attach(&mut set).expect("attach");
            let (Some(tcp_space), Some(quic_space)) = (tcp.log().attached, quic.log().attached)
            else {
                panic!("both members attached");
            };
            assert_ne!(tcp_space, quic_space, "each member has its own space");

            quic.poke();
            let took = wait_for(&mut poll, &mut set, &quic);
            assert!(took < Duration::from_secs(1), "no turn-taking: {took:?}");
            assert_eq!(tcp.dispatched(), 0, "routed by prefix, not broadcast");

            tcp.poke();
            wait_for(&mut poll, &mut set, &tcp);
            assert_eq!(quic.dispatched(), 1);
        }

        #[test]
        fn a_member_inserted_after_attach_receives_its_events() {
            let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
            let mut set = set_of(&[&tcp]);
            let mut poll = SharedPoll::new().expect("poll");
            poll.attach(&mut set).expect("attach");

            let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4);
            set.insert(TransportKind::Quic, [quic.namespace], quic.boxed())
                .expect("late insert attaches");
            assert!(quic.log().attached.is_some(), "attached on insert");
            quic.poke();
            wait_for(&mut poll, &mut set, &quic);
            assert_eq!(tcp.dispatched(), 0);
        }

        #[test]
        fn a_member_inserted_before_attach_is_only_stored() {
            let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
            let _set = set_of(&[&tcp]);
            assert!(tcp.log().attached.is_none());
        }

        #[test]
        fn a_set_nested_too_deep_fails_to_attach_with_a_typed_error() {
            let (mut set, ..) = duo();
            // A space with no more than a member prefix's worth of bits.
            let mut tokens = TokenSpace::full();
            while tokens.bits() > MEMBER_PREFIX_BITS {
                tokens = tokens
                    .subspace(tokens.bits() - MEMBER_PREFIX_BITS, 0)
                    .expect("shrink");
            }
            let poll = mio::Poll::new().expect("poll");
            let waker = alloc::sync::Arc::new(
                mio::Waker::new(poll.registry(), mio::Token(usize::MAX)).expect("waker"),
            );
            let error = crate::PollSource::attach(
                &mut set,
                poll.registry().try_clone().expect("registry"),
                tokens,
                waker,
            )
            .expect_err("no bits left for members");
            let inner = error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<TokenSpaceError>());
            assert!(
                matches!(inner, Some(TokenSpaceError::Exhausted { .. })),
                "{error:?}"
            );
        }
    }
}
