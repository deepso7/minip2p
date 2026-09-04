use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec::Vec;
use core::fmt;

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

#[cfg(feature = "std")]
#[derive(Default)]
struct WakeState {
    handles: Vec<crate::WaitHandle>,
    /// An interrupt sent before any wakeable member joined. The first member
    /// that can park inherits it, preserving [`WaitHandle`]'s next-wait
    /// guarantee across set composition.
    pending: bool,
}

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
    /// Every member's interrupt handle, shared with the handles this set hands
    /// out so a member joining later is still reachable through one taken
    /// earlier. Also the lock that makes an interrupt atomic with respect to
    /// the waits it has to wake.
    #[cfg(feature = "std")]
    wakers: alloc::sync::Arc<std::sync::Mutex<WakeState>>,
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
        {
            let handle = transport.wait_handle();
            if !handle.is_noop() {
                let mut wake = self.wakers();
                if wake.pending {
                    handle.interrupt();
                    wake.pending = false;
                }
                wake.handles.push(handle);
            }
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

    /// The shared handle list, past a poisoned lock: a panic while pushing a
    /// handle leaves the list usable, and refusing to wake anything would be
    /// worse than waking one member twice.
    #[cfg(feature = "std")]
    fn wakers(&self) -> std::sync::MutexGuard<'_, WakeState> {
        self.wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    fn prototype_held(
        &mut self,
        id: ConnectionId,
        stream: StreamId,
    ) -> Result<usize, TransportError> {
        self.for_id(id)?.prototype_held(id, stream)
    }

    fn prototype_enable(
        &mut self,
        id: ConnectionId,
        stream: StreamId,
    ) -> Result<(), TransportError> {
        self.for_id(id)?.prototype_enable(id, stream)
    }

    fn prototype_take(
        &mut self,
        id: ConnectionId,
        stream: StreamId,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        self.for_id(id)?.prototype_take(id, stream)
    }

    fn prototype_release(
        &mut self,
        id: ConnectionId,
        stream: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        self.for_id(id)?.prototype_release(id, stream, bytes)
    }

    fn prototype_try_read(
        &mut self,
        id: ConnectionId,
        stream: StreamId,
        out: &mut [u8],
    ) -> Result<Option<usize>, TransportError> {
        self.for_id(id)?.prototype_try_read(id, stream, out)
    }

    fn prototype_try_write(
        &mut self,
        id: ConnectionId,
        stream: StreamId,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        self.for_id(id)?.prototype_try_write(id, stream, data)
    }

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

    impl TransportSet {
        /// Answers one logical interrupt once.
        ///
        /// The handle wakes every member, so the members that did not win the
        /// race are each left holding a token of the same interrupt. Consuming
        /// them here is what keeps one call to
        /// [`WaitHandle::interrupt`](crate::WaitHandle::interrupt) worth one
        /// `Interrupted`: left behind, each would surface as another wake, and
        /// would do it from the non-blocking probe at the top of the next
        /// wait, ahead of a member with real input to hand over.
        ///
        /// A sibling that reports `Ready` while being drained loses nothing:
        /// readiness outlives this call, and a driver polls the transport after
        /// an interrupt anyway.
        fn settle_interrupt(&mut self, woken: usize) -> WaitOutcome {
            // Taken while draining so an interrupt still fanning out cannot
            // land on a member this loop has already passed. The handle holds
            // the same lock for the whole of its fan-out.
            let wakers = alloc::sync::Arc::clone(&self.wakers);
            let _fanout = wakers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (index, member) in self.members.iter_mut().enumerate() {
                if index != woken {
                    member.transport.wait_for_input(Duration::ZERO);
                }
            }
            WaitOutcome::Interrupted
        }
    }

    impl BlockingTransport for TransportSet {
        fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
            // Events a failed poll held back are input the caller has not seen.
            if !self.pending.is_empty() {
                return WaitOutcome::Ready;
            }

            // Probe every member without blocking before blocking on any of
            // them: a budget spent waiting on a quiet member would report
            // `TimedOut` while another already had something to hand over.
            // The probe also says which members can park at all, and only
            // those are worth a slice of the budget.
            let mut waiters = Vec::new();
            for (index, member) in self.members.iter_mut().enumerate() {
                match member.transport.wait_for_input(Duration::ZERO) {
                    WaitOutcome::Ready => return WaitOutcome::Ready,
                    WaitOutcome::Interrupted => return self.settle_interrupt(index),
                    WaitOutcome::TimedOut => waiters.push(index),
                    WaitOutcome::Unsupported => {}
                }
            }
            if waiters.is_empty() {
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
                for (turn, &index) in waiters.iter().enumerate() {
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
                    // Every member that can park has to get a turn within this
                    // call, so what is left is divided among those still to
                    // come -- and only those: counting a member that answers
                    // instantly would hand the budget to nobody and shorten
                    // every real wait. A share too small to divide degrades to
                    // a non-blocking probe, which is still a turn.
                    let share = u32::try_from(waiters.len() - turn)
                        .map_or(remaining, |left| remaining / left);
                    let slice = SLICE.min(remaining).min(share);
                    let Some(member) = self.members.get_mut(index) else {
                        return WaitOutcome::Unsupported;
                    };
                    match member.transport.wait_for_input(slice) {
                        WaitOutcome::Ready => return WaitOutcome::Ready,
                        WaitOutcome::Interrupted => return self.settle_interrupt(index),
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
            //
            // The list is the set's own and is read when the handle fires, not
            // when it is taken, so a member that joins later is woken by a
            // handle a host already holds. That is why nothing wakeable in the
            // list yet is not grounds for an inert handle either: a host wires
            // its wakeup path while composing the set, and a handle that had
            // answered "inert" then would leave the set asleep inside every
            // member that filled it afterwards. An empty list simply reaches
            // nobody, for as long as it stays empty.
            let wakers = alloc::sync::Arc::clone(&self.wakers);
            WaitHandle::new(move || {
                // Held across the whole fan-out so a wait draining its
                // siblings sees either all of this interrupt or none of it.
                let mut handles = wakers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if handles.handles.is_empty() {
                    handles.pending = true;
                }
                for handle in &handles.handles {
                    handle.interrupt();
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        /// Every timeout this member was asked to wait for, in order, so a
        /// test can see what share of a budget it was given.
        #[cfg(feature = "std")]
        waits: Vec<core::time::Duration>,
        /// Whether a wait finds input ready.
        #[cfg(feature = "std")]
        ready: bool,
        /// Whether this member can park at all. Set before joining a set: a
        /// member's handle is taken when it joins.
        #[cfg(feature = "std")]
        can_wait: bool,
    }

    #[derive(Clone)]
    struct Fake {
        name: &'static str,
        /// The namespace `dial` stamps its ids with, which a test can put out
        /// of step with what the member claimed.
        namespace: ConnectionNamespace,
        shared: Shared,
        /// Interrupts this member has been handed and not yet reported. Held
        /// apart from the log because its [`WaitHandle`] outlives any borrow.
        #[cfg(feature = "std")]
        interrupts: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
    }

    impl Fake {
        fn new(name: &'static str, namespace: ConnectionNamespace) -> Self {
            Self {
                name,
                namespace,
                shared: Shared::new(Log::default().into()),
                #[cfg(feature = "std")]
                interrupts: alloc::sync::Arc::default(),
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

        /// A member that can park on readiness, and so hands out a real
        /// handle. Set before joining, since joining is when the set takes it.
        #[cfg(feature = "std")]
        fn waking(self) -> Self {
            self.log().can_wait = true;
            self
        }

        fn record(&self, call: &str) {
            self.log().calls.push(call.to_string());
        }

        fn calls(&self) -> Vec<String> {
            self.log().calls.clone()
        }

        #[cfg(feature = "std")]
        fn waits(&self) -> Vec<core::time::Duration> {
            self.log().waits.clone()
        }

        /// Interrupts handed to this member and not yet reported.
        #[cfg(feature = "std")]
        fn pending_interrupts(&self) -> usize {
            self.interrupts.load(core::sync::atomic::Ordering::SeqCst)
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

    #[cfg(feature = "std")]
    impl crate::BlockingTransport for Fake {
        fn wait_for_input(&mut self, timeout: core::time::Duration) -> crate::WaitOutcome {
            use core::sync::atomic::Ordering;

            self.log().waits.push(timeout);
            // An interrupt outranks everything else, as it does in the mio
            // waits the real adapters are built on, and consumes its token.
            if self.interrupts.load(Ordering::SeqCst) > 0 {
                self.interrupts.fetch_sub(1, Ordering::SeqCst);
                return crate::WaitOutcome::Interrupted;
            }
            let (can_wait, ready) = {
                let log = self.log();
                (log.can_wait, log.ready)
            };
            if !can_wait {
                return crate::WaitOutcome::Unsupported;
            }
            if ready {
                return crate::WaitOutcome::Ready;
            }
            // Spend the budget, as a real readiness wait would: a fake that
            // returned instantly would make a slice's length unobservable.
            std::thread::sleep(timeout);
            crate::WaitOutcome::TimedOut
        }

        fn wait_handle(&self) -> crate::WaitHandle {
            if !self.log().can_wait {
                return crate::WaitHandle::noop();
            }
            let interrupts = alloc::sync::Arc::clone(&self.interrupts);
            crate::WaitHandle::new(move || {
                interrupts.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            })
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
        tcp.log().events = vec![TransportEvent::Closed { id: tcp_id }];
        quic.log().events = vec![TransportEvent::Closed { id: quic_id }];

        // Both connections, each exactly once: a count alone would pass on a
        // set that reported one member's event twice and lost the other's.
        let events = set.poll(Now::from_millis(0)).expect("poll");
        assert_eq!(
            events,
            vec![
                TransportEvent::Closed { id: tcp_id },
                TransportEvent::Closed { id: quic_id },
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
        quic.log().events = vec![TransportEvent::Closed { id: quic_id }];

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
            vec![TransportEvent::Closed { id: quic_id }],
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
            quic.log().events = vec![TransportEvent::Closed { id: quic_id }];
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
        tcp.log().events = vec![TransportEvent::Closed { id: tcp_id }];
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
    mod waiting {
        use super::*;
        use crate::{BlockingTransport, WaitOutcome};
        use core::time::Duration;

        /// A set of two members that can both park.
        fn waking_duo() -> (TransportSet, Fake, Fake) {
            let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4).waking();
            let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4).waking();
            (set_of(&[&tcp, &quic]), tcp, quic)
        }

        #[test]
        fn input_on_any_member_is_reported_before_blocking_on_another() {
            let (mut set, tcp, quic) = waking_duo();
            quic.log().ready = true;

            let started = std::time::Instant::now();
            assert_eq!(
                set.wait_for_input(Duration::from_secs(30)),
                WaitOutcome::Ready
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "a budget must not be spent on a quiet member while another has input"
            );
            assert_eq!(
                tcp.waits(),
                vec![Duration::ZERO],
                "the quiet member is probed, never blocked on"
            );
        }

        #[test]
        fn one_interrupt_wakes_the_set_once() {
            let (mut set, ..) = waking_duo();
            let handle = set.wait_handle();
            assert!(!handle.is_noop(), "a set of wakeable members is wakeable");

            handle.interrupt();
            assert_eq!(
                set.wait_for_input(Duration::from_millis(50)),
                WaitOutcome::Interrupted
            );
            // The handle woke every member, so every member is holding a token
            // of the same interrupt. A second `Interrupted` would be a wake
            // nobody asked for -- and, coming from the probe at the top, would
            // arrive ahead of a member with real input.
            assert_eq!(
                set.wait_for_input(Duration::ZERO),
                WaitOutcome::TimedOut,
                "one interrupt is worth one wake"
            );
        }

        #[test]
        fn a_handle_taken_early_wakes_a_member_that_joined_later() {
            let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4).waking();
            let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4).waking();
            let mut set = set_of(&[&tcp]);
            // Taken while the set was still being composed, which is exactly
            // when a host wires its wakeup path.
            let handle = set.wait_handle();
            set.insert(
                TransportKind::Quic,
                [ConnectionNamespace::QUIC_IPV4],
                quic.boxed(),
            )
            .expect("quic joins");

            handle.interrupt();
            // The wait parks inside whichever member has the slice, so a
            // handle that missed one of them can leave the set asleep in it.
            assert_eq!(
                quic.pending_interrupts(),
                1,
                "a handle the host already holds has to reach a member that joined after it"
            );
            assert_eq!(
                set.wait_for_input(Duration::from_millis(50)),
                WaitOutcome::Interrupted
            );
            assert_eq!(
                quic.pending_interrupts(),
                0,
                "and the set still answers that interrupt exactly once"
            );
        }

        #[test]
        fn a_handle_taken_before_anything_wakeable_wakes_what_joins_after_it() {
            let mut set = TransportSet::new();
            // Nothing in the set can be woken yet -- and a host wires its
            // wakeup path here, while composing, before it binds a thing.
            let handle = set.wait_handle();
            let unwakeable = Fake::new("smoltcp", ConnectionNamespace::TCP_IPV6);
            set.insert(
                TransportKind::Tcp,
                [ConnectionNamespace::TCP_IPV6],
                unwakeable.boxed(),
            )
            .expect("the unwakeable member joins");
            let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4).waking();
            set.insert(
                TransportKind::Quic,
                [ConnectionNamespace::QUIC_IPV4],
                quic.boxed(),
            )
            .expect("quic joins");

            handle.interrupt();
            assert_eq!(
                quic.pending_interrupts(),
                1,
                "a handle taken before there was anything to wake still has to \
                 reach the members that arrived after it"
            );
            // Otherwise the set parks inside that member for the whole budget
            // with a host holding a handle it believes wakes it.
            assert_eq!(
                set.wait_for_input(Duration::from_secs(30)),
                WaitOutcome::Interrupted
            );
        }

        #[test]
        fn an_interrupt_before_the_first_wakeable_member_reaches_its_next_wait() {
            let mut set = TransportSet::new();
            let handle = set.wait_handle();
            handle.interrupt();

            let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4).waking();
            set.insert(
                TransportKind::Tcp,
                [ConnectionNamespace::TCP_IPV4],
                tcp.boxed(),
            )
            .expect("tcp joins");

            assert_eq!(
                set.wait_for_input(Duration::from_secs(30)),
                WaitOutcome::Interrupted,
                "an early interrupt is retained until a member can receive it"
            );
            assert_eq!(
                set.wait_for_input(Duration::ZERO),
                WaitOutcome::TimedOut,
                "the retained interrupt is consumed exactly once"
            );
        }

        #[test]
        fn a_set_goes_where_its_driver_goes() {
            let (set, ..) = waking_duo();

            // A hosted driver runs on a thread, and applications move an
            // endpoint onto one. A member that could not come along would make
            // the whole set unusable there -- which is a compile error here,
            // not a runtime one.
            std::thread::spawn(move || drop(set)).join().expect("moved");
        }

        #[test]
        fn a_set_that_cannot_park_says_so() {
            let (mut set, tcp, quic) = duo();

            // Neither member can wait, so a prompt return here means "I cannot
            // do this", not "nothing happened yet" -- the caller has to sleep
            // on its own clock rather than spin.
            assert_eq!(
                set.wait_for_input(Duration::from_secs(30)),
                WaitOutcome::Unsupported
            );
            // The handle is still live, though, and interrupting it reaches
            // nobody rather than panicking: membership can grow, and a wakeable
            // member joining later has to be reachable through a handle the
            // host already holds. `Unsupported` is what says the set cannot
            // park -- that is the answer a driver acts on.
            set.wait_handle().interrupt();
            assert_eq!(tcp.waits(), vec![Duration::ZERO]);
            assert_eq!(quic.waits(), vec![Duration::ZERO]);
        }

        #[test]
        fn only_members_that_can_park_are_given_a_share_of_the_budget() {
            let tcp = Fake::new("tcp", ConnectionNamespace::TCP_IPV4);
            let quic = Fake::new("quic", ConnectionNamespace::QUIC_IPV4).waking();
            let mut set = set_of(&[&tcp, &quic]);

            assert_eq!(
                set.wait_for_input(Duration::from_millis(8)),
                WaitOutcome::TimedOut
            );
            assert_eq!(
                tcp.waits(),
                vec![Duration::ZERO],
                "a member that cannot park is probed once and left alone"
            );
            let blocking = quic.waits();
            assert_eq!(blocking.first(), Some(&Duration::ZERO), "probed first");
            assert!(
                blocking[1] >= Duration::from_millis(6),
                "the only member that can park gets the whole budget, not a \
                 share of it split with one that cannot: {blocking:?}"
            );
        }
    }
}
