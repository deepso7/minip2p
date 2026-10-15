//! Runs the mDNS agent against an [`MdnsIo`].

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::Multiaddr;
use minip2p_core::platform::{Deadline, Now};

use crate::io::{MAX_DATAGRAM_BYTES, MdnsError, MdnsIo, source_is_on_link};
use crate::{MdnsAction, MdnsAgent, MdnsConfig, MdnsEvent};

/// Datagrams read in one [`tick`](MdnsDriver::tick).
///
/// A cap rather than "until empty": a link that keeps talking would otherwise
/// hold a caller inside one tick for as long as it kept talking, and the
/// driver has other things to do -- timers, sends, the swarm above it.
pub(crate) const MAX_DATAGRAMS_PER_TICK: usize = 128;

/// Datagrams sent in one [`tick`](MdnsDriver::tick), for the same reason.
pub(crate) const MAX_ACTIONS_PER_TICK: usize = 128;

/// How long, in milliseconds, [`MdnsDriver`] waits after a hard failure before
/// retrying.
///
/// Long enough that a carrier failing on every call costs a host ten ticks a
/// second rather than a spin, short enough that a transient fault -- an
/// interface flapping, a socket briefly refused -- is over before peers notice.
pub const MDNS_FAILURE_RETRY: u64 = 100;

/// How many times a shutdown drains the carrier for a goodbye that did not
/// fit.
///
/// A tick would park it and try again next turn, but a shutdown has no next
/// turn -- so it drains here instead, and gives up rather than hold a host
/// that wants to exit against a carrier that will not take anything.
const SHUTDOWN_DRAIN_ATTEMPTS: usize = 4;

/// Drives [`MdnsAgent`] against an [`MdnsIo`].
///
/// The agent decides what to say and when; this decides how much of that to
/// do in one turn, keeps the agent's view of the interfaces current, drops
/// what did not come from this link, and backs off when the I/O fails. None
/// of that is platform work, which is why it lives here rather than in the
/// host: a hosted socket adapter and an embedded stack get the same behaviour
/// by supplying the same three operations.
///
/// # Time
///
/// Caller-driven, like everything else here: each call is given the host's
/// current [`Now`] and none is taken from a clock this owns, so every deadline
/// this reports is on the host's own timeline and folds directly with the
/// host's other deadlines. There is no epoch here either: the first interface
/// refresh is armed one interval after the first tick, whatever reading that
/// tick carries. The last reading given is retained, so a shutdown that
/// arrives without one -- a drop -- still has a timeline to date its goodbye
/// on.
///
/// # Failure
///
/// A hard I/O failure does not end mDNS. The turn stops at the first one, the
/// driver reports it as [`MdnsEvent::Failed`], and it waits
/// [`MDNS_FAILURE_RETRY`] before trying again: ticks before then do nothing,
/// and [`next_deadline`](Self::next_deadline) reports exactly the retry time,
/// whatever else is overdue, so a host's wait never spins on a carrier that
/// keeps failing. What failed is retried, not lost: an interface refresh stays
/// due, and a datagram whose send failed is parked like a congested one and
/// goes first on the retry (unless the interfaces or listen addresses move
/// first, which makes it stale). The first retried turn that completes
/// cleanly reports [`MdnsEvent::Recovered`].
///
/// There is one failure state, not one per interface. `Failed` is reported
/// when it is entered and whenever the failure changes; the same failure
/// again -- same variant, operation, and interface, whatever the platform's
/// kind or text -- is not reported twice. A goodbye that fails at
/// [`shutdown`](Self::shutdown) is reported as a final `Failed`, even if it
/// repeats the failure already reported, and nothing follows it.
///
/// Three things are not failures. A vanished interface takes its packet with
/// it, because there is nowhere left to send it. A datagram the carrier can
/// never hold ([`MdnsError::Oversized`]) goes the same way, because waiting
/// does not shrink it. A full send buffer ([`MdnsError::Congested`]) parks the
/// packet instead, because the carrier will have drained by the next turn -- a
/// device that spoke faster than its link could carry has a backlog, not a
/// fault.
pub struct MdnsDriver<I: MdnsIo> {
    agent: MdnsAgent,
    /// `None` once shut down.
    io: Option<I>,
    /// When the interfaces are next re-read. `None` until the first tick
    /// arms it: construction just read them, and has no reading to date that
    /// by.
    next_interface_refresh_ms: Option<u64>,
    interface_refresh_ms: u64,
    backlog: bool,
    /// An action the previous tick could not send -- its budget ran out, the
    /// carrier was full, or the send failed. Held rather than dropped so a
    /// burst is delayed instead of lost.
    pending_action: Option<MdnsAction>,
    /// The hard failure mDNS is backing off from, if any.
    failure: Option<Failure>,
    /// The last reading a caller gave, so a drop can date its goodbye.
    last_now: Now,
    /// Reused across ticks: one datagram's worth of buffer is too much to put
    /// on an embedded stack frame every time it is needed.
    buffer: Vec<u8>,
    events: VecDeque<MdnsEvent>,
}

/// The failure state: what failed last, and when to try again.
struct Failure {
    error: MdnsError,
    retry_at: Deadline,
}

impl<I: MdnsIo> MdnsDriver<I> {
    /// Starts a driver, arming the agent with the interfaces `io` reports.
    pub fn new(mut agent: MdnsAgent, io: I, config: &MdnsConfig) -> Self {
        agent.set_interfaces(io.interfaces(), 0);
        Self {
            agent,
            io: Some(io),
            next_interface_refresh_ms: None,
            interface_refresh_ms: config.interface_refresh_ms,
            backlog: false,
            pending_action: None,
            failure: None,
            last_now: Now::from_millis(0),
            // One byte past the limit, so a datagram that fills it is
            // recognisably too big rather than silently truncated.
            buffer: vec![0; MAX_DATAGRAM_BYTES + 1],
            events: VecDeque::new(),
        }
    }

    /// The agent this driver runs.
    pub fn agent(&self) -> &MdnsAgent {
        &self.agent
    }

    /// The agent this driver runs, mutably.
    pub fn agent_mut(&mut self) -> &mut MdnsAgent {
        &mut self.agent
    }

    /// The carrier this driver runs on, or `None` once shut down.
    pub fn io(&self) -> Option<&I> {
        self.io.as_ref()
    }

    /// The carrier this driver runs on, mutably.
    ///
    /// A host that has to reconfigure the thing underneath -- a smoltcp
    /// interface whose addresses arrive by DHCP, say -- reaches it here, since
    /// handing it over is what put it out of reach.
    pub fn io_mut(&mut self) -> Option<&mut I> {
        self.io.as_mut()
    }

    /// Takes the next observation, if any.
    pub fn poll_event(&mut self) -> Option<MdnsEvent> {
        self.events.pop_front()
    }

    /// Whether mDNS is still running.
    ///
    /// True while backing off from a failure; false once shut down, after
    /// which [`tick`](Self::tick) does nothing.
    pub fn is_active(&self) -> bool {
        self.io.is_some()
    }

    /// Does one turn: refresh, receive, tick the agent, send.
    ///
    /// `local_addrs` is what this host currently listens on, which is what
    /// mDNS advertises. A change to it invalidates anything already encoded.
    /// A hard I/O failure is reported as [`MdnsEvent::Failed`] rather than
    /// returned; see [Failure](Self#failure).
    pub fn tick(&mut self, now: Now, local_addrs: &[Multiaddr]) {
        self.last_now = now;
        if self
            .failure
            .as_ref()
            .is_some_and(|failure| !failure.retry_at.is_expired_at(now))
        {
            return;
        }
        // Out for the turn, so it can be held across the agent's borrows.
        let Some(mut io) = self.io.take() else {
            return;
        };
        let result = self.turn(&mut io, now.monotonic_ms, local_addrs);
        self.io = Some(io);
        self.drain_events();
        match result {
            Ok(backlog) => {
                self.backlog = backlog;
                if self.failure.take().is_some() {
                    self.events.push_back(MdnsEvent::Recovered);
                }
            }
            Err(error) => {
                let repeated = self
                    .failure
                    .as_ref()
                    .is_some_and(|failure| same_failure(&failure.error, &error));
                if !repeated {
                    self.events.push_back(MdnsEvent::Failed {
                        error: error.clone(),
                    });
                }
                self.failure = Some(Failure {
                    error,
                    retry_at: now.deadline_after(MDNS_FAILURE_RETRY),
                });
            }
        }
    }

    /// The body of a tick, stopping at the first hard failure. Reports
    /// whether this turn's budget left work over.
    fn turn(
        &mut self,
        io: &mut I,
        now_ms: u64,
        local_addrs: &[Multiaddr],
    ) -> Result<bool, MdnsError> {
        // Anything waiting to come in has to be in before it can be read: a
        // carrier that moves bytes only when driven holds them until now.
        io.poll(now_ms)?;
        let next_refresh = now_ms.saturating_add(self.interface_refresh_ms);
        let refresh_due = match self.next_interface_refresh_ms {
            Some(due) => now_ms >= due,
            // Construction just read the interfaces; the schedule starts here.
            None => {
                self.next_interface_refresh_ms = Some(next_refresh);
                false
            }
        };
        if refresh_due {
            // A refresh that fails stays due, so the retry repeats it.
            if io.refresh()? {
                self.agent.set_interfaces(io.interfaces(), now_ms);
                // The parked action may embed address expansion from the old
                // snapshot even when its stable interface id still exists.
                self.pending_action = None;
            }
            self.next_interface_refresh_ms = Some(next_refresh);
        }
        if self.agent.set_local_addrs(local_addrs, now_ms) {
            // A parked packet was encoded from the previous listen-address
            // snapshot and must not be sent after that snapshot changes.
            self.pending_action = None;
        }

        let mut sent = 0usize;
        let mut congested = false;
        if let Some(action) = self.pending_action.take() {
            match io.send(&action) {
                Ok(()) => sent = 1,
                // Nowhere to send it, or nothing that could ever carry it:
                // either way holding on to it only delays the next word.
                Err(MdnsError::UnknownInterface { .. } | MdnsError::Oversized { .. }) => {}
                // Still no room. Put it back where it was rather than lose it,
                // and do not queue anything behind it: the carrier is full, and
                // what would go next has to wait for the same drain.
                Err(MdnsError::Congested { .. }) => {
                    self.pending_action = Some(action);
                    congested = true;
                }
                // Held for the retry, as a congested one would be.
                Err(error) => {
                    self.pending_action = Some(action);
                    return Err(error);
                }
            }
        }

        let receive_backlog = self.receive_batch(io, now_ms)?;
        self.agent.handle_tick(now_ms);
        let action_backlog =
            congested || self.send_batch(io, MAX_ACTIONS_PER_TICK.saturating_sub(sent))?;

        // And again on the way out, so what was just sent leaves now rather
        // than waiting for whatever wakes the host next.
        io.poll(now_ms)?;
        Ok(receive_backlog || action_backlog)
    }

    /// When this next needs a tick, as an absolute deadline on the host's
    /// monotonic timeline.
    ///
    /// Covers timers only: the next interface refresh, the agent's next word,
    /// and the carrier's own deadlines. A datagram arriving is not a timer --
    /// a hosted carrier's sockets wake the host through its readiness poll,
    /// and an in-process stack reports a datagram it holds as a carrier
    /// deadline of now -- so an idle mDNS host sleeps until something is due.
    /// Work the last tick's budget left over is due now. An overdue timer
    /// reports its past due time.
    ///
    /// While backing off from a failure this is the retry time and nothing
    /// else, however overdue the rest is: those timers are what the retry
    /// serves, and honouring them early would only spin the host. `None` once
    /// shut down, so a host can drop it from its timeline rather than wake for
    /// something that will do nothing.
    pub fn next_deadline(&self, now: Now) -> Option<Deadline> {
        let io = self.io.as_ref()?;
        if let Some(failure) = &self.failure {
            return Some(failure.retry_at);
        }
        if self.backlog {
            // Work was left on the floor by this tick's budget, so the next
            // one is due regardless of what any timer says.
            return Some(now.as_deadline());
        }
        let refresh = self.next_interface_refresh_ms.map(Deadline::from_millis);
        // The carrier's own timers count too: a stack running in this process
        // gets nothing done between ticks, so a host that slept past one of
        // its deadlines would stall it.
        Deadline::earliest_opt(
            Deadline::earliest_opt(refresh, self.agent.next_deadline(now)),
            io.next_deadline(now),
        )
    }

    /// Says goodbye and stops.
    ///
    /// Peers are told to drop this host's records now rather than wait out a
    /// TTL. A goodbye that could not be sent -- a hard I/O failure, or a
    /// carrier still full after a bounded drain ([`MdnsError::Congested`]) --
    /// is returned and also reported as a final [`MdnsEvent::Failed`].
    /// Idempotent: a second call returns `Ok` and reports nothing. The drop
    /// does the same thing for a host that does not get the chance to call
    /// it.
    pub fn shutdown(&mut self, now: Now) -> Result<(), MdnsError> {
        self.last_now = now;
        let now_ms = now.monotonic_ms;
        // Taking the io is what makes this idempotent, and it is the same
        // thing that makes a stopped driver inert: there is one way to be
        // finished here, not two that have to agree.
        let Some(mut io) = self.io.take() else {
            return Ok(());
        };
        self.pending_action = None;
        self.failure = None;
        self.agent.shutdown(now_ms);

        let mut first_error = None;
        // Every goodbye, not a budget's worth: this is the last thing that
        // will be said, and an unsent one costs a peer a full TTL of pointing
        // at a host that has gone.
        while let Some(action) = self.agent.poll_action() {
            let mut result = io.send(&action);
            // There is no next turn to park a congested goodbye until, so the
            // draining a tick would have done has to happen here. Bounded,
            // because a carrier that will not drain must not hold a shutdown
            // open forever -- a host waiting to exit gets to.
            for _ in 0..SHUTDOWN_DRAIN_ATTEMPTS {
                if !matches!(result, Err(MdnsError::Congested { .. })) {
                    break;
                }
                if let Err(error) = io.poll(now_ms) {
                    result = Err(error);
                    break;
                }
                result = io.send(&action);
            }
            if let Err(error) = result
                && !matches!(
                    error,
                    MdnsError::UnknownInterface { .. } | MdnsError::Oversized { .. }
                )
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        // The carrier is about to be dropped, so this is its last chance to
        // put those on the wire. A stack that moves bytes only when driven
        // would otherwise take every goodbye with it -- and a goodbye that
        // never left is the exact thing it exists to prevent.
        if let Err(error) = io.poll(now_ms)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        self.drain_events();
        match first_error {
            Some(error) => {
                self.events.push_back(MdnsEvent::Failed {
                    error: error.clone(),
                });
                Err(error)
            }
            None => Ok(()),
        }
    }

    /// Reads up to one tick's worth of datagrams, reporting whether the cap
    /// was reached.
    fn receive_batch(&mut self, io: &mut I, now_ms: u64) -> Result<bool, MdnsError> {
        let mut processed = 0usize;
        while processed < MAX_DATAGRAMS_PER_TICK {
            let Some(datagram) = io.receive(&mut self.buffer)? else {
                return Ok(false);
            };
            processed += 1;
            // A datagram that got this far cost the same to read whether or
            // not it is usable, so both drops count toward the budget: a flood
            // of unusable ones must not buy an attacker unbounded work.
            if datagram.len > MAX_DATAGRAM_BYTES {
                continue;
            }
            let Some(snapshot) = io
                .interfaces()
                .iter()
                .find(|snapshot| snapshot.id == datagram.interface)
            else {
                continue;
            };
            if !source_is_on_link(snapshot, datagram.from.ip()) {
                continue;
            }
            let Some(payload) = self.buffer.get(..datagram.len) else {
                continue;
            };
            self.agent
                .handle_packet(datagram.interface, datagram.from, payload, now_ms);
        }
        Ok(true)
    }

    /// Sends up to `limit` actions, parking the next one if the budget runs
    /// out, and reporting whether anything was left over.
    fn send_batch(&mut self, io: &mut I, limit: usize) -> Result<bool, MdnsError> {
        for _ in 0..limit {
            let Some(action) = self.agent.poll_action() else {
                return Ok(false);
            };
            match io.send(&action) {
                // An interface that left between the encode and the send takes
                // its packet with it. Nothing is wrong here, and there is
                // nowhere to send it. A datagram bigger than the carrier will
                // ever hold is dropped for the mirror-image reason: parking it
                // would retry an impossible send on every turn from now on.
                Ok(()) | Err(MdnsError::UnknownInterface { .. } | MdnsError::Oversized { .. }) => {}
                // A full send buffer is a moment, not a fault. Park what did
                // not fit and stop here: the next turn begins with a drain, so
                // the burst is delayed rather than lost -- and mDNS does not
                // fail because a device spoke faster than its link could carry.
                Err(MdnsError::Congested { .. }) => {
                    self.pending_action = Some(action);
                    return Ok(true);
                }
                // Parked the same way, for the retry.
                Err(error) => {
                    self.pending_action = Some(action);
                    return Err(error);
                }
            }
        }
        self.pending_action = self.agent.poll_action();
        Ok(self.pending_action.is_some())
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.agent.poll_event() {
            self.events.push_back(event);
        }
    }
}

/// Whether two hard failures are the same one, for reporting purposes.
///
/// I/O failures match on operation and interface: the platform's kind and
/// text can drift between attempts at the same broken thing, and reporting
/// each drift would be noise. Every other variant is its own variant and
/// interface already.
fn same_failure(a: &MdnsError, b: &MdnsError) -> bool {
    match (a, b) {
        (
            MdnsError::Io {
                operation: a_operation,
                interface: a_interface,
                ..
            },
            MdnsError::Io {
                operation: b_operation,
                interface: b_interface,
                ..
            },
        ) => a_operation == b_operation && a_interface == b_interface,
        _ => a == b,
    }
}

impl<I: MdnsIo> Drop for MdnsDriver<I> {
    fn drop(&mut self) {
        // A host that drops its driver said goodbye by doing so. Dated with
        // the last reading a caller gave, since a drop brings no clock with
        // it and a stale-but-real timestamp beats inventing one.
        let now = self.last_now;
        if let Err(error) = self.shutdown(now) {
            // `Drop` cannot return the I/O failure after attempting a goodbye.
            drop(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MdnsIoOperation;
    use crate::io::MdnsDatagram;
    use crate::{InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsTarget};
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use minip2p_core::PeerId;
    use minip2p_core::platform::IoErrorKind;
    use minip2p_identity::{KeyType, PublicKey};

    /// An `MdnsIo` that carries nothing, scripted per test.
    #[derive(Default)]
    struct FakeIo {
        interfaces: Vec<InterfaceSnapshot>,
        /// Datagrams waiting to be received, oldest first.
        inbound: VecDeque<(InterfaceId, SocketAddr, Vec<u8>, usize)>,
        /// Every action handed to `send`, in order. Shared, so a test can
        /// still read it after the driver has released the io -- which is
        /// exactly when the goodbyes go out.
        sent: Sent,
        /// Interfaces whose sends report having gone away.
        vanished: Vec<InterfaceId>,
        /// Whether sending fails outright.
        send_fails: bool,
        /// How many more datagrams the carrier has room for.
        room: Option<usize>,
        /// The largest datagram this carrier could ever hold, if it is smaller
        /// than what the agent encodes.
        max_payload: Option<usize>,
        /// How much room a `poll` frees up. Zero is a carrier that will not
        /// drain at all.
        room_per_poll: usize,
        receive_fails: bool,
        refresh_fails: bool,
        /// How many times `refresh` was asked, and what it reports.
        refreshes: usize,
        refresh_changes: bool,
        /// What this was asked to do, in order. Shared for the same reason
        /// `sent` is: a shutdown drops the io before a test can read it.
        ops: Ops,
        /// What `next_deadline` reports.
        carrier_deadline: Option<Deadline>,
    }

    type Sent = alloc::rc::Rc<core::cell::RefCell<Vec<MdnsAction>>>;
    type Ops = alloc::rc::Rc<core::cell::RefCell<Vec<&'static str>>>;

    impl FakeIo {
        fn with_interfaces(count: u32) -> Self {
            Self {
                interfaces: (1..=count).map(snapshot).collect(),
                ..Self::default()
            }
        }

        /// A datagram from a host on the interface's own prefix.
        fn queue(&mut self, interface: u32, payload: &[u8]) {
            self.queue_from(
                interface,
                Ipv4Addr::new(192, 168, 1, 9),
                payload,
                payload.len(),
            );
        }

        fn queue_from(&mut self, interface: u32, source: Ipv4Addr, payload: &[u8], len: usize) {
            self.inbound.push_back((
                InterfaceId::new(interface),
                SocketAddr::V4(SocketAddrV4::new(source, 5353)),
                payload.to_vec(),
                len,
            ));
        }
    }

    impl MdnsIo for FakeIo {
        fn interfaces(&self) -> &[InterfaceSnapshot] {
            &self.interfaces
        }

        fn poll(&mut self, _now_ms: u64) -> Result<(), MdnsError> {
            self.ops.borrow_mut().push("poll");
            // A carrier drains when it is driven, which is what makes a
            // congested send worth trying again after one.
            if let Some(room) = self.room.as_mut() {
                *room += self.room_per_poll;
            }
            Ok(())
        }

        fn next_deadline(&self, _now: Now) -> Option<Deadline> {
            self.carrier_deadline
        }

        fn refresh(&mut self) -> Result<bool, MdnsError> {
            self.refreshes += 1;
            if self.refresh_fails {
                return Err(io_failure(MdnsIoOperation::EnumerateInterfaces, None));
            }
            Ok(self.refresh_changes)
        }

        fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<MdnsDatagram>, MdnsError> {
            self.ops.borrow_mut().push("receive");
            if self.receive_fails {
                return Err(io_failure(
                    MdnsIoOperation::Receive,
                    Some(InterfaceId::new(1)),
                ));
            }
            let Some((interface, from, payload, len)) = self.inbound.pop_front() else {
                return Ok(None);
            };
            let copied = payload.len().min(buffer.len());
            buffer[..copied].copy_from_slice(&payload[..copied]);
            Ok(Some(MdnsDatagram {
                interface,
                from,
                len,
            }))
        }

        fn send(&mut self, action: &MdnsAction) -> Result<(), MdnsError> {
            self.ops.borrow_mut().push("send");
            let MdnsAction::Send {
                interface, payload, ..
            } = action;
            if self.vanished.contains(interface) {
                return Err(MdnsError::UnknownInterface {
                    interface: *interface,
                });
            }
            if let Some(capacity) = self.max_payload
                && payload.len() > capacity
            {
                return Err(MdnsError::Oversized {
                    interface: *interface,
                    len: payload.len(),
                    capacity,
                });
            }
            if self.send_fails {
                return Err(io_failure(MdnsIoOperation::Send, Some(*interface)));
            }
            if let Some(room) = self.room.as_mut() {
                if *room == 0 {
                    return Err(MdnsError::Congested {
                        interface: *interface,
                    });
                }
                *room -= 1;
            }
            self.sent.borrow_mut().push(action.clone());
            Ok(())
        }
    }

    fn snapshot(index: u32) -> InterfaceSnapshot {
        InterfaceSnapshot {
            id: InterfaceId::new(index),
            index,
            family: IpFamily::V4,
            addrs: vec![IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24).expect("prefix")],
        }
    }

    fn agent() -> MdnsAgent {
        let peer = PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![1; 32]));
        MdnsAgent::new(peer, MdnsConfig::default(), [7; 32]).expect("a valid config")
    }

    fn driver(io: FakeIo) -> MdnsDriver<FakeIo> {
        MdnsDriver::new(agent(), io, &MdnsConfig::default())
    }

    /// A recognisable libp2p mDNS name, malformed as a whole message.
    ///
    /// The agent reacts to it -- with a `ProtocolViolation` -- which makes it
    /// a way to ask "did this datagram reach the agent at all?".
    const CLAIM: &[u8] = b"\x04_p2p\x04_udp\x05local\x00";

    #[test]
    fn a_tick_sends_what_the_agent_asked_for() {
        let io = FakeIo::with_interfaces(2);
        let sent = io.sent.clone();
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        let sent = sent.borrow();
        assert_eq!(sent.len(), 2, "one announcement per interface: {sent:?}");
        assert!(
            sent.iter().all(|action| {
                let MdnsAction::Send { target, .. } = action;
                *target == MdnsTarget::Multicast
            }),
            "an announcement goes to the group: {sent:?}"
        );
    }

    #[test]
    fn a_datagram_from_off_link_is_not_a_peer_on_this_link() {
        let mut io = FakeIo::with_interfaces(1);
        // Outside the interface's /24. mDNS is link-local: acting on this
        // would let a host anywhere put addresses into a local peer book.
        io.queue_from(1, Ipv4Addr::new(203, 0, 113, 7), CLAIM, CLAIM.len());
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert!(
            driver.poll_event().is_none(),
            "an off-link datagram must not reach the agent at all"
        );

        // The same bytes from the link do reach it, so the drop above was
        // about where it came from and not about what it said.
        driver.io.as_mut().expect("still running").queue(1, CLAIM);
        driver.tick(Now::from_millis(1), &[]);
        assert!(
            matches!(
                driver.poll_event(),
                Some(MdnsEvent::ProtocolViolation { .. })
            ),
            "an on-link datagram is the agent's to judge"
        );
    }

    #[test]
    fn an_oversized_datagram_is_dropped_before_it_is_read() {
        let mut io = FakeIo::with_interfaces(1);
        // Filling the buffer is how an implementation says "there was more":
        // the buffer is one byte past what mDNS will read, so anything that
        // reaches its end was truncated on the way in.
        io.queue_from(
            1,
            Ipv4Addr::new(192, 168, 1, 9),
            CLAIM,
            MAX_DATAGRAM_BYTES + 1,
        );
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert!(
            driver.poll_event().is_none(),
            "a truncated claim is not a claim; reading it would judge bytes that never arrived"
        );
        assert!(driver.is_active(), "and dropping one is not a fault");
    }

    #[test]
    fn receiving_stops_at_the_budget_and_says_there_is_more() {
        let mut io = FakeIo::with_interfaces(1);
        for _ in 0..MAX_DATAGRAMS_PER_TICK + 5 {
            io.queue(1, CLAIM);
        }
        let mut driver = driver(io);

        // At nonzero uptime, so "due now" is told apart from `IMMEDIATE`.
        let now = Now::from_millis(7_000);
        driver.tick(now, &[]);
        assert_eq!(
            driver.io.as_ref().expect("still running").inbound.len(),
            5,
            "a link that keeps talking must not hold the caller inside one tick"
        );
        assert_eq!(
            driver.next_deadline(now),
            Some(now.as_deadline()),
            "what was left over is due now, whatever the timers say"
        );
    }

    #[test]
    fn an_unusable_datagram_still_costs_its_share_of_the_budget() {
        let mut io = FakeIo::with_interfaces(1);
        // A flood of datagrams that will all be dropped. If dropping were
        // free, sending them would buy unbounded work inside one tick.
        for _ in 0..MAX_DATAGRAMS_PER_TICK + 5 {
            io.queue_from(1, Ipv4Addr::new(203, 0, 113, 7), CLAIM, CLAIM.len());
        }
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert_eq!(driver.io.as_ref().expect("still running").inbound.len(), 5);
    }

    #[test]
    fn sending_stops_at_the_budget_and_parks_what_is_left() {
        let io = FakeIo::with_interfaces(u32::try_from(MAX_ACTIONS_PER_TICK).expect("fits") + 2);
        let sent = io.sent.clone();
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert_eq!(sent.borrow().len(), MAX_ACTIONS_PER_TICK);
        assert!(
            driver.pending_action.is_some(),
            "the next one is held, not dropped: a burst is delayed, never lost"
        );
        assert_eq!(
            driver.next_deadline(Now::from_millis(0)),
            Some(Deadline::IMMEDIATE)
        );

        // The parked one goes first on the next turn, before anything new.
        driver.tick(Now::from_millis(1), &[]);
        assert_eq!(sent.borrow().len(), MAX_ACTIONS_PER_TICK + 2);
        assert!(driver.pending_action.is_none());
    }

    #[test]
    fn a_full_carrier_delays_a_datagram_instead_of_ending_mdns() {
        let mut io = FakeIo::with_interfaces(3);
        // Room for one of the three announcements. A carrier that only moves
        // bytes when it is driven fills up like this inside a single tick,
        // which is exactly when a burst is queued.
        io.room = Some(1);
        let sent = io.sent.clone();
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert!(
            driver.is_active(),
            "mDNS must not end because a device spoke faster than its link could carry"
        );
        assert_eq!(sent.borrow().len(), 1, "what fit went out");
        let parked = driver
            .pending_action
            .clone()
            .expect("what did not fit is held, not dropped");
        assert_eq!(
            driver.next_deadline(Now::from_millis(0)),
            Some(Deadline::IMMEDIATE),
            "and it is due as soon as the carrier can take it"
        );

        // The carrier drains between turns, and the parked datagram is the
        // first thing said on the next one -- so a burst is delayed, never
        // lost.
        driver.io.as_mut().expect("still running").room = None;
        driver.tick(Now::from_millis(1), &[]);
        assert_eq!(sent.borrow().get(1), Some(&parked));
        assert_eq!(sent.borrow().len(), 3, "and the rest follow it");
        assert!(driver.pending_action.is_none());
    }

    #[test]
    fn a_carrier_still_full_on_the_next_turn_keeps_holding_the_datagram() {
        let mut io = FakeIo::with_interfaces(2);
        io.room = Some(0);
        let sent = io.sent.clone();
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        let parked = driver.pending_action.clone().expect("nothing fit");
        driver.tick(Now::from_millis(1), &[]);

        assert!(driver.is_active());
        assert!(sent.borrow().is_empty(), "nothing got through");
        assert_eq!(
            driver.pending_action.as_ref(),
            Some(&parked),
            "the same datagram is still first in line"
        );
        assert_eq!(
            driver.next_deadline(Now::from_millis(1)),
            Some(Deadline::from_millis(1))
        );
    }

    #[test]
    fn a_datagram_the_carrier_can_never_hold_is_dropped_rather_than_held() {
        let mut io = FakeIo::with_interfaces(2);
        // A send buffer smaller than an announcement. Draining cannot make
        // room that does not exist, so parking this would hand the same
        // datagram back to the same carrier on every turn from now on.
        io.max_payload = Some(0);
        let sent = io.sent.clone();
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert!(driver.is_active());
        assert!(sent.borrow().is_empty(), "nothing could go");
        assert!(
            driver.pending_action.is_none(),
            "an impossible send is dropped, not queued for a drain that cannot help"
        );
        let now = Now::from_millis(0);
        assert!(
            driver
                .next_deadline(now)
                .is_some_and(|deadline| !deadline.is_expired_at(now)),
            "and the tick that dropped it is owed nothing now: holding it would \
             spin on one datagram instead of sleeping until the next word"
        );
    }

    #[test]
    fn a_vanished_interface_takes_its_packet_with_it() {
        let mut io = FakeIo::with_interfaces(2);
        io.vanished.push(InterfaceId::new(1));
        let sent = io.sent.clone();
        let mut driver = driver(io);

        // Not a failure: interfaces come and go, and there is nowhere to send
        // a packet encoded for one that left.
        driver.tick(Now::from_millis(0), &[]);
        assert!(driver.is_active());
        assert_eq!(
            sent.borrow().len(),
            1,
            "the interface that is still there is served"
        );
    }

    /// An I/O failure the way a carrier would report one.
    fn io_failure(operation: MdnsIoOperation, interface: Option<InterfaceId>) -> MdnsError {
        MdnsError::io(operation, IoErrorKind::Other, interface, "scripted failure")
    }

    /// Drains the driver's events, keeping only its failure-state changes.
    fn failure_states(driver: &mut MdnsDriver<FakeIo>) -> Vec<MdnsEvent> {
        core::iter::from_fn(|| driver.poll_event())
            .filter(|event| matches!(event, MdnsEvent::Failed { .. } | MdnsEvent::Recovered))
            .collect()
    }

    #[test]
    fn a_hard_failure_is_reported_once_until_it_changes() {
        let mut io = FakeIo::with_interfaces(1);
        io.queue(1, CLAIM);
        io.send_fails = true;
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        assert!(
            driver.is_active(),
            "a carrier that fails is backed off from, not abandoned"
        );
        // The claim arrived before the send failed, and is still the host's.
        assert!(matches!(
            driver.poll_event(),
            Some(MdnsEvent::ProtocolViolation { .. })
        ));
        assert_eq!(
            failure_states(&mut driver),
            vec![MdnsEvent::Failed {
                error: io_failure(MdnsIoOperation::Send, Some(InterfaceId::new(1)))
            }]
        );

        // The same send failing again, in other words: not news.
        driver.tick(Now::from_millis(MDNS_FAILURE_RETRY), &[]);
        assert_eq!(failure_states(&mut driver), vec![]);

        // A different failure is.
        let io = driver.io_mut().expect("running");
        io.send_fails = false;
        io.receive_fails = true;
        driver.tick(Now::from_millis(2 * MDNS_FAILURE_RETRY), &[]);
        assert_eq!(
            failure_states(&mut driver),
            vec![MdnsEvent::Failed {
                error: io_failure(MdnsIoOperation::Receive, Some(InterfaceId::new(1)))
            }]
        );
    }

    #[test]
    fn a_failure_with_new_wording_is_the_same_failure() {
        let send = |kind, detail| MdnsError::Io {
            operation: MdnsIoOperation::Send,
            kind,
            interface: Some(InterfaceId::new(1)),
            detail: alloc::string::String::from(detail),
        };
        assert!(same_failure(
            &send(IoErrorKind::Other, "down"),
            &send(IoErrorKind::NetworkUnreachable, "unreachable")
        ));
        assert!(!same_failure(
            &send(IoErrorKind::Other, "down"),
            &io_failure(MdnsIoOperation::Send, Some(InterfaceId::new(2)))
        ));
    }

    #[test]
    fn nothing_is_retried_before_the_retry_deadline() {
        let mut io = FakeIo::with_interfaces(1);
        io.send_fails = true;
        let ops = io.ops.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        assert_eq!(failure_states(&mut driver).len(), 1);
        ops.borrow_mut().clear();

        driver.tick(Now::from_millis(1), &[]);
        driver.tick(Now::from_millis(MDNS_FAILURE_RETRY - 1), &[]);
        assert!(
            ops.borrow().is_empty(),
            "a backing-off driver leaves the carrier alone: {:?}",
            ops.borrow()
        );
        assert_eq!(driver.poll_event(), None);
    }

    #[test]
    fn a_clean_retry_reports_recovery_once() {
        let mut io = FakeIo::with_interfaces(1);
        io.send_fails = true;
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        assert_eq!(failure_states(&mut driver).len(), 1);
        assert!(
            driver.pending_action.is_some(),
            "the datagram that failed is held for the retry"
        );

        driver.io_mut().expect("running").send_fails = false;
        driver.tick(Now::from_millis(MDNS_FAILURE_RETRY), &[]);
        assert_eq!(failure_states(&mut driver), vec![MdnsEvent::Recovered]);
        assert_eq!(sent.borrow().len(), 1, "and goes out once it can");

        driver.tick(Now::from_millis(MDNS_FAILURE_RETRY + 1), &[]);
        assert_eq!(failure_states(&mut driver), vec![]);
    }

    #[test]
    fn a_failed_driver_sleeps_until_its_retry_whatever_else_is_overdue() {
        let io = FakeIo::with_interfaces(u32::try_from(MAX_ACTIONS_PER_TICK).expect("fits") + 2);
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        assert!(driver.pending_action.is_some(), "a send backlog");

        // Failing before the agent's next word is handled, so that is overdue
        // too, alongside the backlog and the carrier's timer.
        let agent_due = driver
            .agent
            .next_deadline(Now::from_millis(0))
            .expect("armed");
        let failed_at = Now::from_millis(agent_due.as_millis() + 1);
        let io = driver.io_mut().expect("running");
        io.send_fails = true;
        io.carrier_deadline = Some(Deadline::IMMEDIATE);
        driver.tick(failed_at, &[]);
        assert_eq!(failure_states(&mut driver).len(), 1);
        assert!(
            driver
                .agent
                .next_deadline(failed_at)
                .is_some_and(|deadline| deadline.is_expired_at(failed_at))
        );

        let retry = failed_at.deadline_after(MDNS_FAILURE_RETRY);
        let late = Now::from_millis(retry.as_millis() - 1);
        for now in [failed_at, late] {
            assert_eq!(
                driver.next_deadline(now),
                Some(retry),
                "honouring an overdue timer while failed would spin the host"
            );
        }
    }

    #[test]
    fn a_failed_refresh_stays_due_until_it_is_retried() {
        let mut io = FakeIo::with_interfaces(1);
        io.refresh_fails = true;
        let mut driver = driver(io);
        let refresh_at = MdnsConfig::default().interface_refresh_ms;
        driver.tick(Now::from_millis(0), &[]);

        driver.tick(Now::from_millis(refresh_at), &[]);
        assert_eq!(
            failure_states(&mut driver),
            vec![MdnsEvent::Failed {
                error: io_failure(MdnsIoOperation::EnumerateInterfaces, None)
            }]
        );

        driver.io_mut().expect("running").refresh_fails = false;
        driver.tick(Now::from_millis(refresh_at + MDNS_FAILURE_RETRY), &[]);
        assert_eq!(
            driver.io().expect("running").refreshes,
            2,
            "the retry repeats the refresh rather than waiting out another interval"
        );
        assert_eq!(failure_states(&mut driver), vec![MdnsEvent::Recovered]);
    }

    #[test]
    fn a_goodbye_that_fails_is_a_final_failure() {
        let mut io = FakeIo::with_interfaces(1);
        io.send_fails = true;
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        assert_eq!(failure_states(&mut driver).len(), 1);

        let error = driver
            .shutdown(Now::from_millis(10))
            .expect_err("the goodbye failed");
        assert_eq!(
            failure_states(&mut driver),
            vec![MdnsEvent::Failed { error }],
            "reported even though it repeats the failure already active"
        );

        driver.tick(Now::from_millis(10 + MDNS_FAILURE_RETRY), &[]);
        driver
            .shutdown(Now::from_millis(20 + MDNS_FAILURE_RETRY))
            .expect("a second shutdown is a no-op");
        assert_eq!(driver.poll_event(), None, "and nothing follows it");
    }

    #[test]
    fn a_changed_interface_set_is_given_to_the_agent_and_drops_stale_work() {
        let io = FakeIo::with_interfaces(u32::try_from(MAX_ACTIONS_PER_TICK).expect("fits") + 2);
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        assert!(driver.pending_action.is_some());

        let announced = sent.borrow().len();
        let refresh_at = MdnsConfig::default().interface_refresh_ms;
        let io = driver.io.as_mut().expect("still running");
        io.refresh_changes = true;
        io.interfaces.clear();
        driver.tick(Now::from_millis(refresh_at), &[]);

        // The parked packet was encoded against the interface set that just
        // changed -- every interface went away -- so sending it now would
        // announce a view of this host that no longer exists.
        assert!(
            driver.pending_action.is_none(),
            "work encoded against the old snapshot is dropped, not held"
        );
        assert_eq!(sent.borrow().len(), announced, "and not sent either");
        assert_eq!(driver.io.as_ref().expect("still running").refreshes, 1);
    }

    #[test]
    fn a_changed_listen_address_drops_work_encoded_before_it() {
        let io = FakeIo::with_interfaces(u32::try_from(MAX_ACTIONS_PER_TICK).expect("fits") + 2);
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        let stale = driver
            .pending_action
            .clone()
            .expect("the budget parked one");
        let announced = sent.borrow().len();

        // What mDNS advertises is where this host listens, and the parked
        // packet says what that was a moment ago. The parked one goes out
        // first on the next turn, so if it survived a change it would be the
        // first thing said -- announcing an address the host no longer has.
        let addr: Multiaddr = "/ip4/192.168.1.1/udp/4001/quic-v1"
            .parse()
            .expect("test address");
        driver.tick(Now::from_millis(1), &[addr]);
        assert_ne!(
            sent.borrow().get(announced),
            Some(&stale),
            "work encoded against the old listen addresses must not be sent after they change"
        );
    }

    #[test]
    fn the_carrier_is_driven_before_reading_and_after_writing() {
        let mut io = FakeIo::with_interfaces(1);
        io.queue(1, CLAIM);
        let ops = io.ops.clone();
        let mut driver = driver(io);

        driver.tick(Now::from_millis(0), &[]);
        let ops = ops.borrow();

        // A stack running in this process moves nothing on its own. Reading
        // before driving it would find an empty link however much had
        // arrived, and sending without driving it afterwards would leave the
        // datagram sitting until whatever wakes the host next.
        assert_eq!(ops.first(), Some(&"poll"), "{ops:?}");
        assert_eq!(ops.last(), Some(&"poll"), "{ops:?}");
        let first_receive = ops.iter().position(|op| *op == "receive").expect("a read");
        let last_send = ops.iter().rposition(|op| *op == "send").expect("a write");
        assert!(first_receive > 0 && last_send < ops.len() - 1, "{ops:?}");
    }

    #[test]
    fn a_carrier_with_its_own_timers_is_on_the_hosts_timeline() {
        let mut io = FakeIo::with_interfaces(1);
        io.carrier_deadline = Some(Deadline::from_millis(5));
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);

        // A stack of its own gets nothing done between ticks, so a host that
        // slept through one of its deadlines would stall it -- retransmits
        // included.
        assert_eq!(
            driver.next_deadline(Now::from_millis(0)),
            Some(Deadline::from_millis(5)),
            "the soonest of everything on the timeline, not just mDNS's own"
        );
    }

    #[test]
    fn deadlines_are_on_the_hosts_timeline_from_the_first_tick() {
        let io = FakeIo::with_interfaces(1);
        let mut driver = driver(io);
        // A host whose clock has been running a while before mDNS starts.
        let start = Now::from_millis(50_000);
        driver.tick(start, &[]);

        let refresh_ms = MdnsConfig::default().interface_refresh_ms;
        let first_query = driver.agent.next_deadline(start).expect("armed");
        assert!(first_query < Deadline::from_millis(50_000 + refresh_ms));
        assert_eq!(driver.next_deadline(start), Some(first_query));

        // A host that ran late still sees the query at its own past due time,
        // so it reads as due rather than being pushed out.
        let late = Now::from_millis(first_query.as_millis() + 7_000);
        assert_eq!(driver.next_deadline(late), Some(first_query));

        // The interface refresh is an interval after the first tick, not after
        // some epoch of the driver's own: a host started late is not owed one
        // straight away, and is owed one exactly when the interval is up.
        let refresh_at = 50_000 + refresh_ms;
        driver.tick(Now::from_millis(refresh_at - 1), &[]);
        assert_eq!(driver.io.as_ref().expect("running").refreshes, 0);
        driver.tick(Now::from_millis(refresh_at), &[]);
        assert_eq!(driver.io.as_ref().expect("running").refreshes, 1);
    }

    #[test]
    fn a_shutdown_says_every_goodbye_once() {
        let io = FakeIo::with_interfaces(3);
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        let announced = sent.borrow().len();

        // Every interface, not a budget's worth: this is the last thing that
        // will be said, and an unsent goodbye costs a peer a full TTL of
        // pointing at a host that has gone.
        driver.shutdown(Now::from_millis(10)).expect("goodbye");
        let after_goodbye = sent.borrow().len();
        assert_eq!(
            after_goodbye - announced,
            3,
            "one goodbye per interface: {:?}",
            sent.borrow()
        );
        assert!(!driver.is_active());
        assert_eq!(
            driver.next_deadline(Now::from_millis(10)),
            None,
            "a stopped driver drops off the host's timeline"
        );

        driver
            .shutdown(Now::from_millis(20))
            .expect("a second shutdown is a no-op");
        assert_eq!(
            sent.borrow().len(),
            after_goodbye,
            "a goodbye is said once, not once per call"
        );
    }

    #[test]
    fn a_goodbye_is_driven_out_before_the_carrier_is_let_go() {
        let io = FakeIo::with_interfaces(2);
        let ops = io.ops.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        ops.borrow_mut().clear();

        // The carrier is dropped at the end of a shutdown, so this is its
        // last chance to put the goodbyes on the wire. A stack that moves
        // bytes only when driven would take every one of them with it --
        // and a goodbye that never left is the exact thing it exists to
        // prevent.
        driver.shutdown(Now::from_millis(10)).expect("goodbye");
        let ops = ops.borrow();
        assert!(ops.contains(&"send"), "{ops:?}");
        assert_eq!(
            ops.last(),
            Some(&"poll"),
            "the goodbyes are driven out after they are queued: {ops:?}"
        );
    }

    #[test]
    fn a_goodbye_that_did_not_fit_is_driven_out_rather_than_lost() {
        let mut io = FakeIo::with_interfaces(3);
        io.room = Some(3);
        // A carrier with room for the announcements and nothing left for the
        // goodbyes, which drains a datagram's worth each time it is driven.
        io.room_per_poll = 1;
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        let announced = sent.borrow().len();

        // A tick would park a congested datagram and come back for it. A
        // shutdown has no next turn, so it drains here instead -- and an
        // unsent goodbye costs a peer a full TTL of pointing at a host that
        // has gone, which is the whole reason a shutdown says one.
        driver.shutdown(Now::from_millis(10)).expect("goodbye");
        assert_eq!(
            sent.borrow().len() - announced,
            3,
            "every goodbye still went: {:?}",
            sent.borrow()
        );
    }

    #[test]
    fn an_oversized_goodbye_is_dropped_without_failing_shutdown() {
        let mut io = FakeIo::with_interfaces(1);
        io.max_payload = Some(0);
        let mut driver = driver(io);

        driver
            .shutdown(Now::from_millis(10))
            .expect("an unsendable goodbye is a dropped datagram, not a shutdown failure");
        assert!(!driver.is_active());
    }

    #[test]
    fn a_carrier_that_will_not_drain_does_not_hold_a_shutdown_open() {
        let mut io = FakeIo::with_interfaces(2);
        io.room = Some(0);
        // Nothing this carrier is asked to do frees anything up.
        io.room_per_poll = 0;
        let ops = io.ops.clone();
        let mut driver = driver(io);

        // Reported rather than retried forever: a host that wants to exit
        // gets to, and it is told the goodbye did not make it.
        let error = driver
            .shutdown(Now::from_millis(10))
            .expect_err("the goodbye never got out");
        assert!(matches!(error, MdnsError::Congested { .. }), "{error:?}");
        assert!(!driver.is_active());
        assert_eq!(
            failure_states(&mut driver),
            vec![MdnsEvent::Failed { error }],
            "a goodbye that never left is a final failure"
        );
        let polls = ops.borrow().iter().filter(|op| **op == "poll").count();
        assert!(
            polls <= (SHUTDOWN_DRAIN_ATTEMPTS + 1) * 2 + 1,
            "the drain is bounded, not a spin: {polls} polls"
        );
    }

    #[test]
    fn a_dropped_driver_still_says_goodbye() {
        let io = FakeIo::with_interfaces(2);
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(Now::from_millis(0), &[]);
        let announced = sent.borrow().len();

        // A host that drops its driver has left the link. Peers that are not
        // told keep pointing at it until the records time out.
        drop(driver);
        assert_eq!(
            sent.borrow().len() - announced,
            2,
            "the drop says what a shutdown would have"
        );
    }
}
