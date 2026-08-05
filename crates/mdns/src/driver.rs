//! Runs the mDNS agent against an [`MdnsIo`].

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::Multiaddr;

use crate::io::{MAX_DATAGRAM_BYTES, MdnsError, MdnsIo, source_is_on_link};
use crate::{MdnsAction, MdnsAgent, MdnsConfig, MdnsEvent};

/// Datagrams read in one [`tick`](MdnsDriver::tick).
///
/// A cap rather than "until empty": a link that keeps talking would otherwise
/// hold a caller inside one tick for as long as it kept talking, and the
/// driver has other things to do -- timers, sends, the swarm above it.
pub const MAX_DATAGRAMS_PER_TICK: usize = 128;

/// Datagrams sent in one [`tick`](MdnsDriver::tick), for the same reason.
pub const MAX_ACTIONS_PER_TICK: usize = 128;

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
/// what did not come from this link, and stops for good if the I/O fails.
/// None of that is platform work, which is why it lives here rather than in
/// the host: a hosted socket adapter and an embedded stack get the same
/// behaviour by supplying the same three operations.
///
/// # Time
///
/// Caller-driven, like everything else here: each call is given the host's
/// current millisecond reading and none is taken from a clock this owns. The
/// last one given is retained, so a shutdown that arrives without one -- a
/// drop -- still has a timeline to date its goodbye on.
///
/// # Failure
///
/// A send or receive that fails ends mDNS: the agent is shut down, the I/O is
/// released, and every later tick is a no-op. A stack that cannot carry
/// datagrams cannot participate, and a driver that kept trying would produce
/// the same error forever while the peers' view of it went stale anyway.
/// Events already observed are still drainable afterwards.
///
/// Two things are not failures. A vanished interface takes its packet with it,
/// because there is nowhere left to send it. A full send buffer
/// ([`MdnsError::Congested`]) parks the packet instead, because the carrier
/// will have drained by the next turn -- a device that spoke faster than its
/// link could carry has a backlog, not a fault.
pub struct MdnsDriver<I: MdnsIo> {
    agent: MdnsAgent,
    io: Option<I>,
    next_interface_refresh_ms: u64,
    interface_refresh_ms: u64,
    poll_interval_ms: u64,
    backlog: bool,
    /// An action the previous tick's budget did not cover. Held rather than
    /// dropped so a burst is delayed instead of lost.
    pending_action: Option<MdnsAction>,
    /// The last reading a caller gave, so a drop can date its goodbye.
    last_now_ms: u64,
    /// Reused across ticks: one datagram's worth of buffer is too much to put
    /// on an embedded stack frame every time it is needed.
    buffer: Vec<u8>,
    events: VecDeque<MdnsEvent>,
}

impl<I: MdnsIo> MdnsDriver<I> {
    /// Starts a driver, arming the agent with the interfaces `io` reports.
    pub fn new(mut agent: MdnsAgent, io: I, config: &MdnsConfig) -> Self {
        agent.set_interfaces(io.interfaces(), 0);
        Self {
            agent,
            io: Some(io),
            next_interface_refresh_ms: config.interface_refresh_ms,
            interface_refresh_ms: config.interface_refresh_ms,
            poll_interval_ms: config.socket_poll_interval_ms,
            backlog: false,
            pending_action: None,
            last_now_ms: 0,
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

    /// Takes the next observation, if any.
    pub fn poll_event(&mut self) -> Option<MdnsEvent> {
        self.events.pop_front()
    }

    /// Whether mDNS is still running.
    ///
    /// False once the I/O has failed or a goodbye has been sent, after which
    /// [`tick`](Self::tick) does nothing.
    pub fn is_active(&self) -> bool {
        self.io.is_some()
    }

    /// Does one turn: refresh, receive, tick the agent, send.
    ///
    /// `local_addrs` is what this host currently listens on, which is what
    /// mDNS advertises. A change to it invalidates anything already encoded.
    pub fn tick(&mut self, now_ms: u64, local_addrs: &[Multiaddr]) -> Result<(), MdnsError> {
        self.last_now_ms = now_ms;
        if self.io.is_none() {
            return Ok(());
        }
        // Anything waiting to come in has to be in before it can be read: a
        // carrier that moves bytes only when driven holds them until now.
        if let Err(error) = self.io.as_mut().expect("checked above").poll(now_ms) {
            return Err(self.fail(error, now_ms));
        }
        if now_ms >= self.next_interface_refresh_ms {
            let changed = match self.io.as_mut().expect("checked above").refresh() {
                Ok(changed) => changed,
                Err(error) => return Err(self.fail(error, now_ms)),
            };
            if changed {
                let interfaces = self.io.as_ref().expect("checked above").interfaces();
                self.agent.set_interfaces(interfaces, now_ms);
                // The parked action may embed address expansion from the old
                // snapshot even when its stable interface id still exists.
                self.pending_action = None;
            }
            self.next_interface_refresh_ms = now_ms.saturating_add(self.interface_refresh_ms);
        }
        if self.agent.set_local_addrs(local_addrs, now_ms) {
            // A parked packet was encoded from the previous listen-address
            // snapshot and must not be sent after that snapshot changes.
            self.pending_action = None;
        }

        let mut sent = 0usize;
        let mut congested = false;
        if let Some(action) = self.pending_action.take() {
            match self.io.as_mut().expect("checked above").send(&action) {
                Ok(()) => sent = 1,
                Err(MdnsError::UnknownInterface { .. }) => {}
                // Still no room. Put it back where it was rather than lose it,
                // and do not queue anything behind it: the carrier is full, and
                // what would go next has to wait for the same drain.
                Err(MdnsError::Congested { .. }) => {
                    self.pending_action = Some(action);
                    congested = true;
                }
                Err(error) => return Err(self.fail(error, now_ms)),
            }
        }

        let receive_backlog = match self.receive_batch(now_ms) {
            Ok(backlog) => backlog,
            Err(error) => return Err(self.fail(error, now_ms)),
        };
        self.agent.handle_tick(now_ms);
        let action_backlog = if congested {
            true
        } else {
            match self.send_batch(MAX_ACTIONS_PER_TICK.saturating_sub(sent)) {
                Ok(backlog) => backlog,
                Err(error) => return Err(self.fail(error, now_ms)),
            }
        };

        // And again on the way out, so what was just sent leaves now rather
        // than waiting for whatever wakes the host next.
        if let Err(error) = self.io.as_mut().expect("checked above").poll(now_ms) {
            return Err(self.fail(error, now_ms));
        }

        self.backlog = receive_backlog || action_backlog;
        self.drain_events();
        Ok(())
    }

    /// How long the host may idle before this needs another tick.
    ///
    /// `None` once mDNS has stopped, so a host can drop it from its timeline
    /// rather than wake for something that will do nothing.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        let io = self.io.as_ref()?;
        if self.backlog {
            // Work was left on the floor by this tick's budget, so the next
            // one is due regardless of what any timer says.
            return Some(0);
        }
        let mut timeout = self
            .poll_interval_ms
            .min(self.next_interface_refresh_ms.saturating_sub(now_ms));
        if let Some(agent) = self.agent.next_timeout(now_ms) {
            timeout = timeout.min(agent);
        }
        // The carrier's own timers count too: a stack running in this process
        // gets nothing done between ticks, so a host that slept past one of
        // its deadlines would stall it.
        if let Some(carrier) = io.next_deadline(now_ms) {
            timeout = timeout.min(carrier);
        }
        Some(timeout)
    }

    /// Says goodbye and stops.
    ///
    /// Peers are told to drop this host's records now rather than wait out a
    /// TTL. Idempotent; the drop does the same thing for a host that does not
    /// get the chance to call it.
    pub fn shutdown(&mut self, now_ms: u64) -> Result<(), MdnsError> {
        self.last_now_ms = now_ms;
        // Taking the io is what makes this idempotent, and it is the same
        // thing that makes a stopped driver inert: there is one way to be
        // finished here, not two that have to agree.
        let Some(mut io) = self.io.take() else {
            return Ok(());
        };
        self.pending_action = None;
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
                && !matches!(error, MdnsError::UnknownInterface { .. })
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
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Reads up to one tick's worth of datagrams, reporting whether the cap
    /// was reached.
    fn receive_batch(&mut self, now_ms: u64) -> Result<bool, MdnsError> {
        let io = self.io.as_mut().expect("callers check the io is present");
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
            self.agent.handle_packet(
                datagram.interface,
                datagram.from,
                &self.buffer[..datagram.len],
                now_ms,
            );
        }
        Ok(true)
    }

    /// Sends up to `limit` actions, parking the next one if the budget runs
    /// out, and reporting whether anything was left over.
    fn send_batch(&mut self, limit: usize) -> Result<bool, MdnsError> {
        let io = self.io.as_mut().expect("callers check the io is present");
        for _ in 0..limit {
            let Some(action) = self.agent.poll_action() else {
                return Ok(false);
            };
            match io.send(&action) {
                // An interface that left between the encode and the send takes
                // its packet with it. Nothing is wrong here, and there is
                // nowhere to send it.
                Ok(()) | Err(MdnsError::UnknownInterface { .. }) => {}
                // A full send buffer is a moment, not a fault. Park what did
                // not fit and stop here: the next turn begins with a drain, so
                // the burst is delayed rather than lost -- and mDNS does not
                // end because a device spoke faster than its link could carry.
                Err(MdnsError::Congested { .. }) => {
                    self.pending_action = Some(action);
                    return Ok(true);
                }
                Err(error) => return Err(error),
            }
        }
        self.pending_action = self.agent.poll_action();
        Ok(self.pending_action.is_some())
    }

    /// Ends mDNS after an I/O failure, keeping what was already observed.
    fn fail(&mut self, error: MdnsError, now_ms: u64) -> MdnsError {
        self.pending_action = None;
        self.backlog = false;
        self.agent.shutdown(now_ms);
        // The goodbye the shutdown queued cannot go anywhere: the thing that
        // would carry it is what just failed.
        while self.agent.poll_action().is_some() {}
        self.io = None;
        self.drain_events();
        error
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.agent.poll_event() {
            self.events.push_back(event);
        }
    }
}

impl<I: MdnsIo> Drop for MdnsDriver<I> {
    fn drop(&mut self) {
        // A host that drops its driver said goodbye by doing so. Dated with
        // the last reading a caller gave, since a drop brings no clock with
        // it and a stale-but-real timestamp beats inventing one.
        let now = self.last_now_ms;
        let _ = self.shutdown(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MdnsDatagram;
    use crate::{InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsTarget};
    use alloc::string::ToString;
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use minip2p_core::PeerId;
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
        carrier_deadline: Option<u64>,
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

        fn next_deadline(&self, _now_ms: u64) -> Option<u64> {
            self.carrier_deadline
        }

        fn refresh(&mut self) -> Result<bool, MdnsError> {
            self.refreshes += 1;
            if self.refresh_fails {
                return Err(MdnsError::io("refresh", "no interfaces"));
            }
            Ok(self.refresh_changes)
        }

        fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<MdnsDatagram>, MdnsError> {
            self.ops.borrow_mut().push("receive");
            if self.receive_fails {
                return Err(MdnsError::io("receive", "socket is gone"));
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
            let MdnsAction::Send { interface, .. } = action;
            if self.vanished.contains(interface) {
                return Err(MdnsError::UnknownInterface {
                    interface: *interface,
                });
            }
            if self.send_fails {
                return Err(MdnsError::io("send", "network is down"));
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

        driver.tick(0, &[]).expect("tick");
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

        driver.tick(0, &[]).expect("tick");
        assert!(
            driver.poll_event().is_none(),
            "an off-link datagram must not reach the agent at all"
        );

        // The same bytes from the link do reach it, so the drop above was
        // about where it came from and not about what it said.
        driver.io.as_mut().expect("still running").queue(1, CLAIM);
        driver.tick(1, &[]).expect("tick");
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

        driver.tick(0, &[]).expect("tick");
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

        driver.tick(0, &[]).expect("tick");
        assert_eq!(
            driver.io.as_ref().expect("still running").inbound.len(),
            5,
            "a link that keeps talking must not hold the caller inside one tick"
        );
        assert_eq!(
            driver.next_timeout(0),
            Some(0),
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

        driver.tick(0, &[]).expect("tick");
        assert_eq!(driver.io.as_ref().expect("still running").inbound.len(), 5);
    }

    #[test]
    fn sending_stops_at_the_budget_and_parks_what_is_left() {
        let io = FakeIo::with_interfaces(u32::try_from(MAX_ACTIONS_PER_TICK).expect("fits") + 2);
        let sent = io.sent.clone();
        let mut driver = driver(io);

        driver.tick(0, &[]).expect("tick");
        assert_eq!(sent.borrow().len(), MAX_ACTIONS_PER_TICK);
        assert!(
            driver.pending_action.is_some(),
            "the next one is held, not dropped: a burst is delayed, never lost"
        );
        assert_eq!(driver.next_timeout(0), Some(0));

        // The parked one goes first on the next turn, before anything new.
        driver.tick(1, &[]).expect("second tick");
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

        driver
            .tick(0, &[])
            .expect("a full send buffer is a moment, not a fault");
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
            driver.next_timeout(0),
            Some(0),
            "and it is due as soon as the carrier can take it"
        );

        // The carrier drains between turns, and the parked datagram is the
        // first thing said on the next one -- so a burst is delayed, never
        // lost.
        driver.io.as_mut().expect("still running").room = None;
        driver.tick(1, &[]).expect("tick");
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

        driver.tick(0, &[]).expect("tick");
        let parked = driver.pending_action.clone().expect("nothing fit");
        driver
            .tick(1, &[])
            .expect("a link that is still full is not a fault");

        assert!(driver.is_active());
        assert!(sent.borrow().is_empty(), "nothing got through");
        assert_eq!(
            driver.pending_action.as_ref(),
            Some(&parked),
            "the same datagram is still first in line"
        );
        assert_eq!(driver.next_timeout(1), Some(0));
    }

    #[test]
    fn a_vanished_interface_takes_its_packet_with_it() {
        let mut io = FakeIo::with_interfaces(2);
        io.vanished.push(InterfaceId::new(1));
        let sent = io.sent.clone();
        let mut driver = driver(io);

        // Not a failure: interfaces come and go, and there is nowhere to send
        // a packet encoded for one that left.
        driver
            .tick(0, &[])
            .expect("a vanished interface is not a fault");
        assert!(driver.is_active());
        assert_eq!(
            sent.borrow().len(),
            1,
            "the interface that is still there is served"
        );
    }

    #[test]
    fn io_that_fails_ends_mdns_and_leaves_what_was_seen() {
        let mut io = FakeIo::with_interfaces(1);
        io.queue(1, CLAIM);
        io.send_fails = true;
        let mut driver = driver(io);

        let error = driver.tick(0, &[]).expect_err("the send failed");
        assert!(matches!(error, MdnsError::Io { .. }), "got {error:?}");
        assert!(
            !driver.is_active(),
            "a stack that cannot send cannot participate; retrying would only repeat this"
        );
        assert_eq!(
            driver.next_timeout(0),
            None,
            "a host must not keep waking for something that will do nothing"
        );
        driver.tick(1, &[]).expect("a stopped driver does nothing");

        // The claim was observed before the send failed, and losing it would
        // lose something the host had already learned.
        assert!(
            matches!(
                driver.poll_event(),
                Some(MdnsEvent::ProtocolViolation { .. })
            ),
            "what was observed survives the failure"
        );
    }

    #[test]
    fn a_receive_that_fails_ends_mdns_too() {
        let mut io = FakeIo::with_interfaces(1);
        io.receive_fails = true;
        let mut driver = driver(io);

        let error = driver.tick(0, &[]).expect_err("the receive failed");
        assert_eq!(error.to_string(), "receive failed: socket is gone");
        assert!(!driver.is_active());
    }

    #[test]
    fn a_refresh_that_fails_ends_mdns_too() {
        let mut io = FakeIo::with_interfaces(1);
        io.refresh_fails = true;
        let mut driver = driver(io);

        // The refresh is due at the configured interval, not immediately.
        let refresh_at = MdnsConfig::default().interface_refresh_ms;
        driver.tick(0, &[]).expect("nothing is due yet");
        let error = driver
            .tick(refresh_at, &[])
            .expect_err("the refresh failed");
        assert!(matches!(error, MdnsError::Io { .. }), "got {error:?}");
        assert!(!driver.is_active());
    }

    #[test]
    fn a_changed_interface_set_is_given_to_the_agent_and_drops_stale_work() {
        let io = FakeIo::with_interfaces(u32::try_from(MAX_ACTIONS_PER_TICK).expect("fits") + 2);
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(0, &[]).expect("tick");
        assert!(driver.pending_action.is_some());

        let announced = sent.borrow().len();
        let refresh_at = MdnsConfig::default().interface_refresh_ms;
        let io = driver.io.as_mut().expect("still running");
        io.refresh_changes = true;
        io.interfaces.clear();
        driver.tick(refresh_at, &[]).expect("tick");

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
        driver.tick(0, &[]).expect("tick");
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
        driver.tick(1, &[addr]).expect("tick");
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

        driver.tick(0, &[]).expect("tick");
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
        io.carrier_deadline = Some(5);
        let mut driver = driver(io);
        driver.tick(0, &[]).expect("tick");

        // A stack of its own gets nothing done between ticks, so a host that
        // slept through one of its deadlines would stall it -- retransmits
        // included.
        assert_eq!(
            driver.next_timeout(0),
            Some(5),
            "the soonest of everything on the timeline, not just mDNS's own"
        );
    }

    #[test]
    fn a_shutdown_says_every_goodbye_once() {
        let io = FakeIo::with_interfaces(3);
        let sent = io.sent.clone();
        let mut driver = driver(io);
        driver.tick(0, &[]).expect("tick");
        let announced = sent.borrow().len();

        // Every interface, not a budget's worth: this is the last thing that
        // will be said, and an unsent goodbye costs a peer a full TTL of
        // pointing at a host that has gone.
        driver.shutdown(10).expect("goodbye");
        let after_goodbye = sent.borrow().len();
        assert_eq!(
            after_goodbye - announced,
            3,
            "one goodbye per interface: {:?}",
            sent.borrow()
        );
        assert!(!driver.is_active());

        driver.shutdown(20).expect("a second shutdown is a no-op");
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
        driver.tick(0, &[]).expect("tick");
        ops.borrow_mut().clear();

        // The carrier is dropped at the end of a shutdown, so this is its
        // last chance to put the goodbyes on the wire. A stack that moves
        // bytes only when driven would take every one of them with it --
        // and a goodbye that never left is the exact thing it exists to
        // prevent.
        driver.shutdown(10).expect("goodbye");
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
        driver.tick(0, &[]).expect("tick");
        let announced = sent.borrow().len();

        // A tick would park a congested datagram and come back for it. A
        // shutdown has no next turn, so it drains here instead -- and an
        // unsent goodbye costs a peer a full TTL of pointing at a host that
        // has gone, which is the whole reason a shutdown says one.
        driver.shutdown(10).expect("goodbye");
        assert_eq!(
            sent.borrow().len() - announced,
            3,
            "every goodbye still went: {:?}",
            sent.borrow()
        );
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
        let error = driver.shutdown(10).expect_err("the goodbye never got out");
        assert!(matches!(error, MdnsError::Congested { .. }), "{error:?}");
        assert!(!driver.is_active());
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
        driver.tick(0, &[]).expect("tick");
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
