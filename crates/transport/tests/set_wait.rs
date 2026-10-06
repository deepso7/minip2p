//! `TransportSet`'s blocking wait over members that expose a readiness fd.
//!
//! The members are mio-backed fakes built the way the real adapters are: one
//! edge-triggered selector over a UDP socket and a `Waker`, harvested by every
//! zero-timeout probe and by `poll`, which reads the socket directly.
//!
//! Gated to the targets where mio's selector is an fd (epoll, kqueue, event
//! ports); elsewhere the set's turn-taking fallback is covered by the unit
//! tests in `set.rs`.
#![cfg(all(
    feature = "std",
    any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    )
))]

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use minip2p_core::{Multiaddr, PeerAddr, TransportKind};
use minip2p_platform::Now;
use minip2p_transport::{
    BlockingTransport, ConnectionId, ConnectionNamespace, StreamId, Transport, TransportError,
    TransportEvent, TransportSet, WaitHandle, WaitOutcome,
};
use mio::{Events, Interest, Poll, Token, Waker};

const WAKER: Token = Token(0);
const SOCKET: Token = Token(1);

/// "Well under one 10 ms slice", the bound the old turn-taking could not meet.
const PROMPT: Duration = Duration::from_millis(5);

/// A member with one UDP socket, waited on through its own mio selector.
struct MioMember {
    poll: Poll,
    events: Events,
    socket: mio::net::UdpSocket,
    waker: Arc<Waker>,
    /// A wake `poll` harvested while nobody was waiting, as TCP keeps it.
    pending_interrupt: bool,
    /// Datagrams `poll` has read.
    received: Arc<AtomicUsize>,
    /// Sends a datagram to itself right after the next probe that times out,
    /// so input lands between the set's probe and its block.
    arrive_after_probe: bool,
    /// Keeps the fd to itself, like a member that cannot offer one.
    hides_fd: bool,
    /// Offers this fd instead of its selector's: one that never stops
    /// reporting, as an invalid or hung-up fd would.
    broken_fd: Option<std::os::unix::net::UnixStream>,
    /// Zero-timeout waits this member has answered.
    probes: Arc<AtomicUsize>,
}

/// What a test keeps of a member once the set owns it.
struct Remote {
    addr: SocketAddr,
    received: Arc<AtomicUsize>,
}

impl Remote {
    /// Sends one datagram to the member.
    fn send(&self) {
        UdpSocket::bind("127.0.0.1:0")
            .expect("sender")
            .send_to(&[1], self.addr)
            .expect("send datagram");
    }

    /// Sends one datagram after `delay`, from another thread, returning when
    /// it went.
    fn send_later(&self, delay: Duration) -> thread::JoinHandle<Instant> {
        let addr = self.addr;
        thread::spawn(move || {
            let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
            thread::sleep(delay);
            let sent = Instant::now();
            sender.send_to(&[1], addr).expect("send datagram");
            sent
        })
    }

    fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

impl MioMember {
    fn new() -> (Self, Remote) {
        let poll = Poll::new().expect("poll");
        let mut socket =
            mio::net::UdpSocket::bind("127.0.0.1:0".parse().expect("addr")).expect("bind");
        poll.registry()
            .register(&mut socket, SOCKET, Interest::READABLE)
            .expect("register");
        let waker = Arc::new(Waker::new(poll.registry(), WAKER).expect("waker"));
        let received = Arc::default();
        let remote = Remote {
            addr: socket.local_addr().expect("local addr"),
            received: Arc::clone(&received),
        };
        let member = Self {
            poll,
            events: Events::with_capacity(4),
            socket,
            waker,
            pending_interrupt: false,
            received,
            arrive_after_probe: false,
            hides_fd: false,
            broken_fd: None,
            probes: Arc::default(),
        };
        (member, remote)
    }

    /// Waits up to `timeout`; any wake harvested goes to `pending_interrupt`.
    /// Returns whether a socket event fired.
    fn harvest(&mut self, timeout: Duration) -> bool {
        self.events.clear();
        self.poll
            .poll(&mut self.events, Some(timeout))
            .expect("mio poll");
        let mut socket = false;
        for event in &self.events {
            if event.token() == WAKER {
                self.pending_interrupt = true;
            } else {
                socket = true;
            }
        }
        socket
    }

    fn has_queued_input(&self) -> bool {
        let mut buf = [0u8; 1];
        self.socket.peek_from(&mut buf).is_ok()
    }
}

impl Transport for MioMember {
    fn dial(&mut self, _addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Ok(addr.clone())
    }

    fn open_stream(&mut self, _id: ConnectionId) -> Result<StreamId, TransportError> {
        Err(TransportError::Unsupported {
            operation: "open_stream",
        })
    }

    fn send_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _data: Vec<u8>,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, _id: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    /// Reads the socket dry, and absorbs whatever the selector holds.
    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        self.harvest(Duration::ZERO);
        let mut buf = [0u8; 64];
        while self.socket.recv_from(&mut buf).is_ok() {
            self.received.fetch_add(1, Ordering::SeqCst);
        }
        Ok(Vec::new())
    }
}

impl BlockingTransport for MioMember {
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        self.harvest(Duration::ZERO);
        if std::mem::take(&mut self.pending_interrupt) {
            return WaitOutcome::Interrupted;
        }
        if self.has_queued_input() {
            return WaitOutcome::Ready;
        }
        if timeout.is_zero() {
            self.probes.fetch_add(1, Ordering::SeqCst);
            if std::mem::take(&mut self.arrive_after_probe) {
                let addr = self.socket.local_addr().expect("local addr");
                UdpSocket::bind("127.0.0.1:0")
                    .expect("sender")
                    .send_to(&[1], addr)
                    .expect("send to self");
            }
            return WaitOutcome::TimedOut;
        }
        let socket = self.harvest(timeout);
        if std::mem::take(&mut self.pending_interrupt) {
            WaitOutcome::Interrupted
        } else if socket {
            WaitOutcome::Ready
        } else {
            WaitOutcome::TimedOut
        }
    }

    fn wait_handle(&self) -> WaitHandle {
        let waker = Arc::clone(&self.waker);
        WaitHandle::new(move || waker.wake().expect("wake"))
    }

    fn readiness_fd(&self) -> Option<BorrowedFd<'_>> {
        if let Some(broken) = &self.broken_fd {
            return Some(broken.as_fd());
        }
        (!self.hides_fd).then(|| self.poll.registry().as_fd())
    }
}

/// A set of two mio members, TCP-shaped first, and their remotes.
fn duo() -> (TransportSet, Remote, Remote) {
    duo_with(|_, _| {})
}

/// [`duo`], with a chance to adjust the members before they join.
fn duo_with(adjust: impl FnOnce(&mut MioMember, &mut MioMember)) -> (TransportSet, Remote, Remote) {
    let (mut first, first_remote) = MioMember::new();
    let (mut second, second_remote) = MioMember::new();
    adjust(&mut first, &mut second);
    let mut set = TransportSet::new();
    set.insert(
        TransportKind::Tcp,
        [ConnectionNamespace::TCP_IPV4],
        Box::new(first),
    )
    .expect("join");
    set.insert(
        TransportKind::Quic,
        [ConnectionNamespace::QUIC_IPV4],
        Box::new(second),
    )
    .expect("join");
    (set, first_remote, second_remote)
}

#[test]
fn input_on_either_member_wakes_a_blocked_set_promptly() {
    // Each arrival lands mid-slice in the *other* member's turn of a set
    // taking 10 ms turns (first member: 0-10 ms, second: 10-20 ms, ...), where
    // it would wait about 7 ms. The best of three is what is held to the
    // bound, so one descheduled thread on a busy runner cannot fail it.
    for (member, delays_ms) in [(0, [13, 33, 53]), (1, [3, 23, 43])] {
        let mut latencies = Vec::new();
        for delay_ms in delays_ms {
            let (mut set, first, second) = duo();
            let target = if member == 0 { &first } else { &second };
            let sender = target.send_later(Duration::from_millis(delay_ms));

            let outcome = set.wait_for_input(Duration::from_secs(5));
            let woke = Instant::now();
            let sent = sender.join().expect("sender");

            assert_eq!(outcome, WaitOutcome::Ready);
            latencies.push(woke.saturating_duration_since(sent));
        }
        let best = latencies.iter().min().expect("three trials");
        assert!(
            *best < PROMPT,
            "member {member}'s input woke the set after {latencies:?}"
        );
    }
}

/// Hands every member's input over, as a driver's poll would.
fn drain(set: &mut TransportSet) {
    set.poll(Now::from_millis(0)).expect("poll");
}

#[test]
fn repeated_input_on_one_member_wakes_the_set_every_time() {
    // `poll` reads the socket directly between waits, so each round checks
    // that no readiness is left stale (a spurious wake) or lost (a hang).
    let (mut set, _first, second) = duo();
    for round in 1..=5 {
        let sender = second.send_later(Duration::from_millis(5));
        let started = Instant::now();
        assert_eq!(
            set.wait_for_input(Duration::from_secs(5)),
            WaitOutcome::Ready
        );
        sender.join().expect("sender");
        assert!(started.elapsed() < Duration::from_secs(1), "round {round}");
        drain(&mut set);
        assert_eq!(second.received(), round);
        assert_eq!(
            set.wait_for_input(Duration::from_millis(20)),
            WaitOutcome::TimedOut,
            "round {round} left readiness behind"
        );
    }
}

#[test]
fn input_landing_between_the_probe_and_the_block_is_not_missed() {
    let (mut set, _first, second) = duo_with(|_, second| second.arrive_after_probe = true);

    let started = Instant::now();
    assert_eq!(
        set.wait_for_input(Duration::from_secs(5)),
        WaitOutcome::Ready
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    drain(&mut set);
    assert_eq!(second.received(), 1);
}

/// Waits until the set has nothing left to report, and returns what it said.
fn outcomes_until_quiet(set: &mut TransportSet) -> Vec<WaitOutcome> {
    let mut outcomes = Vec::new();
    loop {
        let outcome = set.wait_for_input(Duration::from_millis(30));
        if outcome == WaitOutcome::TimedOut {
            return outcomes;
        }
        outcomes.push(outcome);
        drain(set);
        assert!(outcomes.len() < 10, "the set never settled: {outcomes:?}");
    }
}

#[test]
fn an_interrupt_before_the_wait_is_reported_once() {
    let (mut set, _first, _second) = duo();
    set.wait_handle().interrupt();

    assert_eq!(
        set.wait_for_input(Duration::from_secs(5)),
        WaitOutcome::Interrupted
    );
    assert_eq!(outcomes_until_quiet(&mut set), []);
}

#[test]
fn an_interrupt_during_the_wait_is_reported_once() {
    let (mut set, _first, _second) = duo();
    let handle = set.wait_handle();
    let interrupter = thread::spawn(move || {
        thread::sleep(Duration::from_millis(13));
        let sent = Instant::now();
        handle.interrupt();
        sent
    });

    let outcome = set.wait_for_input(Duration::from_secs(5));
    let woke = Instant::now();
    let sent = interrupter.join().expect("interrupter");

    assert_eq!(outcome, WaitOutcome::Interrupted);
    // Correctness, not latency: a lost wake would sit out the 5 s budget.
    let latency = woke.saturating_duration_since(sent);
    assert!(latency < Duration::from_secs(1), "woke after {latency:?}");
    assert_eq!(outcomes_until_quiet(&mut set), []);
}

#[test]
fn an_interrupt_a_member_absorbed_while_polling_is_reported_once() {
    // TCP's `poll` harvests its selector, wake included, and keeps the wake
    // as a pending interrupt for its next wait.
    let (mut set, _first, _second) = duo();
    set.wait_handle().interrupt();
    drain(&mut set);

    assert_eq!(
        set.wait_for_input(Duration::from_secs(5)),
        WaitOutcome::Interrupted
    );
    assert_eq!(outcomes_until_quiet(&mut set), []);
}

#[test]
fn input_and_an_interrupt_together_lose_neither() {
    let (mut set, _first, second) = duo();
    second.send();
    let queued = Instant::now();
    while set.wait_for_input(Duration::ZERO) != WaitOutcome::Ready {
        assert!(
            queued.elapsed() < Duration::from_secs(1),
            "input never arrived"
        );
    }
    set.wait_handle().interrupt();

    let mut outcomes = vec![set.wait_for_input(Duration::from_secs(5))];
    drain(&mut set);
    outcomes.extend(outcomes_until_quiet(&mut set));

    assert_eq!(second.received(), 1, "the input was handed over");
    let interrupts = outcomes
        .iter()
        .filter(|outcome| **outcome == WaitOutcome::Interrupted)
        .count();
    assert_eq!(interrupts, 1, "one interrupt, reported once: {outcomes:?}");
}

#[test]
fn a_member_without_an_fd_is_still_heard_from_within_a_slice() {
    let (mut set, first, second) = duo_with(|first, _| first.hides_fd = true);

    for (name, remote) in [("fd-less", &first), ("fd", &second)] {
        let sender = remote.send_later(Duration::from_millis(13));
        assert_eq!(
            set.wait_for_input(Duration::from_secs(5)),
            WaitOutcome::Ready
        );
        let latency = Instant::now().saturating_duration_since(sender.join().expect("sender"));
        // The fallback takes 10 ms turns: an arrival waits at most one turn.
        assert!(
            latency < Duration::from_millis(50),
            "{name} member's input took {latency:?}"
        );
        drain(&mut set);
    }
}

#[test]
fn a_member_fd_that_hung_up_does_not_spin_the_set() {
    let mut probes = None;
    let (mut set, _first, _second) = duo_with(|first, _| {
        // A socket whose peer is gone reports hang-up on every `poll(2)`.
        let (hung_up, peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        drop(peer);
        first.broken_fd = Some(hung_up);
        probes = Some(Arc::clone(&first.probes));
    });
    let probes = probes.expect("probe counter");
    let budget = Duration::from_millis(50);

    let started = Instant::now();
    assert_eq!(set.wait_for_input(budget), WaitOutcome::TimedOut);

    assert!(started.elapsed() >= budget);
    // Waiting in turns probes a handful of times; a spin, thousands.
    let probed = probes.load(Ordering::SeqCst);
    assert!(probed < 20, "the set spun: {probed} probes in {budget:?}");
}

#[test]
fn a_quiet_set_waits_out_its_budget() {
    let (mut set, _first, _second) = duo();
    let budget = Duration::from_millis(50);

    let started = Instant::now();
    assert_eq!(set.wait_for_input(budget), WaitOutcome::TimedOut);
    let waited = started.elapsed();

    assert!(waited >= budget, "returned early, after {waited:?}");
    assert!(waited < budget * 3, "overran to {waited:?}");
}

#[cfg(feature = "bench")]
#[test]
fn bench_counters_count_the_one_wait_a_quiet_set_blocks_in() {
    use minip2p_transport::bench::wait_counters;

    let (mut set, _first, _second) = duo();
    let before = wait_counters();
    assert_eq!(
        set.wait_for_input(Duration::from_millis(50)),
        WaitOutcome::TimedOut
    );
    let seen = wait_counters().since(&before);

    assert_eq!(seen.timed_out, 1, "{seen:?}");
    assert_eq!(seen.wakeups(), 1, "{seen:?}");
    assert_eq!(seen.set_waits, 1, "{seen:?}");
}
