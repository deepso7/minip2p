//! Std [`Swarm`]: a [`SwarmCore`] plus a clock, one shared readiness poll, and
//! blocking drive loops.
//!
//! This is the DX-friendly entrypoint for applications: it samples time
//! itself, so callers need not thread `now_ms` through every call, and it
//! idles the calling thread between polls on one edge-triggered `mio::Poll`
//! that every source of input registers with (ADR 0013).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use minip2p_core::platform::{Clock, Now, StdClock, StdEntropy};
use minip2p_core::{Bytes, PeerId};
use minip2p_identify::IdentifyConfig;
use minip2p_transport::{
    BlockingTransport, ConnectionId, PollSource, SharedPoll, StreamId, TransportError, WaitHandle,
    WakeHandle,
};

use crate::core::{DriverError, SwarmCore};
use crate::events::SwarmEvent;
use crate::state::SwarmTimeouts;
use crate::wait_deadline::WaitDeadline;

/// Cap on a single readiness wait when the caller has no deadline
/// ([`WaitDeadline::NEVER`]). Re-arming the wait occasionally is harmless (one
/// syscall a minute) and keeps unbounded durations out of OS interfaces.
const MAX_IDLE_WAIT: Duration = Duration::from_secs(60);

/// Maximum number of non-matching events [`Swarm::run_until`] sets aside
/// while scanning for a match.
///
/// Skipped events are buffered so they can be restored for later consumers;
/// without a cap, a peer streaming [`SwarmEvent::StreamData`] payloads while
/// the caller waits for an unrelated event could grow that buffer without
/// bound. Hitting the cap aborts the wait with
/// [`DriverError::EventBacklogExceeded`] after restoring every skipped event.
pub const RUN_UNTIL_SKIP_LIMIT: usize = 1024;

/// Result of an interruptible swarm wait.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "PollNext preserves event ownership without an allocation on the ready path."
)]
pub enum PollNext {
    /// A fresh swarm event is ready.
    Event(SwarmEvent),
    /// The caller's deadline elapsed.
    Deadline,
    /// A [`WaitHandle`] interrupted the wait. Interrupts sent before one is
    /// reported coalesce into this one.
    Interrupted,
    /// Host work may be ready: a [`WakeHandle`] woke the wait, input arrived
    /// on a source attached with [`Swarm::attach_host_source`], or a
    /// socket-less transport woke the shared `Waker`. Kept pending across
    /// competing returns until reported, so the host services it once.
    Woken,
}

/// Std driver: a [`SwarmCore`] plus a clock, one shared readiness poll, and
/// blocking drive loops.
///
/// This is the DX-friendly entrypoint for applications. It samples the clock
/// itself for the commands that take time, and it can idle the calling thread
/// between polls. Everything that needs no clock -- listening, dialing,
/// protocol registration, peer and connection queries -- is on
/// [`core`](Self::core) / [`core_mut`](Self::core_mut).
///
/// # Waiting
///
/// The swarm owns one `mio::Poll` and its one `Waker`, and attaches the
/// transport to them when it is built. A wait blocks once, for every source,
/// until input arrives, the earliest timer is due, or the caller's deadline
/// passes. [`wait_handle`](Self::wait_handle) interrupts it from another
/// thread; [`wake_handle`](Self::wake_handle) wakes it for host work without
/// interrupting. Every drive path, blocking or not, first collects one bounded
/// batch of readiness without blocking.
///
/// Hosts without a thread to block -- embedded boards, single-threaded event
/// loops -- should drive [`SwarmCore`] directly instead.
pub struct Swarm<T: BlockingTransport> {
    core: SwarmCore<T, StdEntropy>,
    /// Logical clock used to drive Sans-I/O timers.
    clock: Box<dyn Clock + Send + Sync>,
    /// The readiness every source registers with.
    poll: SharedPoll,
    /// Every blocking budget handed to the poll, for budget tests.
    #[cfg(test)]
    wait_budgets: Vec<Duration>,
    /// Stands in for a blocking wait, so tests can move a fake clock across
    /// one without sleeping.
    #[cfg(test)]
    simulated_wait: Option<Box<dyn FnMut(Duration) + Send + Sync>>,
}

/// A failed poll operation, as the transport error the drive paths report.
fn poll_error(operation: &'static str, error: &std::io::Error) -> DriverError {
    DriverError::Transport(TransportError::io(operation, error))
}

impl<T: BlockingTransport> Swarm<T> {
    /// Creates a swarm driver around the given transport, identify config,
    /// and protocol deadlines, and attaches the transport to its readiness poll.
    ///
    /// Fails if a deadline is zero ([`crate::SwarmError::ZeroTimeout`]), or
    /// if the poll cannot be opened or the transport's sockets cannot be
    /// registered with it.
    pub fn new(
        transport: T,
        identify_config: IdentifyConfig,
        timeouts: SwarmTimeouts,
        local_peer_id: PeerId,
    ) -> Result<Self, DriverError> {
        Self::with_clock(
            transport,
            identify_config,
            timeouts,
            local_peer_id,
            Box::new(StdClock::new()),
        )
    }

    /// Creates a swarm driver with an injected clock.
    ///
    /// This is primarily for deterministic tests around protocol timeouts. The
    /// default [`Swarm::new`] constructor remains the right choice for normal
    /// applications. Fails as [`Swarm::new`] does.
    pub fn with_clock(
        mut transport: T,
        identify_config: IdentifyConfig,
        timeouts: SwarmTimeouts,
        local_peer_id: PeerId,
        clock: Box<dyn Clock + Send + Sync>,
    ) -> Result<Self, DriverError> {
        timeouts.validate()?;
        let mut poll =
            SharedPoll::new().map_err(|error| poll_error("opening the readiness poll", &error))?;
        poll.attach(&mut transport)
            .map_err(|error| poll_error("attaching the transport", &error))?;
        Ok(Self {
            core: SwarmCore::new(
                transport,
                identify_config,
                timeouts,
                local_peer_id,
                StdEntropy::new(),
            )?,
            clock,
            poll,
            #[cfg(test)]
            wait_budgets: Vec::new(),
            #[cfg(test)]
            simulated_wait: None,
        })
    }

    /// A handle that interrupts this swarm's waits from another thread.
    ///
    /// The interrupted wait returns [`PollNext::Interrupted`]; interrupts sent
    /// before one is reported coalesce into one, and one sent with no wait in
    /// progress is kept for the next.
    pub fn wait_handle(&self) -> WaitHandle {
        self.poll.wait_handle()
    }

    /// A handle that wakes this swarm's waits for host work, without
    /// interrupting them: the wait returns [`PollNext::Woken`].
    pub fn wake_handle(&self) -> WakeHandle {
        self.poll.wake_handle()
    }

    /// Registers a source the host services itself -- mDNS sockets, say --
    /// with this swarm's poll, in a spare token space.
    ///
    /// The swarm never dispatches to it: readiness in its space ends a wait
    /// with [`PollNext::Woken`], and the host then services the source. At
    /// most 14 such sources can be attached.
    pub fn attach_host_source<S: PollSource + ?Sized>(
        &mut self,
        source: &mut S,
    ) -> Result<(), DriverError> {
        self.poll
            .attach_host_source(source)
            .map_err(|error| poll_error("attaching a host source", &error))
    }

    /// Collects one bounded batch of readiness, blocking up to `timeout`, and
    /// dispatches the transport's share.
    fn harvest(&mut self, timeout: Duration) -> Result<(), DriverError> {
        #[cfg(test)]
        let timeout = if timeout.is_zero() {
            timeout
        } else {
            self.wait_budgets.push(timeout);
            match self.simulated_wait.as_mut() {
                Some(simulate) => {
                    simulate(timeout);
                    Duration::ZERO
                }
                None => timeout,
            }
        };
        self.poll
            .harvest(self.core.transport_mut(), timeout)
            .map(drop)
            .map_err(|error| poll_error("waiting for readiness", &error))
    }

    /// Returns the swarm this driver wraps.
    pub fn core(&self) -> &SwarmCore<T, StdEntropy> {
        &self.core
    }

    /// Returns the swarm this driver wraps, mutably.
    ///
    /// Commands called through it take the caller's time sample; sample
    /// [`Swarm::now`] first and pass its `monotonic_ms`, so they share this
    /// driver's timeline. The clock-taking
    /// commands on `Swarm` itself sample it for you.
    pub fn core_mut(&mut self) -> &mut SwarmCore<T, StdEntropy> {
        &mut self.core
    }

    /// Samples this swarm's clock.
    ///
    /// Composed hosts that share the swarm's timeline (Connection attempts,
    /// protocol timers) should use this sample rather than reading a second
    /// clock.
    pub fn now(&mut self) -> Now {
        self.clock.now()
    }

    fn now_ms(&mut self) -> u64 {
        self.now().monotonic_ms
    }

    /// See [`SwarmCore::ping`].
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), DriverError> {
        let now_ms = self.now_ms();
        self.core.ping(peer_id, now_ms)
    }

    /// See [`SwarmCore::disconnect`].
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), DriverError> {
        let now_ms = self.now_ms();
        self.core.disconnect(peer_id, now_ms)
    }

    /// See [`SwarmCore::open_stream`].
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<(ConnectionId, StreamId), DriverError> {
        let now_ms = self.now_ms();
        self.core.open_stream(peer_id, protocol_id, now_ms)
    }

    /// See [`SwarmCore::send_stream`].
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), DriverError> {
        let now_ms = self.now_ms();
        self.core
            .send_stream(peer_id, conn_id, stream_id, data, now_ms)
    }

    /// See [`SwarmCore::close_stream_write`].
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), DriverError> {
        let now_ms = self.now_ms();
        self.core
            .close_stream_write(peer_id, conn_id, stream_id, now_ms)
    }

    /// See [`SwarmCore::reset_stream`].
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), DriverError> {
        let now_ms = self.now_ms();
        self.core.reset_stream(peer_id, conn_id, stream_id, now_ms)
    }

    /// See [`SwarmCore::abandon_stream`].
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), DriverError> {
        let now_ms = self.now_ms();
        self.core
            .abandon_stream(peer_id, conn_id, stream_id, now_ms)
    }

    /// Drives the swarm one iteration, sampling the clock for the caller.
    ///
    /// Returns every queued event, including ones a blocking wait left
    /// undelivered. See [`SwarmCore::poll`].
    pub fn poll(&mut self) -> Result<Vec<SwarmEvent>, DriverError> {
        self.harvest(Duration::ZERO)?;
        let now = self.now();
        self.core.poll(now)
    }

    /// Queues `events`, in order, ahead of every event already buffered and
    /// anything the next [`Self::poll`] reads from the transport.
    ///
    /// The Endpoint uses this to hand back swarm events a failed step did not
    /// reach, and its tests to pin step order when one poll returns several
    /// swarm events.
    #[doc(hidden)]
    pub fn preload_poll_events(&mut self, events: impl IntoIterator<Item = SwarmEvent>) {
        let events: Vec<SwarmEvent> = events.into_iter().collect();
        for event in events.into_iter().rev() {
            self.core.state.events.push_front(event);
        }
    }
    /// Returns the next swarm event, sleeping internally until one arrives
    /// or `deadline` is reached.
    ///
    /// `Ok(Some(ev))` — a fresh event is ready. `Ok(None)` — `deadline`
    /// passed before any event arrived. `Err(_)` — transport-level error.
    ///
    /// Makes single-event CLIs and scripts much easier to write than the
    /// raw [`Swarm::poll`] loop: no sleep-then-match-all-events
    /// boilerplate.
    pub fn poll_next(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<Option<SwarmEvent>, DriverError> {
        let deadline = deadline.into();
        loop {
            match self.poll_next_interruptible(deadline)? {
                PollNext::Event(event) => return Ok(Some(event)),
                PollNext::Deadline => return Ok(None),
                PollNext::Interrupted | PollNext::Woken => {}
            }
        }
    }

    /// Returns the next event while preserving interrupts and host wakeups as
    /// distinct from the caller's deadline.
    ///
    /// In priority order: a buffered or freshly driven [`PollNext::Event`],
    /// a pending [`PollNext::Interrupted`], a pending [`PollNext::Woken`],
    /// then [`PollNext::Deadline`]. A pending interrupt or wake is only
    /// cleared by the return that reports it, so an earlier event or an
    /// expired deadline never loses one. An expired deadline still drives the
    /// swarm once.
    pub fn poll_next_interruptible(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<PollNext, DriverError> {
        let deadline = deadline.into();
        let mut harvested = false;
        loop {
            if let Some(ev) = self.core.next_event() {
                return Ok(PollNext::Event(ev));
            }
            if !harvested {
                self.harvest(Duration::ZERO)?;
            }
            let now = self.now();
            self.core.drive(now)?;
            if let Some(ev) = self.core.next_event() {
                return Ok(PollNext::Event(ev));
            }
            if self.poll.take_interrupt() {
                return Ok(PollNext::Interrupted);
            }
            if self.poll.take_wake() {
                return Ok(PollNext::Woken);
            }
            let now = Instant::now();
            if deadline.is_expired_at(now) {
                return Ok(PollNext::Deadline);
            }
            let mut budget = deadline.remaining_at(now).unwrap_or(MAX_IDLE_WAIT);
            let now = self.now();
            if let Some(next) = self.core.next_deadline(now) {
                budget = budget.min(Duration::from_millis(next.millis_until(now)));
            }
            harvested = !budget.is_zero();
            if harvested {
                self.harvest(budget)?;
            }
        }
    }

    /// Polls events in a loop, returning the first one for which
    /// `predicate` returns `true`, or `Ok(None)` if `deadline` expires
    /// first.
    ///
    /// `predicate` sees every event as it arrives. Events for which it returns
    /// `false` are restored to the front of the event buffer before this method
    /// returns, preserving their original order for later consumers.
    ///
    /// At most [`RUN_UNTIL_SKIP_LIMIT`] non-matching events are set aside
    /// this way; an unbounded wait (e.g. [`WaitDeadline::NEVER`]) must not buffer
    /// arbitrary amounts of event data while a peer floods us with, say,
    /// [`SwarmEvent::StreamData`]. When the cap is hit, every skipped event
    /// is restored in order and [`DriverError::EventBacklogExceeded`] is
    /// returned; drain the buffer with [`Swarm::poll_next`].
    ///
    /// The deadline never truncates the scan mid-buffer: once it passes,
    /// every event that is already synchronously available -- buffered
    /// events plus at most one final transport poll -- is still tested, so
    /// a buffered match is found regardless of its position. No sleeping
    /// and no repeated polling happen past the deadline, so an event flood
    /// cannot livelock an expired wait.
    pub fn run_until<F>(
        &mut self,
        deadline: impl Into<WaitDeadline>,
        mut predicate: F,
    ) -> Result<Option<SwarmEvent>, DriverError>
    where
        F: FnMut(&SwarmEvent) -> bool,
    {
        let deadline = deadline.into();
        let mut skipped = VecDeque::new();
        let mut result = Ok(None);

        let mut polled_past_deadline = false;
        while !deadline.is_expired_at(Instant::now()) {
            match self.poll_next_interruptible(deadline) {
                Err(error) => {
                    result = Err(error);
                    break;
                }
                Ok(PollNext::Deadline) => {
                    polled_past_deadline = true;
                    break;
                }
                Ok(PollNext::Interrupted | PollNext::Woken) => continue,
                Ok(PollNext::Event(ev)) => {
                    if predicate(&ev) {
                        result = Ok(Some(ev));
                        break;
                    }
                    skipped.push_back(ev);
                    if skipped.len() >= RUN_UNTIL_SKIP_LIMIT {
                        result = Err(DriverError::EventBacklogExceeded {
                            limit: RUN_UNTIL_SKIP_LIMIT,
                        });
                        break;
                    }
                }
            }
        }

        if matches!(result, Ok(None)) {
            loop {
                let Some(ev) = self.core.next_event() else {
                    if polled_past_deadline {
                        break;
                    }
                    polled_past_deadline = true;
                    if let Err(error) = self.harvest(Duration::ZERO) {
                        result = Err(error);
                        break;
                    }
                    let now = self.now();
                    match self.core.drive(now) {
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                        Ok(()) => continue,
                    }
                };
                if predicate(&ev) {
                    result = Ok(Some(ev));
                    break;
                }
                skipped.push_back(ev);
                if skipped.len() >= RUN_UNTIL_SKIP_LIMIT {
                    result = Err(DriverError::EventBacklogExceeded {
                        limit: RUN_UNTIL_SKIP_LIMIT,
                    });
                    break;
                }
            }
        }

        for event in skipped.into_iter().rev() {
            self.core.state.events.push_front(event);
        }
        result
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
