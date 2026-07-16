//! Std driver that owns a [`Transport`] and drives [`SwarmCore`].
//!
//! This is the DX-friendly entrypoint for applications: it tracks wall
//! time internally, auto-allocates connection ids, and translates between
//! the Sans-I/O core's actions and concrete transport calls.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_identify::{IdentifyConfig, IdentifyMessage};
use minip2p_ping::{PING_PAYLOAD_LEN, PingConfig};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, WaitOutcome};

use crate::core::SwarmCore;
use crate::events::{
    SwarmAction, SwarmError, SwarmErrorKind, SwarmEvent, SwarmInput, SwarmOutput, SwarmRuntimeError,
};

/// Errors returned synchronously by the std swarm driver.
///
/// Protocol-state rejections remain distinguishable from transport failures;
/// callers no longer need to recover their meaning from a flattened string.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The underlying transport rejected the operation.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The Sans-I/O swarm core rejected the operation.
    #[error(transparent)]
    Swarm(#[from] SwarmError),
    /// The driver and core violated their internal action contract.
    #[error("swarm driver invariant violated: {reason}")]
    Invariant { reason: &'static str },
    /// [`Swarm::run_until`] set aside [`RUN_UNTIL_SKIP_LIMIT`] non-matching
    /// events without finding a match.
    ///
    /// The skipped events were restored to the event buffer in their
    /// original order; drain them with [`Swarm::poll_next`] before waiting
    /// again, or use a predicate that matches (and thereby consumes) the
    /// high-volume events.
    #[error(
        "run_until skipped {limit} events without a match; drain the event buffer with poll_next"
    )]
    EventBacklogExceeded { limit: usize },
}

/// Fallback sleep cadence when [`Swarm::poll_next`] idles over a transport
/// that cannot wait for socket readiness ([`WaitOutcome::Unsupported`]).
///
/// 1ms is short enough that single-digit-millisecond RTTs are
/// observable on loopback (two wakeups bound RTT, so ~2ms floor)
/// without noticeably burning CPU on idle. Transports that implement
/// [`Transport::wait_for_input`] skip this entirely and block until
/// input arrives or the timer budget elapses.
const POLL_IDLE_SLEEP: Duration = Duration::from_millis(1);

/// Cap on a single readiness wait when the caller has no deadline
/// ([`Deadline::NEVER`]). Re-arming the wait occasionally is harmless (one
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

/// When a blocking wait should give up.
///
/// Everywhere the driver can wait ([`Swarm::poll_next`], [`Swarm::run_until`])
/// accepts `impl Into<Deadline>`, so callers pass whichever is natural:
///
/// - an [`Instant`] -- absolute deadline,
/// - a [`Duration`] -- relative timeout from now,
/// - [`Deadline::NEVER`] -- wait indefinitely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// Wait indefinitely; the call returns only when an event arrives (or,
    /// for `run_until`, when the predicate matches).
    pub const NEVER: Deadline = Deadline(None);

    /// Absolute deadline. Equivalent to `Deadline::from(instant)`.
    pub fn at(instant: Instant) -> Self {
        Deadline(Some(instant))
    }

    /// Whether the deadline has already passed. [`Deadline::NEVER`] never
    /// passes.
    pub fn has_passed(self) -> bool {
        self.is_expired_at(Instant::now())
    }

    /// The earlier of two deadlines ([`Deadline::NEVER`] is latest).
    ///
    /// Lets callers fold an extra timer source into a wait without access
    /// to the deadline's internals, mirroring how [`Swarm::poll_next`]
    /// folds the core's protocol timers into its budget.
    pub fn earliest(self, other: Deadline) -> Deadline {
        match (self.0, other.0) {
            (Some(a), Some(b)) => Deadline(Some(a.min(b))),
            (a, b) => Deadline(a.or(b)),
        }
    }

    /// Whether the deadline has passed at `now`.
    fn is_expired_at(self, now: Instant) -> bool {
        self.0.is_some_and(|deadline| now >= deadline)
    }

    /// Time left from `now`; `None` means unbounded.
    fn remaining_at(self, now: Instant) -> Option<Duration> {
        self.0
            .map(|deadline| deadline.saturating_duration_since(now))
    }
}

impl From<Instant> for Deadline {
    fn from(instant: Instant) -> Self {
        Deadline(Some(instant))
    }
}

impl From<Duration> for Deadline {
    /// Relative timeout starting now. A duration too large for `Instant`
    /// arithmetic means [`Deadline::NEVER`].
    fn from(timeout: Duration) -> Self {
        Deadline(Instant::now().checked_add(timeout))
    }
}

/// Clock source used by the std swarm driver.
///
/// The Sans-I/O core remains clockless; the driver reads this clock and passes
/// milliseconds into the core. Tests can inject a deterministic clock while
/// normal callers use the default system monotonic clock.
pub trait Clock: Send + Sync {
    /// Returns monotonic milliseconds since an arbitrary start point.
    fn now_ms(&self) -> u64;
}

struct SystemClock {
    start: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// Thin std driver wrapping [`SwarmCore`] and a concrete [`Transport`].
///
/// Preserves the one-call DX built on top of the core:
/// - `dial(addr) -> ConnectionId` delegates connection-id allocation to the transport.
/// - `poll()` reads the wall clock internally; callers need not thread
///   `now_ms` through every call.
/// - `ping(peer)` opens a ping stream if needed and fires the payload as
///   soon as negotiation completes.
pub struct Swarm<T: Transport> {
    transport: T,
    core: SwarmCore,

    /// Our own `PeerId`. Cached from the [`crate::SwarmBuilder`]'s keypair
    /// so applications don't have to drill into the transport to get it.
    local_peer_id: PeerId,

    /// Buffer of events yielded by [`Swarm::poll`] that haven't yet been
    /// consumed by [`Swarm::poll_next`]. Each `poll()` returns a batch;
    /// `poll_next` hands them out one at a time and calls `poll()` again
    /// when the buffer drains.
    event_buffer: VecDeque<SwarmEvent>,

    /// Externally validated addresses advertised through Identify in
    /// addition to the transport's bound set. See
    /// [`Swarm::set_external_addresses`].
    external_addresses: Vec<Multiaddr>,

    /// Logical clock used to drive Sans-I/O timers.
    clock: Arc<dyn Clock>,
}

impl<T: Transport> Swarm<T> {
    /// Creates a swarm driver around the given transport, identify config,
    /// and ping config.
    ///
    /// Most callers should construct via `crate::SwarmBuilder` instead,
    /// which derives `local_peer_id` from the keypair automatically.
    pub fn new(
        transport: T,
        identify_config: IdentifyConfig,
        ping_config: PingConfig,
        local_peer_id: PeerId,
    ) -> Self {
        Self::with_clock(
            transport,
            identify_config,
            ping_config,
            local_peer_id,
            Arc::new(SystemClock::new()),
        )
    }

    /// Creates a swarm driver with an injected clock.
    ///
    /// This is primarily for deterministic tests around protocol timeouts. The
    /// default [`Swarm::new`] constructor remains the right choice for normal
    /// applications.
    pub fn with_clock(
        transport: T,
        identify_config: IdentifyConfig,
        ping_config: PingConfig,
        local_peer_id: PeerId,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            transport,
            core: SwarmCore::new(identify_config, ping_config),
            local_peer_id,
            event_buffer: VecDeque::new(),
            external_addresses: Vec::new(),
            clock,
        }
    }

    /// Sets externally validated addresses (e.g. AutoNAT-confirmed public
    /// addresses or relay circuit addresses) to advertise through Identify
    /// alongside the transport's bound addresses.
    ///
    /// Replaces the previous external set; pass an empty vector to stop
    /// advertising extras. Duplicates of transport-bound addresses are
    /// dropped.
    pub fn set_external_addresses(&mut self, addrs: Vec<Multiaddr>) {
        self.external_addresses = addrs;
    }

    /// Returns a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns a reference to the Sans-I/O core (for advanced introspection).
    pub fn core(&self) -> &SwarmCore {
        &self.core
    }

    /// Crate-internal mutable access to the Sans-I/O core.
    ///
    /// Used by [`crate::SwarmBuilder`] to register user protocols during
    /// `build()`. Not public: mutating the core without flushing its
    /// actions would desynchronize the driver.
    pub(crate) fn core_mut(&mut self) -> &mut SwarmCore {
        &mut self.core
    }

    /// Returns peers currently surfaced through `ConnectionEstablished` and not yet closed.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.core.connected_peers()
    }

    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.core.peer_info(peer_id)
    }

    /// Returns whether `peer_id` has emitted `PeerReady`.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.core.is_peer_ready(peer_id)
    }

    /// Returns this node's own `PeerId`.
    ///
    /// This accessor is infallible because the [`crate::SwarmBuilder`] requires
    /// a keypair at construction time.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Registers an application protocol id for inbound acceptance and
    /// outbound opens.
    ///
    /// Built-in ids ([`crate::RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]; the swarm's own handlers already
    /// own them.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), DriverError> {
        self.core.add_protocol(protocol_id)?;
        Ok(())
    }

    /// Start listening on the given multiaddr and return the resolved local address.
    pub fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, DriverError> {
        Ok(self.transport.listen(addr)?)
    }

    /// Start listening on the transport's already-bound local addresses.
    ///
    /// Transports that know their bound addresses expose them via
    /// `Transport::local_addresses()`. Multi-socket transports such as a
    /// dual-stack QUIC endpoint can therefore advertise every bound address
    /// without forcing callers to pick one.
    pub fn listen_on_bound_addrs(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        let addrs = self.transport.local_addresses();
        if addrs.is_empty() {
            return Err(TransportError::InvalidConfig {
                reason: "transport does not expose a bound local address".into(),
            }
            .into());
        }

        let mut resolved = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let addr = self.transport.listen(&addr)?;
            let peer_addr = PeerAddr::new(addr, self.local_peer_id.clone()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to build local PeerAddr: {e}"),
                }
            })?;
            resolved.push(peer_addr);
        }
        Ok(resolved)
    }

    /// Start listening on the transport's first already-bound local address.
    ///
    /// Prefer [`Swarm::listen_on_bound_addrs`] for transports that may bind
    /// more than one socket.
    pub fn listen_on_bound_addr(&mut self) -> Result<PeerAddr, DriverError> {
        let addr = self
            .transport
            .local_addresses()
            .into_iter()
            .next()
            .ok_or_else(|| TransportError::InvalidConfig {
                reason: "transport does not expose a bound local address".into(),
            })?;
        let addr = self.transport.listen(&addr)?;
        Ok(
            PeerAddr::new(addr, self.local_peer_id.clone()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to build local PeerAddr: {e}"),
                }
            })?,
        )
    }

    /// Dial a remote peer. The transport allocates the connection id.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, DriverError> {
        Ok(self.transport.dial(addr)?)
    }

    /// Pings a peer, sending a random 32-byte payload and measuring RTT.
    ///
    /// If a ping stream isn't yet negotiated the payload is queued and
    /// fires when the stream becomes ready. The resulting RTT is delivered
    /// via [`SwarmEvent::PingRttMeasured`] on the next `poll()`.
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), DriverError> {
        let payload = rand_ping_payload();
        self.core.ping(peer_id, payload, self.now_ms())?;
        self.flush_actions();
        Ok(())
    }

    /// Close the connection to a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), DriverError> {
        self.core.disconnect(peer_id)?;
        self.flush_actions();
        Ok(())
    }

    /// Opens a new outbound stream and negotiates `protocol_id` via
    /// multistream-select.
    ///
    /// The protocol must have been registered via
    /// [`Swarm::add_protocol`] first. When negotiation completes the
    /// [`SwarmEvent::StreamReady`] event fires with the allocated
    /// stream id; subsequent stream data arrives as
    /// [`SwarmEvent::StreamData`].
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<StreamId, DriverError> {
        // Flush anything already queued first, so the capture window below
        // contains only this call's own action cascade. A failure from an
        // unrelated, previously queued open must surface asynchronously as
        // SwarmEvent::Error -- not as this caller's synchronous error.
        self.flush_actions();

        // The core emits a Pending OpenStream action; we drain it now so
        // the transport.open_stream call happens synchronously and we can
        // return the allocated StreamId to the caller (for DX symmetry
        // with the previous API).
        self.core.open_stream(peer_id, protocol_id)?;

        // Flush all actions, capturing the stream id allocated for this
        // user-protocol open. We inspect actions as we execute them.
        // `window_start` marks where this call's events begin in the buffer
        // so a synchronously reported failure can suppress its duplicate
        // buffered event below.
        let window_start = self.event_buffer.len();
        let mut allocated_stream: Option<StreamId> = None;
        let mut open_error: Option<TransportError> = None;
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) => {
                    self.dispatch_action(action, &mut allocated_stream, &mut open_error, &mut None);
                }
                SwarmOutput::Event(event) => self.event_buffer.push_back(event),
            }
        }

        // Any cascade from dispatch_action (e.g. MSS header SendStream) is
        // already in the core's action queue. Drain those too.
        self.flush_actions();

        if let Some(error) = open_error {
            // The failure is reported synchronously through Err, so drop the
            // OpenStreamFailed event this call buffered -- applications must
            // not observe the same failure twice. Failures outside a
            // synchronous call keep flowing as SwarmEvent::Error.
            if let Some(index) = (window_start..self.event_buffer.len()).find(|&i| {
                matches!(
                    &self.event_buffer[i],
                    SwarmEvent::Error(e) if e.kind == SwarmErrorKind::OpenStreamFailed
                )
            }) {
                self.event_buffer.remove(index);
            }
            return Err(DriverError::Transport(error));
        }
        allocated_stream.ok_or(DriverError::Invariant {
            reason: "core did not allocate a stream id for open_stream",
        })
    }

    /// Sends raw bytes on a negotiated user stream.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), DriverError> {
        // Flush anything already queued first, so the capture window below
        // contains only this call's own action cascade (same discipline as
        // `Swarm::open_stream`).
        self.flush_actions();

        self.core.send_stream(peer_id, stream_id, data)?;

        // Dispatch this call's own actions synchronously, capturing a
        // transport rejection. Callers that commit state once a stream
        // closes (e.g. the pubsub one-shot sender) must learn that the
        // write was never accepted -- a buffered error event carries no
        // stream correlation to recover that from.
        let window_start = self.event_buffer.len();
        let mut send_error: Option<TransportError> = None;
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) => {
                    self.dispatch_action(action, &mut None, &mut None, &mut send_error);
                }
                SwarmOutput::Event(event) => self.event_buffer.push_back(event),
            }
        }
        self.flush_actions();

        if let Some(error) = send_error {
            // Reported synchronously through Err: drop the duplicate
            // buffered runtime-error event this call produced.
            if let Some(index) = (window_start..self.event_buffer.len()).find(|&i| {
                matches!(
                    &self.event_buffer[i],
                    SwarmEvent::Error(e) if e.kind == SwarmErrorKind::Transport
                )
            }) {
                self.event_buffer.remove(index);
            }
            return Err(DriverError::Transport(error));
        }
        Ok(())
    }

    /// Half-closes the write side of a user stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), DriverError> {
        self.core.close_stream_write(peer_id, stream_id)?;
        self.flush_actions();
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), DriverError> {
        self.core.reset_stream(peer_id, stream_id)?;
        self.flush_actions();
        Ok(())
    }

    /// Drive the swarm: poll transport, feed events to core, dispatch
    /// actions, return application-visible events. Must be called repeatedly.
    ///
    /// Most event-loop code can be simpler to write against
    /// [`Swarm::poll_next`] or [`Swarm::run_until`], which internally
    /// call this in a sleep/poll loop and return one event at a time.
    pub fn poll(&mut self) -> Result<Vec<SwarmEvent>, DriverError> {
        let now_ms = self.now_ms();

        // 0. Refresh the core's snapshot of our listening addresses so
        //    Identify advertises the current bound set plus any validated
        //    external addresses. Cheap -- a handful of multiaddrs at most.
        let mut local_addresses = self.transport.local_addresses();
        for addr in &self.external_addresses {
            if !local_addresses.contains(addr) {
                local_addresses.push(addr.clone());
            }
        }
        self.core.set_local_addresses(local_addresses);

        // 1. Feed transport events to the core.
        let events = self.transport.poll()?;
        for event in events {
            self.core
                .handle_input(SwarmInput::Transport { event, now_ms });
        }

        // 2. Advance timers.
        self.core.handle_input(SwarmInput::Tick { now_ms });

        // 3. Execute all queued actions (may cascade -- see flush_actions).
        self.flush_actions();

        // 4. Return the application's events.
        let mut events: Vec<SwarmEvent> = self.event_buffer.drain(..).collect();
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) => {
                    self.dispatch_action(action, &mut None, &mut None, &mut None)
                }
                SwarmOutput::Event(event) => events.push(event),
            }
        }
        Ok(events)
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
        deadline: impl Into<Deadline>,
    ) -> Result<Option<SwarmEvent>, DriverError> {
        let deadline = deadline.into();
        loop {
            if let Some(ev) = self.event_buffer.pop_front() {
                return Ok(Some(ev));
            }
            // Always poll at least once -- even if we're already past the
            // deadline -- so a caller using a short or elapsed deadline
            // still sees any events the transport has already produced.
            let events = self.poll()?;
            self.event_buffer.extend(events);
            if let Some(ev) = self.event_buffer.pop_front() {
                return Ok(Some(ev));
            }
            let now = Instant::now();
            if deadline.is_expired_at(now) {
                return Ok(None);
            }
            // Budget: never sleep past the caller's deadline, the
            // transport's next protocol timer, or the core's next internal
            // timer (e.g. a ping timeout, which only fires when a Tick is
            // fed into the core by `poll()`).
            let mut budget = deadline.remaining_at(now).unwrap_or(MAX_IDLE_WAIT);
            if let Some(timeout) = self.transport.next_timeout() {
                budget = budget.min(timeout);
            }
            if let Some(timeout_ms) = self.core.next_timeout(self.now_ms()) {
                budget = budget.min(Duration::from_millis(timeout_ms));
            }
            if budget.is_zero() {
                continue;
            }
            // Prefer a real readiness wait so idle loops don't burn CPU on a
            // fixed cadence; fall back to a short sleep for transports that
            // can't wait.
            if self.transport.wait_for_input(budget) == WaitOutcome::Unsupported {
                std::thread::sleep(budget.min(POLL_IDLE_SLEEP));
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
    /// this way; an unbounded wait (e.g. [`Deadline::NEVER`]) must not buffer
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
        deadline: impl Into<Deadline>,
        mut predicate: F,
    ) -> Result<Option<SwarmEvent>, DriverError>
    where
        F: FnMut(&SwarmEvent) -> bool,
    {
        let deadline = deadline.into();
        let mut skipped = VecDeque::new();
        let mut result = Ok(None);

        // Phase 1: before the deadline, wait for fresh events normally.
        // `poll_next` sleeps between transport polls with a bounded budget.
        let mut polled_past_deadline = false;
        while !deadline.is_expired_at(Instant::now()) {
            match self.poll_next(deadline) {
                Err(error) => {
                    result = Err(error);
                    break;
                }
                // Deadline expired while idle. `poll_next` has already done
                // its final "at least once" transport poll and found the
                // buffer empty, so the drain below must not poll again.
                Ok(None) => {
                    polled_past_deadline = true;
                    break;
                }
                Ok(Some(ev)) => {
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

        // Phase 2: past the deadline, still scan everything that is already
        // synchronously available: the buffered events plus at most one
        // transport poll.
        if matches!(result, Ok(None)) {
            loop {
                let Some(ev) = self.event_buffer.pop_front() else {
                    if polled_past_deadline {
                        break;
                    }
                    polled_past_deadline = true;
                    match self.poll() {
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                        Ok(events) => {
                            self.event_buffer.extend(events);
                            continue;
                        }
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

        // Restore skipped events in their original order -- on a match, on
        // deadline expiry, and on error alike.
        for event in skipped.into_iter().rev() {
            self.event_buffer.push_front(event);
        }
        result
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Drains all actions from the core and dispatches each to the
    /// transport, repeating until the core has nothing left. This handles
    /// cascades where executing an action causes the core to emit more
    /// (e.g. `OpenStream` leading to `SendStream` once the stream id is
    /// reported back).
    fn flush_actions(&mut self) {
        let mut allocated: Option<StreamId> = None;
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) => {
                    self.dispatch_action(action, &mut allocated, &mut None, &mut None)
                }
                SwarmOutput::Event(event) => self.event_buffer.push_back(event),
            }
        }
    }

    /// Executes a single action against the transport and feeds any result
    /// back into the core.
    ///
    /// `captured_stream_id` is used by [`Swarm::open_stream`] to
    /// synchronously recover the stream id for the caller. The driver
    /// remembers the **last** stream id allocated during the flush, which
    /// is accurate because `open_stream` triggers exactly one
    /// `OpenStream` action per call.
    fn dispatch_action(
        &mut self,
        action: SwarmAction,
        captured_stream_id: &mut Option<StreamId>,
        captured_open_error: &mut Option<TransportError>,
        captured_send_error: &mut Option<TransportError>,
    ) {
        match action {
            SwarmAction::OpenStream { conn_id, token } => match self.transport.open_stream(conn_id)
            {
                Ok(stream_id) => {
                    *captured_stream_id = Some(stream_id);
                    self.core.handle_input(SwarmInput::StreamOpened {
                        conn_id,
                        stream_id,
                        token,
                        now_ms: self.now_ms(),
                    });
                }
                Err(e) => {
                    let reason = format!("{e}");
                    *captured_open_error = Some(e);
                    self.core.handle_input(SwarmInput::OpenStreamFailed {
                        token,
                        reason,
                        now_ms: self.now_ms(),
                    });
                }
            },
            SwarmAction::SendStream {
                conn_id,
                stream_id,
                data,
            } => {
                if let Err(e) = self.transport.send_stream(conn_id, stream_id, data) {
                    let reason = format!(
                        "send_stream to connection {conn_id} stream {stream_id} failed: {e}"
                    );
                    *captured_send_error = Some(e);
                    self.core
                        .handle_input(SwarmInput::RuntimeError(runtime_error(
                            SwarmErrorKind::Transport,
                            Some(conn_id),
                            reason,
                        )));
                }
            }
            SwarmAction::CloseStreamWrite { conn_id, stream_id } => {
                if let Err(e) = self.transport.close_stream_write(conn_id, stream_id) {
                    self.core.handle_input(SwarmInput::RuntimeError(runtime_error(
                        SwarmErrorKind::Transport,
                        Some(conn_id),
                        format!(
                            "close_stream_write on connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    )));
                }
            }
            SwarmAction::ResetStream { conn_id, stream_id } => {
                if let Err(e) = self.transport.reset_stream(conn_id, stream_id) {
                    self.core.handle_input(SwarmInput::RuntimeError(runtime_error(
                        SwarmErrorKind::Transport,
                        Some(conn_id),
                        format!(
                            "reset_stream on connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    )));
                }
            }
            SwarmAction::CloseConnection { conn_id } => {
                if let Err(e) = self.transport.close(conn_id) {
                    self.core
                        .handle_input(SwarmInput::RuntimeError(runtime_error(
                            SwarmErrorKind::Transport,
                            Some(conn_id),
                            format!("close on connection {conn_id} failed: {e}"),
                        )));
                }
            }
        }
    }
}

fn runtime_error(
    kind: SwarmErrorKind,
    conn_id: Option<ConnectionId>,
    detail: String,
) -> SwarmRuntimeError {
    SwarmRuntimeError {
        kind,
        peer_id: None,
        conn_id,
        detail,
    }
}

/// Generates a random 32-byte ping payload using OS randomness, falling
/// back to a deterministic-but-non-repeating pattern seeded from the wall
/// clock if the CSPRNG is unavailable.
fn rand_ping_payload() -> [u8; PING_PAYLOAD_LEN] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut payload = [0u8; PING_PAYLOAD_LEN];
    if getrandom::fill(&mut payload).is_ok() {
        return payload;
    }

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = ((seed >> (i % 8)) as u8) ^ (i as u8);
    }
    payload
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use minip2p_core::SansIoProtocol;
    use minip2p_identify::IDENTIFY_PROTOCOL_ID;
    use minip2p_identity::Ed25519Keypair;
    use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
    use minip2p_ping::PING_PROTOCOL_ID;
    use minip2p_transport::{ConnectionEndpoint, TransportEvent};

    /// Transport that never produces events; counts `poll()` calls so tests
    /// can assert how often an expired wait touches the transport.
    #[derive(Default)]
    struct IdleTransport {
        poll_calls: usize,
    }

    impl Transport for IdleTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            unreachable!()
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
            self.poll_calls += 1;
            Ok(Vec::new())
        }
    }

    /// Transport whose `open_stream` fails on exactly one (1-based) call and
    /// succeeds otherwise, returning the call index as the stream id.
    struct FailingUserOpenTransport {
        events: VecDeque<TransportEvent>,
        open_calls: usize,
        fail_on_call: usize,
    }

    impl FailingUserOpenTransport {
        fn connected(peer_id: PeerId, fail_on_call: usize) -> Self {
            let endpoint = ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
            Self {
                events: VecDeque::from([TransportEvent::Connected {
                    id: ConnectionId::new(1),
                    endpoint,
                }]),
                open_calls: 0,
                fail_on_call,
            }
        }
    }

    impl Transport for FailingUserOpenTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            self.open_calls += 1;
            if self.open_calls == self.fail_on_call {
                Err(TransportError::ResourceExhausted {
                    resource: "test stream capacity",
                })
            } else {
                Ok(StreamId::new(self.open_calls as u64))
            }
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

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            Ok(())
        }

        fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(self.events.drain(..).collect())
        }
    }

    /// Swarm over an [`IdleTransport`] with throwaway identity and defaults.
    fn idle_swarm() -> Swarm<IdleTransport> {
        let keypair = Ed25519Keypair::generate();
        let identify = IdentifyConfig {
            protocol_version: "test/1".into(),
            agent_version: "test/1".into(),
            protocols: Vec::new(),
            public_key: keypair.public_key().encode_protobuf(),
        };
        Swarm::new(
            IdleTransport::default(),
            identify,
            PingConfig::default(),
            keypair.peer_id(),
        )
    }

    #[test]
    fn external_addresses_merge_into_the_identify_snapshot() {
        let mut swarm = idle_swarm();
        let external: Multiaddr = "/ip4/203.0.113.9/udp/4001/quic-v1".parse().unwrap();
        let circuit: Multiaddr = "/ip4/203.0.113.1/udp/4001/quic-v1/p2p-circuit"
            .parse()
            .unwrap();

        swarm.set_external_addresses(vec![external.clone(), circuit.clone()]);
        swarm.poll().unwrap();
        // IdleTransport binds nothing, so the snapshot is exactly the
        // external set.
        assert_eq!(swarm.core().local_addresses(), &[external.clone(), circuit]);

        // Replacing the set (here: clearing it) stops advertising extras.
        swarm.set_external_addresses(Vec::new());
        swarm.poll().unwrap();
        assert!(swarm.core().local_addresses().is_empty());
    }

    #[test]
    fn deadline_earliest_picks_the_sooner_deadline() {
        let soon = Deadline::from(Duration::from_millis(10));
        let later = Deadline::from(Duration::from_secs(60));
        assert_eq!(soon.earliest(later), soon);
        assert_eq!(later.earliest(soon), soon);
        assert_eq!(Deadline::NEVER.earliest(soon), soon);
        assert_eq!(soon.earliest(Deadline::NEVER), soon);
        assert_eq!(Deadline::NEVER.earliest(Deadline::NEVER), Deadline::NEVER);
    }

    #[test]
    fn deadline_conversions_cover_instant_duration_and_never() {
        // A relative Duration lands in the future.
        let relative: Deadline = Duration::from_secs(1).into();
        assert!(!relative.is_expired_at(Instant::now()));
        assert!(relative.remaining_at(Instant::now()).is_some());

        // A Duration too large for Instant arithmetic degrades to NEVER.
        let unbounded: Deadline = Duration::MAX.into();
        assert_eq!(unbounded, Deadline::NEVER);

        // NEVER neither expires nor bounds the wait budget.
        assert!(!Deadline::NEVER.is_expired_at(Instant::now()));
        assert_eq!(Deadline::NEVER.remaining_at(Instant::now()), None);

        // An Instant behaves as an absolute deadline.
        let past = Deadline::at(Instant::now());
        assert!(past.is_expired_at(Instant::now() + Duration::from_millis(1)));
    }

    #[test]
    fn poll_next_with_never_deadline_returns_buffered_event() {
        let peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        swarm
            .event_buffer
            .push_back(SwarmEvent::ConnectionEstablished {
                peer_id: peer_id.clone(),
            });

        let event = swarm
            .poll_next(Deadline::NEVER)
            .expect("poll")
            .expect("buffered event");
        assert!(matches!(
            event,
            SwarmEvent::ConnectionEstablished { peer_id: p } if p == peer_id
        ));
    }

    #[test]
    fn run_until_preserves_non_matching_events() {
        let target_peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        swarm
            .event_buffer
            .push_back(SwarmEvent::ConnectionEstablished {
                peer_id: target_peer_id.clone(),
            });
        swarm.event_buffer.push_back(SwarmEvent::PeerReady {
            peer_id: target_peer_id.clone(),
            protocols: Vec::new(),
        });

        let found = swarm
            .run_until(Instant::now() + Duration::from_secs(1), |event| {
                matches!(event, SwarmEvent::PeerReady { .. })
            })
            .expect("wait")
            .expect("matching event");
        assert!(matches!(found, SwarmEvent::PeerReady { .. }));

        let restored = swarm
            .poll_next(Instant::now())
            .expect("poll")
            .expect("restored event");
        assert!(matches!(
            restored,
            SwarmEvent::ConnectionEstablished { peer_id } if peer_id == target_peer_id
        ));
    }

    #[test]
    fn run_until_honors_expired_deadline_with_buffered_events() {
        let peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        swarm
            .event_buffer
            .push_back(SwarmEvent::ConnectionEstablished {
                peer_id: peer_id.clone(),
            });
        swarm.event_buffer.push_back(SwarmEvent::PeerReady {
            peer_id,
            protocols: Vec::new(),
        });

        let found = swarm
            .run_until(Instant::now(), |event| {
                matches!(event, SwarmEvent::PingRttMeasured { .. })
            })
            .expect("wait");
        assert!(found.is_none(), "no buffered event matches the predicate");
        assert_eq!(
            swarm.transport().poll_calls,
            1,
            "an expired wait must poll the transport at most once"
        );
        assert_eq!(swarm.event_buffer.len(), 2, "events must be preserved");
        assert!(matches!(
            swarm.event_buffer.front(),
            Some(SwarmEvent::ConnectionEstablished { .. })
        ));
        assert!(matches!(
            swarm.event_buffer.back(),
            Some(SwarmEvent::PeerReady { .. })
        ));
    }

    #[test]
    fn run_until_finds_buffered_match_in_second_position_past_deadline() {
        let peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        swarm
            .event_buffer
            .push_back(SwarmEvent::ConnectionEstablished {
                peer_id: peer_id.clone(),
            });
        swarm.event_buffer.push_back(SwarmEvent::PeerReady {
            peer_id: peer_id.clone(),
            protocols: Vec::new(),
        });

        // Regression: the deadline is already expired, but the matching
        // event sits *behind* a non-matching one. The scan must still reach
        // it instead of bailing after the first rejection.
        let found = swarm
            .run_until(Instant::now() - Duration::from_secs(1), |event| {
                matches!(event, SwarmEvent::PeerReady { .. })
            })
            .expect("wait")
            .expect("buffered match must be found past the deadline");
        assert!(matches!(found, SwarmEvent::PeerReady { .. }));

        // The skipped event is restored in order and no extra events appear.
        assert_eq!(swarm.event_buffer.len(), 1);
        assert!(matches!(
            swarm.event_buffer.front(),
            Some(SwarmEvent::ConnectionEstablished { peer_id: restored }) if *restored == peer_id
        ));
    }

    /// Swarm over a [`FailingUserOpenTransport`] that has already processed
    /// the initial `Connected` event (which consumes `open_stream` call 1
    /// for the auto-opened identify stream).
    fn connected_swarm(
        remote_peer: &PeerId,
        protocol: &str,
        fail_on_call: usize,
    ) -> Swarm<FailingUserOpenTransport> {
        let keypair = Ed25519Keypair::generate();
        let identify = IdentifyConfig {
            protocol_version: "test/1".into(),
            agent_version: "test/1".into(),
            protocols: vec![protocol.into()],
            public_key: keypair.public_key().encode_protobuf(),
        };
        let transport = FailingUserOpenTransport::connected(remote_peer.clone(), fail_on_call);
        let mut swarm = Swarm::new(
            transport,
            identify,
            PingConfig::default(),
            keypair.peer_id(),
        );
        swarm
            .add_protocol(protocol)
            .expect("test protocol id is not reserved");
        swarm.poll().expect("process connected event");
        swarm
    }

    fn buffered_open_failures(swarm: &Swarm<FailingUserOpenTransport>) -> usize {
        swarm
            .event_buffer
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    SwarmEvent::Error(error) if error.kind == SwarmErrorKind::OpenStreamFailed
                )
            })
            .count()
    }

    #[test]
    fn stream_open_preserves_transport_error_type() {
        const PROTOCOL: &str = "/test/1.0.0";
        let remote_peer = Ed25519Keypair::generate().peer_id();
        // open_stream call 1 = identify (ok), call 2 = the user's open (fails).
        let mut swarm = connected_swarm(&remote_peer, PROTOCOL, 2);

        let error = swarm
            .open_stream(&remote_peer, PROTOCOL)
            .expect_err("transport must reject user stream");
        assert!(matches!(
            error,
            DriverError::Transport(TransportError::ResourceExhausted {
                resource: "test stream capacity"
            })
        ));
        assert!(swarm.core.is_idle(), "failed open must clear core state");
        // The failure is reported synchronously via Err; it must not be
        // double-reported through a buffered SwarmEvent::Error.
        assert_eq!(
            buffered_open_failures(&swarm),
            0,
            "synchronous Err must suppress the duplicate buffered event"
        );
    }

    #[test]
    fn stream_open_not_misattributed_to_queued_failure() {
        const PROTOCOL: &str = "/test/1.0.0";
        let remote_peer = Ed25519Keypair::generate().peer_id();
        // open_stream call 1 = identify (ok), call 2 = the stale queued open
        // (fails), call 3 = the caller's own open (ok).
        let mut swarm = connected_swarm(&remote_peer, PROTOCOL, 2);

        // Queue an unrelated open directly on the core, bypassing the
        // driver's flush, so it is still pending when the application call
        // arrives.
        swarm
            .core
            .open_stream(&remote_peer, PROTOCOL)
            .expect("queue stale open");

        let stream_id = swarm
            .open_stream(&remote_peer, PROTOCOL)
            .expect("the caller's own open succeeds; the stale failure is not its error");
        assert_eq!(stream_id, StreamId::new(3), "caller gets its own stream id");

        // The stale open's failure was not tied to a synchronous call, so it
        // must keep flowing to the application as SwarmEvent::Error.
        assert_eq!(
            buffered_open_failures(&swarm),
            1,
            "asynchronous failure must surface exactly once"
        );
    }

    /// Transport that completes multistream negotiation for every locally
    /// opened stream (identify, ping, and one user protocol) and then
    /// rejects payload sends on the stream that negotiated the user
    /// protocol.
    struct FailingSendTransport {
        events: VecDeque<TransportEvent>,
        negotiators: BTreeMap<StreamId, MultistreamSelect>,
        next_stream: u64,
        user_protocol: String,
        failing_stream: Option<StreamId>,
    }

    impl FailingSendTransport {
        fn connected(peer_id: PeerId, user_protocol: &str) -> Self {
            let endpoint = ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
            Self {
                events: VecDeque::from([TransportEvent::Connected {
                    id: ConnectionId::new(1),
                    endpoint,
                }]),
                negotiators: BTreeMap::new(),
                next_stream: 1,
                user_protocol: user_protocol.to_string(),
                failing_stream: None,
            }
        }
    }

    impl Transport for FailingSendTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            let stream_id = StreamId::new(self.next_stream);
            self.next_stream += 1;
            let mut listener = MultistreamSelect::listener(vec![
                IDENTIFY_PROTOCOL_ID.to_string(),
                PING_PROTOCOL_ID.to_string(),
                self.user_protocol.clone(),
            ]);
            listener
                .handle_input(MultistreamInput::Start)
                .expect("listener start");
            self.negotiators.insert(stream_id, listener);
            Ok(stream_id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Vec<u8>,
        ) -> Result<(), TransportError> {
            let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
                if self.failing_stream == Some(stream_id) {
                    return Err(TransportError::ResourceExhausted {
                        resource: "test send capacity",
                    });
                }
                // Other negotiated streams (identify, ping): swallow.
                return Ok(());
            };
            negotiator
                .handle_input(MultistreamInput::Data(data))
                .expect("listener negotiation input");
            let mut negotiated_protocol = None;
            let mut outbound = Vec::new();
            while let Some(output) = negotiator.poll_output() {
                match output {
                    MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                    MultistreamOutput::Negotiated { protocol } => {
                        negotiated_protocol = Some(protocol);
                    }
                    other => panic!("unexpected multistream output: {other:?}"),
                }
            }
            if let Some(protocol) = negotiated_protocol {
                self.negotiators.remove(&stream_id);
                if protocol == self.user_protocol {
                    self.failing_stream = Some(stream_id);
                }
            }
            for data in outbound {
                self.events.push_back(TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                });
            }
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

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            Ok(())
        }

        fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(self.events.drain(..).collect())
        }
    }

    #[test]
    fn send_stream_transport_failure_is_a_synchronous_error() {
        const PROTOCOL: &str = "/test/1.0.0";
        let remote_peer = Ed25519Keypair::generate().peer_id();
        let keypair = Ed25519Keypair::generate();
        let identify = IdentifyConfig {
            protocol_version: "test/1".into(),
            agent_version: "test/1".into(),
            protocols: vec![PROTOCOL.into()],
            public_key: keypair.public_key().encode_protobuf(),
        };
        let transport = FailingSendTransport::connected(remote_peer.clone(), PROTOCOL);
        let mut swarm = Swarm::new(
            transport,
            identify,
            PingConfig::default(),
            keypair.peer_id(),
        );
        swarm
            .add_protocol(PROTOCOL)
            .expect("test protocol id is not reserved");
        swarm.poll().expect("process connected event");

        let stream_id = swarm
            .open_stream(&remote_peer, PROTOCOL)
            .expect("open user stream");
        let mut ready = false;
        for _ in 0..5 {
            for event in swarm.poll().expect("drive negotiation") {
                if matches!(
                    &event,
                    SwarmEvent::StreamReady { stream_id: sid, initiated_locally: true, .. }
                        if *sid == stream_id
                ) {
                    ready = true;
                }
            }
            if ready {
                break;
            }
        }
        assert!(ready, "user stream must finish multistream negotiation");

        // The transport rejects the payload write. Callers that commit
        // state once a stream closes (the pubsub one-shot sender) must see
        // this synchronously -- an Ok here would let a never-sent frame
        // commit on StreamClosed.
        let error = swarm
            .send_stream(&remote_peer, stream_id, b"payload".to_vec())
            .expect_err("transport must reject the payload send");
        assert!(matches!(
            error,
            DriverError::Transport(TransportError::ResourceExhausted {
                resource: "test send capacity"
            })
        ));
        // Reported through Err; it must not also surface as a buffered
        // runtime-error event.
        assert!(
            !swarm.event_buffer.iter().any(|event| matches!(
                event,
                SwarmEvent::Error(e) if e.kind == SwarmErrorKind::Transport
            )),
            "synchronous Err must suppress the duplicate buffered event"
        );
    }

    /// A `StreamData` event whose stream id encodes its position, so tests
    /// can assert restoration order after `run_until` skips it.
    fn indexed_stream_data(peer_id: &PeerId, index: u64) -> SwarmEvent {
        SwarmEvent::StreamData {
            peer_id: peer_id.clone(),
            stream_id: StreamId::new(index),
            data: vec![0u8; 8],
        }
    }

    fn assert_indexed_order(swarm: &Swarm<IdleTransport>, expected_len: usize) {
        assert_eq!(
            swarm.event_buffer.len(),
            expected_len,
            "every skipped event must be restored"
        );
        for (i, event) in swarm.event_buffer.iter().enumerate() {
            assert!(
                matches!(
                    event,
                    SwarmEvent::StreamData { stream_id, .. } if *stream_id == StreamId::new(i as u64)
                ),
                "restored event {i} is out of order: {event:?}"
            );
        }
    }

    #[test]
    fn run_until_overflow_returns_error_and_restores_events_in_order() {
        let peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        let total = RUN_UNTIL_SKIP_LIMIT + 5;
        for i in 0..total {
            swarm
                .event_buffer
                .push_back(indexed_stream_data(&peer_id, i as u64));
        }

        // An unbounded wait over a flood of non-matching events must abort
        // at the cap instead of buffering them forever.
        let error = swarm
            .run_until(Deadline::NEVER, |event| {
                matches!(event, SwarmEvent::PingTimeout { .. })
            })
            .expect_err("skip cap must abort an unbounded wait");
        assert!(matches!(
            error,
            DriverError::EventBacklogExceeded { limit } if limit == RUN_UNTIL_SKIP_LIMIT
        ));

        assert_indexed_order(&swarm, total);
    }

    #[test]
    fn run_until_overflow_applies_to_expired_deadline_scan() {
        let peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        let total = RUN_UNTIL_SKIP_LIMIT + 3;
        for i in 0..total {
            swarm
                .event_buffer
                .push_back(indexed_stream_data(&peer_id, i as u64));
        }

        // Past the deadline, the synchronous buffered scan must honor the
        // same cap as the waiting phase.
        let error = swarm
            .run_until(Instant::now() - Duration::from_secs(1), |event| {
                matches!(event, SwarmEvent::PingTimeout { .. })
            })
            .expect_err("skip cap must bound the expired-deadline scan");
        assert!(matches!(
            error,
            DriverError::EventBacklogExceeded { limit } if limit == RUN_UNTIL_SKIP_LIMIT
        ));

        assert_indexed_order(&swarm, total);
    }

    #[test]
    fn run_until_under_cap_still_finds_match() {
        let peer_id = Ed25519Keypair::generate().peer_id();
        let mut swarm = idle_swarm();
        for i in 0..RUN_UNTIL_SKIP_LIMIT - 1 {
            swarm
                .event_buffer
                .push_back(indexed_stream_data(&peer_id, i as u64));
        }
        swarm.event_buffer.push_back(SwarmEvent::PeerReady {
            peer_id: peer_id.clone(),
            protocols: Vec::new(),
        });

        // Exactly RUN_UNTIL_SKIP_LIMIT - 1 events are skipped: one below the
        // cap, so the match right behind them must still be found.
        let found = swarm
            .run_until(Deadline::NEVER, |event| {
                matches!(event, SwarmEvent::PeerReady { .. })
            })
            .expect("wait")
            .expect("match just under the cap");
        assert!(matches!(found, SwarmEvent::PeerReady { .. }));
        assert_indexed_order(&swarm, RUN_UNTIL_SKIP_LIMIT - 1);
    }

    /// Deterministic, manually advanced clock shared between the swarm
    /// driver and a mock transport.
    #[derive(Default)]
    struct TestClock {
        now_ms: AtomicU64,
    }

    impl TestClock {
        fn advance(&self, ms: u64) {
            self.now_ms.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }
    }

    /// Readiness-capable transport simulating a remote peer that accepts any
    /// multistream-select negotiation but never sends protocol data, so an
    /// outbound ping dangles until its timeout. `wait_for_input` records each
    /// budget it is handed and jumps the shared clock, standing in for a
    /// transport that blocks for the full budget on an idle connection.
    struct NeverRespondTransport {
        clock: Arc<TestClock>,
        events: VecDeque<TransportEvent>,
        negotiators: BTreeMap<StreamId, MultistreamSelect>,
        next_stream: u64,
        waits: Vec<Duration>,
        advance_per_wait_ms: u64,
    }

    impl NeverRespondTransport {
        fn connected(clock: Arc<TestClock>, peer_id: PeerId, advance_per_wait_ms: u64) -> Self {
            let endpoint = ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
            Self {
                clock,
                events: VecDeque::from([TransportEvent::Connected {
                    id: ConnectionId::new(1),
                    endpoint,
                }]),
                negotiators: BTreeMap::new(),
                next_stream: 1,
                waits: Vec::new(),
                advance_per_wait_ms,
            }
        }
    }

    impl Transport for NeverRespondTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            let stream_id = StreamId::new(self.next_stream);
            self.next_stream += 1;
            let mut listener = MultistreamSelect::listener(vec![
                IDENTIFY_PROTOCOL_ID.to_string(),
                PING_PROTOCOL_ID.to_string(),
            ]);
            listener
                .handle_input(MultistreamInput::Start)
                .expect("listener start");
            self.negotiators.insert(stream_id, listener);
            Ok(stream_id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Vec<u8>,
        ) -> Result<(), TransportError> {
            let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
                // Stream already negotiated: swallow protocol payloads so
                // pings never receive a response.
                return Ok(());
            };
            negotiator
                .handle_input(MultistreamInput::Data(data))
                .expect("listener negotiation input");
            let mut negotiated = false;
            let mut outbound = Vec::new();
            while let Some(output) = negotiator.poll_output() {
                match output {
                    MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                    MultistreamOutput::Negotiated { .. } => negotiated = true,
                    other => panic!("unexpected multistream output: {other:?}"),
                }
            }
            if negotiated {
                self.negotiators.remove(&stream_id);
            }
            for data in outbound {
                self.events.push_back(TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                });
            }
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

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            Ok(())
        }

        fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(self.events.drain(..).collect())
        }

        fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
            self.waits.push(timeout);
            self.clock.advance(self.advance_per_wait_ms);
            WaitOutcome::TimedOut
        }
    }

    #[test]
    fn poll_next_budget_respects_core_ping_timer() {
        const PING_TIMEOUT_MS: u64 = 5_000;

        let remote_peer = Ed25519Keypair::generate().peer_id();
        let keypair = Ed25519Keypair::generate();
        let identify = IdentifyConfig {
            protocol_version: "test/1".into(),
            agent_version: "test/1".into(),
            protocols: Vec::new(),
            public_key: keypair.public_key().encode_protobuf(),
        };
        let clock = Arc::new(TestClock::default());
        // Each blocking wait pretends the transport slept its full budget
        // and jumps the clock past the ping deadline.
        let transport = NeverRespondTransport::connected(
            clock.clone(),
            remote_peer.clone(),
            PING_TIMEOUT_MS + 1_000,
        );
        let mut swarm = Swarm::with_clock(
            transport,
            identify,
            PingConfig {
                request_timeout_ms: PING_TIMEOUT_MS,
            },
            keypair.peer_id(),
            clock.clone(),
        );

        // Settle connection setup and identify stream negotiation, then get
        // a real ping in flight over the negotiated ping stream.
        for _ in 0..5 {
            swarm.poll().expect("setup poll");
        }
        swarm.ping(&remote_peer).expect("queue ping");
        for _ in 0..5 {
            swarm.poll().expect("negotiate ping stream");
        }
        assert_eq!(
            swarm.core().next_timeout(clock.now_ms()),
            Some(PING_TIMEOUT_MS + 1),
            "ping must be in flight with an armed core timer"
        );

        // Drop setup events (ConnectionEstablished, ...) so poll_next blocks.
        swarm.event_buffer.clear();
        let event = swarm
            .poll_next(Deadline::NEVER)
            .expect("poll")
            .expect("ping timeout event");
        assert!(matches!(
            event,
            SwarmEvent::PingTimeout { peer_id } if peer_id == remote_peer
        ));

        let waits = &swarm.transport().waits;
        assert_eq!(waits.len(), 1, "one blocking wait resolves the timer");
        assert_eq!(
            waits[0],
            Duration::from_millis(PING_TIMEOUT_MS + 1),
            "wait budget must shrink to the core's ping deadline instead of MAX_IDLE_WAIT"
        );
    }
}
