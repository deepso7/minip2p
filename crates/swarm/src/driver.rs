//! Std driver that owns a [`Transport`] and drives [`SwarmCore`].
//!
//! This is the DX-friendly entrypoint for applications: it tracks wall
//! time internally, auto-allocates connection ids, and translates between
//! the Sans-I/O core's actions and concrete transport calls.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_identify::IdentifyConfig;
use minip2p_ping::{PingConfig, PING_PAYLOAD_LEN};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

use crate::core::SwarmCore;
use crate::events::{SwarmAction, SwarmError, SwarmEvent};

/// Sleep cadence when [`Swarm::poll_next`] idles.
///
/// 1ms is short enough that single-digit-millisecond RTTs are
/// observable on loopback (two wakeups bound RTT, so ~2ms floor)
/// without noticeably burning CPU on idle. The transport's `poll()` is
/// a non-blocking `recvfrom` that returns `WouldBlock` immediately
/// when there's no data, so the hot loop is cheap.
const POLL_IDLE_SLEEP: Duration = Duration::from_millis(1);

/// Thin std driver wrapping [`SwarmCore`] and a concrete [`Transport`].
///
/// Preserves the one-call DX built on top of the core:
/// - `dial(addr) -> ConnectionId` auto-allocates the connection id.
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

    /// Auto-incrementing connection-id counter for outbound dials.
    next_connection_id: u64,
    /// Start of the logical clock. The driver tracks wall time so callers
    /// don't have to thread `now_ms` through every method.
    start: Instant,
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
        Self {
            transport,
            core: SwarmCore::new(identify_config, ping_config),
            local_peer_id,
            event_buffer: VecDeque::new(),
            next_connection_id: 1,
            start: Instant::now(),
        }
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

    /// Returns this node's own `PeerId`.
    ///
    /// Unlike `swarm.transport().local_peer_id()` (transport-specific and
    /// `Option`-wrapped), this accessor is infallible because the
    /// [`crate::SwarmBuilder`] requires a keypair at construction time.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Registers a user protocol id for inbound acceptance and outbound opens.
    pub fn add_user_protocol(&mut self, protocol_id: impl Into<String>) {
        self.core.add_user_protocol(protocol_id);
    }

    /// Start listening on the given multiaddr.
    pub fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError> {
        self.transport.listen(addr)
    }

    /// Dial a remote peer. Swarm auto-allocates a connection id.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.allocate_connection_id();
        self.transport.dial(id, addr)?;
        self.core.on_dialed(id);
        Ok(id)
    }

    /// Pings a peer, sending a random 32-byte payload and measuring RTT.
    ///
    /// If a ping stream isn't yet negotiated the payload is queued and
    /// fires when the stream becomes ready. The resulting RTT is delivered
    /// via [`SwarmEvent::PingRttMeasured`] on the next `poll()`.
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), TransportError> {
        let payload = rand_ping_payload();
        self.core
            .ping(peer_id, payload, self.now_ms())
            .map_err(swarm_to_transport_error)?;
        self.flush_actions();
        Ok(())
    }

    /// Close the connection to a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), TransportError> {
        self.core
            .disconnect(peer_id)
            .map_err(swarm_to_transport_error)?;
        self.flush_actions();
        Ok(())
    }

    /// Opens a new outbound stream and negotiates `protocol_id` via
    /// multistream-select.
    ///
    /// The protocol must have been registered via
    /// [`Swarm::add_user_protocol`] first. When negotiation completes the
    /// [`SwarmEvent::UserStreamReady`] event fires with the allocated
    /// stream id; subsequent stream data arrives as
    /// [`SwarmEvent::UserStreamData`].
    pub fn open_user_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<StreamId, TransportError> {
        // The core emits a Pending OpenStream action; we drain it now so
        // the transport.open_stream call happens synchronously and we can
        // return the allocated StreamId to the caller (for DX symmetry
        // with the previous API).
        self.core
            .open_user_stream(peer_id, protocol_id)
            .map_err(swarm_to_transport_error)?;

        // Flush all actions, capturing the stream id allocated for this
        // user-protocol open. We inspect actions as we execute them.
        let actions = self.core.take_actions();
        let mut allocated_stream: Option<StreamId> = None;
        for action in actions {
            self.dispatch_action(action, &mut allocated_stream);
        }

        // Any cascade from dispatch_action (e.g. MSS header SendStream) is
        // already in the core's action queue. Drain those too.
        self.flush_actions();

        allocated_stream.ok_or_else(|| TransportError::PollError {
            reason: "core did not allocate a stream id for open_user_stream".into(),
        })
    }

    /// Sends raw bytes on a negotiated user stream.
    pub fn send_user_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.core
            .send_user_stream(peer_id, stream_id, data)
            .map_err(swarm_to_transport_error)?;
        self.flush_actions();
        Ok(())
    }

    /// Half-closes the write side of a user stream.
    pub fn close_user_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.core
            .close_user_stream_write(peer_id, stream_id)
            .map_err(swarm_to_transport_error)?;
        self.flush_actions();
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_user_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.core
            .reset_user_stream(peer_id, stream_id)
            .map_err(swarm_to_transport_error)?;
        self.flush_actions();
        Ok(())
    }

    /// Drive the swarm: poll transport, feed events to core, dispatch
    /// actions, return application-visible events. Must be called repeatedly.
    ///
    /// Most event-loop code can be simpler to write against
    /// [`Swarm::poll_next`] or [`Swarm::run_until`], which internally
    /// call this in a sleep/poll loop and return one event at a time.
    pub fn poll(&mut self) -> Result<Vec<SwarmEvent>, TransportError> {
        let now_ms = self.now_ms();

        // 0. Refresh the core's snapshot of our listening addresses so
        //    Identify advertises the current bound set. Cheap -- a
        //    handful of multiaddrs at most.
        self.core
            .set_local_addresses(self.transport.local_addresses());

        // 1. Feed transport events to the core.
        let events = self.transport.poll()?;
        for event in events {
            self.core.on_transport_event(event, now_ms);
        }

        // 2. Advance timers.
        self.core.on_tick(now_ms);

        // 3. Execute all queued actions (may cascade -- see flush_actions).
        self.flush_actions();

        // 4. Return the application's events.
        Ok(self.core.poll_events())
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
        deadline: Instant,
    ) -> Result<Option<SwarmEvent>, TransportError> {
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
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL_IDLE_SLEEP);
        }
    }

    /// Polls events in a loop, returning the first one for which
    /// `predicate` returns `true`, or `Ok(None)` if `deadline` expires
    /// first.
    ///
    /// `predicate` sees every event as it arrives (even the ones that
    /// don't trigger a return), so it's the natural place to put event
    /// logging. Events for which `predicate` returns `false` are
    /// discarded.
    pub fn run_until<F>(
        &mut self,
        deadline: Instant,
        mut predicate: F,
    ) -> Result<Option<SwarmEvent>, TransportError>
    where
        F: FnMut(&SwarmEvent) -> bool,
    {
        loop {
            match self.poll_next(deadline)? {
                None => return Ok(None),
                Some(ev) => {
                    if predicate(&ev) {
                        return Ok(Some(ev));
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn allocate_connection_id(&mut self) -> ConnectionId {
        loop {
            let raw = self.next_connection_id;
            self.next_connection_id = self.next_connection_id.wrapping_add(1);
            if raw != 0 {
                return ConnectionId::new(raw);
            }
        }
    }

    /// Drains all actions from the core and dispatches each to the
    /// transport, repeating until the core has nothing left. This handles
    /// cascades where executing an action causes the core to emit more
    /// (e.g. `OpenStream` leading to `SendStream` once the stream id is
    /// reported back).
    fn flush_actions(&mut self) {
        let mut allocated: Option<StreamId> = None;
        loop {
            let actions = self.core.take_actions();
            if actions.is_empty() {
                break;
            }
            for action in actions {
                self.dispatch_action(action, &mut allocated);
            }
        }
    }

    /// Executes a single action against the transport and feeds any result
    /// back into the core.
    ///
    /// `captured_stream_id` is used by [`Swarm::open_user_stream`] to
    /// synchronously recover the stream id for the caller. The driver
    /// remembers the **last** stream id allocated during the flush, which
    /// is accurate because `open_user_stream` triggers exactly one
    /// `OpenStream` action per call.
    fn dispatch_action(
        &mut self,
        action: SwarmAction,
        captured_stream_id: &mut Option<StreamId>,
    ) {
        match action {
            SwarmAction::OpenStream { conn_id, token } => match self.transport.open_stream(conn_id) {
                Ok(stream_id) => {
                    *captured_stream_id = Some(stream_id);
                    self.core
                        .on_stream_opened(conn_id, stream_id, token, self.now_ms());
                }
                Err(e) => {
                    let reason = format!("{e}");
                    self.core.on_open_stream_failed(token, reason, self.now_ms());
                }
            },
            SwarmAction::SendStream {
                conn_id,
                stream_id,
                data,
            } => {
                if let Err(e) = self.transport.send_stream(conn_id, stream_id, data) {
                    self.core.record_error(format!(
                        "send_stream to connection {conn_id} stream {stream_id} failed: {e}"
                    ));
                }
            }
            SwarmAction::CloseStreamWrite { conn_id, stream_id } => {
                if let Err(e) = self.transport.close_stream_write(conn_id, stream_id) {
                    self.core.record_error(format!(
                        "close_stream_write on connection {conn_id} stream {stream_id} failed: {e}"
                    ));
                }
            }
            SwarmAction::ResetStream { conn_id, stream_id } => {
                if let Err(e) = self.transport.reset_stream(conn_id, stream_id) {
                    self.core.record_error(format!(
                        "reset_stream on connection {conn_id} stream {stream_id} failed: {e}"
                    ));
                }
            }
            SwarmAction::CloseConnection { conn_id } => {
                if let Err(e) = self.transport.close(conn_id) {
                    self.core.record_error(format!(
                        "close on connection {conn_id} failed: {e}"
                    ));
                }
            }
        }
    }
}

/// Bridges a [`SwarmError`] to the driver's public `TransportError` surface.
///
/// We keep the std-facing error type as `TransportError` so callers that
/// already handle transport errors don't have to add a new variant path.
fn swarm_to_transport_error(err: SwarmError) -> TransportError {
    match err {
        SwarmError::NotConnected { peer_id } => TransportError::PollError {
            reason: format!("peer {peer_id} is not connected"),
        },
        SwarmError::ProtocolNotRegistered { protocol_id } => TransportError::InvalidConfig {
            reason: format!(
                "protocol '{protocol_id}' is not registered; call add_user_protocol first"
            ),
        },
        SwarmError::PingError { reason } => TransportError::PollError {
            reason: format!("ping error: {reason}"),
        },
        SwarmError::IdentifyError { reason } => TransportError::PollError {
            reason: format!("identify error: {reason}"),
        },
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


